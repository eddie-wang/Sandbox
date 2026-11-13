use std::{pin::Pin, sync::Arc, task::{Context, Poll}, time::Duration};
use axum::{Json, Router, body::{Body, Bytes}, extract::{Path, Request, State, rejection::{JsonRejection, PathRejection}}, http::{StatusCode, header}, response::{IntoResponse, Response}, routing::{get, post}};
use hyper::body::Frame;
use serde::Serialize;
use crate::{config::WorkerConfig, engine::{ExecEvent, ExecSink, Handle, Outcome, Reply, Work}, http::{self, ApiError}, lifecycle::Health,
    model::{CaptureRequest, CreateRequest, ExecRequest, sandbox_owner, valid_id}, native::ExecEnd};

// Return a safe service-unavailable error for a disabled or failed runtime.
fn unavailable() -> ApiError { ApiError(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable", "Runtime is disabled or preflight failed") }
// Extract the sandbox ID and require its owner to match this worker.
fn id(handle: &Handle, input: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(id) = input.map_err(|_| http::invalid_input())?;
    let node = handle.snapshot.read().map_err(|_| unavailable())?.status.node_id.clone();
    if sandbox_owner(&id) != Some(node.as_str()) { return Err(http::invalid_input()); }
    Ok(id)
}
// Map an engine/runtime error code to its HTTP status and fixed message. Unlisted runtime failures
// are 500 with their static code. Too many waiting DELETE or kill requests answer with the public
// `busy` code.
fn failure(code: &'static str) -> ApiError {
    if code == "waiter_limit" {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Too many requests already wait for this delete or kill; nothing was started");
    }
    let (status, message) = match code {
        "sandbox_not_found" => (StatusCode::NOT_FOUND, "Sandbox does not exist"),
        "idempotency_conflict" => (StatusCode::CONFLICT, "Sandbox ID was already used for a different create request"),
        "sandbox_busy" => (StatusCode::CONFLICT, "Another create, capture or delete of this sandbox is in progress, or a command blocks this capture"),
        "exec_limit" => (StatusCode::CONFLICT, "This sandbox already runs its maximum number of commands"),
        "exec_not_found" => (StatusCode::NOT_FOUND, "No such running command in this sandbox"),
        "sandbox_not_running" => (StatusCode::CONFLICT, "Sandbox is not running"),
        "template_busy" => (StatusCode::CONFLICT, "Another capture is publishing this template ID"),
        "template_unavailable" => (StatusCode::UNPROCESSABLE_ENTITY, "Template is missing, invalid or incompatible with this worker; nothing was started"),
        "template_resource_mismatch" => (StatusCode::UNPROCESSABLE_ENTITY, "Warm template requires its captured memory_mib/vcpus; nothing was started"),
        "resources_required" => (StatusCode::UNPROCESSABLE_ENTITY, "Template declares no default memory_mib/vcpus; supply them"),
        "template_already_exists" => (StatusCode::CONFLICT, "Capture rejected before checkpoint; the source keeps running"),
        "template_layer_limit" => (StatusCode::CONFLICT, "Source template already has the maximum sealed layers; capture rejected before checkpoint, the source keeps running"),
        "checkpoint_interrupted" => (StatusCode::INTERNAL_SERVER_ERROR, "Checkpoint was stopped at its deadline or output limit; nothing was published. The source was thawed and kept only if still running; read sandbox state"),
        "service_port_not_authorized" => (StatusCode::FORBIDDEN, "Port is not an approved service port of this sandbox"),
        "busy" => (StatusCode::SERVICE_UNAVAILABLE, "Operation pool, restore slots or command limit are busy; nothing was started"),
        "admission_exhausted" => (StatusCode::SERVICE_UNAVAILABLE, "Worker capacity is exhausted; nothing was started or recorded"),
        "record_limit" => (StatusCode::SERVICE_UNAVAILABLE, "Durable record limit reached; nothing was started"),
        "worker_unavailable" => (StatusCode::SERVICE_UNAVAILABLE, "Worker is not admitting work; nothing was started"),
        "erofs_loop_devices_exhausted" => (StatusCode::INTERNAL_SERVER_ERROR, "EROFS loop devices are exhausted; no free visible loop nodes remain"),
        "cleanup_failed" => (StatusCode::INTERNAL_SERVER_ERROR, "Cleanup failed; capacity stays reserved and cleanup retries automatically"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Operation failed; read sandbox state, which may be terminated"),
    };
    ApiError(status, code, message)
}
// Hand work to the engine and wait up to `wait` for its real outcome, then turn it into the HTTP
// response. Dropping this future (client disconnect or an expired wait) never cancels the job: the
// engine owns it and discards the reply, except that an undelivered create is deleted
// (`create_response_lost`).
async fn call(handle: &Handle, wait: Duration, work: impl FnOnce(Reply) -> Work) -> Result<Response, ApiError> {
    let sender = handle.sender.as_ref().ok_or_else(unavailable)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.try_send(work(tx)).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Lifecycle mailbox is full; nothing was started"))?;
    let outcome = match tokio::time::timeout(wait, rx).await {
        Err(_) => return Err(ApiError(StatusCode::GATEWAY_TIMEOUT, "operation_timeout", "Outcome wait expired; the operation still runs to a terminal state with normal cleanup (an undelivered create is deleted). Read sandbox state")),
        Ok(Err(_)) => return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "worker_reply_lost", "Worker stopped before reporting the outcome; read sandbox state")),
        Ok(Ok(result)) => result.map_err(failure)?,
    };
    Ok(match outcome {
        Outcome::Created(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Outcome::Sandbox(view) => Json(view).into_response(),
        Outcome::Captured(result) => Json(result).into_response(),
        Outcome::Killed(result) => Json(result).into_response(),
    })
}
// Turn a millisecond count into a duration.
fn millis(ms: u64) -> Duration { Duration::from_millis(ms) }
// Accept a controller create only for a valid request whose ID names this worker, and wait for it
// to finish.
async fn create(State(handle): State<Handle>, input: Result<Json<CreateRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let received = std::time::Instant::now();
    let request = http::json(input)?;
    let node = handle.snapshot.read().map_err(|_| unavailable())?.status.node_id.clone();
    if !request.valid() || sandbox_owner(&request.sandbox_id) != Some(node.as_str()) { return Err(http::invalid_input()); }
    call(&handle, millis(handle.deadlines.create_ms), |reply| Work::Create(request, received, reply)).await
}
// Return a sandbox's current state from the published snapshot without contacting the engine.
async fn get_sandbox(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    let snapshot = handle.snapshot.read().map_err(|_| unavailable())?;
    let record = snapshot.records.get(&id).ok_or(ApiError(StatusCode::NOT_FOUND, "sandbox_not_found", "Sandbox does not exist"))?;
    Ok(Json(record.view()).into_response())
}
// Timestamp and submit a delete, then wait for its cleanup result.
async fn delete(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    call(&handle, millis(handle.deadlines.delete_ms), |reply| Work::Delete(id, std::time::Instant::now(), reply)).await
}
#[derive(Serialize)]
struct ExecResult {
    exec_id: u64, exit_code: Option<i32>, stdout: String, stderr: String, interrupted: bool,
    error: Option<&'static str>, sandbox_state: String,
}
// Read a sandbox's current state from the published snapshot ("deleted" once it is gone).
fn sandbox_state(handle: &Handle, id: &str) -> String {
    handle.snapshot.read().ok().and_then(|s| s.records.get(id).map(|r| r.state.clone())).unwrap_or_else(|| "deleted".into())
}
// Encode bytes as standard padded base64 (output frames of a streamed exec).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..4 { out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' }); }
    }
    out
}
// Format one server-sent event with a JSON data line.
fn event(name: &str, data: serde_json::Value) -> Bytes { Bytes::from(format!("event: {name}\ndata: {data}\n\n")) }
// The body of a streamed exec: a `start` event with the exec ID, `stdout`/`stderr` events with base64
// data as output arrives, then one `exit` event with the exit code, interruption, error and sandbox
// state. A lost event channel ends with an `exit` event carrying worker_reply_lost.
struct ExecStream { handle: Handle, id: String, exec: u64, events: tokio::sync::mpsc::UnboundedReceiver<ExecEvent>, started: bool, done: bool }
impl hyper::body::Body for ExecStream {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    // Emit the next event as soon as the command produces it.
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if !this.started {
            this.started = true;
            return Poll::Ready(Some(Ok(Frame::data(event("start", serde_json::json!({"exec_id": this.exec}))))));
        }
        if this.done { return Poll::Ready(None); }
        let finish = |this: &mut Self, end: ExecEnd| {
            this.done = true;
            event("exit", serde_json::json!({"exit_code": end.exit_code, "interrupted": end.interrupted, "error": end.error, "sandbox_state": sandbox_state(&this.handle, &this.id)}))
        };
        let bytes = match this.events.poll_recv(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(ExecEvent::Stdout(data))) => event("stdout", serde_json::json!({"data": base64(&data)})),
            Poll::Ready(Some(ExecEvent::Stderr(data))) => event("stderr", serde_json::json!({"data": base64(&data)})),
            Poll::Ready(Some(ExecEvent::End(end))) => finish(this, end),
            Poll::Ready(None) => finish(this, ExecEnd { exit_code: None, interrupted: true, error: Some("worker_reply_lost"), cleanup_failed: false }),
        };
        Poll::Ready(Some(Ok(Frame::data(bytes))))
    }
}
// Admit a command, then either stream its output as server-sent events or wait for its full result
// (up to its own timeout plus the margin). Admission is immediate and the command runs on its own
// thread, so a client that leaves never stops it; a bound violation stops only this command.
async fn exec(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let arrived = std::time::Instant::now();
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    let sender = handle.sender.as_ref().ok_or_else(unavailable)?;
    let (started, admitted) = tokio::sync::oneshot::channel();
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
    let (stream, wait) = (request.stream, millis(request.timeout_ms + handle.deadlines.margin_ms));
    sender.try_send(Work::Exec(id.clone(), request, arrived, ExecSink { started, events }))
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Lifecycle mailbox is full; nothing was started"))?;
    let exec = match admitted.await {
        Ok(result) => result.map_err(failure)?,
        Err(_) => return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "worker_reply_lost", "Worker stopped before admitting the command")),
    };
    if stream {
        let body = ExecStream { handle: handle.clone(), id, exec, events: received, started: false, done: false };
        return Ok(([(header::CONTENT_TYPE, "text/event-stream")], Body::new(body)).into_response());
    }
    let collect = async {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        while let Some(event) = received.recv().await {
            match event {
                ExecEvent::Stdout(data) => stdout.extend_from_slice(&data),
                ExecEvent::Stderr(data) => stderr.extend_from_slice(&data),
                ExecEvent::End(end) => return Some((stdout, stderr, end)),
            }
        }
        None
    };
    match tokio::time::timeout(wait, collect).await {
        Err(_) => Err(ApiError(StatusCode::GATEWAY_TIMEOUT, "operation_timeout", "Outcome wait expired; the command still runs to its own deadline with normal cleanup")),
        Ok(None) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "worker_reply_lost", "Worker stopped before reporting the outcome; read sandbox state")),
        Ok(Some((stdout, stderr, end))) => Ok(Json(ExecResult { exec_id: exec, exit_code: end.exit_code, stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(), interrupted: end.interrupted, error: end.error, sandbox_state: sandbox_state(&handle, &id) }).into_response()),
    }
}
// Stop one running command of a sandbox and wait (up to the margin) until it has ended and its
// resource group is gone.
async fn kill(State(handle): State<Handle>, path: Result<Path<(String, u64)>, PathRejection>) -> Result<Response, ApiError> {
    let Path((id, exec)) = path.map_err(|_| http::invalid_input())?;
    let id = self::id(&handle, Ok(Path(id)))?;
    call(&handle, millis(handle.deadlines.margin_ms), |reply| Work::Kill(id, exec, reply)).await
}
// Forward one app request to an approved service port of a running (or capturing) sandbox through its
// routing slot, holding a connection permit for the whole exchange (see proxy.rs). Deletion of the
// sandbox ends the exchange.
async fn app_proxy(handle: Handle, request: Request) -> Response {
    let Some((id, port, app)) = crate::proxy::parse(request.uri().path()) else { return http::invalid_input().into_response() };
    let app = request.uri().query().map_or(app.clone(), |query| format!("{app}?{query}"));
    let Some(native) = handle.native.clone().filter(|_| handle.sender.is_some()) else { return unavailable().into_response() };
    if let Err(error) = self::id(&handle, Ok(Path(id.clone()))) { return error.into_response(); }
    let Ok(permit) = handle.proxy_permits.clone().try_acquire_owned() else {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Proxy connection limit reached").into_response();
    };
    let target = {
        let Ok(mut snapshot) = handle.snapshot.write() else { return unavailable().into_response() };
        match snapshot.records.get(&id).cloned() {
            None => Err(failure("sandbox_not_found")),
            Some(r) if r.delete_requested || r.expires_at <= crate::engine::now() || !matches!(r.state.as_str(), "running" | "capturing") => Err(failure("sandbox_not_running")),
            Some(r) => match (r.network_policy.as_ref().is_some_and(|p| p.serves(port)), r.network_slot) {
                (true, Some(slot)) => Ok((slot, snapshot.proxy_close.entry(id.clone()).or_insert_with(|| tokio::sync::watch::channel(()).0).subscribe())),
                _ => Err(failure("service_port_not_authorized")),
            },
        }
    };
    match target {
        Err(error) => error.into_response(),
        Ok((slot, stop)) => crate::proxy::to_sandbox(native.slot_namespace(slot), port, app, request, handle.proxy.idle(), stop, permit).await,
    }
}
// Check the new template ID and wait for the capture outcome within the capture deadline.
async fn capture(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<CaptureRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !valid_id(&request.template_id) { return Err(http::invalid_input()); }
    call(&handle, millis(handle.deadlines.capture_ms), |reply| Work::Capture(id, request, std::time::Instant::now(), reply)).await
}

// Return the cached worker state and, for loop fallback, a fresh advisory capacity snapshot. All
// device reads happen off request threads and outside the shared state lock.
async fn status(State(handle): State<Handle>) -> Result<Json<crate::model::WorkerStatus>, ApiError> {
    let mut status = handle.snapshot.read().map_err(|_| unavailable())?.status.clone();
    if let Some(erofs) = status.erofs.as_mut().filter(|e| e.file_backed != Some(true)) {
        erofs.loop_devices = tokio::task::spawn_blocking(crate::native::loop_capacity).await.map_err(|_| unavailable())?;
    }
    Ok(Json(status))
}

// Serve protected management and app routes using ownership established before request threads.
// On termination stop admission, cancel live work, finish serving and wait for owned cleanup.
pub async fn run(config: WorkerConfig, token: String, handle: Handle) -> Result<(), &'static str> {
    let server = config.server.clone();
    let router = Router::new()
        .route("/healthz", get(|| async { Json(Health { service: "worker", live: true }) }))
        .route("/v1/status", get(status))
        .route("/v1/preflight", get(|State(h): State<Handle>| async move { Json(h.preflight.clone()) }))
        .route("/v1/sandboxes", post(create))
        .route("/v1/sandboxes/{id}", get(get_sandbox).delete(delete))
        .route("/v1/sandboxes/{id}/exec", post(exec))
        .route("/v1/sandboxes/{id}/exec/{exec_id}/kill", post(kill))
        .route("/v1/sandboxes/{id}/capture", post(capture))
        .with_state(handle.clone());
    let proxy_handle = handle.clone();
    let proxy: http::Proxy = Arc::new(move |request| Box::pin(app_proxy(proxy_handle.clone(), request)));
    let app = http::protect(router, &server, token, 1, proxy, None);
    let listener = tokio::net::TcpListener::bind(server.address(8081)).await.map_err(|_| "cannot bind worker listener")?;
    println!("worker listening; consult authenticated runtime status and qualification");
    // Stop admission and cancel live work as soon as termination is requested, so
    // blocked requests receive their (failed) outcomes and HTTP draining finishes.
    let (stopped_tx, stopped_rx) = std::sync::mpsc::channel();
    let sender = handle.sender.clone();
    let stop = async move {
        http::shutdown().await;
        if let Some(sender) = sender {
            let _ = tokio::task::spawn_blocking(move || sender.send(Work::Stop(stopped_tx))).await;
        }
    };
    let result = axum::serve(axum::serve::ListenerExt::tap_io(listener, http::no_delay), app).with_graceful_shutdown(stop).await;
    if let Some(sender) = handle.sender {
        tokio::task::spawn_blocking(move || stopped_rx.recv().or_else(|_| {
            // The server ended without a termination signal: stop it now.
            let (tx, rx) = std::sync::mpsc::channel();
            sender.send(Work::Stop(tx)).map_err(|_| "worker_shutdown_failed")?;
            rx.recv().map_err(|_| "worker_shutdown_failed")
        })?).await.map_err(|_| "worker_shutdown_failed")??;
    }
    result.map_err(|_| "worker HTTP server failed")
}
