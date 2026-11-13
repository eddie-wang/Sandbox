use std::time::Duration;
use axum::{Json, Router, extract::{Path, State, rejection::{JsonRejection, PathRejection}}, http::StatusCode, response::{IntoResponse, Response}, routing::{get, post}};
use crate::{config::WorkerConfig, engine::{Handle, Outcome, Reply, Work}, http::{self, ApiError}, lifecycle::Health,
    model::{CaptureRequest, CreateRequest, ExecRequest, HttpRequest, sandbox_owner, valid_id}};

// Return a safe service-unavailable error for a disabled or failed runtime.
fn unavailable() -> ApiError { ApiError(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable", "Runtime is disabled or preflight failed") }
// Extract the sandbox ID and require its owner to match this worker.
fn id(handle: &Handle, input: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(id) = input.map_err(|_| http::invalid_input())?;
    let node = handle.snapshot.read().map_err(|_| unavailable())?.status.node_id.clone();
    if sandbox_owner(&id) != Some(node.as_str()) { return Err(http::invalid_input()); }
    Ok(id)
}
// Static engine/runtime codes. Unlisted runtime failures are 500 with their static code.
fn failure(code: &'static str) -> ApiError {
    let (status, message) = match code {
        "sandbox_not_found" => (StatusCode::NOT_FOUND, "Sandbox does not exist"),
        "idempotency_conflict" => (StatusCode::CONFLICT, "Sandbox ID was already used for a different create request"),
        "sandbox_busy" => (StatusCode::CONFLICT, "Another create, exec, HTTP, capture or delete of this sandbox is in progress"),
        "sandbox_not_running" => (StatusCode::CONFLICT, "Sandbox is not running"),
        "template_busy" => (StatusCode::CONFLICT, "Another capture is publishing this template ID"),
        "template_unavailable" => (StatusCode::UNPROCESSABLE_ENTITY, "Template is missing, invalid or incompatible with this worker; nothing was started"),
        "template_resource_mismatch" => (StatusCode::UNPROCESSABLE_ENTITY, "Warm template requires its captured memory_mib/vcpus; nothing was started"),
        "resources_required" => (StatusCode::UNPROCESSABLE_ENTITY, "Template declares no default memory_mib/vcpus; supply them"),
        "template_already_exists" | "capture_requires_quiescent_tcp" => (StatusCode::CONFLICT, "Capture rejected before checkpoint; the source keeps running"),
        "service_port_not_authorized" => (StatusCode::FORBIDDEN, "Port is not an approved service port of this sandbox"),
        "application_http_failed_or_bounded" | "application_http_invalid_result" => (StatusCode::BAD_GATEWAY, "Application HTTP failed, timed out or exceeded a bound"),
        "busy" => (StatusCode::SERVICE_UNAVAILABLE, "Operation pool or restore slots are busy; nothing was started"),
        "admission_exhausted" => (StatusCode::SERVICE_UNAVAILABLE, "Worker capacity is exhausted; nothing was started or recorded"),
        "record_limit" => (StatusCode::SERVICE_UNAVAILABLE, "Durable record limit reached; nothing was started"),
        "worker_unavailable" => (StatusCode::SERVICE_UNAVAILABLE, "Worker is not admitting work; nothing was started"),
        "cleanup_failed" => (StatusCode::INTERNAL_SERVER_ERROR, "Cleanup failed; capacity stays reserved and cleanup retries automatically"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Operation failed; read sandbox state, which may be terminated"),
    };
    ApiError(status, code, message)
}
// Waits for the real outcome. Dropping this future (client disconnect or an
// expired wait) never cancels the job: the engine owns it and discards the reply,
// except that an undelivered create is deleted (`create_response_lost`).
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
        Outcome::Exec(result) => Json(result).into_response(),
        Outcome::Http(result) => Json(result).into_response(),
        Outcome::Captured(result) => Json(result).into_response(),
    })
}
fn millis(ms: u64) -> Duration { Duration::from_millis(ms) }
async fn create(State(handle): State<Handle>, input: Result<Json<CreateRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let request = http::json(input)?;
    let node = handle.snapshot.read().map_err(|_| unavailable())?.status.node_id.clone();
    if !request.valid() || sandbox_owner(&request.sandbox_id) != Some(node.as_str()) { return Err(http::invalid_input()); }
    call(&handle, millis(handle.deadlines.create_ms), |reply| Work::Create(request, reply)).await
}
async fn get_sandbox(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    let snapshot = handle.snapshot.read().map_err(|_| unavailable())?;
    let record = snapshot.records.get(&id).ok_or(ApiError(StatusCode::NOT_FOUND, "sandbox_not_found", "Sandbox does not exist"))?;
    Ok(Json(record.view()).into_response())
}
async fn delete(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    call(&handle, millis(handle.deadlines.delete_ms), |reply| Work::Delete(id, reply)).await
}
async fn exec(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    let wait = millis(request.timeout_ms + handle.deadlines.margin_ms);
    call(&handle, wait, |reply| Work::Exec(id, request, reply)).await
}
async fn application_http(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<HttpRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !request.valid_for(&handle.application_http_limits) { return Err(http::invalid_input()); }
    let wait = millis(request.timeout_ms + handle.deadlines.margin_ms);
    call(&handle, wait, |reply| Work::Http(id, request, reply)).await
}
async fn capture(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<CaptureRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !valid_id(&request.template_id) { return Err(http::invalid_input()); }
    call(&handle, millis(handle.deadlines.capture_ms), |reply| Work::Capture(id, request, reply)).await
}

// Initialize preflight and lifecycle ownership away from request handling, then serve protected
// management routes. On shutdown, stop serving and wait for engine-owned cleanup before returning.
pub async fn run(config: WorkerConfig, token: String) -> Result<(), &'static str> {
    let server = config.server.clone();
    let handle = tokio::task::spawn_blocking(move || {
        let report = crate::native::preflight(config.native.as_ref());
        Handle::start(&config, report)
    }).await.map_err(|_| "runtime_initialization_failed")??;
    let router = Router::new()
        .route("/healthz", get(|| async { Json(Health { service: "worker", live: true }) }))
        .route("/v1/status", get(|State(h): State<Handle>| async move { Json(h.snapshot.read().expect("snapshot poisoned").status.clone()) }))
        .route("/v1/preflight", get(|State(h): State<Handle>| async move { Json(h.preflight.clone()) }))
        .route("/v1/sandboxes", post(create))
        .route("/v1/sandboxes/{id}", get(get_sandbox).delete(delete))
        .route("/v1/sandboxes/{id}/exec", post(exec))
        .route("/v1/sandboxes/{id}/http", post(application_http))
        .route("/v1/sandboxes/{id}/capture", post(capture))
        .with_state(handle.clone());
    let app = http::protect(router, &server, token, 1);
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
    let result = axum::serve(listener, app).with_graceful_shutdown(stop).await;
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
