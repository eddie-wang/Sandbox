use axum::{Json, Router, extract::{Path, State, rejection::{JsonRejection, PathRejection}}, http::StatusCode, routing::{get, post}};
use serde_json::{Value, json};
use crate::{config::WorkerConfig, engine::{Handle, Work}, http::{self, ApiError}, lifecycle::Health,
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
// Enqueue work without waiting for queue space, then wait for the engine's durable-acceptance reply.
// Map admission errors to safe HTTP errors; disconnecting does not cancel accepted jobs.
async fn submit(handle: &Handle, work: impl FnOnce(crate::engine::Ack) -> Work) -> Result<(), ApiError> {
    let sender = handle.sender.as_ref().ok_or_else(unavailable)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.try_send(work(tx)).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Lifecycle queue is full or unavailable"))?;
    // HTTP cancellation leaves the actor alive; callers can retry exactly the
    // same caller-chosen sandbox/operation ID after any ambiguous transport error.
    match rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err("sandbox_not_found")) => Err(ApiError(StatusCode::NOT_FOUND, "sandbox_not_found", "Sandbox does not exist")),
        Ok(Err("idempotency_conflict")) => Err(ApiError(StatusCode::CONFLICT, "idempotency_conflict", "Identifier was already used for a different request")),
        Ok(Err("busy")) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Sandbox, operation pool or restore slots are busy")),
        Ok(Err("operation_limit" | "record_limit" | "result_limit")) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "retention_limit", "Durable record retention limit reached")),
        _ => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable", "Worker could not durably accept the operation")),
    }
}
// Return HTTP 202 with the identifiers callers can use to poll accepted work.
fn accepted(id: String, operation: Option<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::ACCEPTED, Json(json!({"sandbox_id":id,"operation_id":operation})))
}
// Validate the request and local ownership, then submit creation. Return 202 after saved acceptance;
// callers poll sandbox state for completion.
async fn create(State(handle): State<Handle>, input: Result<Json<CreateRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let request = http::json(input)?;
    let node = handle.snapshot.read().map_err(|_| unavailable())?.status.node_id.clone();
    if !request.valid() || sandbox_owner(&request.sandbox_id) != Some(node.as_str()) { return Err(http::invalid_input()); }
    let id = request.sandbox_id.clone();
    submit(&handle, |ack| Work::Create(request, ack)).await?;
    Ok(accepted(id, None))
}
// Read the owned sandbox's snapshot and return state plus operation summaries, excluding result
// bodies.
async fn get_sandbox(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>) -> Result<Json<Value>, ApiError> {
    let id = id(&handle, path)?;
    let snapshot = handle.snapshot.read().map_err(|_| unavailable())?;
    let record = snapshot.records.get(&id).ok_or(ApiError(StatusCode::NOT_FOUND, "sandbox_not_found", "Sandbox does not exist"))?;
    let operations: Vec<_> = record.operations.iter().map(|(id, op)| json!({"operation_id":id,"kind":op.kind,"state":op.state,"error":op.error,"template_id":op.template_id})).collect();
    Ok(Json(json!({"sandbox_id":id,"state":record.state,"error":record.error,"expires_at":record.expires_at,"operations":operations})))
}
// Validate local ownership, submit deletion and return 202 after the engine acknowledges it.
async fn delete(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = id(&handle, path)?;
    submit(&handle, |ack| Work::Delete(id.clone(), ack)).await?;
    Ok(accepted(id, None))
}
// Validate local ownership and command bounds, then submit exec. Return 202 after saved acceptance;
// callers poll the operation for its eventual output.
async fn exec(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    let op = request.operation_id.clone();
    submit(&handle, |ack| Work::Exec(id.clone(), request, ack)).await?;
    Ok(accepted(id, Some(op)))
}
// Validate local ownership and configured HTTP bounds, then submit the application request. Return 202
// after saved acceptance; callers poll the operation for its eventual response.
async fn application_http(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<HttpRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !request.valid_for(&handle.application_http_limits) { return Err(http::invalid_input()); }
    let op = request.operation_id.clone();
    submit(&handle, |ack| Work::Http(id.clone(), request, ack)).await?;
    Ok(accepted(id, Some(op)))
}
// Validate local ownership and capture identifiers, then submit capture. Return 202 after saved
// acceptance; callers poll for publication success or failure.
async fn capture(State(handle): State<Handle>, path: Result<Path<String>, PathRejection>, input: Result<Json<CaptureRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = id(&handle, path)?;
    let request = http::json(input)?;
    if !valid_id(&request.template_id) || !valid_id(&request.operation_id) { return Err(http::invalid_input()); }
    let op = request.operation_id.clone();
    submit(&handle, |ack| Work::Capture(id.clone(), request, ack)).await?;
    Ok(accepted(id, Some(op)))
}
// Validate local ownership and the operation ID, then return its saved state and any retained result.
async fn operation(State(handle): State<Handle>, path: Result<Path<(String, String)>, PathRejection>) -> Result<Json<crate::engine::Operation>, ApiError> {
    let Path((sandbox, op)) = path.map_err(|_| http::invalid_input())?;
    let snapshot = handle.snapshot.read().map_err(|_| unavailable())?;
    if sandbox_owner(&sandbox) != Some(snapshot.status.node_id.as_str()) || !valid_id(&op) { return Err(http::invalid_input()); }
    let operation = snapshot.records.get(&sandbox).and_then(|r| r.operations.get(&op)).ok_or(ApiError(StatusCode::NOT_FOUND, "operation_not_found", "Operation does not exist"))?;
    Ok(Json(operation.clone()))
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
        .route("/v1/sandboxes/{id}/operations/{op}", get(operation))
        .with_state(handle.clone());
    let app = http::protect(router, &server, token);
    let listener = tokio::net::TcpListener::bind(server.address(8081)).await.map_err(|_| "cannot bind worker listener")?;
    println!("worker listening; consult authenticated runtime status and qualification");
    let result = axum::serve(listener, app).with_graceful_shutdown(http::shutdown()).await;
    if let Some(sender) = handle.sender {
        tokio::task::spawn_blocking(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            sender.send(Work::Stop(tx)).map_err(|_| "worker_shutdown_failed")?;
            rx.recv().map_err(|_| "worker_shutdown_failed")?
        }).await.map_err(|_| "worker_shutdown_failed")??;
    }
    result.map_err(|_| "worker HTTP server failed")
}
