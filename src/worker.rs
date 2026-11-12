use axum::{Json, Router, extract::{State, rejection::JsonRejection}, http::StatusCode, routing::{get, post}};

use crate::{
    config::WorkerConfig,
    http::{self, ApiError},
    lifecycle,
    model::{CreateRequest, RuntimeCapability, WorkerStatus},
};

async fn create(input: Result<Json<CreateRequest>, JsonRejection>) -> Result<(), ApiError> {
    let request = http::json(input)?;
    if !request.valid() {
        return Err(http::invalid_input());
    }
    Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable", "No runtime backend or worker admission implementation is available"))
}

pub async fn run(config: WorkerConfig, token: String) -> Result<(), &'static str> {
    let status = WorkerStatus {
        schema_version: 1,
        node_id: config.node_id,
        architecture: std::env::consts::ARCH.to_owned(),
        os: std::env::consts::OS.to_owned(),
        capacity: config.capacity,
        // Configured budgets are not measurements, reservations or resource enforcement.
        usage: None,
        admission_ready: false,
        runtimes: config.runtimes.into_iter().map(|runtime| RuntimeCapability {
            runtime, ready: false, reason: "not_implemented".to_owned(),
        }).collect(),
    };
    let router = Router::new()
        .route("/healthz", get(|| async { Json(lifecycle::Health { service: "worker", live: true }) }))
        .route("/v1/status", get(|State(status): State<WorkerStatus>| async { Json(status) }))
        .route("/v1/sandboxes", post(create))
        .route("/v1/sandboxes/{id}/exec", post(lifecycle::exec))
        .route("/v1/sandboxes/{id}/capture", post(lifecycle::capture))
        .with_state(status);
    let app = http::protect(router, &config.server, token);
    let listener = tokio::net::TcpListener::bind(config.server.address(8081)).await
        .map_err(|_| "cannot bind worker listener")?;
    println!("worker listening; all runtime candidates unavailable");
    axum::serve(listener, app).with_graceful_shutdown(http::shutdown()).await
        .map_err(|_| "worker HTTP server failed")
}
