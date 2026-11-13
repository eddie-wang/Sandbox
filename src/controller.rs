use std::{sync::Arc, time::{Duration, Instant}};

use axum::{Json, Router, extract::{Path, State, rejection::{JsonRejection, PathRejection}}, http::StatusCode, routing::{get, post}};
use serde_json::Value;
use serde::Serialize;
use tokio::{sync::RwLock, task::JoinSet};

use crate::{
    config::{ControllerConfig, WorkerEndpoint},
    http::{self, ApiError},
    lifecycle,
    model::{CaptureRequest, CreateRequest, ExecRequest, HttpRequest, WorkerStatus, sandbox_owner, valid_id},
    scheduler,
};

const MAX_STATUS_BYTES: usize = 65_536;

struct CachedNode {
    node_id: String,
    status: Option<WorkerStatus>,
    observed: Option<Instant>,
    error: Option<&'static str>,
}

#[derive(Serialize)]
pub struct NodeView {
    pub node_id: String,
    pub fresh: bool,
    pub reachable: bool,
    pub age_ms: Option<u64>,
    pub error: Option<&'static str>,
    pub status: Option<WorkerStatus>,
}

#[derive(Clone)]
struct Controller {
    nodes: Arc<RwLock<Vec<CachedNode>>>,
    freshness: Duration,
    endpoints: Arc<Vec<WorkerEndpoint>>,
    client: reqwest::Client,
    worker_token: Arc<String>,
    application_http_limits: crate::config::ApplicationHttpLimits,
}

impl Controller {
    async fn snapshot(&self) -> Vec<NodeView> {
        let nodes = self.nodes.read().await;
        let now = Instant::now();
        nodes.iter().map(|node| {
            let age = node.observed.map(|time| now.duration_since(time));
            let reachable = node.error.is_none() && node.observed.is_some();
            NodeView {
                node_id: node.node_id.clone(),
                fresh: reachable && age.is_some_and(|age| age <= self.freshness),
                reachable,
                age_ms: age.map(|age| age.as_millis().min(u64::MAX as u128) as u64),
                error: node.error,
                status: node.status.clone(),
            }
        }).collect()
    }
}

#[derive(Serialize)]
struct ControllerStatus {
    service: &'static str,
    lifecycle_implemented: bool,
    nodes: Vec<NodeView>,
}

async fn status(State(controller): State<Controller>) -> Json<ControllerStatus> {
    Json(ControllerStatus {
        service: "controller",
        lifecycle_implemented: true,
        nodes: controller.snapshot().await,
    })
}

async fn create(
    State(controller): State<Controller>,
    input: Result<Json<CreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    let owner = sandbox_owner(&request.sandbox_id).ok_or_else(http::invalid_input)?;
    let nodes: Vec<_> = controller.snapshot().await.into_iter().filter(|n| n.node_id == owner).collect();
    if scheduler::choose(&nodes, &request).is_none() {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "no_ready_runtime", "Owner worker is not fresh, compatible and ready with advisory capacity"));
    }
    forward(&controller, owner, reqwest::Method::POST, "/v1/sandboxes", Some(serde_json::to_value(&request).map_err(|_| http::invalid_input())?)).await
}

fn path_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(id) = path.map_err(|_| http::invalid_input())?;
    if sandbox_owner(&id).is_none() { return Err(http::invalid_input()); }
    Ok(id)
}
async fn get_sandbox(State(c): State<Controller>, path: Result<Path<String>, PathRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = path_id(path)?;
    forward(&c, sandbox_owner(&id).unwrap(), reqwest::Method::GET, &format!("/v1/sandboxes/{id}"), None).await
}
async fn delete(State(c): State<Controller>, path: Result<Path<String>, PathRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = path_id(path)?;
    forward(&c, sandbox_owner(&id).unwrap(), reqwest::Method::DELETE, &format!("/v1/sandboxes/{id}"), None).await
}
async fn exec(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = path_id(path)?;
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    forward(&c, sandbox_owner(&id).unwrap(), reqwest::Method::POST, &format!("/v1/sandboxes/{id}/exec"), Some(serde_json::to_value(request).map_err(|_| http::invalid_input())?)).await
}
async fn application_http(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<HttpRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = path_id(path)?;
    let request = http::json(input)?;
    if !request.valid_for(&c.application_http_limits) { return Err(http::invalid_input()); }
    forward(&c, sandbox_owner(&id).unwrap(), reqwest::Method::POST, &format!("/v1/sandboxes/{id}/http"), Some(serde_json::to_value(request).map_err(|_| http::invalid_input())?)).await
}
async fn capture(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<CaptureRequest>, JsonRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let id = path_id(path)?;
    let request = http::json(input)?;
    if !valid_id(&request.template_id) || !valid_id(&request.operation_id) { return Err(http::invalid_input()); }
    forward(&c, sandbox_owner(&id).unwrap(), reqwest::Method::POST, &format!("/v1/sandboxes/{id}/capture"), Some(serde_json::to_value(request).map_err(|_| http::invalid_input())?)).await
}
async fn operation(State(c): State<Controller>, path: Result<Path<(String, String)>, PathRejection>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Path((id, op)) = path.map_err(|_| http::invalid_input())?;
    let owner = sandbox_owner(&id).ok_or_else(http::invalid_input)?;
    if !valid_id(&op) { return Err(http::invalid_input()); }
    forward(&c, owner, reqwest::Method::GET, &format!("/v1/sandboxes/{id}/operations/{op}"), None).await
}
async fn forward(c: &Controller, owner: &str, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let endpoint = c.endpoints.iter().find(|e| e.node_id == owner).ok_or(http::invalid_input())?;
    let nodes = c.snapshot().await;
    if !nodes.iter().any(|n| n.node_id == owner && n.fresh) {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "owner_unavailable", "Owner identity has no fresh validated observation"));
    }
    let mut url = reqwest::Url::parse(&endpoint.url).map_err(|_| http::invalid_input())?;
    url.set_path(path);
    let mut request = c.client.request(method, url).bearer_auth(c.worker_token.as_str());
    if let Some(body) = body { request = request.header("content-type", "application/json").body(serde_json::to_vec(&body).map_err(|_| http::invalid_input())?); }
    let uncertain = || ApiError(StatusCode::SERVICE_UNAVAILABLE, "owner_response_unavailable", "Read state or retry the identical identifiers; an operation may already be accepted");
    let mut response = request.send().await.map_err(|_| uncertain())?;
    let status = response.status();
    let max_response = c.application_http_limits.response_reservation().max(8388608);
    if response.content_length().is_some_and(|n| n > max_response as u64) { return Err(uncertain()); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| uncertain())? {
        if bytes.len() + chunk.len() > max_response { return Err(uncertain()); }
        bytes.extend_from_slice(&chunk);
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| uncertain())?;
    Ok((status, Json(value)))
}

pub async fn run(config: ControllerConfig, token: String, worker_token: String) -> Result<(), &'static str> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(config.poll.timeout_ms.min(1_000)))
        .timeout(Duration::from_millis(config.poll.timeout_ms))
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30))
        .build().map_err(|_| "cannot initialize worker HTTP client")?;
    let controller = Controller {
        nodes: Arc::new(RwLock::new(config.workers.iter().map(|worker| CachedNode {
            node_id: worker.node_id.clone(), status: None, observed: None, error: Some("not_polled"),
        }).collect())),
        freshness: Duration::from_millis(config.poll.freshness_ms),
        endpoints: Arc::new(config.workers.clone()), client: client.clone(), worker_token: Arc::new(worker_token),
        application_http_limits: config.server.application_http.clone(),
    };
    let router = Router::new()
        .route("/healthz", get(|| async { Json(lifecycle::Health { service: "controller", live: true }) }))
        .route("/v1/status", get(status))
        .route("/v1/sandboxes", post(create))
        .route("/v1/sandboxes/{id}", get(get_sandbox).delete(delete))
        .route("/v1/sandboxes/{id}/exec", post(exec))
        .route("/v1/sandboxes/{id}/http", post(application_http))
        .route("/v1/sandboxes/{id}/capture", post(capture))
        .route("/v1/sandboxes/{id}/operations/{op}", get(operation))
        .with_state(controller.clone());
    let app = http::protect(router, &config.server, token);
    let listener = tokio::net::TcpListener::bind(config.server.address(8080)).await
        .map_err(|_| "cannot bind controller listener")?;
    let worker_token = controller.worker_token.clone();
    let poller = tokio::spawn(poll(controller, config, client, worker_token));
    println!("controller listening; stable owner routing enabled");
    let result = axum::serve(listener, app).with_graceful_shutdown(http::shutdown()).await;
    poller.abort();
    let _ = poller.await;
    result.map_err(|_| "controller HTTP server failed")
}

async fn poll(controller: Controller, config: ControllerConfig, client: reqwest::Client, token: Arc<String>) {
    let mut interval = tokio::time::interval(Duration::from_millis(config.poll.interval_ms));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut pending = config.workers.iter().enumerate();
        let mut tasks = JoinSet::new();
        loop {
            while tasks.len() < config.poll.fanout {
                let Some((index, endpoint)) = pending.next() else { break };
                let endpoint = endpoint.clone();
                let client = client.clone();
                let token = token.clone();
                let timeout = Duration::from_millis(config.poll.timeout_ms);
                tasks.spawn(async move {
                    let status = tokio::time::timeout(timeout, fetch_status(&client, &endpoint, &token))
                        .await.unwrap_or(Err("poll_timeout"));
                    (index, status)
                });
            }
            let Some(completed) = tasks.join_next().await else { break };
            if let Ok((index, result)) = completed {
                let mut nodes = controller.nodes.write().await;
                match result {
                    Ok(status) => {
                        nodes[index].status = Some(status);
                        nodes[index].observed = Some(Instant::now());
                        nodes[index].error = None;
                    }
                    Err(error) => nodes[index].error = Some(error),
                }
            }
        }
    }
}

async fn fetch_status(client: &reqwest::Client, endpoint: &WorkerEndpoint, token: &str) -> Result<WorkerStatus, &'static str> {
    let mut url = reqwest::Url::parse(&endpoint.url).map_err(|_| "invalid_endpoint")?;
    url.set_path("/v1/status");
    let mut response = client.get(url).bearer_auth(token).send().await.map_err(|_| "worker_unreachable")?;
    if !response.status().is_success() {
        return Err("worker_http_error");
    }
    if response.content_length().is_some_and(|length| length > MAX_STATUS_BYTES as u64) {
        return Err("status_too_large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "status_read_error")? {
        if bytes.len() + chunk.len() > MAX_STATUS_BYTES {
            return Err("status_too_large");
        }
        bytes.extend_from_slice(&chunk);
    }
    let status: WorkerStatus = serde_json::from_slice(&bytes).map_err(|_| "invalid_status")?;
    if !status.valid_for(&endpoint.node_id) {
        return Err("invalid_status");
    }
    Ok(status)
}
