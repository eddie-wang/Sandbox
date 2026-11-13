use std::{sync::Arc, time::{Duration, Instant}};

use axum::{Json, Router, extract::{Path, State, rejection::{JsonRejection, PathRejection}}, http::StatusCode, response::{IntoResponse, Response}, routing::{get, post}};
use serde_json::Value;
use serde::Serialize;
use tokio::{sync::RwLock, task::JoinSet};

use crate::{
    config::{ControllerConfig, ServerConfig, WorkerEndpoint},
    http::{self, ApiError},
    lifecycle,
    model::{CaptureRequest, CreateSpec, ExecRequest, HttpRequest, WorkerStatus, sandbox_owner, valid_id},
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
    server: ServerConfig,
    short_wait: Duration,
}

impl Controller {
    // The owner waits `wait` for its outcome; one request_timeout_ms of slack lets
    // it report its own operation_timeout before this forward gives up.
    fn operation_timeout(&self, wait: Duration) -> Duration { wait + self.server.timeout() }
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

// Return controller status with the current cached worker views.
async fn status(State(controller): State<Controller>) -> Json<ControllerStatus> {
    Json(ControllerStatus {
        service: "controller",
        lifecycle_implemented: true,
        nodes: controller.snapshot().await,
    })
}

// Definitive pre-launch rejections: the worker answered before creating any
// resource or record. Safe to fail over with a new ID.
const PRE_LAUNCH_REJECTIONS: &[&str] = &["busy", "admission_exhausted", "record_limit", "runtime_unavailable", "worker_unavailable", "template_unavailable"];
const MAX_CREATE_ATTEMPTS: usize = 3;
const MAX_SANDBOX_VIEW_BYTES: usize = 65_536;

fn random_local_id() -> Result<String, ApiError> {
    let mut bytes = [0u8; 16];
    // Nonblocking after kernel entropy initialization; never reads a file.
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) } != bytes.len() as isize {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "id_generation_failed", "Cannot generate a sandbox ID"));
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

// An ambiguous create outcome names the generated ID so callers can GET/DELETE it.
fn with_sandbox_id(status: StatusCode, mut body: Value, sandbox_id: &str) -> Response {
    if let Some(object) = body.as_object_mut() { object.insert("sandbox_id".into(), Value::String(sandbox_id.into())); }
    (status, Json(body)).into_response()
}

async fn create(State(c): State<Controller>, input: Result<Json<CreateSpec>, JsonRejection>) -> Result<Response, ApiError> {
    let spec = http::json(input)?;
    if !spec.valid() { return Err(http::invalid_input()); }
    let nodes = c.snapshot().await;
    let candidates: Vec<String> = scheduler::rank(&nodes, &spec).into_iter().take(MAX_CREATE_ATTEMPTS).map(str::to_owned).collect();
    let wait = Duration::from_millis(c.server.operation_deadlines.create_ms);
    // All attempts share one budget that ends a request_timeout_ms before this
    // route's guard deadline, so a running attempt reports its ID, never a bare 408.
    let budget_end = Instant::now() + c.operation_timeout(wait);
    // template_unavailable is reported only if every candidate answered exactly that.
    let mut only_template_rejections = !candidates.is_empty();
    for owner in candidates {
        let remaining = budget_end.saturating_duration_since(Instant::now());
        // Too little budget left for another attempt: nothing was sent to it.
        if remaining < c.server.timeout() { only_template_rejections = false; break; }
        let sandbox_id = format!("{owner}.{}", random_local_id()?);
        let body = serde_json::to_value(spec.clone().with_id(sandbox_id.clone())).map_err(|_| http::invalid_input())?;
        match forward(&c, &owner, reqwest::Method::POST, "/v1/sandboxes", Some(body), remaining, MAX_SANDBOX_VIEW_BYTES).await {
            Err(Forward::NotSent(_)) => { only_template_rejections = false; continue; }
            Err(Forward::Lost(ApiError(status, code, message))) =>
                return Ok(with_sandbox_id(status, serde_json::json!({"error":{"code":code,"message":message}}), &sandbox_id)),
            Ok((status, body)) if status.is_success() => return Ok((status, Json(body)).into_response()),
            Ok((_, body)) if body["error"]["code"].as_str().is_some_and(|code| PRE_LAUNCH_REJECTIONS.contains(&code)) => {
                only_template_rejections &= body["error"]["code"] == "template_unavailable";
                continue;
            }
            // Other 4xx answers created nothing: invalid input or template resource rules.
            Ok((status, body)) if status.is_client_error() => return Ok((status, Json(body)).into_response()),
            // Any other answer (including a failed launch) is final for this ID; never retry elsewhere.
            Ok((status, body)) => return Ok(with_sandbox_id(status, body, &sandbox_id)),
        }
    }
    if only_template_rejections {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "template_unavailable", "No candidate worker holds a valid, compatible template with this ID"));
    }
    Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "no_capacity", "No fresh, ready worker admitted the sandbox"))
}

fn path_id(path: Result<Path<String>, PathRejection>) -> Result<(String, String), ApiError> {
    let Path(id) = path.map_err(|_| http::invalid_input())?;
    let owner = sandbox_owner(&id).ok_or_else(http::invalid_input)?.to_owned();
    Ok((id, owner))
}
fn reply(result: Result<(StatusCode, Value), Forward>) -> Result<Response, ApiError> {
    let (status, body) = result.map_err(Forward::error)?;
    Ok((status, Json(body)).into_response())
}
async fn get_sandbox(State(c): State<Controller>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    reply(forward(&c, &owner, reqwest::Method::GET, &format!("/v1/sandboxes/{id}"), None, c.short_wait, MAX_SANDBOX_VIEW_BYTES).await)
}
async fn delete(State(c): State<Controller>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    let wait = Duration::from_millis(c.server.operation_deadlines.delete_ms);
    reply(forward(&c, &owner, reqwest::Method::DELETE, &format!("/v1/sandboxes/{id}"), None, c.operation_timeout(wait), MAX_SANDBOX_VIEW_BYTES).await)
}
async fn exec(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    let wait = Duration::from_millis(request.timeout_ms + c.server.operation_deadlines.margin_ms);
    let limit = request.max_result_bytes();
    reply(forward(&c, &owner, reqwest::Method::POST, &format!("/v1/sandboxes/{id}/exec"), Some(serde_json::to_value(request).map_err(|_| http::invalid_input())?), c.operation_timeout(wait), limit).await)
}
async fn application_http(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<HttpRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    let request = http::json(input)?;
    if !request.valid_for(&c.server.application_http) { return Err(http::invalid_input()); }
    let wait = Duration::from_millis(request.timeout_ms + c.server.operation_deadlines.margin_ms);
    let limit = request.max_result_bytes();
    reply(forward(&c, &owner, reqwest::Method::POST, &format!("/v1/sandboxes/{id}/http"), Some(serde_json::to_value(request).map_err(|_| http::invalid_input())?), c.operation_timeout(wait), limit).await)
}
async fn capture(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<CaptureRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    let request = http::json(input)?;
    if !valid_id(&request.template_id) { return Err(http::invalid_input()); }
    let wait = Duration::from_millis(c.server.operation_deadlines.capture_ms);
    reply(forward(&c, &owner, reqwest::Method::POST, &format!("/v1/sandboxes/{id}/capture"), Some(serde_json::to_value(request).map_err(|_| http::invalid_input())?), c.operation_timeout(wait), MAX_SANDBOX_VIEW_BYTES).await)
}

enum Forward {
    // Nothing reached the owner; the caller may choose another node for a create.
    NotSent(ApiError),
    // The owner may have acted; exec/HTTP are not exactly-once, so read state.
    Lost(ApiError),
}
impl Forward {
    fn error(self) -> ApiError { match self { Self::NotSent(e) | Self::Lost(e) => e } }
}

// `timeout` covers the whole owner exchange; `limit` is the largest valid result body.
async fn forward(c: &Controller, owner: &str, method: reqwest::Method, path: &str, body: Option<Value>, timeout: Duration, limit: usize) -> Result<(StatusCode, Value), Forward> {
    let endpoint = c.endpoints.iter().find(|e| e.node_id == owner).ok_or(Forward::NotSent(http::invalid_input()))?;
    let nodes = c.snapshot().await;
    if !nodes.iter().any(|n| n.node_id == owner && n.fresh) {
        return Err(Forward::NotSent(ApiError(StatusCode::SERVICE_UNAVAILABLE, "owner_unavailable", "Owner identity has no fresh validated observation")));
    }
    let mut url = reqwest::Url::parse(&endpoint.url).map_err(|_| Forward::NotSent(http::invalid_input()))?;
    url.set_path(path);
    let mut request = c.client.request(method, url).bearer_auth(c.worker_token.as_str()).timeout(timeout);
    if let Some(body) = body { request = request.header("content-type", "application/json").body(serde_json::to_vec(&body).map_err(|_| Forward::NotSent(http::invalid_input()))?); }
    let lost = |timeout: bool| Forward::Lost(if timeout {
        ApiError(StatusCode::GATEWAY_TIMEOUT, "owner_response_timeout", "Owner did not answer in time; the operation may continue there. Read sandbox state")
    } else {
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "owner_response_unavailable", "Owner response was lost; the operation may have run. Read sandbox state")
    });
    let mut response = request.send().await.map_err(|e| lost(e.is_timeout()))?;
    let status = response.status();
    if response.content_length().is_some_and(|n| n > limit as u64) { return Err(lost(false)); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| lost(e.is_timeout()))? {
        if bytes.len() + chunk.len() > limit { return Err(lost(false)); }
        bytes.extend_from_slice(&chunk);
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| lost(false))?;
    Ok((status, value))
}

// Start protected management routes and bounded worker polling with redirects and proxies disabled. On
// shutdown, stop serving and cancel the poller.
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
        server: config.server.clone(),
        // Plain reads stay within the short route deadline.
        short_wait: Duration::from_millis(config.poll.timeout_ms.min(config.server.request_timeout_ms / 2)),
    };
    let router = Router::new()
        .route("/healthz", get(|| async { Json(lifecycle::Health { service: "controller", live: true }) }))
        .route("/v1/status", get(status))
        .route("/v1/sandboxes", post(create))
        .route("/v1/sandboxes/{id}", get(get_sandbox).delete(delete))
        .route("/v1/sandboxes/{id}/exec", post(exec))
        .route("/v1/sandboxes/{id}/http", post(application_http))
        .route("/v1/sandboxes/{id}/capture", post(capture))
        .with_state(controller.clone());
    let app = http::protect(router, &config.server, token, 2);
    let listener = tokio::net::TcpListener::bind(config.server.address(8080)).await
        .map_err(|_| "cannot bind controller listener")?;
    let worker_token = controller.worker_token.clone();
    let poller = tokio::spawn(poll(controller, config, client, worker_token));
    println!("controller listening; controller-assigned placement and ID-prefix routing enabled");
    let result = axum::serve(listener, app).with_graceful_shutdown(http::shutdown()).await;
    poller.abort();
    let _ = poller.await;
    result.map_err(|_| "controller HTTP server failed")
}

// Poll configured workers in bounded parallel batches. Save successful observations and flag failures
// without discarding the last known status.
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

// Fetch authenticated worker status within a response-size bound. Reject unsuccessful responses,
// malformed status and mismatched worker identity.
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
