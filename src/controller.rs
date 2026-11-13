use std::{sync::Arc, time::{Duration, Instant}};

use axum::{Json, Router, body::Body, extract::{Path, Request, State, rejection::{JsonRejection, PathRejection}}, http::{StatusCode, header}, response::{IntoResponse, Response}, routing::{get, post}};
use serde_json::Value;
use serde::Serialize;
use tokio::{sync::RwLock, task::JoinSet};

use crate::{
    config::{ControllerConfig, ServerConfig, WorkerEndpoint},
    http::{self, ApiError},
    lifecycle,
    model::{CaptureRequest, CreateSpec, ExecRequest, WorkerStatus, sandbox_owner, valid_id},
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
    // Streams app traffic and streaming exec output to owners: no total deadline (see ProxyLimits).
    proxy_client: reqwest::Client,
    proxy_permits: Arc<tokio::sync::Semaphore>,
    worker_token: Arc<String>,
    server: ServerConfig,
    short_wait: Duration,
}

impl Controller {
    // Return how long a forward to the owner may take: the owner's own outcome wait plus one
    // request_timeout_ms of slack, so the owner reports its own operation_timeout before this
    // forward gives up.
    fn operation_timeout(&self, wait: Duration) -> Duration { wait + self.server.timeout() }
    // Return the cached view of every configured worker, marking it fresh only if its last poll
    // succeeded within the freshness window.
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

// Return 32 random hex characters for the local part of a new sandbox ID, or a 503 error if the
// kernel cannot supply randomness without blocking.
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

// Validate a client create, rank fresh workers and try up to three of them, each with a newly
// generated owner-prefixed ID, within one shared deadline. Move on only after a definitive pre-launch
// rejection; any other answer is final and names the ID when the outcome is uncertain. Return 422
// if every candidate answered template_unavailable, otherwise 503 no_capacity.
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

// Read the sandbox ID from the route and return it with the owner node named in its prefix.
fn path_id(path: Result<Path<String>, PathRejection>) -> Result<(String, String), ApiError> {
    let Path(id) = path.map_err(|_| http::invalid_input())?;
    let owner = sandbox_owner(&id).ok_or_else(http::invalid_input)?.to_owned();
    Ok((id, owner))
}
// Pass the owner's status and JSON body back to the client, or the forwarding error.
fn reply(result: Result<(StatusCode, Value), Forward>) -> Result<Response, ApiError> {
    let (status, body) = result.map_err(Forward::error)?;
    Ok((status, Json(body)).into_response())
}
// Read a sandbox's state from its owner within the short read deadline.
async fn get_sandbox(State(c): State<Controller>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    reply(forward(&c, &owner, reqwest::Method::GET, &format!("/v1/sandboxes/{id}"), None, c.short_wait, MAX_SANDBOX_VIEW_BYTES).await)
}
// Forward a delete to the owner and wait for its final outcome within the delete deadline.
async fn delete(State(c): State<Controller>, path: Result<Path<String>, PathRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    let wait = Duration::from_millis(c.server.operation_deadlines.delete_ms);
    reply(forward(&c, &owner, reqwest::Method::DELETE, &format!("/v1/sandboxes/{id}"), None, c.operation_timeout(wait), MAX_SANDBOX_VIEW_BYTES).await)
}
// Take a proxy connection permit for a streamed exchange, or refuse with 503 busy.
fn proxy_permit(c: &Controller) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    c.proxy_permits.clone().try_acquire_owned().map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Proxy connection limit reached"))
}
// Validate a command and forward it to the owner. A blocking command waits for its own timeout plus
// the margin and accepts a reply up to the largest possible exec result; a streaming command's events
// are passed through as they arrive, under the proxy connection and idle bounds.
async fn exec(State(c): State<Controller>, path: Result<Path<String>, PathRejection>, input: Result<Json<ExecRequest>, JsonRejection>) -> Result<Response, ApiError> {
    let (id, owner) = path_id(path)?;
    let request = http::json(input)?;
    if !request.valid() { return Err(http::invalid_input()); }
    let route = format!("/v1/sandboxes/{id}/exec");
    let body = serde_json::to_vec(&request).map_err(|_| http::invalid_input())?;
    if request.stream {
        let url = owner_url(&c, &owner, &route, None).await?;
        let permit = proxy_permit(&c)?;
        let upstream = Request::builder().method("POST").uri(&route).header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body)).map_err(|_| http::invalid_input())?;
        return Ok(crate::proxy::to_owner(&c.proxy_client, url, &c.worker_token, upstream, c.server.proxy.idle(), permit).await);
    }
    let wait = Duration::from_millis(request.timeout_ms + c.server.operation_deadlines.margin_ms);
    let limit = request.max_result_bytes();
    reply(forward(&c, &owner, reqwest::Method::POST, &route, Some(serde_json::from_slice(&body).map_err(|_| http::invalid_input())?), c.operation_timeout(wait), limit).await)
}
// Forward a kill of one running command to the owner and wait (margin plus one request timeout) until
// the command has ended there.
async fn kill(State(c): State<Controller>, path: Result<Path<(String, u64)>, PathRejection>) -> Result<Response, ApiError> {
    let Path((id, exec)) = path.map_err(|_| http::invalid_input())?;
    let owner = sandbox_owner(&id).ok_or_else(http::invalid_input)?.to_owned();
    let wait = Duration::from_millis(c.server.operation_deadlines.margin_ms);
    reply(forward(&c, &owner, reqwest::Method::POST, &format!("/v1/sandboxes/{id}/exec/{exec}/kill"), None, c.operation_timeout(wait), MAX_SANDBOX_VIEW_BYTES).await)
}
// Route one authenticated app-proxy request (path form, or host form rewritten to it by the guard) to
// the sandbox's owner by its ID prefix and stream the exchange, under the proxy connection and idle
// bounds.
async fn app_proxy(c: Controller, request: Request) -> Response {
    let Some((id, _, _)) = crate::proxy::parse(request.uri().path()) else { return http::invalid_input().into_response() };
    let owner = sandbox_owner(&id).unwrap_or_default().to_owned();
    let url = match owner_url(&c, &owner, request.uri().path(), request.uri().query()).await {
        Ok(url) => url,
        Err(error) => return error.into_response(),
    };
    match proxy_permit(&c) {
        Ok(permit) => crate::proxy::to_owner(&c.proxy_client, url, &c.worker_token, request, c.server.proxy.idle(), permit).await,
        Err(error) => error.into_response(),
    }
}
// Check the new template ID and forward the capture to the owner within the capture deadline.
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
    // The owner may have acted; exec is not exactly-once, so read state.
    Lost(ApiError),
}
impl Forward {
    // Return the client-facing error, whether or not the request reached the owner.
    fn error(self) -> ApiError { match self { Self::NotSent(e) | Self::Lost(e) => e } }
}

// Build the owner's URL for a path (and query), only for a configured owner with a fresh validated
// observation.
async fn owner_url(c: &Controller, owner: &str, path: &str, query: Option<&str>) -> Result<reqwest::Url, ApiError> {
    let endpoint = c.endpoints.iter().find(|e| e.node_id == owner).ok_or_else(http::invalid_input)?;
    let nodes = c.snapshot().await;
    if !nodes.iter().any(|n| n.node_id == owner && n.fresh) {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "owner_unavailable", "Owner identity has no fresh validated observation"));
    }
    let mut url = reqwest::Url::parse(&endpoint.url).map_err(|_| http::invalid_input())?;
    url.set_path(path);
    url.set_query(query);
    Ok(url)
}

// Send an authenticated request to the owner only if it has a fresh observation, and read its JSON
// reply up to `limit` bytes. `timeout` covers the whole exchange. Fail as NotSent when nothing left
// this controller, or as Lost when the owner may have acted (timeout, dropped or oversized reply).
async fn forward(c: &Controller, owner: &str, method: reqwest::Method, path: &str, body: Option<Value>, timeout: Duration, limit: usize) -> Result<(StatusCode, Value), Forward> {
    let url = owner_url(c, owner, path, None).await.map_err(Forward::NotSent)?;
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

// Start protected management routes, the app proxy (path form, plus host routing below the configured
// proxy domain) and bounded worker polling, with redirects and environment proxies disabled. On
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
    let proxy_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(config.poll.timeout_ms.min(1_000)))
        .pool_idle_timeout(Duration::from_secs(30))
        .build().map_err(|_| "cannot initialize worker proxy client")?;
    let controller = Controller {
        nodes: Arc::new(RwLock::new(config.workers.iter().map(|worker| CachedNode {
            node_id: worker.node_id.clone(), status: None, observed: None, error: Some("not_polled"),
        }).collect())),
        freshness: Duration::from_millis(config.poll.freshness_ms),
        endpoints: Arc::new(config.workers.clone()), client: client.clone(), proxy_client,
        proxy_permits: Arc::new(tokio::sync::Semaphore::new(config.server.proxy.max_connections)), worker_token: Arc::new(worker_token),
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
        .route("/v1/sandboxes/{id}/exec/{exec_id}/kill", post(kill))
        .route("/v1/sandboxes/{id}/capture", post(capture))
        .with_state(controller.clone());
    let proxy_controller = controller.clone();
    let proxy: http::Proxy = Arc::new(move |request| Box::pin(app_proxy(proxy_controller.clone(), request)));
    let app = http::protect(router, &config.server, token, 2, proxy, config.proxy_domain.clone());
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
