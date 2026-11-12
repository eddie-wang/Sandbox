use std::{sync::Arc, time::{Duration, Instant}};

use axum::{Json, Router, extract::{State, rejection::JsonRejection}, http::StatusCode, routing::{get, post}};
use serde::Serialize;
use tokio::{sync::RwLock, task::JoinSet};

use crate::{
    config::{ControllerConfig, WorkerEndpoint},
    http::{self, ApiError},
    lifecycle,
    model::{CreateRequest, WorkerStatus},
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
        lifecycle_implemented: false,
        nodes: controller.snapshot().await,
    })
}

async fn create(
    State(controller): State<Controller>,
    input: Result<Json<CreateRequest>, JsonRejection>,
) -> Result<(), ApiError> {
    let request = http::json(input)?;
    if !request.valid() {
        return Err(http::invalid_input());
    }
    let nodes = controller.snapshot().await;
    if scheduler::choose(&nodes, &request).is_none() {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "no_ready_runtime", "No fresh compatible worker has ready runtime admission and capacity"));
    }
    // A future/foreign worker advertising readiness cannot enable this controller's lifecycle.
    // No reservation, dispatch, or sandbox state is created by this informational selection.
    Err(http::not_implemented())
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
    };
    let router = Router::new()
        .route("/healthz", get(|| async { Json(lifecycle::Health { service: "controller", live: true }) }))
        .route("/v1/status", get(status))
        .route("/v1/sandboxes", post(create))
        .route("/v1/sandboxes/{id}/exec", post(lifecycle::exec))
        .route("/v1/sandboxes/{id}/capture", post(lifecycle::capture))
        .with_state(controller.clone());
    let app = http::protect(router, &config.server, token);
    let listener = tokio::net::TcpListener::bind(config.server.address(8080)).await
        .map_err(|_| "cannot bind controller listener")?;
    let poller = tokio::spawn(poll(controller, config, client, Arc::new(worker_token)));
    println!("controller listening; sandbox lifecycle unavailable");
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
