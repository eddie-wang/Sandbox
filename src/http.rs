use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State, rejection::JsonRejection},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

use crate::config::ServerConfig;

#[derive(Clone)]
struct Limits {
    token: Arc<String>,
    permits: Arc<Semaphore>,
    max_body_bytes: usize,
    timeout: Duration,
    server: ServerConfig,
    hops: u32,
}

pub struct ApiError(pub StatusCode, pub &'static str, pub &'static str);

impl IntoResponse for ApiError {
    // Return the safe API error envelope with caching disabled and a bearer challenge when unauthorized.
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody {
            code: &'static str,
            message: &'static str,
        }
        #[derive(Serialize)]
        struct Envelope {
            error: ErrorBody,
        }
        let mut response = (self.0, Json(Envelope {
            error: ErrorBody { code: self.1, message: self.2 },
        })).into_response();
        response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if self.0 == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        response
    }
}

// Return a generic bad-request error without echoing submitted data.
pub fn invalid_input() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_input", "Invalid request fields or JSON")
}

// Extract parsed request data or replace parsing details with a generic input error.
pub fn json<T>(input: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    input.map(|Json(value)| value).map_err(|_| invalid_input())
}

// Wrap routes with authentication, request limits and deadlines, and a JSON 404 for unknown routes.
// `hops` is 1 on a worker and 2 on the controller: each forwarding layer gets one
// extra request_timeout_ms so the inner layer reports its own timeout first.
pub fn protect(router: Router, config: &ServerConfig, token: String, hops: u32) -> Router {
    router
        .fallback(|| async {
            ApiError(StatusCode::NOT_FOUND, "not_found", "Unknown API route")
        })
        .layer(middleware::from_fn_with_state(Limits {
            token: Arc::new(token),
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            max_body_bytes: config.max_body_bytes,
            timeout: config.timeout(),
            server: config.clone(),
            hops,
        }, guard))
}

// Require a single matching bearer token except for public health reads. Limit concurrent requests,
// body size and body-read time; blocking routes may run for their outcome wait plus one
// request_timeout_ms per hop, others for request_timeout_ms. Then disable response caching.
async fn guard(State(limits): State<Limits>, request: Request, next: Next) -> Response {
    let public_health = request.method() == Method::GET && request.uri().path() == "/healthz";
    if !public_health {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let provided = values.next().and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let authorized = values.next().is_none() && provided.is_some_and(|provided| {
            bool::from(provided.as_bytes().ct_eq(limits.token.as_bytes()))
        });
        if !authorized {
            return ApiError(StatusCode::UNAUTHORIZED, "unauthorized", "Bearer authentication required").into_response();
        }
    }
    let Ok(_permit) = limits.permits.clone().try_acquire_owned() else {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy", "Request concurrency limit reached").into_response();
    };
    let handler_deadline = limits.server.route_wait(request.method(), request.uri().path())
        .map_or(limits.timeout, |wait| wait + limits.timeout * limits.hops);
    let (parts, body) = request.into_parts();
    if parts.headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > limits.max_body_bytes as u64)
    {
        return ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "Request body limit exceeded").into_response();
    }
    let timed_out = || ApiError(StatusCode::REQUEST_TIMEOUT, "request_timeout", "Request deadline exceeded").into_response();
    // The body deadline is always short; only the handler wait is route-specific.
    let bytes = match tokio::time::timeout(limits.timeout, to_bytes(body, limits.max_body_bytes)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "Request body unavailable or exceeds limit").into_response(),
        Err(_) => return timed_out(),
    };
    // Dropping a handler future never cancels worker-owned jobs (an undelivered
    // create is deleted as create_response_lost); see engine.rs.
    let mut response = tokio::time::timeout(handler_deadline, next.run(Request::from_parts(parts, Body::from(bytes)))).await
        .unwrap_or_else(|_| timed_out());
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

// Wait for an interrupt or, where supported, a termination signal to begin graceful shutdown.
pub async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("cannot install termination handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
