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

// Wrap management routes with authentication and request bounds, plus a safe unknown-route response.
pub fn protect(router: Router, config: &ServerConfig, token: String) -> Router {
    router
        .fallback(|| async {
            ApiError(StatusCode::NOT_FOUND, "not_found", "Unknown API route")
        })
        .layer(middleware::from_fn_with_state(Limits {
            token: Arc::new(token),
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            max_body_bytes: config.max_body_bytes,
            timeout: config.timeout(),
        }, guard))
}

// Require a single matching bearer token except for public health reads. Limit concurrent requests,
// body size and handling time, then disable response caching.
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
    let response = tokio::time::timeout(limits.timeout, async {
        let (parts, body) = request.into_parts();
        if parts.headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limits.max_body_bytes as u64)
        {
            return ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "Request body limit exceeded").into_response();
        }
        let bytes = match to_bytes(body, limits.max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(_) => return ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "Request body unavailable or exceeds limit").into_response(),
        };
        next.run(Request::from_parts(parts, Body::from(bytes))).await
    }).await;
    let mut response = response.unwrap_or_else(|_| {
        ApiError(StatusCode::REQUEST_TIMEOUT, "request_timeout", "Request deadline exceeded").into_response()
    });
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
