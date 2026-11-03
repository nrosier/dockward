//! The Harbor webhook route (`specs/integrations.md`, Harbor webhook; `specs/security.md`,
//! Hardening). It is public: no session and no CSRF token. The mapping token is only in
//! the URL path.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::api::hardening::{ClientIp, RateLimiter, too_many_requests};
use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::harbor_webhook::{self, Received};
use crate::worker::now_secs;

/// Largest accepted webhook body (`specs/security.md`, Hardening).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Requests per minute per mapping token (`specs/security.md`).
const TOKEN_LIMIT: u32 = 60;
/// Failed authentications (`401`) per minute per client IP.
const FAILURE_LIMIT: u32 = 30;
const WINDOW: Duration = Duration::from_secs(60);

/// Per-token request budget.
fn token_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(TOKEN_LIMIT, WINDOW))
}

/// Failed-authentication budget per client IP.
fn failure_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(FAILURE_LIMIT, WINDOW))
}

#[derive(Serialize)]
struct Accepted {
    status: &'static str,
}

/// `POST /api/v1/webhooks/harbor/:mapping_token`.
///
/// Order: the per-token budget, then the per-IP failure budget (checked only, not
/// consumed), then the body cap, then the auth and job logic. A `401` consumes one slot
/// of the failure budget for the client IP.
pub async fn receive(
    State(state): State<AppState>,
    Path(token): Path<String>,
    client: Option<axum::Extension<ClientIp>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let client_ip = client.map(|axum::Extension(ClientIp(ip))| ip);
    let now = Instant::now();
    let budget_key = format!("token:{}", crate::services::mappings::digest(&token));
    if let Err(retry) = token_limiter().check(&budget_key, now) {
        return Ok(too_many_requests(retry));
    }
    if let Some(ip) = client_ip
        && failure_limiter().is_exhausted(&format!("fail:{ip}"), now)
    {
        return Ok(too_many_requests(WINDOW.as_secs()));
    }
    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let job_id = crate::services::ids::new_id();
    match harbor_webhook::receive(
        &state.pool,
        &token,
        authorization,
        &body,
        now_secs(),
        &job_id,
    )
    .await
    {
        Ok(Received::Queued) | Ok(Received::Ignored) => {
            Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response())
        }
        Err(AppError::InvalidCredentials) => {
            if let Some(ip) = client_ip {
                let _ = failure_limiter().check(&format!("fail:{ip}"), now);
            }
            Err(AppError::InvalidCredentials)
        }
        Err(other) => Err(other),
    }
}
