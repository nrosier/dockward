//! The Harbor webhook route (`specs/integrations.md`, Harbor webhook; `specs/security.md`,
//! Hardening). It is public: no session and no CSRF token. The mapping token is only in
//! the URL path.

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
use crate::db;
use crate::error::AppError;
use crate::services::harbor_webhook::{self, Received};
use crate::worker::now_secs;

/// Largest accepted webhook body (`specs/security.md`, Hardening).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Requests per minute per mapping (`specs/security.md`).
const TOKEN_LIMIT: u32 = 60;
/// Failed authentications (`401`) per minute per client IP.
const FAILURE_LIMIT: u32 = 30;
const WINDOW: Duration = Duration::from_secs(60);

/// A fresh per-mapping request budget. The router state holds one (see `AppState`).
pub fn new_token_limiter() -> RateLimiter {
    RateLimiter::new(TOKEN_LIMIT, WINDOW)
}

/// A fresh failed-authentication budget per client IP. The router state holds one.
pub fn new_failure_limiter() -> RateLimiter {
    RateLimiter::new(FAILURE_LIMIT, WINDOW)
}

#[derive(Serialize)]
struct Accepted {
    status: &'static str,
}

/// Counts one failed authentication for the client IP, when there is one. The returned
/// error is always the same `401`, so an unknown token and a wrong secret look alike.
fn refuse(state: &AppState, failure_key: Option<&str>, now: Instant) -> AppError {
    if let Some(key) = failure_key {
        let _ = state.webhook_failure_limiter.check(key, now);
    }
    AppError::InvalidCredentials
}

/// `POST /api/v1/webhooks/harbor/project/:project_token` (#132, `specs/integrations.md`).
///
/// One project webhook serves every mapping on its Harbor project. Order, as for the mapping
/// receiver:
/// 1. The per-IP failure budget is checked, not consumed.
/// 2. The body is read under the 64 KiB cap.
/// 3. The project token is looked up by digest. An unknown token is a `401` and counts one IP
///    failure.
/// 4. The `Authorization` secret is checked against the project secret's digest, before the
///    body is parsed. A failure is a `401` that counts one IP failure.
/// 5. The event must name a repository in the webhook's own project, else `202` and nothing
///    is stored or counted. The repository picks the mapping on that project. No mapping
///    matches: a valid name is counted as unmatched and the request returns `202`.
/// 6. The per-mapping budget is charged, then the event logic runs.
pub async fn receive_project(
    State(state): State<AppState>,
    Path(project_token): Path<String>,
    client: Option<axum::Extension<ClientIp>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let client_ip = client.map(|axum::Extension(ClientIp(ip))| ip);
    let now = Instant::now();
    let failure_key = client_ip.map(|ip| format!("fail:{ip}"));
    if let Some(key) = &failure_key
        && state.webhook_failure_limiter.is_exhausted(key, now)
    {
        return Ok(too_many_requests(WINDOW.as_secs()));
    }
    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    let token_hash = crate::services::mappings::digest(&project_token);
    let Some(project) = db::project_webhooks::find_by_token_hash(&state.pool, &token_hash).await?
    else {
        return Err(refuse(&state, failure_key.as_deref(), now));
    };
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    // The project secret is known as soon as the token is found, so it is checked before the
    // body is looked at: a token-only caller gets the same 401 for any body, and learns
    // nothing about whether the token is valid (#145).
    if !harbor_webhook::secret_matches(&project.secret_hash, authorization) {
        return Err(refuse(&state, failure_key.as_deref(), now));
    }
    let Some(repository) = harbor_webhook::event_repository(&body) else {
        return Err(AppError::InvalidRequest(
            "the event does not name a repository.".to_owned(),
        ));
    };
    // Project scope (#145): an event for another Harbor project is not for this webhook. It is
    // acknowledged, stored nowhere, and not counted. This check comes before any routing.
    let Some(event_repository) =
        harbor_webhook::repository_in_project(&project.harbor_project, &repository)
    else {
        return Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response());
    };
    let Some(mapping) = db::project_webhooks::mapping_for_repository(
        &state.pool,
        &project.harbor_base_url,
        &project.harbor_project,
        event_repository,
    )
    .await?
    else {
        // No mapping covers this repository. The sender is authenticated, so an unknown
        // sender cannot fill the count. A name that fails Harbor's name rule is ignored
        // (#145); a valid one is counted. Either way nothing is queued.
        if harbor_webhook::unmatched_name_is_valid(&project.harbor_project, &repository) {
            db::project_webhooks::record_unmatched(
                &state.pool,
                &project.id,
                &repository,
                now_secs(),
            )
            .await?;
        }
        return Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response());
    };
    // The per-mapping budget is charged only for an authenticated event.
    if let Err(retry) = state
        .webhook_token_limiter
        .check(&format!("mapping:{}", mapping.id), now)
    {
        return Ok(too_many_requests(retry));
    }
    let job_id = crate::services::ids::new_id()?;
    // The repository name always comes from the mapping, never from the event (#145).
    let repo_full_name = format!("{}/{}", project.harbor_project, mapping.harbor_repository);
    match harbor_webhook::queue_event(
        &state.pool,
        &mapping.id,
        &repo_full_name,
        &body,
        now_secs(),
        &job_id,
    )
    .await
    {
        Ok(Received::Queued) | Ok(Received::Ignored) => {
            Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response())
        }
        Err(other) => Err(other),
    }
}

/// `POST /api/v1/webhooks/harbor/:mapping_token`.
///
/// Order:
/// 1. The per-IP failure budget is checked, not consumed. An exhausted IP gets `429`
///    before anything else is read or looked up.
/// 2. The body is read under the 64 KiB cap.
/// 3. The token is looked up by digest. An unknown token is a `401` that counts one IP
///    failure. No per-token budget entry is created for it.
/// 4. The per-token budget is charged, keyed by mapping id and never by the presented
///    token.
/// 5. The `Authorization` secret and the job logic run. A `401` counts one IP failure.
pub async fn receive(
    State(state): State<AppState>,
    Path(token): Path<String>,
    client: Option<axum::Extension<ClientIp>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let client_ip = client.map(|axum::Extension(ClientIp(ip))| ip);
    let now = Instant::now();
    let failure_key = client_ip.map(|ip| format!("fail:{ip}"));
    if let Some(key) = &failure_key
        && state.webhook_failure_limiter.is_exhausted(key, now)
    {
        return Ok(too_many_requests(WINDOW.as_secs()));
    }
    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    let Some(mapping_id) = harbor_webhook::find_mapping(&state.pool, &token).await? else {
        return Err(refuse(&state, failure_key.as_deref(), now));
    };
    if let Err(retry) = state
        .webhook_token_limiter
        .check(&format!("mapping:{mapping_id}"), now)
    {
        return Ok(too_many_requests(retry));
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let job_id = crate::services::ids::new_id()?;
    match harbor_webhook::receive_for(
        &state.pool,
        &mapping_id,
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
        Err(AppError::InvalidCredentials) => Err(refuse(&state, failure_key.as_deref(), now)),
        Err(other) => Err(other),
    }
}
