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
use crate::api::state::{AppState, HarborFetchHandle};
use crate::db;
use crate::error::AppError;
use crate::services::harbor_webhook::{self, HarborTagLookup, Received};
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
/// 4. The event's repository picks the mapping on that project. No mapping matches: the event
///    is counted as unmatched and the request returns `202` with nothing queued.
/// 5. The per-mapping budget is charged, then the `Authorization` secret and the event logic
///    run. The secret is the project secret, checked against its digest.
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
    let Some(repository) = harbor_webhook::event_repository(&body) else {
        return Err(AppError::InvalidRequest(
            "the event does not name a repository.".to_owned(),
        ));
    };
    let Some(mapping_id) = db::project_webhooks::mapping_for_repository(
        &state.pool,
        &project.harbor_base_url,
        &project.harbor_project,
        repository_name(&repository),
    )
    .await?
    else {
        // No mapping covers this repository. The event is authenticated first, so an unknown
        // sender cannot fill the count, then counted and acknowledged with nothing queued.
        if !harbor_webhook::secret_matches(&project.secret_hash, authorization) {
            return Err(refuse(&state, failure_key.as_deref(), now));
        }
        db::project_webhooks::record_unmatched(&state.pool, &project.id, &repository, now_secs())
            .await?;
        return Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response());
    };
    if let Err(retry) = state
        .webhook_token_limiter
        .check(&format!("mapping:{mapping_id}"), now)
    {
        return Ok(too_many_requests(retry));
    }
    // The project secret is checked here, not the mapping's: a project event is authenticated
    // by the project webhook it arrived at (#132).
    if !harbor_webhook::secret_matches(&project.secret_hash, authorization) {
        return Err(refuse(&state, failure_key.as_deref(), now));
    }
    // The event's own repo_full_name is already `project/repository`, the form classify compares.
    let repo_full_name = repository.clone();
    match harbor_webhook::queue_event(
        &state.pool,
        &mapping_id,
        &repo_full_name,
        &body,
        now_secs(),
        &tag_lookup(&state),
        crate::services::ids::new_id,
    )
    .await
    {
        Ok(Received::Queued) | Ok(Received::Ignored) => {
            Ok((StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response())
        }
        Err(other) => Err(other),
    }
}

/// The Harbor tag lookup for an untagged scan event, on the app's guarded Harbor reader. Both
/// webhook routes use it, so a digest-only event is handled the same on either.
fn tag_lookup(state: &AppState) -> HarborTagLookup<'_, HarborFetchHandle> {
    HarborTagLookup {
        pool: &state.pool,
        key: &state.credentials_key,
        http: &state.harbor_fetch,
    }
}

/// The repository part of `owner/name` (the Harbor repository), as the mapping stores it.
fn repository_name(full: &str) -> &str {
    full.split_once('/')
        .map_or(full, |(_, repository)| repository)
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
    match harbor_webhook::receive_for(
        &state.pool,
        &mapping_id,
        authorization,
        &body,
        now_secs(),
        &tag_lookup(&state),
        crate::services::ids::new_id,
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
