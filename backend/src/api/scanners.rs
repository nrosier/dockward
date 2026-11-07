//! Scanner routes (`specs/api.md`, "Scanners and tag scans"; #224). Every handler takes
//! `AuthUser`, so a missing session is `401`. The mapping owner and any admin may read and start
//! a scan; another tenant's mapping is `404`, checked before any limit.
//!
//! Rate limits, declared per route:
//! - `GET /mappings/:id/scanners`: 60 per minute per user, in memory, after the tenancy check.
//! - `POST /mappings/:id/tags/:tag/scan`: one scan per (mapping, tag, scanner) per 5 minutes, in
//!   memory, after the tenancy check. Over it: `429` with `Retry-After`.
//! - `GET /mappings/:id/tags/:tag/scans`: no limit. It reads only the database (`specs/api.md`).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::pickers::fail_response;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::poller;
use crate::services::scanner_launch;
use crate::services::sessions::AuthUser;
use crate::services::tag_scans;
use crate::worker::now_secs;

/// The `POST .../scan` body. Both members are optional.
#[derive(Debug, Default, Deserialize)]
struct ScanBody {
    #[serde(default)]
    scanner_uuid: Option<String>,
}

/// `GET /api/v1/mappings/:id/scanners`. The owner or any admin.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    let is_admin = user.role == Role::Admin;
    let mapping = match poller::find_pullable(&state.pool, &user.id, is_admin, &id).await {
        Ok(mapping) => mapping,
        Err(error) => return error.into_response(),
    };
    match scanner_launch::list(
        &state.scanner_launch,
        &state.pool,
        &state.credentials_key,
        &state.harbor_fetch,
        &user.id,
        &mapping,
    )
    .await
    {
        Ok(list) => Json(list).into_response(),
        Err(fail) => fail_response(fail),
    }
}

/// `GET /api/v1/mappings/:id/tags/:tag/scans`. The owner or any admin. Reads only the database:
/// it makes no Harbor call and has no rate limit (`specs/api.md`). Another tenant's mapping is
/// `404`.
pub async fn scans(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, tag)): Path<(String, String)>,
) -> Response {
    let is_admin = user.role == Role::Admin;
    let mapping = match poller::find_pullable(&state.pool, &user.id, is_admin, &id).await {
        Ok(mapping) => mapping,
        Err(error) => return error.into_response(),
    };
    match tag_scans::list(&state.pool, &mapping, &tag).await {
        Ok(items) => Json(serde_json::json!({ "items": items })).into_response(),
        Err(error) => error.into_response(),
    }
}

/// `POST /api/v1/mappings/:id/tags/:tag/scan`. The owner or any admin. Queues one job and
/// answers `202`; it does not wait for Harbor.
pub async fn scan(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, tag)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let parsed: ScanBody = if body.is_empty() {
        ScanBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => {
                return AppError::InvalidRequest("The request body is not valid.".to_owned())
                    .into_response();
            }
        }
    };
    let is_admin = user.role == Role::Admin;
    let mapping = match poller::find_pullable(&state.pool, &user.id, is_admin, &id).await {
        Ok(mapping) => mapping,
        Err(error) => return error.into_response(),
    };
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    match scanner_launch::start_scan(
        &state.scanner_launch,
        &state.pool,
        &state.credentials_key,
        &state.harbor_fetch,
        &actor,
        &mapping,
        &tag,
        parsed.scanner_uuid.as_deref(),
        now_secs(),
    )
    .await
    {
        Ok(queued) => (StatusCode::ACCEPTED, Json(queued)).into_response(),
        Err(fail) => fail_response(fail),
    }
}
