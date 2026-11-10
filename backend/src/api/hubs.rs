//! Hub routes (`specs/spinoff-local-scan.md`, section 10; decisions 13, 44 and 45). Listing is
//! for any session. Adding and removing are admin-only, and adding is limited to 60 per minute
//! per user because it resolves the entered host.

use std::time::Instant;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::auth::AdminUser;
use crate::api::hardening::too_many_requests;
use crate::api::json::parse_body;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::audit::Actor;
use crate::services::hubs::{self, Hub, NewHub};
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;

/// Raw query values for `GET /api/v1/hubs`.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// `GET /api/v1/hubs`. Any session. `id`, `host`, `pull_endpoint` or null, `kind`.
pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Page<Hub>>, AppError> {
    Ok(Json(
        hubs::list(&state.pool, params.page, params.page_size).await?,
    ))
}

/// `POST /api/v1/hubs`. Admin only, limited. Returns `201` with the new custom hub.
pub async fn create(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    if let Err(retry_after) = state.registry_limiter.check(&admin.id, Instant::now()) {
        return Ok(too_many_requests(retry_after));
    }
    let input: NewHub = parse_body(&body)?;
    let actor = Actor {
        user_id: Some(admin.id.clone()),
        username: admin.username.clone(),
    };
    let hub = hubs::create(
        &state.pool,
        state.discovery.client(),
        &actor,
        &admin.id,
        input,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(hub)).into_response())
}

/// `DELETE /api/v1/hubs/:id`. Admin only. `204`, or `409` for a default hub or a hub in use.
pub async fn delete(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    hubs::delete(&state.pool, &actor, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
