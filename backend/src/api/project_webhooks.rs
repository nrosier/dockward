//! Project webhook routes (`specs/api.md`, Project webhooks; #132). Every handler takes
//! `AuthUser`, so a missing or invalid session returns `401`. Ownership and the admin read
//! rule are enforced in the service. The public receiver is in `api::webhooks`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::pagination::Page;
use crate::services::project_webhooks::{
    self as service, ProjectWebhook, SecretRotated, TokenRotated, Unmatched, UnmatchedQuery,
};
use crate::services::sessions::AuthUser;

/// The `POST /api/v1/project-webhooks` body.
#[derive(Debug, Deserialize)]
pub struct CreateBody {
    pub mapping_id: String,
}

/// Raw query values for `GET /api/v1/project-webhooks/:id/unmatched`.
#[derive(Debug, Deserialize)]
pub struct UnmatchedParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

/// `POST /api/v1/project-webhooks`. Returns `201` with the id and the two values shown once.
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: CreateBody = serde_json::from_slice(&body)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))?;
    let created = service::create(&state.pool, &user, &state.public_url, &input.mapping_id).await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// `GET /api/v1/project-webhooks/:id`. Owner or admin.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ProjectWebhook>, AppError> {
    Ok(Json(service::get(&state.pool, &user, &id).await?))
}

/// `POST /api/v1/project-webhooks/:id/rotate-token`. Owner only.
pub async fn rotate_token(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TokenRotated>, AppError> {
    Ok(Json(
        service::rotate_token(&state.pool, &user, &state.public_url, &id).await?,
    ))
}

/// `POST /api/v1/project-webhooks/:id/rotate-secret`. Owner only.
pub async fn rotate_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<SecretRotated>, AppError> {
    Ok(Json(service::rotate_secret(&state.pool, &user, &id).await?))
}

/// `GET /api/v1/project-webhooks/:id/unmatched`. Owner or admin.
pub async fn unmatched(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<UnmatchedParams>,
) -> Result<Json<Page<Unmatched>>, AppError> {
    let query = UnmatchedQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
    };
    Ok(Json(
        service::unmatched(&state.pool, &user, &id, &query).await?,
    ))
}
