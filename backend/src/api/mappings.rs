//! Mapping routes (`specs/api.md`, Mappings). Every handler takes `AuthUser`, so a missing
//! or invalid session returns `401`. Ownership is enforced in the service, so another
//! user's mapping is `404`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::credential_probe::{OutboundGithubProbe, OutboundHarborProbe};
use crate::services::mappings::{self, Created, ListQuery, Mapping, NewMapping};
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;

/// Raw query values for `GET /api/v1/mappings`.
#[derive(Debug, Deserialize)]
pub struct MappingListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub scope: Option<String>,
}

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`.
fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

fn actor_of(user: &AuthUser) -> Actor {
    Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    }
}

/// `GET /api/v1/mappings`. `scope=all` is honored for admins only.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<MappingListParams>,
) -> Result<Json<Page<Mapping>>, AppError> {
    let all_users = match params.scope.as_deref() {
        None => false,
        Some("all") if user.role == Role::Admin => true,
        Some("all") => return Err(AppError::Forbidden),
        Some(_) => return Err(AppError::InvalidRequest("scope must be all.".to_owned())),
    };
    let query = ListQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        all_users,
    };
    Ok(Json(mappings::list(&state.pool, &user.id, &query).await?))
}

/// `POST /api/v1/mappings`. Returns `201` with the mapping and the two values shown once.
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: NewMapping = parse_body(&body)?;
    let actor = actor_of(&user);
    let probe = OutboundHarborProbe::new(state.allow_private_harbor)?;
    let github_probe = OutboundGithubProbe::new()?;
    let created: Created = mappings::create(
        &state.pool,
        &state.credentials_key,
        &probe,
        &github_probe,
        &actor,
        &user.id,
        &state.public_url,
        input,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// `GET /api/v1/mappings/:id`.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Mapping>, AppError> {
    Ok(Json(
        mappings::load_owned(&state.pool, &user.id, &id).await?,
    ))
}

/// `DELETE /api/v1/mappings/:id`. Returns `204`. Owner only.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = actor_of(&user);
    mappings::delete(&state.pool, &actor, &user.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/mappings/:id/rotate-webhook-token`. Owner only.
pub async fn rotate_webhook_token(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor = actor_of(&user);
    let url = mappings::rotate_webhook_token(&state.pool, &actor, &user.id, &state.public_url, &id)
        .await?;
    Ok(Json(serde_json::json!({ "webhook_url": url })))
}

/// `POST /api/v1/mappings/:id/rotate-auth-secret`. Owner only.
pub async fn rotate_auth_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor = actor_of(&user);
    let secret = mappings::rotate_auth_secret(&state.pool, &actor, &user.id, &id).await?;
    Ok(Json(serde_json::json!({ "auth_secret": secret })))
}
