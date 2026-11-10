//! Source routes (`specs/spinoff-local-scan.md`, section 10): the source CRUD, the source
//! credential, the credential test, the tag preview and the image lists. Every handler takes
//! `AuthUser`, so a missing session is `401`. Another user's source is `404`; an admin reads
//! any source and changes none (`403`). No response carries a token.

use std::time::Instant;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::hardening::too_many_requests;
use crate::api::json::parse_body;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::images::{self, Image, Query as ImageQuery};
use crate::services::pagination::Page;
use crate::services::sessions::AuthUser;
use crate::services::source_credentials::{
    self as credentials, CredentialInput, CredentialView, TestInput, TestResult,
};
use crate::services::sources::{self, ListQuery, Need, Preview, Source, SourceInput};
use crate::services::storage::StoreRoot;

fn actor_of(user: &AuthUser) -> Actor {
    Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    }
}

/// `scope=all` is honored for admins only (`403` for a user); any other value is `400`.
fn scope_all(user: &AuthUser, scope: Option<&str>) -> Result<bool, AppError> {
    match scope {
        None => Ok(false),
        Some("all") if user.role == Role::Admin => Ok(true),
        Some("all") => Err(AppError::Forbidden),
        Some(_) => Err(AppError::InvalidRequest("scope must be all.".to_owned())),
    }
}

/// Raw query values for `GET /api/v1/image-sources`.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub scope: Option<String>,
}

/// `GET /api/v1/image-sources`. The caller's sources; `scope=all` for an admin.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Page<Source>>, AppError> {
    let query = ListQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        all_users: scope_all(&user, params.scope.as_deref())?,
    };
    Ok(Json(sources::list(&state.pool, &user.id, &query).await?))
}

/// `POST /api/v1/image-sources`. Returns `201`.
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: SourceInput = parse_body(&body)?;
    let created = sources::create(&state.pool, &actor_of(&user), &user, input).await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// `GET /api/v1/image-sources/:id`. Owner, or an admin (read only).
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Source>, AppError> {
    Ok(Json(sources::get(&state.pool, &user, &id).await?))
}

/// `PUT /api/v1/image-sources/:id`. Owner only.
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Source>, AppError> {
    let input: SourceInput = parse_body(&body)?;
    Ok(Json(
        sources::update(&state.pool, &actor_of(&user), &user, &id, input).await?,
    ))
}

/// `DELETE /api/v1/image-sources/:id`. Owner only. `204`, or `409` while work of the source is
/// running.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let store = StoreRoot::under(&state.data_dir);
    sources::delete(&state.pool, &store, &actor_of(&user), &user, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/v1/image-sources/:id/credential`. Owner only. `201` when the source had none,
/// `200` when it replaces one. The token is write-only.
pub async fn put_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: CredentialInput = parse_body(&body)?;
    let (view, created): (CredentialView, bool) = credentials::put(
        &state.pool,
        &state.credentials_key,
        &actor_of(&user),
        &user,
        &id,
        input,
    )
    .await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(view)).into_response())
}

/// `DELETE /api/v1/image-sources/:id/credential`. Owner only. `204`.
pub async fn delete_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    credentials::remove(&state.pool, &actor_of(&user), &user, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/image-sources/:id/credential/test`. Owner only, limited. `{"ok","detail"}`.
pub async fn test_credential(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let input: TestInput = parse_body(&body)?;
    // Ownership first, so a foreign source is 404 whatever the limiter holds.
    {
        let mut conn = state
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        sources::load(&mut conn, &user, &id, Need::Write).await?;
    }
    if let Err(retry_after) = state.registry_limiter.check(&user.id, Instant::now()) {
        return Ok(too_many_requests(retry_after));
    }
    let result: TestResult =
        credentials::test(&state.pool, &state.discovery, &user, &id, &input).await?;
    Ok(Json(result).into_response())
}

/// `GET /api/v1/image-sources/:id/tag-preview`. Owner only, limited. The matches from the last
/// discovery; the registry is not contacted.
pub async fn tag_preview(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let source = {
        let mut conn = state
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        sources::load(&mut conn, &user, &id, Need::Write).await?
    };
    if let Err(retry_after) = state.registry_limiter.check(&user.id, Instant::now()) {
        return Ok(too_many_requests(retry_after));
    }
    let preview: Preview = sources::preview(&state.pool, &source).await?;
    Ok(Json(preview).into_response())
}

/// Raw query values for the image lists.
#[derive(Debug, Deserialize)]
pub struct ImageParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub state: Option<String>,
    pub source_id: Option<String>,
    pub scope: Option<String>,
}

/// `GET /api/v1/image-sources/:id/images`. Owner, or an admin (read).
pub async fn source_images(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<ImageParams>,
) -> Result<Json<Page<Image>>, AppError> {
    {
        let mut conn = state
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        sources::load(&mut conn, &user, &id, Need::Read).await?;
    }
    let query = ImageQuery {
        page: params.page,
        page_size: params.page_size,
        state: params.state,
        source_id: Some(id),
    };
    Ok(Json(images::list(&state.pool, None, &query).await?))
}

/// `GET /api/v1/images`. The images of the caller's sources; `scope=all` for an admin. The
/// `source_id` filter narrows to one of them.
pub async fn all_images(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ImageParams>,
) -> Result<Json<Page<Image>>, AppError> {
    let all = scope_all(&user, params.scope.as_deref())?;
    let query = ImageQuery {
        page: params.page,
        page_size: params.page_size,
        state: params.state,
        source_id: params.source_id,
    };
    let owner = if all { None } else { Some(user.id.as_str()) };
    Ok(Json(images::list(&state.pool, owner, &query).await?))
}
