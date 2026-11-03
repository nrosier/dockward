//! Admin routes. Every handler takes `AdminUser`, so a non-admin gets `403` and a
//! missing or invalid session gets `401`.

use std::fmt;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::auth::AdminUser;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::models::user::User;
use crate::services::audit::{self, AuditEntry, AuditQuery};
use crate::services::pagination::Page;
use crate::services::users as user_service;

/// Raw query values for `GET /api/v1/admin/audit-log`.
#[derive(Debug, Deserialize)]
pub struct AuditLogParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub action: Option<String>,
    pub actor_user_id: Option<String>,
}

/// `GET /api/v1/admin/audit-log`. Paginated, with `action` and `actor_user_id` filters.
pub async fn audit_log(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<AuditLogParams>,
) -> Result<Json<Page<AuditEntry>>, AppError> {
    let query = AuditQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        action: params.action,
        actor_user_id: params.actor_user_id,
    };
    Ok(Json(audit::list(&state.pool, &query).await?))
}

/// Body for `POST /api/v1/admin/users`. Local accounts only.
#[derive(Deserialize)]
pub struct CreateUserBody {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub role: String,
}

const REDACTED: &str = "<redacted>";

impl fmt::Debug for CreateUserBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserBody")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &REDACTED)
            .field("role", &self.role)
            .finish()
    }
}

/// Body for `PUT /api/v1/admin/users/:id/role`.
#[derive(Debug, Deserialize)]
pub struct RoleBody {
    pub role: String,
}

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`.
fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

/// `GET /api/v1/admin/users`. Every user, oldest first.
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<User>>, AppError> {
    let rows = user_service::list(&state.pool).await?;
    let users = rows
        .into_iter()
        .map(User::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(users))
}

/// `POST /api/v1/admin/users`. Creates a local user. Returns `201`.
pub async fn create_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body: CreateUserBody = parse_body(&body)?;
    let role = user_service::parse_role(&body.role)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    let id = user_service::create_local(
        &state.pool,
        &actor,
        &body.username,
        body.email.as_deref(),
        &body.password,
        role,
    )
    .await?;
    let row = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::InternalError)?;
    Ok((StatusCode::CREATED, Json(User::try_from(row)?)).into_response())
}

/// `DELETE /api/v1/admin/users/:id`. Returns `204`, or `409` for the self and last-admin cases.
pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    user_service::delete_user(&state.pool, &actor, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/v1/admin/users/:id/role`. Returns the updated `User`.
pub async fn set_role(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<User>, AppError> {
    let body: RoleBody = parse_body(&body)?;
    let role: Role = user_service::parse_role(&body.role)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    user_service::change_role(&state.pool, &actor, &id, role).await?;
    let row = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(User::try_from(row)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user_body_debug_redacts_password() {
        let body = CreateUserBody {
            username: "fake-new-user".to_owned(),
            email: Some("new@example.test".to_owned()),
            password: "FAKE_PASSWORD_CREATE_1".to_owned(),
            role: "user".to_owned(),
        };
        let out = format!("{body:?}");
        assert!(
            !out.contains("FAKE_PASSWORD_CREATE_1"),
            "password leaked: {out}"
        );
        assert!(out.contains("fake-new-user"), "username missing: {out}");
        assert!(out.contains("new@example.test"), "email missing: {out}");
        assert!(out.contains("user"), "role missing: {out}");
    }
}
