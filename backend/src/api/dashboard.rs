//! Dashboard route (`specs/api.md`, Dashboard). The handler takes `AuthUser`, so a missing or
//! invalid session is `401`. `scope=all` is honored for admins only.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::dashboard::{self, Summary};
use crate::services::sessions::AuthUser;
use crate::worker::now_secs;

/// Raw query values for `GET /api/v1/dashboard/summary`.
#[derive(Debug, Deserialize)]
pub struct SummaryParams {
    pub scope: Option<String>,
}

/// `GET /api/v1/dashboard/summary`. A user sees their own mappings; an admin with
/// `scope=all` sees every mapping. A regular user with `scope=all` is `403`.
pub async fn summary(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<SummaryParams>,
) -> Result<Json<Summary>, AppError> {
    let scope: Option<&str> = match params.scope.as_deref() {
        None => Some(user.id.as_str()),
        Some("all") if user.role == Role::Admin => None,
        Some("all") => return Err(AppError::Forbidden),
        Some(_) => return Err(AppError::InvalidRequest("scope must be all.".to_owned())),
    };
    Ok(Json(
        dashboard::summary(&state.pool, scope, now_secs()).await?,
    ))
}
