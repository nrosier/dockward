//! Admin routes. Every handler takes `AdminUser`, so a non-admin gets `403` and a
//! missing or invalid session gets `401`.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;

use crate::api::auth::AdminUser;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::audit::{self, AuditEntry, AuditQuery};
use crate::services::pagination::Page;

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
