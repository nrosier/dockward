//! `GET` and `PUT /api/v1/admin/scan-settings` (`specs/spinoff-local-scan.md`, sections 10 and
//! 13; decisions 18 and 19). Admin only. A value outside its bounds is `422`.

use axum::{Json, extract::State};

use crate::api::auth::AdminUser;
use crate::api::json::parse_body;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::audit::Actor;
use crate::services::scan_settings::{self, ScanSettings};

/// `GET /api/v1/admin/scan-settings`.
pub async fn get(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ScanSettings>, AppError> {
    Ok(Json(scan_settings::read(&state.pool).await?))
}

/// `PUT /api/v1/admin/scan-settings`. The whole object is replaced.
pub async fn put(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Json<ScanSettings>, AppError> {
    let next: ScanSettings = parse_body(&body)?;
    let actor = Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    Ok(Json(scan_settings::write(&state.pool, &actor, next).await?))
}
