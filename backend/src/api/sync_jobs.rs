//! Sync job routes (`specs/api.md`, Sync jobs).

use axum::{
    Json,
    extract::{Path, State},
};

use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::audit::Actor;
use crate::services::sessions::AuthUser;
use crate::services::sync_jobs;
use crate::worker::now_secs;

/// `POST /api/v1/sync-jobs/:id/retry`. The mapping owner or an admin. Returns `200`
/// with the `SyncJob`. Only a `failed` job can be retried (`409` otherwise).
pub async fn retry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<crate::db::sync_jobs::SyncJobView>, AppError> {
    let is_admin = user.role == crate::models::role::Role::Admin;
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    let job = sync_jobs::retry(&state.pool, &actor, is_admin, &id, now_secs()).await?;
    Ok(Json(job))
}
