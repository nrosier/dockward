//! `POST /api/v1/image-sources/:id/scan` (`specs/spinoff-local-scan.md`, section 10; decision
//! 17): run discovery for one source now. The source's owner or any admin may call it. It is
//! limited to one start per source per 5 minutes, held in memory (`429` with `Retry-After`).

use std::time::Instant;

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::api::hardening::too_many_requests;
use crate::api::state::AppState;
use crate::db::discovery as db;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::{self, Actor};
use crate::services::discovery::DiscoverPayload;
use crate::services::sessions::AuthUser;
use crate::worker::now_secs;

#[derive(Serialize)]
struct Queued {
    queued: usize,
}

/// Runs discovery for the source now and returns the number of images queued for pull. Another
/// user's source is `404`, the same as a missing one, unless the caller is an admin.
pub async fn scan(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let target = {
        let mut conn = state
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        db::source_target(&mut conn, &id).await?
    };
    let target = target
        .filter(|found| user.role == Role::Admin || found.user_id == user.id)
        .ok_or(AppError::NotFound)?;
    if let Err(retry_after) = state.scan_limiter.check(&id, Instant::now()) {
        return Ok(too_many_requests(retry_after));
    }
    let now = now_secs();
    let payload = DiscoverPayload::new(&target.hub_id, &target.repository, Some(&id));
    let report = state.discovery.discover_now(&payload, now).await?;
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::InternalError)?;
    audit::record(
        &mut tx,
        &actor,
        "source.scan",
        &format!("source:{id}"),
        Some(&serde_json::json!({ "source_id": id, "queued": report.queued })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(Json(Queued {
        queued: report.queued,
    })
    .into_response())
}
