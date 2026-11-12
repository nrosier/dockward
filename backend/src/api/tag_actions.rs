//! `POST /api/v1/image-sources/{id}/tags/{tag}/pull` and `.../scan` (#335): manual pull and
//! forced scan of the image one tag points at. The source's owner or any admin may call them.
//! Order: a missing or foreign source is `404`; a tag the source has not observed is `404`, and a
//! pull while a platform is `pulling` or `evicting` is `409`, both before any limiter slot is
//! used; then one call per action, source and tag per 5 minutes
//! (`429` with `Retry-After`, key `tag:{action}:{source}:{tag}` on the shared scan limiter);
//! then the action. Both return `{"queued": n}`. The logic is `services::tag_actions`.

use std::time::Instant;

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::api::hardening::too_many_requests;
use crate::api::state::AppState;
use crate::db::discovery as sources_db;
use crate::db::scans as scans_db;
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::Actor;
use crate::services::registry::grammar::validate_tag;
use crate::services::sessions::AuthUser;
use crate::services::tag_actions::{self, TagAction};
use crate::worker::now_secs;

#[derive(Serialize)]
struct Queued {
    queued: usize,
}

/// `POST .../tags/{tag}/pull`.
pub async fn pull(
    state: State<AppState>,
    user: AuthUser,
    path: Path<(String, String)>,
) -> Result<Response, AppError> {
    act(state, user, path, TagAction::Pull).await
}

/// `POST .../tags/{tag}/scan`.
pub async fn scan(
    state: State<AppState>,
    user: AuthUser,
    path: Path<(String, String)>,
) -> Result<Response, AppError> {
    act(state, user, path, TagAction::Scan).await
}

async fn act(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, tag)): Path<(String, String)>,
    action: TagAction,
) -> Result<Response, AppError> {
    {
        let mut conn = state
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        sources_db::source_target(&mut conn, &id)
            .await?
            .filter(|found| user.role == Role::Admin || found.user_id == user.id)
            .ok_or(AppError::NotFound)?;
        // A tag outside the grammar was never observed, so it is the same 404.
        validate_tag(&tag).map_err(|_| AppError::NotFound)?;
        let image = scans_db::current_tag_image(&mut conn, &id, &tag)
            .await?
            .ok_or(AppError::NotFound)?;
        if action == TagAction::Pull {
            tag_actions::check_pullable(&image)?;
        }
    }
    let key = format!("tag:{}:{id}:{tag}", action.key());
    if let Err(retry_after) = state.scan_limiter.check(&key, Instant::now()) {
        return Ok(too_many_requests(retry_after));
    }
    let actor = Actor {
        user_id: Some(user.id.clone()),
        username: user.username.clone(),
    };
    let queued = tag_actions::run(&state.pool, &actor, &id, &tag, action, now_secs()).await?;
    Ok(Json(Queued { queued }).into_response())
}
