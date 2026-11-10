//! Count-based eviction (`specs/spinoff-local-scan.md`, section 4; decisions 9 and 18).
//!
//! Eviction removes the oldest stored layouts while the stored count is above the maximum. It
//! deletes the layout directory only. It never touches the host's Docker, never runs a prune,
//! and keeps every findings, run and history row (the `image_platforms` row becomes `evicted`).
//!
//! Each step is ordered so a crash is repairable:
//!
//! 1. The claim (one immediate transaction) moves a `stored` row to `evicting`.
//! 2. The layout directory is removed.
//! 3. The row becomes `evicted` with `evicted_at`, and the `image.evict` audit row is written in
//!    the same transaction.
//!
//! A crash after 1 leaves an `evicting` row. Startup repair ([`super::startup`]) finishes it.

use std::fs;

use crate::db::storage::EvictionClaim;
use crate::error::AppError;
use crate::services::ids;
use crate::services::storage::StoreRoot;
use crate::services::storage::repository::StoreRepository;

/// Runs eviction until the stored count is at the maximum or no image is eligible. Returns the
/// number of images evicted. `protect` is a platform that must not be claimed (the image just
/// pulled, which the caller passes so it is never removed by its own pull).
pub async fn enforce<R: StoreRepository>(
    repo: &R,
    store: &StoreRoot,
    max_stored: i64,
    protect: Option<String>,
    now: i64,
) -> Result<usize, AppError> {
    let claims = repo.claim_over_limit(max_stored, protect).await?;
    let mut evicted = 0usize;
    for claim in &claims {
        complete_one(repo, store, claim, now).await?;
        evicted += 1;
    }
    Ok(evicted)
}

/// Completes one claimed eviction: removes its layout, then records it. Used by [`enforce`] and
/// by startup repair for an `evicting` row.
pub async fn complete_one<R: StoreRepository>(
    repo: &R,
    store: &StoreRoot,
    claim: &EvictionClaim,
    now: i64,
) -> Result<(), AppError> {
    remove_layout(store, &claim.platform_id)?;
    let audit_id = ids::new_id()?;
    let details = audit_details(claim)?;
    repo.finish_eviction(claim, now, &audit_id, &details).await
}

/// Removes the layout directory of one platform. A missing directory is not an error: the
/// directory being gone is the state the eviction is trying to reach.
pub fn remove_layout(store: &StoreRoot, platform_id: &str) -> Result<(), AppError> {
    let dir = store.layout_dir(platform_id)?;
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AppError::InternalError),
    }
}

/// True when a layout directory of `platform_id` still exists under the store.
pub fn layout_exists(store: &StoreRoot, platform_id: &str) -> Result<bool, AppError> {
    Ok(store.layout_dir(platform_id)?.is_dir())
}

/// The `image.evict` audit details: the hub, the repository and the platform digest. No path,
/// no token, no registry header.
fn audit_details(claim: &EvictionClaim) -> Result<String, AppError> {
    let value = serde_json::json!({
        "hub": claim.hub_host,
        "repository": claim.repository,
        "platform_digest": claim.platform_digest,
    });
    serde_json::to_string(&value).map_err(|_| AppError::InternalError)
}
