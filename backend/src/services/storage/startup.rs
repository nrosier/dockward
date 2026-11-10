//! Startup repair of the store (`specs/spinoff-local-scan.md`, section 4).
//!
//! Runs once at start, before any job. It makes the database and the disk agree after a crash:
//!
//! - A row in `evicting` is completed: its layout directory is removed if it still exists, and the
//!   row becomes `evicted` with the `image.evict` audit row. A directory already gone is the state
//!   the eviction was reaching.
//! - A row in `pulling` (a pull cut off by the crash) is marked `failed`, so a later retry can pull
//!   it again.
//! - Everything in `images/.tmp` is deleted.
//! - A directory in `images/` with no `stored` or `evicting` row is deleted.
//!
//! Nothing here logs a path or a registry string; the report carries counts only.

use std::collections::HashSet;
use std::fs;

use crate::error::AppError;
use crate::services::storage::eviction;
use crate::services::storage::repository::StoreRepository;
use crate::services::storage::{StoreRoot, TMP_DIR};

/// What startup repair changed. Counts only, so the log line names no path.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RepairReport {
    /// `evicting` rows completed.
    pub evictions_completed: usize,
    /// `pulling` rows marked `failed`.
    pub pulls_failed: usize,
    /// Entries removed from `.tmp` and orphan directories.
    pub directories_removed: usize,
}

/// Runs the repair. `now` is the eviction time stamped on completed rows.
pub async fn repair<R: StoreRepository>(
    repo: &R,
    store: &StoreRoot,
    now: i64,
) -> Result<RepairReport, AppError> {
    let mut report = RepairReport::default();

    for claim in repo.evicting_claims().await? {
        eviction::complete_one(repo, store, &claim, now).await?;
        report.evictions_completed += 1;
    }

    for id in repo.pulling_ids().await? {
        repo.mark_failed(&id).await?;
        report.pulls_failed += 1;
    }

    report.directories_removed += clear_tmp(store)?;
    report.directories_removed += remove_orphans(repo, store).await?;
    Ok(report)
}

/// Deletes everything under `images/.tmp`. Returns the number of entries removed.
fn clear_tmp(store: &StoreRoot) -> Result<usize, AppError> {
    let tmp = store.tmp_root();
    let entries = match fs::read_dir(&tmp) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(AppError::InternalError),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = entry.map_err(|_| AppError::InternalError)?;
        let path = entry.path();
        let outcome = if path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        outcome.map_err(|_| AppError::InternalError)?;
        removed += 1;
    }
    Ok(removed)
}

/// Deletes each layout directory whose id has no `stored` or `evicting` row. Returns the count.
/// The `.tmp` directory is skipped, because [`clear_tmp`] handles it.
async fn remove_orphans<R: StoreRepository>(
    repo: &R,
    store: &StoreRoot,
) -> Result<usize, AppError> {
    let live: HashSet<String> = repo.live_ids().await?.into_iter().collect();
    let entries = match fs::read_dir(store.root()) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(AppError::InternalError),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = entry.map_err(|_| AppError::InternalError)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == TMP_DIR || !entry.path().is_dir() {
            continue;
        }
        if live.contains(name) {
            continue;
        }
        fs::remove_dir_all(entry.path()).map_err(|_| AppError::InternalError)?;
        removed += 1;
    }
    Ok(removed)
}
