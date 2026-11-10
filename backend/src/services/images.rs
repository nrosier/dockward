//! The image list (`specs/spinoff-local-scan.md`, section 10): images with per-platform
//! `state`, `size_bytes`, `pulled_at` and the latest run of each scanner (`status`, `version`,
//! `error`, `db_built_at`). A user sees images their own sources observe; an admin reads all
//! with `scope=all`.

use std::collections::HashMap;

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::image_sources::{self as db, RunRow};
use crate::error::AppError;
use crate::services::pagination::{Page, Pagination};
use crate::services::time;

const SORTS: &[&str] = &["created_at"];
const STATES: &[&str] = &[
    "queued", "pulling", "stored", "evicting", "evicted", "failed",
];

/// The latest run of one scanner on one platform.
#[derive(Debug, Serialize)]
pub struct ScannerRun {
    pub scanner: String,
    pub status: String,
    pub version: Option<String>,
    pub error: Option<String>,
    pub db_built_at: Option<String>,
}

/// One platform of an image.
#[derive(Debug, Serialize)]
pub struct Platform {
    pub id: String,
    pub platform: String,
    pub state: String,
    pub size_bytes: Option<i64>,
    pub pulled_at: Option<String>,
    pub scans: Vec<ScannerRun>,
}

/// One image.
#[derive(Debug, Serialize)]
pub struct Image {
    pub id: String,
    pub hub_host: String,
    pub repository: String,
    pub digest: String,
    pub is_index: bool,
    pub tags: Vec<String>,
    pub platforms: Vec<Platform>,
}

/// Which images to list.
#[derive(Debug, Default)]
pub struct Query {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub state: Option<String>,
    pub source_id: Option<String>,
}

fn run_view(run: &RunRow) -> Result<ScannerRun, AppError> {
    Ok(ScannerRun {
        scanner: run.scanner.clone(),
        status: run.status.clone(),
        version: run.scanner_version.clone(),
        error: run.error.clone(),
        db_built_at: run.db_built_at.map(time::rfc3339).transpose()?,
    })
}

/// One page of images. `user_id` scopes the list to one owner; `None` lists every owner and is
/// passed only for an admin who asked for `scope=all` or reads one source.
pub async fn list(
    pool: &SqlitePool,
    user_id: Option<&str>,
    query: &Query,
) -> Result<Page<Image>, AppError> {
    let paging = Pagination::parse(query.page, query.page_size, None, None, SORTS)?;
    let state = query.state.as_deref();
    if let Some(state) = state
        && !STATES.contains(&state)
    {
        return Err(AppError::InvalidRequest(
            "state is not a platform state.".to_owned(),
        ));
    }
    let source = query.source_id.as_deref();
    let heads = db::images(
        pool,
        user_id,
        source,
        state,
        paging.page_size,
        paging.offset(),
    )
    .await?;
    let mut items = Vec::with_capacity(heads.len());
    for head in heads {
        let tags = db::image_tags(pool, &head.id, user_id, source).await?;
        let rows = db::image_platforms(pool, &head.id, state).await?;
        let runs = db::latest_runs(pool, &head.id).await?;
        let mut by_platform: HashMap<&str, Vec<&RunRow>> = HashMap::new();
        for run in &runs {
            by_platform
                .entry(run.image_platform_id.as_str())
                .or_default()
                .push(run);
        }
        let mut platforms = Vec::with_capacity(rows.len());
        for row in rows {
            let scans = by_platform
                .get(row.id.as_str())
                .map(|list| list.iter().map(|run| run_view(run)).collect())
                .transpose()?
                .unwrap_or_default();
            platforms.push(Platform {
                pulled_at: row.pulled_at.map(time::rfc3339).transpose()?,
                id: row.id,
                platform: row.platform,
                state: row.state,
                size_bytes: row.size_bytes,
                scans,
            });
        }
        items.push(Image {
            id: head.id,
            hub_host: head.hub_host,
            repository: head.repository,
            digest: head.digest,
            is_index: head.is_index,
            tags,
            platforms,
        });
    }
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total: db::count_images(pool, user_id, source, state).await?,
    })
}
