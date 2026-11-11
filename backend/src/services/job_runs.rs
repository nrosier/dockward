//! Housekeeping run history for `GET /api/v1/admin/jobs` (`specs/api.md`, Admin;
//! `specs/database.md`, `job_runs`). Rows hold counts and error text only.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::job_runs as db;
use crate::error::AppError;
use crate::services::pagination::{Page, Pagination};
use crate::services::time;

/// Sort keys `GET /admin/jobs` accepts. The first is the default, newest first.
const SORTS: &[&str] = &["started_at"];

/// The run kinds a `kind` filter may name (`job_runs.job_kind`).
const KINDS: &[&str] = &["cleanup", "retention", "discover", "db_update"];

/// One run in the `GET /admin/jobs` response. `error_summary` is capped in SQL, and the
/// timestamps are RFC 3339 strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobRunItem {
    pub id: String,
    pub job_kind: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub processed_count: i64,
    pub error_summary: Option<String>,
    /// `trivy` or `grype` for a `db_update` run, otherwise `null`.
    pub scanner: Option<String>,
}

/// Query values for `GET /admin/jobs`, already parsed by the handler.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub kind: Option<String>,
}

/// One page of housekeeping runs, newest first, with an optional `kind` filter.
pub async fn list(pool: &SqlitePool, query: &ListQuery) -> Result<Page<JobRunItem>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        SORTS,
    )?;
    if let Some(kind) = query.kind.as_deref()
        && !KINDS.contains(&kind)
    {
        return Err(AppError::InvalidRequest(
            "kind is not a housekeeping run kind.".to_owned(),
        ));
    }
    let kind = query.kind.as_deref();
    let rows = db::list(
        pool,
        kind,
        paging.ascending,
        paging.page_size,
        paging.offset(),
    )
    .await?;
    let total = db::count(pool, kind).await?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(JobRunItem {
                id: row.id,
                job_kind: row.job_kind,
                started_at: time::rfc3339(row.started_at)?,
                finished_at: row.finished_at.map(time::rfc3339).transpose()?,
                status: row.status,
                processed_count: row.processed_count,
                error_summary: row.error_summary,
                scanner: row.scanner,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}
