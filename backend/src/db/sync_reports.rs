//! SQL for the `publish_reports` table (`specs/spinoff-local-scan.md`, section 9; replaces
//! `sync_reports`). One row per published image digest and tag. Rows hold counts and error text
//! only, never secrets.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// The fields of a report that is about to be uploaded. It is stored with
/// `sarif_status = 'pending'`.
pub struct NewReport<'a> {
    pub id: &'a str,
    /// The image source the report belongs to (`publish_reports.source_id`).
    pub source_id: &'a str,
    /// The image the report publishes (`publish_reports.image_id`).
    pub image_id: Option<&'a str>,
    pub job_id: &'a str,
    pub image_tag: &'a str,
    pub image_digest: &'a str,
    pub commit_sha: Option<&'a str>,
    /// JSON text: `{"critical": 0, "high": 2, ...}`.
    pub vulnerability_summary: &'a str,
}

/// A pending report found for a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    pub id: String,
    /// GitHub's SARIF id, set once the upload was accepted.
    pub github_sarif_id: Option<String>,
}

/// Stores a report with `sarif_status = 'pending'`.
pub async fn insert_pending(
    conn: &mut SqliteConnection,
    report: &NewReport<'_>,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO publish_reports
            (id, source_id, image_id, job_id, image_tag, image_digest,
             commit_sha, vulnerability_summary, sarif_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
        report.id,
        report.source_id,
        report.image_id,
        report.job_id,
        report.image_tag,
        report.image_digest,
        report.commit_sha,
        report.vulnerability_summary
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// The newest pending report of a job, if any. A retry uses it to poll the same upload
/// instead of uploading again.
pub async fn find_pending_for_job(
    pool: &SqlitePool,
    job_id: &str,
) -> Result<Option<ReportRow>, AppError> {
    sqlx::query_as!(
        ReportRow,
        r#"SELECT id AS "id!", github_sarif_id
           FROM publish_reports
           WHERE job_id = ? AND sarif_status = 'pending'
           ORDER BY rowid DESC
           LIMIT 1"#,
        job_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Records GitHub's SARIF id after an accepted upload.
pub async fn set_sarif_id(pool: &SqlitePool, id: &str, sarif_id: &str) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE publish_reports SET github_sarif_id = ? WHERE id = ?",
        sarif_id,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// The last stored successful report for a digest of a source, as its tag. `None` when no such
/// report exists. The dedupe that the Harbor poller used (`has_success`, `set_cve_ids`) and its
/// `cve_ids` columns are removed with the Harbor code (section 9).
pub async fn last_result_for_digest(
    pool: &SqlitePool,
    source_id: &str,
    digest: &str,
    job_id: &str,
) -> Result<Option<(String, Option<String>)>, AppError> {
    let row = sqlx::query!(
        r#"SELECT r.image_tag AS "image_tag!" FROM publish_reports r
           WHERE r.source_id = ?1 AND r.image_digest = ?2 AND r.sarif_status = 'success'
             AND (r.job_id IS NULL OR r.job_id <> ?3)
           ORDER BY r.synced_at DESC, r.rowid DESC
           LIMIT 1"#,
        source_id,
        digest,
        job_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| (r.image_tag, None)))
}

/// Ends a report with `sarif_status` (`success` or `failed`) and an optional error text.
pub async fn finish(
    pool: &SqlitePool,
    id: &str,
    sarif_status: &str,
    error_message: Option<&str>,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE publish_reports SET sarif_status = ?, error_message = ?, synced_at = ? WHERE id = ?",
        sarif_status,
        error_message,
        now,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}
