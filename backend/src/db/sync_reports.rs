//! SQL for the `sync_reports` table (`specs/database.md`). One row per processed image
//! digest and tag. Rows hold counts and error text only, never secrets.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// The fields of a report that is about to be uploaded. It is stored with
/// `sarif_status = 'pending'`.
pub struct NewReport<'a> {
    pub id: &'a str,
    pub mapping_id: &'a str,
    pub sync_job_id: &'a str,
    pub harbor_repository: &'a str,
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
        "INSERT INTO sync_reports
            (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest,
             commit_sha, vulnerability_summary, sarif_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
        report.id,
        report.mapping_id,
        report.sync_job_id,
        report.harbor_repository,
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
           FROM sync_reports
           WHERE sync_job_id = ? AND sarif_status = 'pending'
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
        "UPDATE sync_reports SET github_sarif_id = ? WHERE id = ?",
        sarif_id,
        id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// True when polling must not queue this `(digest, tag)` for the mapping: either a
/// successful sync exists (`sync_jobs.status = 'done'` and `sarif_status = 'success'` on
/// the linked report), or a `queued` or `running` job for the same digest and tag exists.
pub async fn has_success(
    pool: &SqlitePool,
    mapping_id: &str,
    harbor_repository: &str,
    tag: &str,
    digest: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT (
               EXISTS (
                   SELECT 1 FROM sync_reports r
                   JOIN sync_jobs j ON j.id = r.sync_job_id
                   WHERE r.mapping_id = ? AND r.harbor_repository = ?
                     AND r.image_tag = ? AND r.image_digest = ?
                     AND r.sarif_status = 'success' AND j.status = 'done'
               )
               OR EXISTS (
                   SELECT 1 FROM sync_jobs q
                   WHERE q.mapping_id = ? AND q.status IN ('queued', 'running')
                     AND json_extract(q.payload, '$.digest') = ?
                     AND json_extract(q.payload, '$.tag') = ?
               )
           ) AS "found!: i64""#,
        mapping_id,
        harbor_repository,
        tag,
        digest,
        mapping_id,
        digest,
        tag
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.found != 0)
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
        "UPDATE sync_reports SET sarif_status = ?, error_message = ?, synced_at = ? WHERE id = ?",
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
