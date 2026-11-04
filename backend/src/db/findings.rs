//! SQL for the `cve_findings` table (`specs/database.md`, `specs/cve-lifecycle.md`,
//! "Tracking per tag"). One row per (mapping, Harbor repository, image tag, CVE).
//! Rows hold CVE facts only, never secrets.
//!
//! Every function takes a connection so the caller can run them in one transaction.
//! None of them touches `github_issues`.

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One vulnerability of one tag, ready to store.
pub struct Finding<'a> {
    /// Primary key used when the row is new; an existing row keeps its own.
    pub id: &'a str,
    pub mapping_id: &'a str,
    pub harbor_repository: &'a str,
    pub image_tag: &'a str,
    pub cve_id: &'a str,
    pub package: Option<&'a str>,
    /// One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
    pub severity: &'a str,
    pub fixed_in_version: Option<&'a str>,
    /// At most 4,000 characters; `None` when the report has no text.
    pub description: Option<&'a str>,
    /// Unix seconds of the scan.
    pub now: i64,
}

/// Stores a finding. A new row is `open`. An existing row for the same tag and CVE takes
/// the new facts, moves `last_seen_at` forward and goes back to `open` (a CVE that returns
/// on a tag reopens its row). `first_seen_at` is kept.
pub async fn upsert(conn: &mut SqliteConnection, finding: &Finding<'_>) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO cve_findings
            (id, mapping_id, harbor_repository, image_tag, cve_id, package, severity,
             fixed_in_version, description, first_seen_at, last_seen_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
         ON CONFLICT (mapping_id, harbor_repository, image_tag, cve_id) DO UPDATE SET
            severity = excluded.severity,
            package = excluded.package,
            fixed_in_version = excluded.fixed_in_version,
            description = excluded.description,
            last_seen_at = excluded.last_seen_at,
            status = 'open'",
        finding.id,
        finding.mapping_id,
        finding.harbor_repository,
        finding.image_tag,
        finding.cve_id,
        finding.package,
        finding.severity,
        finding.fixed_in_version,
        finding.description,
        finding.now,
        finding.now
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// True when the mapping has a row for this CVE on any tag, in any status.
pub async fn exists_for_mapping(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    cve_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM cve_findings WHERE mapping_id = ? AND cve_id = ?
           ) AS "found!: i64""#,
        mapping_id,
        cve_id
    )
    .fetch_one(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.found != 0)
}

/// Marks the tag's `open` rows `fixed` when their CVE is not in `seen_ids`. The ids go to
/// SQLite as one JSON array, so the list length is not limited by the bind count. Returns
/// the number of rows changed.
pub async fn mark_missing_fixed(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    tag: &str,
    seen_ids: &[String],
) -> Result<u64, AppError> {
    let seen = serde_json::to_string(seen_ids).map_err(|_| AppError::InternalError)?;
    sqlx::query!(
        "UPDATE cve_findings SET status = 'fixed'
         WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ?
           AND status = 'open'
           AND cve_id NOT IN (SELECT value FROM json_each(?))",
        mapping_id,
        repo,
        tag,
        seen
    )
    .execute(conn)
    .await
    .map(|result| result.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// The mapping's tracked tags, newest first. A tag is tracked when it has a successful
/// `sync_reports` row, so a tag with zero CVEs counts. Its scan time is the latest
/// `synced_at` among its successful reports; ties go to the report stored last.
pub async fn tags_by_recency(
    conn: &mut SqliteConnection,
    mapping_id: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT image_tag AS "image_tag!"
           FROM sync_reports
           WHERE mapping_id = ? AND sarif_status = 'success'
           GROUP BY image_tag
           ORDER BY MAX(synced_at) DESC, MAX(rowid) DESC"#,
        mapping_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.image_tag).collect())
}

/// Deletes a tag's `cve_findings` and `sync_reports`. It never touches `github_issues`;
/// their `sync_report_id` and the findings' `github_issue_id` are `ON DELETE SET NULL`.
/// Returns the number of rows deleted from both tables.
pub async fn delete_tag(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    tag: &str,
) -> Result<u64, AppError> {
    let findings = sqlx::query!(
        "DELETE FROM cve_findings
         WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ?",
        mapping_id,
        repo,
        tag
    )
    .execute(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    let reports = sqlx::query!(
        "DELETE FROM sync_reports
         WHERE mapping_id = ? AND harbor_repository = ? AND image_tag = ?",
        mapping_id,
        repo,
        tag
    )
    .execute(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(findings.rows_affected() + reports.rows_affected())
}
