//! SQL for removing the data of a tag Harbor no longer has (`specs/integrations.md`, "Removing
//! deleted artifacts"; #249). Every function takes a connection so the caller can run one
//! removal in one transaction. None of them touches `github_issues`.

use sqlx::SqliteConnection;

use crate::db::findings;
use crate::error::AppError;

/// Every tag HarborGate holds data for on a mapping: a tag with findings, a sync report, or a
/// job whose payload names it. Only data created before `before` (Unix seconds) counts, so a
/// tag pushed and synced while a poll read the listing is not taken for a deleted one. Sorted,
/// without duplicates.
pub async fn tracked_tags(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    before: i64,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT image_tag AS "tag!: String" FROM cve_findings
           WHERE mapping_id = ?1 AND harbor_repository = ?2 AND COALESCE(first_seen_at, 0) < ?3
           UNION
           SELECT image_tag FROM sync_reports
           WHERE mapping_id = ?1 AND harbor_repository = ?2 AND COALESCE(synced_at, 0) < ?3
           UNION
           SELECT CAST(json_extract(payload, '$.tag') AS TEXT) FROM sync_jobs
           WHERE mapping_id = ?1 AND json_valid(payload)
             AND json_extract(payload, '$.tag') IS NOT NULL
             AND COALESCE(created_at, 0) < ?3
           ORDER BY 1"#,
        mapping_id,
        repo,
        before
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.tag).collect())
}

/// The tags of a mapping whose newest sync report points at `digest`. A tag that has moved on
/// to another digest is not listed.
pub async fn tags_at_digest(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    digest: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT DISTINCT r.image_tag AS "tag!: String" FROM sync_reports r
           WHERE r.mapping_id = ?1 AND r.harbor_repository = ?2 AND r.image_digest = ?3
             AND (SELECT l.image_digest FROM sync_reports l
                  WHERE l.mapping_id = r.mapping_id AND l.harbor_repository = r.harbor_repository
                    AND l.image_tag = r.image_tag
                  ORDER BY COALESCE(l.synced_at, 0) DESC, l.rowid DESC LIMIT 1) = ?3
           ORDER BY 1"#,
        mapping_id,
        repo,
        digest
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.tag).collect())
}

/// The digests a tag's reports and jobs name.
async fn digests_of_tag(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    tag: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT image_digest AS "digest!: String" FROM sync_reports
           WHERE mapping_id = ?1 AND harbor_repository = ?2 AND image_tag = ?3
           UNION
           SELECT CAST(json_extract(payload, '$.digest') AS TEXT) FROM sync_jobs
           WHERE mapping_id = ?1 AND json_valid(payload) AND json_extract(payload, '$.tag') = ?3
             AND json_extract(payload, '$.digest') IS NOT NULL"#,
        mapping_id,
        repo,
        tag
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.digest).collect())
}

/// Deletes the jobs of a tag: queued, done and failed ones, and `current_job` even while it
/// runs. Another running job and a job that holds a project scanner lock stay (the lock row
/// cascades with its job, and the scanner restore needs it). Returns the rows deleted.
async fn delete_jobs(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    tag: &str,
    current_job: Option<&str>,
) -> Result<u64, AppError> {
    let done = sqlx::query!(
        "DELETE FROM sync_jobs
         WHERE mapping_id = ?1 AND json_valid(payload) AND json_extract(payload, '$.tag') = ?2
           AND (status <> 'running' OR id = ?3)
           AND id NOT IN (SELECT job_id FROM project_scanner_locks)",
        mapping_id,
        tag,
        current_job
    )
    .execute(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(done.rows_affected())
}

/// Deletes the stored scanner reports (and, by cascade, their findings) of `digest` when no
/// sync report and no job of the mapping still names it. Returns the reports deleted.
async fn delete_orphan_scanner_reports(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    digest: &str,
) -> Result<u64, AppError> {
    let done = sqlx::query!(
        "DELETE FROM scanner_reports
         WHERE mapping_id = ?1 AND image_digest = ?2
           AND NOT EXISTS (SELECT 1 FROM sync_reports
                           WHERE mapping_id = ?1 AND image_digest = ?2)
           AND NOT EXISTS (SELECT 1 FROM sync_jobs
                           WHERE mapping_id = ?1 AND json_valid(payload)
                             AND json_extract(payload, '$.digest') = ?2)",
        mapping_id,
        digest
    )
    .execute(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(done.rows_affected())
}

/// Removes one tag's findings, sync reports, jobs and, when no other tag holds the digest, the
/// scanner reports. Returns the number of rows removed.
pub async fn remove_tag(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    repo: &str,
    tag: &str,
    current_job: Option<&str>,
) -> Result<u64, AppError> {
    let digests = digests_of_tag(conn, mapping_id, repo, tag).await?;
    let mut removed = delete_jobs(conn, mapping_id, tag, current_job).await?;
    removed += findings::delete_tag(conn, mapping_id, repo, tag).await?;
    for digest in &digests {
        removed += delete_orphan_scanner_reports(conn, mapping_id, digest).await?;
    }
    Ok(removed)
}
