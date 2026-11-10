//! SQL for the dashboard counts and the mapping list's `open_cves` (`specs/cve-lifecycle.md`,
//! Dashboard counts). Each count is one query. A caller passes `user_id` `None` to count
//! every mapping (admin `scope=all`), and `Some(id)` to count one user's mappings.

use sqlx::SqlitePool;

use crate::error::AppError;

/// Open CVEs of one source by severity, every severity (`specs/cve-lifecycle.md`, changed
/// on #129). A source with none is absent from the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCount {
    pub source_id: String,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub unknown: i64,
}

/// Open CVEs by severity, per mapping. `source_id` `Some` limits the result to that mapping.
///
/// Only the rows of the newest-digest tags count (#196, decision 21; the `newest_digest_tags`
/// view, migration 0010). A CVE open only on an older tag is not counted.
///
/// Implements the spec bullets (`specs/cve-lifecycle.md`, Dashboard counts): "Open CVEs by
/// severity: distinct `cve_id` in the mapping with at least one tracked-tag row at
/// `status = 'open'` and no active acceptance, grouped by severity", and "If the same CVE has
/// different severities on different tags ... count it once at the highest severity". The
/// severity is taken from the open rows only (decided on #55). Tracked tags are the rows that
/// remain in `cve_findings`, because the 10-tag pruning deletes the rest.
///
/// An acceptance is active when `revoked_at IS NULL` and (`expires_at IS NULL` or
/// `expires_at > now`), as in `db::acceptances::active`.
pub async fn open_by_source(
    pool: &SqlitePool,
    user_id: Option<&str>,
    source_id: Option<&str>,
    now: i64,
) -> Result<Vec<OpenCount>, AppError> {
    let rows = sqlx::query!(
        r#"WITH open_best AS (
               SELECT f.source_id AS source_id, f.cve_id AS cve_id,
                      MAX(CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) AS sev_rank
               FROM cve_findings f
               JOIN image_sources m ON m.id = f.source_id
               JOIN newest_digest_tags nd
                    ON nd.source_id = f.source_id AND nd.image_tag = f.image_tag
               WHERE f.status = 'open' AND (?1 IS NULL OR m.user_id = ?1)
                 AND (?3 IS NULL OR f.source_id = ?3)
               GROUP BY f.source_id, f.cve_id
           )
           SELECT ob.source_id AS "source_id!",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 5 THEN 1 ELSE 0 END), 0) AS "critical!: i64",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 4 THEN 1 ELSE 0 END), 0) AS "high!: i64",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 3 THEN 1 ELSE 0 END), 0) AS "medium!: i64",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 2 THEN 1 ELSE 0 END), 0) AS "low!: i64",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 1 THEN 1 ELSE 0 END), 0) AS "unknown!: i64"
           FROM open_best ob
           WHERE NOT EXISTS (
               SELECT 1 FROM cve_acceptances ca
               WHERE ca.source_id = ob.source_id AND ca.cve_id = ob.cve_id
                 AND ca.revoked_at IS NULL
                 AND (ca.expires_at IS NULL OR ca.expires_at > ?2)
           )
           GROUP BY ob.source_id"#,
        user_id,
        now,
        source_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| OpenCount {
            source_id: row.source_id,
            critical: row.critical,
            high: row.high,
            medium: row.medium,
            low: row.low,
            unknown: row.unknown,
        })
        .collect())
}

/// Fixed CVEs: distinct `cve_id` per mapping where every newest-digest-tag row is `fixed`
/// (#196, decisions 21 and 23): rows of older tags are not read, so a CVE that only an older
/// digest had as `fixed` adds nothing.
///
/// Implements the spec bullet (`specs/cve-lifecycle.md`, Dashboard counts): "Fixed CVEs:
/// distinct `cve_id` in the mapping where every tracked-tag row is `fixed`". The acceptance
/// rule does not apply to fixed CVEs (decided on #55), so an accepted fixed CVE still counts.
pub async fn fixed_cves(pool: &SqlitePool, user_id: Option<&str>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM (
               SELECT f.source_id, f.cve_id
               FROM cve_findings f
               JOIN image_sources m ON m.id = f.source_id
               JOIN newest_digest_tags nd
                    ON nd.source_id = f.source_id AND nd.image_tag = f.image_tag
               WHERE (?1 IS NULL OR m.user_id = ?1)
               GROUP BY f.source_id, f.cve_id
               HAVING SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) = 0
           )"#,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Accepted CVEs (#247): distinct `cve_id` per mapping with at least one newest-digest-tag row
/// at `status = 'open'` and an active acceptance. These are exactly the CVEs `open_by_source`
/// leaves out, so an accepted CVE is never in both counts. An acceptance is active when
/// `revoked_at IS NULL` and (`expires_at IS NULL` or `expires_at > now`).
pub async fn accepted_cves(
    pool: &SqlitePool,
    user_id: Option<&str>,
    now: i64,
) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM (
               SELECT f.source_id, f.cve_id
               FROM cve_findings f
               JOIN image_sources m ON m.id = f.source_id
               JOIN newest_digest_tags nd
                    ON nd.source_id = f.source_id AND nd.image_tag = f.image_tag
               WHERE f.status = 'open' AND (?1 IS NULL OR m.user_id = ?1)
                 AND EXISTS (
                     SELECT 1 FROM cve_acceptances ca
                     WHERE ca.source_id = f.source_id AND ca.cve_id = f.cve_id
                       AND ca.revoked_at IS NULL
                       AND (ca.expires_at IS NULL OR ca.expires_at > ?2)
                 )
               GROUP BY f.source_id, f.cve_id
           )"#,
        user_id,
        now
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Open GitHub issues: `github_issues` rows with `status = 'open'` for the GitHub target of
/// the user's sources (`specs/cve-lifecycle.md`, Dashboard counts). Sources may share a
/// GitHub repository (decision 47); an issue row is counted once.
pub async fn open_issues(pool: &SqlitePool, user_id: Option<&str>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM github_issues gi
           WHERE gi.status = 'open' AND EXISTS (
               SELECT 1 FROM image_sources m
               WHERE m.github_owner = gi.github_owner AND m.github_repo = gi.github_repo
                 AND (?1 IS NULL OR m.user_id = ?1))"#,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Failed syncs: `sync_jobs` rows with `status = 'failed'` last updated at or after `since`
/// (Unix seconds).
///
/// Implements the spec bullet (`specs/cve-lifecycle.md`, Dashboard counts): "Failed syncs:
/// count of `sync_jobs` rows with `status = 'failed'` ... Period: last 90 days". The period is
/// measured on `sync_jobs.updated_at` (decided on #55).
pub async fn failed_syncs_since(
    pool: &SqlitePool,
    user_id: Option<&str>,
    since: i64,
) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM sync_jobs j
           LEFT JOIN image_sources m ON m.id = j.source_id
           WHERE j.status = 'failed' AND j.updated_at >= ?2
             AND (?1 IS NULL OR m.user_id = ?1)"#,
        user_id,
        since
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}
