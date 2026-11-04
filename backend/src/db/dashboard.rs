//! SQL for the dashboard counts and the mapping list's `open_cves` (`specs/cve-lifecycle.md`,
//! Dashboard counts). Each count is one query. A caller passes `user_id` `None` to count
//! every mapping (admin `scope=all`), and `Some(id)` to count one user's mappings.

use sqlx::SqlitePool;

use crate::error::AppError;

/// Open CVEs of one mapping by severity. Only `CRITICAL` and `HIGH` are shown
/// (`specs/cve-lifecycle.md`). A mapping with none is absent from the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCount {
    pub mapping_id: String,
    pub critical: i64,
    pub high: i64,
}

/// Open CVEs by severity, per mapping. `mapping_id` `Some` limits the result to that mapping.
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
pub async fn open_by_mapping(
    pool: &SqlitePool,
    user_id: Option<&str>,
    mapping_id: Option<&str>,
    now: i64,
) -> Result<Vec<OpenCount>, AppError> {
    let rows = sqlx::query!(
        r#"WITH open_best AS (
               SELECT f.mapping_id AS mapping_id, f.cve_id AS cve_id,
                      MAX(CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) AS sev_rank
               FROM cve_findings f
               JOIN repo_mappings m ON m.id = f.mapping_id
               WHERE f.status = 'open' AND (?1 IS NULL OR m.user_id = ?1)
                 AND (?3 IS NULL OR f.mapping_id = ?3)
               GROUP BY f.mapping_id, f.cve_id
           )
           SELECT ob.mapping_id AS "mapping_id!",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 5 THEN 1 ELSE 0 END), 0) AS "critical!: i64",
                  COALESCE(SUM(CASE WHEN ob.sev_rank = 4 THEN 1 ELSE 0 END), 0) AS "high!: i64"
           FROM open_best ob
           WHERE NOT EXISTS (
               SELECT 1 FROM cve_acceptances ca
               WHERE ca.mapping_id = ob.mapping_id AND ca.cve_id = ob.cve_id
                 AND ca.revoked_at IS NULL
                 AND (ca.expires_at IS NULL OR ca.expires_at > ?2)
           )
           GROUP BY ob.mapping_id"#,
        user_id,
        now,
        mapping_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows
        .into_iter()
        .map(|row| OpenCount {
            mapping_id: row.mapping_id,
            critical: row.critical,
            high: row.high,
        })
        .collect())
}

/// Fixed CVEs: distinct `cve_id` per mapping where every tracked-tag row is `fixed`.
///
/// Implements the spec bullet (`specs/cve-lifecycle.md`, Dashboard counts): "Fixed CVEs:
/// distinct `cve_id` in the mapping where every tracked-tag row is `fixed`". The acceptance
/// rule does not apply to fixed CVEs (decided on #55), so an accepted fixed CVE still counts.
pub async fn fixed_cves(pool: &SqlitePool, user_id: Option<&str>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM (
               SELECT f.mapping_id, f.cve_id
               FROM cve_findings f
               JOIN repo_mappings m ON m.id = f.mapping_id
               WHERE (?1 IS NULL OR m.user_id = ?1)
               GROUP BY f.mapping_id, f.cve_id
               HAVING SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) = 0
           )"#,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Open GitHub issues: `github_issues` rows with `status = 'open'` for the GitHub target of
/// the user's mappings (`specs/cve-lifecycle.md`, Dashboard counts). One mapping exists per
/// GitHub repository, so each issue row is counted once.
pub async fn open_issues(pool: &SqlitePool, user_id: Option<&str>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM github_issues gi
           JOIN repo_mappings m
             ON m.github_owner = gi.github_owner AND m.github_repo = gi.github_repo
           WHERE gi.status = 'open' AND (?1 IS NULL OR m.user_id = ?1)"#,
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
           JOIN repo_mappings m ON m.id = j.mapping_id
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
