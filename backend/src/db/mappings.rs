//! SQL for the `repo_mappings` table. Every owner-scoped query takes the caller's id, so
//! another user's mapping is indistinguishable from a missing one (`404`).

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// One mapping row as stored. The webhook token and auth secret are digests only.
#[derive(Debug, Clone)]
pub struct MappingRow {
    pub id: String,
    pub user_id: String,
    pub harbor_cred_id: String,
    pub github_cred_id: String,
    pub harbor_base_url: String,
    pub harbor_project: String,
    pub harbor_repository: String,
    pub github_owner: String,
    pub github_repo: String,
    pub webhook_token_hash: String,
    pub webhook_auth_secret_hash: String,
    pub auto_create_issues: Option<bool>,
    pub min_issue_severity: Option<String>,
    pub default_branch: String,
    pub created_at: Option<i64>,
}

/// Inserts a mapping row. The digests are the only secret material stored.
pub async fn insert(conn: &mut SqliteConnection, row: &MappingRow) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO repo_mappings (
            id, user_id, harbor_cred_id, github_cred_id, harbor_base_url,
            harbor_project, harbor_repository, github_owner, github_repo,
            webhook_token_hash, webhook_auth_secret_hash,
            auto_create_issues, min_issue_severity, default_branch)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        row.id,
        row.user_id,
        row.harbor_cred_id,
        row.github_cred_id,
        row.harbor_base_url,
        row.harbor_project,
        row.harbor_repository,
        row.github_owner,
        row.github_repo,
        row.webhook_token_hash,
        row.webhook_auth_secret_hash,
        row.auto_create_issues,
        row.min_issue_severity,
        row.default_branch
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Finds one mapping owned by `user_id`.
pub async fn find_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<Option<MappingRow>, AppError> {
    sqlx::query_as!(
        MappingRow,
        r#"SELECT id AS "id!", user_id AS "user_id!", harbor_cred_id AS "harbor_cred_id!",
                  github_cred_id AS "github_cred_id!", harbor_base_url AS "harbor_base_url!",
                  harbor_project AS "harbor_project!", harbor_repository AS "harbor_repository!",
                  github_owner AS "github_owner!", github_repo AS "github_repo!",
                  webhook_token_hash AS "webhook_token_hash!",
                  webhook_auth_secret_hash AS "webhook_auth_secret_hash!",
                  auto_create_issues, min_issue_severity, default_branch AS "default_branch!",
                  created_at
           FROM repo_mappings WHERE id = ? AND user_id = ?"#,
        id,
        user_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Replaces the editable columns of one owned mapping. Returns the rows changed. The
/// raw `sqlx::Error` is returned so the caller can tell a UNIQUE violation (`409`).
pub async fn update_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    row: &MappingRow,
) -> Result<u64, sqlx::Error> {
    sqlx::query!(
        "UPDATE repo_mappings
            SET harbor_cred_id = ?, github_cred_id = ?, harbor_base_url = ?,
                harbor_project = ?, harbor_repository = ?, github_owner = ?, github_repo = ?,
                auto_create_issues = ?, min_issue_severity = ?, default_branch = ?
          WHERE id = ? AND user_id = ?",
        row.harbor_cred_id,
        row.github_cred_id,
        row.harbor_base_url,
        row.harbor_project,
        row.harbor_repository,
        row.github_owner,
        row.github_repo,
        row.auto_create_issues,
        row.min_issue_severity,
        row.default_branch,
        row.id,
        user_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
}

/// Replaces the webhook token digest of one owned mapping.
pub async fn set_token_hash(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
    hash: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE repo_mappings SET webhook_token_hash = ? WHERE id = ? AND user_id = ?",
        hash,
        id,
        user_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Replaces the auth secret digest of one owned mapping.
pub async fn set_auth_secret_hash(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
    hash: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE repo_mappings SET webhook_auth_secret_hash = ? WHERE id = ? AND user_id = ?",
        hash,
        id,
        user_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Deletes one owned mapping. `ON DELETE CASCADE` removes its child rows.
pub async fn delete_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM repo_mappings WHERE id = ? AND user_id = ?",
        id,
        user_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Lists the GitHub issue numbers still open that the delete of `mapping_id` removes: open
/// `github_issues` rows of the GitHub repository that no other mapping of that repository
/// reports with an `open` finding. These are the numbers the `mapping.delete` audit lists.
pub async fn open_issue_numbers(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    github_owner: &str,
    github_repo: &str,
) -> Result<Vec<i64>, AppError> {
    sqlx::query_scalar!(
        r#"SELECT gi.github_issue_number AS "number!: i64" FROM github_issues gi
           WHERE gi.github_owner = ? AND gi.github_repo = ? AND gi.status = 'open'
             AND NOT EXISTS (
                 SELECT 1 FROM cve_findings f
                 JOIN repo_mappings m ON m.id = f.mapping_id
                 WHERE m.id <> ? AND m.github_owner = gi.github_owner
                   AND m.github_repo = gi.github_repo
                   AND f.cve_id = gi.cve_id AND f.status = 'open')
           ORDER BY gi.github_issue_number"#,
        github_owner,
        github_repo,
        mapping_id
    )
    .fetch_all(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Deletes the `github_issues` rows of a GitHub repository that no other mapping of that
/// repository reports with an `open` finding. Rows are shared by every mapping that targets
/// the repository (`specs/database.md`, #185), so a row still reported elsewhere stays.
/// Nothing is changed on GitHub. Run it before the mapping row is deleted.
pub async fn delete_github_issues(
    conn: &mut SqliteConnection,
    mapping_id: &str,
    github_owner: &str,
    github_repo: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "DELETE FROM github_issues
         WHERE github_owner = ? AND github_repo = ?
           AND NOT EXISTS (
               SELECT 1 FROM cve_findings f
               JOIN repo_mappings m ON m.id = f.mapping_id
               WHERE m.id <> ? AND m.github_owner = github_issues.github_owner
                 AND m.github_repo = github_issues.github_repo
                 AND f.cve_id = github_issues.cve_id AND f.status = 'open')",
        github_owner,
        github_repo,
        mapping_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// The Harbor repository names (without the project) that have a mapping on this Harbor
/// base URL and project, for any user (#189). Names only: no id or owner.
pub async fn mapped_repositories(
    pool: &SqlitePool,
    harbor_base_url: &str,
    harbor_project: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT harbor_repository AS "harbor_repository!" FROM repo_mappings
           WHERE harbor_base_url = ? AND harbor_project = ?"#,
        harbor_base_url,
        harbor_project
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.harbor_repository).collect())
}

/// True when another mapping (not `exclude_id`) already maps this Harbor repository on
/// this Harbor instance, for any user. Returns no id or owner, so a caller cannot reveal
/// the other mapping (#180). The GitHub target is not checked: several mappings may target
/// one GitHub repository (`specs/database.md`, #185).
pub async fn harbor_repository_mapped(
    conn: &mut SqliteConnection,
    harbor_base_url: &str,
    harbor_project: &str,
    harbor_repository: &str,
    exclude_id: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (
               SELECT 1 FROM repo_mappings
               WHERE id <> ?
                 AND harbor_base_url = ? AND harbor_project = ? AND harbor_repository = ?
           ) AS "mapped!: bool""#,
        exclude_id,
        harbor_base_url,
        harbor_project,
        harbor_repository
    )
    .fetch_one(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.mapped)
}

/// Returns the id of the one mapping using `hash` as its webhook token digest.
pub async fn find_by_token_hash(pool: &SqlitePool, hash: &str) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        "SELECT id AS \"id!\" FROM repo_mappings WHERE webhook_token_hash = ?",
        hash
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| r.id))
}

/// The columns a list query fills. `sort_column` is a fixed key chosen by the service.
pub struct ListFilter<'a> {
    /// `None` lists every user's mappings (admin `scope=all`).
    pub user_id: Option<&'a str>,
    pub sort: &'a str,
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Returns one page of mappings. `ORDER BY` uses CASE terms, so every sort key stays
/// a compile-checked query.
pub async fn list_owned(
    pool: &SqlitePool,
    filter: &ListFilter<'_>,
) -> Result<Vec<MappingRow>, AppError> {
    sqlx::query_as!(
        MappingRow,
        r#"SELECT id AS "id!", user_id AS "user_id!", harbor_cred_id AS "harbor_cred_id!",
                  github_cred_id AS "github_cred_id!", harbor_base_url AS "harbor_base_url!",
                  harbor_project AS "harbor_project!", harbor_repository AS "harbor_repository!",
                  github_owner AS "github_owner!", github_repo AS "github_repo!",
                  webhook_token_hash AS "webhook_token_hash!",
                  webhook_auth_secret_hash AS "webhook_auth_secret_hash!",
                  auto_create_issues, min_issue_severity, default_branch AS "default_branch!",
                  created_at
           FROM repo_mappings
           LEFT JOIN (
               SELECT m.id AS mapping_id,
                      SUM(CASE WHEN b.rank = 5 THEN 1 ELSE 0 END) AS crit,
                      SUM(CASE WHEN b.rank = 4 THEN 1 ELSE 0 END) AS high,
                      SUM(CASE WHEN b.rank = 3 THEN 1 ELSE 0 END) AS med,
                      SUM(CASE WHEN b.rank = 2 THEN 1 ELSE 0 END) AS low
               FROM github_issues gi
               JOIN repo_mappings m
                 ON m.github_owner = gi.github_owner AND m.github_repo = gi.github_repo
               JOIN (
                   SELECT f.mapping_id AS mapping_id, f.cve_id AS cve_id,
                          MAX(CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                              WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) AS rank
                   FROM cve_findings f
                   GROUP BY f.mapping_id, f.cve_id
               ) b ON b.mapping_id = m.id AND b.cve_id = gi.cve_id
               WHERE gi.status = 'open'
               GROUP BY m.id
           ) oi ON oi.mapping_id = repo_mappings.id
           LEFT JOIN (
               SELECT mapping_id, MAX(updated_at) AS last_at
               FROM sync_jobs
               GROUP BY mapping_id
           ) ls ON ls.mapping_id = repo_mappings.id
           WHERE (?1 IS NULL OR user_id = ?1)
           ORDER BY
             CASE WHEN ?2 = 'last_sync_at' THEN ls.last_at IS NULL END ASC,
             CASE WHEN ?2 = 'harbor_repository' AND ?3 = 1 THEN harbor_repository END ASC,
             CASE WHEN ?2 = 'harbor_repository' AND ?3 = -1 THEN harbor_repository END DESC,
             CASE WHEN ?2 = 'harbor_project' AND ?3 = 1 THEN harbor_project END ASC,
             CASE WHEN ?2 = 'harbor_project' AND ?3 = -1 THEN harbor_project END DESC,
             CASE WHEN ?2 = 'harbor_project' AND ?3 = 1 THEN harbor_repository END ASC,
             CASE WHEN ?2 = 'harbor_project' AND ?3 = -1 THEN harbor_repository END DESC,
             CASE WHEN ?2 = 'github_owner' AND ?3 = 1 THEN github_owner END ASC,
             CASE WHEN ?2 = 'github_owner' AND ?3 = -1 THEN github_owner END DESC,
             CASE WHEN ?2 = 'github_owner' AND ?3 = 1 THEN github_repo END ASC,
             CASE WHEN ?2 = 'github_owner' AND ?3 = -1 THEN github_repo END DESC,
             CASE WHEN ?2 = 'github_repo' AND ?3 = 1 THEN github_repo END ASC,
             CASE WHEN ?2 = 'github_repo' AND ?3 = -1 THEN github_repo END DESC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = 1 THEN COALESCE(oi.crit, 0) END ASC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = -1 THEN COALESCE(oi.crit, 0) END DESC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = 1 THEN COALESCE(oi.high, 0) END ASC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = -1 THEN COALESCE(oi.high, 0) END DESC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = 1 THEN COALESCE(oi.med, 0) END ASC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = -1 THEN COALESCE(oi.med, 0) END DESC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = 1 THEN COALESCE(oi.low, 0) END ASC,
             CASE WHEN ?2 = 'open_issues' AND ?3 = -1 THEN COALESCE(oi.low, 0) END DESC,
             CASE WHEN ?2 = 'last_sync_at' AND ?3 = 1 THEN ls.last_at END ASC,
             CASE WHEN ?2 = 'last_sync_at' AND ?3 = -1 THEN ls.last_at END DESC,
             CASE WHEN ?2 = 'created_at' AND ?3 = 1 THEN created_at END ASC,
             CASE WHEN ?2 = 'created_at' AND ?3 = -1 THEN created_at END DESC,
             id ASC
           LIMIT ?4 OFFSET ?5"#,
        filter.user_id,
        filter.sort,
        filter.sort_sign,
        filter.limit,
        filter.offset
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Counts mappings for the same filter as [`list_owned`].
pub async fn count_owned(pool: &SqlitePool, user_id: Option<&str>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM repo_mappings WHERE (? IS NULL OR user_id = ?)",
        user_id,
        user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// The fields the admin health route needs from one mapping: its owner, its GitHub
/// credential, and its GitHub target. No Harbor or token material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRow {
    pub mapping_id: String,
    pub user_id: String,
    pub github_cred_id: String,
    pub github_owner: String,
    pub github_repo: String,
}

/// Every mapping, ordered by GitHub owner and repository. Only the admin health route
/// reads it, one check per mapping target (`specs/api.md`, Health).
pub async fn all_targets(pool: &SqlitePool) -> Result<Vec<TargetRow>, AppError> {
    sqlx::query_as!(
        TargetRow,
        r#"SELECT id AS "mapping_id!", user_id AS "user_id!",
                  github_cred_id AS "github_cred_id!", github_owner AS "github_owner!",
                  github_repo AS "github_repo!"
           FROM repo_mappings
           ORDER BY github_owner, github_repo"#
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Reads one mapping by id with no owner check. Callers check access first or have already
/// selected the mapping: the webhook path (by token digest), the worker, and the manual
/// scan pull, which checks owner or admin in `services::poller::find_pullable`.
pub async fn find_by_id(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<MappingRow>, AppError> {
    sqlx::query_as!(
        MappingRow,
        r#"SELECT id AS "id!", user_id AS "user_id!", harbor_cred_id AS "harbor_cred_id!",
                  github_cred_id AS "github_cred_id!", harbor_base_url AS "harbor_base_url!",
                  harbor_project AS "harbor_project!", harbor_repository AS "harbor_repository!",
                  github_owner AS "github_owner!", github_repo AS "github_repo!",
                  webhook_token_hash AS "webhook_token_hash!",
                  webhook_auth_secret_hash AS "webhook_auth_secret_hash!",
                  auto_create_issues AS "auto_create_issues?", min_issue_severity AS "min_issue_severity?",
                  default_branch AS "default_branch!", created_at AS "created_at?"
           FROM repo_mappings WHERE id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}
