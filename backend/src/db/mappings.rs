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

/// Replaces the editable columns of one owned mapping.
pub async fn update_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    row: &MappingRow,
) -> Result<(), AppError> {
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
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
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

/// Returns the id of any mapping that uses the same Harbor repository on the same
/// Harbor instance, or the same GitHub target. `None` when neither is taken.
pub async fn find_conflict(
    conn: &mut SqliteConnection,
    harbor_base_url: &str,
    harbor_project: &str,
    harbor_repository: &str,
    github_owner: &str,
    github_repo: &str,
    exclude_id: &str,
) -> Result<Option<(String, String)>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!", user_id AS "user_id!" FROM repo_mappings
           WHERE id <> ?
             AND ((harbor_base_url = ? AND harbor_project = ? AND harbor_repository = ?)
               OR (github_owner = ? AND github_repo = ?))
           LIMIT 1"#,
        exclude_id,
        harbor_base_url,
        harbor_project,
        harbor_repository,
        github_owner,
        github_repo
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| (r.id, r.user_id)))
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
           WHERE (? IS NULL OR user_id = ?)
           ORDER BY
             CASE WHEN ? = 'harbor_repository' AND ? = 1 THEN harbor_repository END ASC,
             CASE WHEN ? = 'harbor_repository' AND ? = -1 THEN harbor_repository END DESC,
             CASE WHEN ? = 'created_at' AND ? = 1 THEN created_at END ASC,
             CASE WHEN ? = 'created_at' AND ? = -1 THEN created_at END DESC,
             id ASC
           LIMIT ? OFFSET ?"#,
        filter.user_id,
        filter.user_id,
        filter.sort,
        filter.sort_sign,
        filter.sort,
        filter.sort_sign,
        filter.sort,
        filter.sort_sign,
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
