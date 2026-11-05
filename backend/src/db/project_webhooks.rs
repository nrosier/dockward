//! SQL for the `project_webhooks` and `project_webhook_unmatched` tables (migration 0003,
//! issue #132). Holds digests and counts only: never a token, a secret, or an event body.

use sqlx::SqlitePool;

use crate::error::AppError;

/// A project webhook, found by its token digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectWebhook {
    pub id: String,
    pub user_id: String,
    pub harbor_base_url: String,
    pub harbor_project: String,
    pub secret_hash: String,
}

/// Looks up a project webhook by the digest of its project token.
pub async fn find_by_token_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<ProjectWebhook>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!", user_id AS "user_id!", harbor_base_url AS "harbor_base_url!",
                  harbor_project AS "harbor_project!", secret_hash AS "secret_hash!"
           FROM project_webhooks WHERE token_hash = ?"#,
        token_hash
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| ProjectWebhook {
        id: r.id,
        user_id: r.user_id,
        harbor_base_url: r.harbor_base_url,
        harbor_project: r.harbor_project,
        secret_hash: r.secret_hash,
    }))
}

/// The id of the mapping on this project whose Harbor repository matches, or `None`.
/// A mapping's Harbor repository is unique per Harbor instance, so at most one matches.
pub async fn mapping_for_repository(
    pool: &SqlitePool,
    harbor_base_url: &str,
    harbor_project: &str,
    harbor_repository: &str,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        "SELECT id AS \"id!\" FROM repo_mappings
         WHERE harbor_base_url = ? AND harbor_project = ? AND harbor_repository = ?",
        harbor_base_url,
        harbor_project,
        harbor_repository
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| r.id))
}

/// Counts one unmatched event for a repository on a project webhook (#132). No event body is
/// stored.
pub async fn record_unmatched(
    pool: &SqlitePool,
    project_webhook_id: &str,
    repository: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO project_webhook_unmatched (project_webhook_id, repository, count, last_seen_at)
         VALUES (?, ?, 1, ?)
         ON CONFLICT (project_webhook_id, repository)
         DO UPDATE SET count = count + 1, last_seen_at = excluded.last_seen_at",
        project_webhook_id,
        repository,
        now
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}
