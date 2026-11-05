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

/// A mapping chosen by a project event: its id and its own Harbor repository name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedMapping {
    pub id: String,
    pub harbor_repository: String,
}

/// The mapping on this project whose Harbor repository matches, or `None`.
/// A mapping's Harbor repository is unique per Harbor instance, so at most one matches.
pub async fn mapping_for_repository(
    pool: &SqlitePool,
    harbor_base_url: &str,
    harbor_project: &str,
    harbor_repository: &str,
) -> Result<Option<RoutedMapping>, AppError> {
    let row = sqlx::query!(
        "SELECT id AS \"id!\", harbor_repository AS \"harbor_repository!\" FROM repo_mappings
         WHERE harbor_base_url = ? AND harbor_project = ? AND harbor_repository = ?",
        harbor_base_url,
        harbor_project,
        harbor_repository
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| RoutedMapping {
        id: r.id,
        harbor_repository: r.harbor_repository,
    }))
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

/// The columns a new project webhook row needs. Digests only, never the values.
pub struct NewProjectWebhook<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub harbor_base_url: &'a str,
    pub harbor_project: &'a str,
    pub token_hash: &'a str,
    pub secret_hash: &'a str,
}

/// Inserts a project webhook. `rotated_at` is written as NULL: the API reports `null`
/// until the first rotation (`specs/api.md`, Project webhooks). The raw `sqlx::Error` is
/// returned so the caller can tell a UNIQUE violation (`409`).
pub async fn insert(
    conn: &mut sqlx::SqliteConnection,
    row: &NewProjectWebhook<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO project_webhooks
            (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash, rotated_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)",
        row.id,
        row.user_id,
        row.harbor_base_url,
        row.harbor_project,
        row.token_hash,
        row.secret_hash
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// A project webhook with its owner's username, for the management API. No digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectWebhookRow {
    pub id: String,
    pub user_id: String,
    pub owner_username: String,
    pub harbor_base_url: String,
    pub harbor_project: String,
    pub created_at: Option<i64>,
    pub rotated_at: Option<i64>,
}

/// Looks up a project webhook by id.
pub async fn find_by_id(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<Option<ProjectWebhookRow>, AppError> {
    sqlx::query_as!(
        ProjectWebhookRow,
        r#"SELECT p.id AS "id!", p.user_id AS "user_id!", u.username AS "owner_username!",
                  p.harbor_base_url AS "harbor_base_url!", p.harbor_project AS "harbor_project!",
                  p.created_at, p.rotated_at
           FROM project_webhooks p JOIN users u ON u.id = p.user_id
           WHERE p.id = ?"#,
        id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The id of the project webhook for a Harbor base URL and project, or `None`.
pub async fn find_by_project(
    conn: &mut sqlx::SqliteConnection,
    harbor_base_url: &str,
    harbor_project: &str,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!" FROM project_webhooks
           WHERE harbor_base_url = ? AND harbor_project = ?"#,
        harbor_base_url,
        harbor_project
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| r.id))
}

/// Replaces the project token digest and sets `rotated_at`. Returns the rows changed.
pub async fn set_token_hash(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    token_hash: &str,
    now: i64,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE project_webhooks SET token_hash = ?, rotated_at = ? WHERE id = ?",
        token_hash,
        now,
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Replaces the project secret digest and sets `rotated_at`. Returns the rows changed.
pub async fn set_secret_hash(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    secret_hash: &str,
    now: i64,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE project_webhooks SET secret_hash = ?, rotated_at = ? WHERE id = ?",
        secret_hash,
        now,
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// The Harbor repository names (`harbor_repository`) of every mapping on a Harbor base URL
/// and project, any owner. Names only: no ids, owners, or targets.
pub async fn mapping_repositories(
    conn: &mut sqlx::SqliteConnection,
    harbor_base_url: &str,
    harbor_project: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT harbor_repository AS "harbor_repository!" FROM repo_mappings
           WHERE harbor_base_url = ? AND harbor_project = ?
           ORDER BY harbor_repository"#,
        harbor_base_url,
        harbor_project
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|r| r.harbor_repository).collect())
}

/// One unmatched-event count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmatchedRow {
    pub repository: String,
    pub count: i64,
    pub last_seen_at: i64,
}

/// Paging for [`list_unmatched`]. `sort` is a fixed key chosen by the service.
pub struct UnmatchedFilter<'a> {
    pub project_webhook_id: &'a str,
    pub sort: &'a str,
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
}

// A row is hidden once a mapping covers its repository. "Covers" is the receiver's routing
// rule (`api::webhooks::receive_project`): the part of the stored `project/repository` after
// the first `/` equals a mapping's `harbor_repository` on the project's base URL and project.

/// One page of unmatched counts for a project webhook, without rows whose repository now
/// has a mapping. `ORDER BY` uses CASE terms so every sort key stays compile-checked.
pub async fn list_unmatched(
    pool: &SqlitePool,
    filter: &UnmatchedFilter<'_>,
) -> Result<Vec<UnmatchedRow>, AppError> {
    sqlx::query_as!(
        UnmatchedRow,
        r#"SELECT un.repository AS "repository!", un.count AS "count!: i64",
                  un.last_seen_at AS "last_seen_at!: i64"
           FROM project_webhook_unmatched un
           JOIN project_webhooks p ON p.id = un.project_webhook_id
           WHERE un.project_webhook_id = ?
             AND NOT EXISTS (
               SELECT 1 FROM repo_mappings m
               WHERE m.harbor_base_url = p.harbor_base_url
                 AND m.harbor_project = p.harbor_project
                 AND m.harbor_repository = CASE
                   WHEN instr(un.repository, '/') > 0
                     THEN substr(un.repository, instr(un.repository, '/') + 1)
                   ELSE un.repository END)
           ORDER BY
             CASE WHEN ? = 'last_seen_at' AND ? = 1 THEN un.last_seen_at END ASC,
             CASE WHEN ? = 'last_seen_at' AND ? = -1 THEN un.last_seen_at END DESC,
             CASE WHEN ? = 'count' AND ? = 1 THEN un.count END ASC,
             CASE WHEN ? = 'count' AND ? = -1 THEN un.count END DESC,
             CASE WHEN ? = 'repository' AND ? = 1 THEN un.repository END ASC,
             CASE WHEN ? = 'repository' AND ? = -1 THEN un.repository END DESC,
             un.repository ASC
           LIMIT ? OFFSET ?"#,
        filter.project_webhook_id,
        filter.sort,
        filter.sort_sign,
        filter.sort,
        filter.sort_sign,
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

/// Counts the rows [`list_unmatched`] would return over all pages.
pub async fn count_unmatched(pool: &SqlitePool, project_webhook_id: &str) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64"
           FROM project_webhook_unmatched un
           JOIN project_webhooks p ON p.id = un.project_webhook_id
           WHERE un.project_webhook_id = ?
             AND NOT EXISTS (
               SELECT 1 FROM repo_mappings m
               WHERE m.harbor_base_url = p.harbor_base_url
                 AND m.harbor_project = p.harbor_project
                 AND m.harbor_repository = CASE
                   WHEN instr(un.repository, '/') > 0
                     THEN substr(un.repository, instr(un.repository, '/') + 1)
                   ELSE un.repository END)"#,
        project_webhook_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// A project webhook a user owns, as the user-deletion path needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProject {
    pub id: String,
    pub harbor_base_url: String,
    pub harbor_project: String,
}

/// Every project webhook a user owns.
pub async fn owned_by(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
) -> Result<Vec<OwnedProject>, AppError> {
    sqlx::query_as!(
        OwnedProject,
        r#"SELECT id AS "id!", harbor_base_url AS "harbor_base_url!",
                  harbor_project AS "harbor_project!"
           FROM project_webhooks WHERE user_id = ? ORDER BY id"#,
        user_id
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// The user to take over a project webhook: another user with a mapping on the same Harbor
/// base URL and project. The user with the oldest such mapping wins (a NULL `created_at`
/// sorts last), then the lowest id, so the choice is deterministic.
pub async fn transfer_candidate(
    conn: &mut sqlx::SqliteConnection,
    harbor_base_url: &str,
    harbor_project: &str,
    excluded_user_id: &str,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        r#"SELECT user_id AS "user_id!" FROM repo_mappings
           WHERE harbor_base_url = ? AND harbor_project = ? AND user_id <> ?
           GROUP BY user_id
           ORDER BY (MIN(created_at) IS NULL), MIN(created_at) ASC, user_id ASC
           LIMIT 1"#,
        harbor_base_url,
        harbor_project,
        excluded_user_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| r.user_id))
}

/// Moves a project webhook to a new owner. Returns the rows changed.
pub async fn set_owner(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    user_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE project_webhooks SET user_id = ? WHERE id = ?",
        user_id,
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}
