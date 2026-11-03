//! SQL for the `audit_log` table. Business rules live in `services::audit`.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// One `audit_log` row as read back from the database.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub actor_username: String,
    pub action: String,
    pub target: String,
    pub created_at: Option<i64>,
    pub details: Option<String>,
}

/// A row to insert. `details` is already-serialized JSON, checked by the caller.
pub struct NewAudit<'a> {
    pub id: &'a str,
    pub actor_user_id: Option<&'a str>,
    pub actor_username: &'a str,
    pub action: &'a str,
    pub target: &'a str,
    pub details: Option<&'a str>,
}

/// Filters and paging for the audit list. `sort_sign` is `1` for ascending and
/// `-1` for descending order on `created_at`.
pub struct AuditFilter<'a> {
    pub action: Option<&'a str>,
    pub actor_user_id: Option<&'a str>,
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Inserts one audit row on the given connection, so it can join a transaction.
pub async fn insert(conn: &mut SqliteConnection, row: NewAudit<'_>) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO audit_log (id, actor_user_id, actor_username, action, target, details)
         VALUES (?, ?, ?, ?, ?, ?)",
        row.id,
        row.actor_user_id,
        row.actor_username,
        row.action,
        row.target,
        row.details
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Counts the rows that match `filter`.
pub async fn count(pool: &SqlitePool, filter: &AuditFilter<'_>) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n: i64" FROM audit_log
           WHERE (? IS NULL OR action = ?) AND (? IS NULL OR actor_user_id = ?)"#,
        filter.action,
        filter.action,
        filter.actor_user_id,
        filter.actor_user_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Returns one page of rows that match `filter`, ordered by `created_at`.
pub async fn list(
    pool: &SqlitePool,
    filter: &AuditFilter<'_>,
) -> Result<Vec<AuditRecord>, AppError> {
    sqlx::query_as!(
        AuditRecord,
        r#"SELECT id AS "id!", actor_user_id, actor_username AS "actor_username!",
                  action AS "action!", target AS "target!", created_at, details
           FROM audit_log
           WHERE (? IS NULL OR action = ?) AND (? IS NULL OR actor_user_id = ?)
           ORDER BY CASE WHEN ? = 1 THEN created_at END ASC,
                    CASE WHEN ? = -1 THEN created_at END DESC,
                    id ASC
           LIMIT ? OFFSET ?"#,
        filter.action,
        filter.action,
        filter.actor_user_id,
        filter.actor_user_id,
        filter.sort_sign,
        filter.sort_sign,
        filter.limit,
        filter.offset
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}
