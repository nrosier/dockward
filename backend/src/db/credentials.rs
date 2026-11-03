//! SQL for the `user_credentials` table. Every query is scoped to one owner, so a
//! credential of another user is indistinguishable from a missing one (`404`).

use std::fmt;

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// A stored credential. `encrypted_token` is the `v1:` ciphertext and never leaves
/// the service layer. `Debug` is hand-written so the ciphertext is not printed.
#[derive(Clone)]
pub struct CredentialRow {
    pub id: String,
    pub service_type: String,
    pub label: String,
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub encrypted_token: String,
    pub expires_at: Option<i64>,
    pub created_at: Option<i64>,
}

impl fmt::Debug for CredentialRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRow")
            .field("id", &self.id)
            .field("service_type", &self.service_type)
            .field("label", &self.label)
            .field("base_url", &self.base_url)
            .field("username", &self.username)
            .field("encrypted_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Inserts a credential row on `conn`.
pub async fn insert(
    conn: &mut SqliteConnection,
    row: &CredentialRow,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO user_credentials
            (id, user_id, service_type, label, base_url, username, encrypted_token, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        row.id,
        user_id,
        row.service_type,
        row.label,
        row.base_url,
        row.username,
        row.encrypted_token,
        row.expires_at
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Finds one credential owned by `user_id`. Returns `None` for another user's row.
pub async fn find_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<Option<CredentialRow>, AppError> {
    sqlx::query_as!(
        CredentialRow,
        r#"SELECT id AS "id!", service_type AS "service_type!", label AS "label!",
                  base_url, username, encrypted_token AS "encrypted_token!",
                  expires_at, created_at
           FROM user_credentials WHERE id = ? AND user_id = ?"#,
        id,
        user_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Replaces the mutable columns of one owned credential.
pub async fn update_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    row: &CredentialRow,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE user_credentials
            SET label = ?, base_url = ?, username = ?, encrypted_token = ?, expires_at = ?
          WHERE id = ? AND user_id = ?",
        row.label,
        row.base_url,
        row.username,
        row.encrypted_token,
        row.expires_at,
        row.id,
        user_id
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Deletes one owned credential. Returns the number of rows removed. A mapping that
/// references the row makes SQLite fail the statement (`ON DELETE RESTRICT`).
pub async fn delete_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query!(
        "DELETE FROM user_credentials WHERE id = ? AND user_id = ?",
        id,
        user_id
    )
    .execute(conn)
    .await
    .map(|done| done.rows_affected())
}

/// Counts the mappings that reference a credential on either side.
pub async fn mapping_refs(conn: &mut SqliteConnection, id: &str) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM repo_mappings WHERE harbor_cred_id = ? OR github_cred_id = ?",
        id,
        id
    )
    .fetch_one(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Counts the mappings that use a credential as their Harbor side.
pub async fn harbor_mapping_refs(conn: &mut SqliteConnection, id: &str) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM repo_mappings WHERE harbor_cred_id = ?",
        id
    )
    .fetch_one(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// The columns a list query fills. `sort` is one of `label`, `created_at`, or
/// `expires_at`, chosen by the service. `ascending` is `1` or `-1`.
pub struct ListFilter<'a> {
    /// `None` lists every user's credentials (admin `scope=all`).
    pub user_id: Option<&'a str>,
    pub service_type: Option<&'a str>,
    pub sort: &'a str,
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Returns one page of the owner's credentials. `ORDER BY` uses CASE terms, so every
/// sort key stays a compile-checked query.
pub async fn list_owned(
    pool: &SqlitePool,
    filter: &ListFilter<'_>,
) -> Result<Vec<CredentialRow>, AppError> {
    sqlx::query_as!(
        CredentialRow,
        r#"SELECT id AS "id!", service_type AS "service_type!", label AS "label!",
                  base_url, username, encrypted_token AS "encrypted_token!",
                  expires_at, created_at
           FROM user_credentials
           WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR service_type = ?)
           ORDER BY
             CASE WHEN ? = 'label' AND ? = 1 THEN label END ASC,
             CASE WHEN ? = 'label' AND ? = -1 THEN label END DESC,
             CASE WHEN ? = 'created_at' AND ? = 1 THEN created_at END ASC,
             CASE WHEN ? = 'created_at' AND ? = -1 THEN created_at END DESC,
             CASE WHEN ? = 'expires_at' AND ? = 1 THEN expires_at END ASC,
             CASE WHEN ? = 'expires_at' AND ? = -1 THEN expires_at END DESC,
             id ASC
           LIMIT ? OFFSET ?"#,
        filter.user_id,
        filter.user_id,
        filter.service_type,
        filter.service_type,
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

/// Every Harbor credential of every user, soonest expiry first, with no expiry last.
/// Only the admin health route reads it (`specs/api.md`, Health).
pub async fn all_harbor(pool: &SqlitePool) -> Result<Vec<CredentialRow>, AppError> {
    sqlx::query_as!(
        CredentialRow,
        r#"SELECT id AS "id!", service_type AS "service_type!", label AS "label!",
                  base_url, username, encrypted_token AS "encrypted_token!",
                  expires_at, created_at
           FROM user_credentials
           WHERE service_type = 'harbor'
           ORDER BY expires_at IS NULL, expires_at, label"#
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Counts credentials for the same filter as [`list_owned`].
pub async fn count_owned(
    pool: &SqlitePool,
    user_id: Option<&str>,
    service_type: Option<&str>,
) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM user_credentials
          WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR service_type = ?)",
        user_id,
        user_id,
        service_type,
        service_type
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}
