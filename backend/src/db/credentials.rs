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

/// The columns `user_credentials` holds (GitHub only). Converted to [`CredentialRow`] after
/// the query, which sets the removed Harbor-only fields to `None` and the service type to
/// `github`.
struct StoredCredential {
    id: String,
    label: String,
    encrypted_token: String,
    expires_at: Option<i64>,
    created_at: Option<i64>,
}

impl From<StoredCredential> for CredentialRow {
    fn from(row: StoredCredential) -> Self {
        CredentialRow {
            id: row.id,
            service_type: "github".to_owned(),
            label: row.label,
            base_url: None,
            username: None,
            encrypted_token: row.encrypted_token,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

/// Inserts a GitHub credential row on `conn`. `user_credentials` holds GitHub credentials only
/// (`specs/spinoff-local-scan.md`, section 9): `service_type`, `base_url` and `username` are
/// not stored, so they are not written.
pub async fn insert(
    conn: &mut SqliteConnection,
    row: &CredentialRow,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO user_credentials
            (id, user_id, label, encrypted_token, expires_at)
         VALUES (?, ?, ?, ?, ?)",
        row.id,
        user_id,
        row.label,
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
    let row = sqlx::query_as!(
        StoredCredential,
        r#"SELECT id AS "id!", label AS "label!", encrypted_token AS "encrypted_token!",
                  expires_at, created_at
           FROM user_credentials WHERE id = ? AND user_id = ?"#,
        id,
        user_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(CredentialRow::from))
}

/// Replaces the mutable columns of one owned credential.
pub async fn update_owned(
    conn: &mut SqliteConnection,
    user_id: &str,
    row: &CredentialRow,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE user_credentials
            SET label = ?, encrypted_token = ?, expires_at = ?
          WHERE id = ? AND user_id = ?",
        row.label,
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

/// Counts the image sources that use a credential (`source_credentials` is one per source; the
/// GitHub side is `image_sources.github_cred_id`, which is `RESTRICT`).
pub async fn mapping_refs(conn: &mut SqliteConnection, id: &str) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM image_sources WHERE github_cred_id = ?",
        id
    )
    .fetch_one(conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Harbor credentials no longer exist. Always zero (`specs/spinoff-local-scan.md`, section 9).
pub async fn harbor_mapping_refs(
    _conn: &mut SqliteConnection,
    _id: &str,
) -> Result<i64, AppError> {
    Ok(0)
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
    let rows = sqlx::query_as!(
        StoredCredential,
        r#"SELECT id AS "id!", label AS "label!", encrypted_token AS "encrypted_token!",
                  expires_at, created_at
           FROM user_credentials
           WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR 'github' = ?)
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
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(CredentialRow::from).collect())
}

/// Harbor credentials no longer exist, so there are none to list (`specs/spinoff-local-scan.md`,
/// section 9). Kept as an empty list until the admin health route is ported.
pub async fn all_harbor(_pool: &SqlitePool) -> Result<Vec<CredentialRow>, AppError> {
    Ok(Vec::new())
}

/// Counts credentials for the same filter as [`list_owned`].
pub async fn count_owned(
    pool: &SqlitePool,
    user_id: Option<&str>,
    service_type: Option<&str>,
) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM user_credentials
          WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR 'github' = ?)",
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
