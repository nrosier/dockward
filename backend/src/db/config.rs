//! Reads `system_config` values. Keys are listed in `specs/database.md`.

use sqlx::SqlitePool;

use crate::error::AppError;

/// Returns the value of one key, or `None` when the row is missing.
pub async fn get(pool: &SqlitePool, key: &str) -> Result<Option<String>, AppError> {
    let row = sqlx::query!("SELECT value FROM system_config WHERE key = ?", key)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| r.value))
}

/// Whether a key is present at all, without reading its value.
pub async fn exists(pool: &SqlitePool, key: &str) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (SELECT 1 FROM system_config WHERE key = ?) AS "exists_flag: i64""#,
        key
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.exists_flag != 0)
}

/// Inserts or replaces one key on `conn`. The OIDC settings save runs it inside its
/// transaction, so the settings and the audit row commit together.
pub async fn upsert(
    conn: &mut sqlx::SqliteConnection,
    key: &str,
    value: &str,
    is_encrypted: bool,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO system_config (key, value, is_encrypted) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
             value = excluded.value,
             is_encrypted = excluded.is_encrypted,
             updated_at = unixepoch()",
        key,
        value,
        is_encrypted
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Removes one key on `conn`. A missing row is not an error.
pub async fn delete(conn: &mut sqlx::SqliteConnection, key: &str) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM system_config WHERE key = ?", key)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
}
