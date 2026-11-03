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
