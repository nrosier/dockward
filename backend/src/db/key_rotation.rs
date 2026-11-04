//! SQL for the offline key rotation (`services::key_rotation`). Every function takes the
//! transaction's connection, so all rewrites commit or roll back together. A ciphertext
//! read here never leaves the service layer, and `Debug` does not print it.

use std::fmt;

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One stored ciphertext and the id of its row. For `system_config` the id is the key.
pub struct SealedValue {
    pub id: String,
    pub value: String,
}

impl fmt::Debug for SealedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedValue")
            .field("id", &self.id)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Every `user_credentials.encrypted_token`, Harbor and GitHub rows alike.
pub async fn list_credential_tokens(
    conn: &mut SqliteConnection,
) -> Result<Vec<SealedValue>, AppError> {
    sqlx::query_as!(
        SealedValue,
        r#"SELECT id AS "id!", encrypted_token AS "value!"
           FROM user_credentials ORDER BY id"#
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Replaces one credential's ciphertext. Returns the number of rows changed.
pub async fn set_credential_token(
    conn: &mut SqliteConnection,
    id: &str,
    value: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE user_credentials SET encrypted_token = ? WHERE id = ?",
        value,
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Every `system_config.value` whose row has `is_encrypted = 1`. The id is the key.
pub async fn list_encrypted_config(
    conn: &mut SqliteConnection,
) -> Result<Vec<SealedValue>, AppError> {
    sqlx::query_as!(
        SealedValue,
        r#"SELECT key AS "id!", value AS "value!"
           FROM system_config WHERE is_encrypted = 1 ORDER BY key"#
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Replaces one encrypted config value. `updated_at` is left alone: the setting did
/// not change. Returns the number of rows changed.
pub async fn set_config_value(
    conn: &mut SqliteConnection,
    key: &str,
    value: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE system_config SET value = ? WHERE key = ? AND is_encrypted = 1",
        value,
        key
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Every `alert_channels.config_encrypted`.
pub async fn list_alert_configs(conn: &mut SqliteConnection) -> Result<Vec<SealedValue>, AppError> {
    sqlx::query_as!(
        SealedValue,
        r#"SELECT id AS "id!", config_encrypted AS "value!"
           FROM alert_channels ORDER BY id"#
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Replaces one channel's ciphertext. `updated_at` is left alone. Returns the number
/// of rows changed.
pub async fn set_alert_config(
    conn: &mut SqliteConnection,
    id: &str,
    value: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE alert_channels SET config_encrypted = ? WHERE id = ?",
        value,
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}
