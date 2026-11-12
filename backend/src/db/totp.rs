//! SQL for `totp_secrets` and `totp_recovery_codes` (`specs/database.md`, `specs/security.md`).
//! A ciphertext or a hash read here never leaves the service layer, and `Debug` does not print it.

use std::fmt;

use sqlx::SqliteConnection;

use crate::error::AppError;

/// One user's TOTP secret row. `secret_encrypted` is a `v1:` ciphertext.
pub struct SecretRow {
    pub secret_encrypted: String,
    pub enabled: bool,
    pub totp_last_step: Option<i64>,
}

impl fmt::Debug for SecretRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRow")
            .field("secret_encrypted", &"<redacted>")
            .field("enabled", &self.enabled)
            .field("totp_last_step", &self.totp_last_step)
            .finish()
    }
}

/// An unused recovery code: its row id and its Argon2id hash.
pub struct RecoveryRow {
    pub id: String,
    pub code_hash: String,
}

impl fmt::Debug for RecoveryRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryRow")
            .field("id", &self.id)
            .field("code_hash", &"<redacted>")
            .finish()
    }
}

fn internal<E>(_: E) -> AppError {
    AppError::InternalError
}

/// The user's secret row, enabled or pending. `None` when the user never started enrolment.
pub async fn find_secret(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<Option<SecretRow>, AppError> {
    sqlx::query_as!(
        SecretRow,
        r#"SELECT secret_encrypted, enabled AS "enabled: bool", totp_last_step
           FROM totp_secrets WHERE user_id = ?"#,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(internal)
}

/// Stores a pending (disabled) secret. A pending row is replaced by a new one. An enabled row
/// is left alone: the result is `0` and the caller answers `409`.
pub async fn upsert_pending(
    conn: &mut SqliteConnection,
    user_id: &str,
    secret_encrypted: &str,
) -> Result<u64, AppError> {
    sqlx::query!(
        "INSERT INTO totp_secrets (user_id, secret_encrypted, enabled)
         VALUES (?, ?, 0)
         ON CONFLICT(user_id) DO UPDATE SET
             secret_encrypted = excluded.secret_encrypted,
             totp_last_step = NULL,
             created_at = unixepoch(),
             enabled_at = NULL
         WHERE totp_secrets.enabled = 0",
        user_id,
        secret_encrypted
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(internal)
}

/// Enables a pending secret and records the step of the confirming code. `0` when the row is
/// missing or already enabled.
pub async fn enable(
    conn: &mut SqliteConnection,
    user_id: &str,
    step: i64,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE totp_secrets
         SET enabled = 1, enabled_at = unixepoch(), totp_last_step = ?
         WHERE user_id = ? AND enabled = 0",
        step,
        user_id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(internal)
}

/// Moves `totp_last_step` forward to `step`. One statement, so two requests that present the
/// same code cannot both win: the second sees `0` rows changed.
pub async fn advance_step(
    conn: &mut SqliteConnection,
    user_id: &str,
    step: i64,
) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE totp_secrets SET totp_last_step = ?
         WHERE user_id = ? AND enabled = 1
           AND (totp_last_step IS NULL OR totp_last_step < ?)",
        step,
        user_id,
        step
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(internal)
}

/// Deletes the user's secret row. Returns the number of rows removed.
pub async fn delete_secret(conn: &mut SqliteConnection, user_id: &str) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM totp_secrets WHERE user_id = ?", user_id)
        .execute(&mut *conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(internal)
}

/// Deletes every recovery code of the user, used or not.
pub async fn delete_recovery_codes(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM totp_recovery_codes WHERE user_id = ?", user_id)
        .execute(&mut *conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(internal)
}

/// Stores one recovery code hash.
pub async fn insert_recovery_code(
    conn: &mut SqliteConnection,
    id: &str,
    user_id: &str,
    code_hash: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO totp_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)",
        id,
        user_id,
        code_hash
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(internal)
}

/// The recovery codes of the user that are not used yet.
pub async fn unused_recovery_codes(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<Vec<RecoveryRow>, AppError> {
    sqlx::query_as!(
        RecoveryRow,
        r#"SELECT id AS "id!", code_hash FROM totp_recovery_codes
           WHERE user_id = ? AND used_at IS NULL ORDER BY id"#,
        user_id
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

/// Marks a recovery code used. `0` when it was used already, so a code works once even when two
/// requests present it together.
pub async fn mark_recovery_used(conn: &mut SqliteConnection, id: &str) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE totp_recovery_codes SET used_at = unixepoch() WHERE id = ? AND used_at IS NULL",
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected())
    .map_err(internal)
}
