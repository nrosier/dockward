//! SQL for the `alert_deliveries` table (`specs/database.md`, Decisions: the 24-hour window
//! is enforced by the write). Rows hold a channel id, a dedupe key and a time. They never
//! hold an alert payload, a URL, or a secret.

use sqlx::{SqliteConnection, SqlitePool};

use crate::db::alert_channels::ChannelRow;
use crate::error::AppError;

/// Claims the right to send `dedupe_key` on `channel_id` at `now` (Unix seconds).
///
/// The row is inserted when none exists. When one exists, its `sent_at` is moved to `now`
/// only if it is more than 24 hours old. Returns true when one row changed, and the caller
/// may then send. When it returns false nothing was changed and nothing may be sent: the
/// `DO UPDATE ... WHERE` is a no-op while the old row is inside the window.
pub async fn claim(
    conn: &mut SqliteConnection,
    id: &str,
    channel_id: &str,
    dedupe_key: &str,
    now: i64,
) -> Result<bool, AppError> {
    sqlx::query!(
        "INSERT INTO alert_deliveries (id, channel_id, dedupe_key, sent_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (channel_id, dedupe_key) DO UPDATE SET sent_at = excluded.sent_at
         WHERE alert_deliveries.sent_at < excluded.sent_at - 86400",
        id,
        channel_id,
        dedupe_key,
        now
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected() == 1)
    .map_err(|_| AppError::InternalError)
}

/// Releases a claim made at `claimed_at`, after the send failed, so a later trigger can
/// try again. A row with another `sent_at` belongs to a newer claim and is left alone.
pub async fn release(
    conn: &mut SqliteConnection,
    channel_id: &str,
    dedupe_key: &str,
    claimed_at: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "DELETE FROM alert_deliveries
         WHERE channel_id = ? AND dedupe_key = ? AND sent_at = ?",
        channel_id,
        dedupe_key,
        claimed_at
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Every enabled alert channel, oldest first. The dispatcher reads the channels with this
/// one query, so channel CRUD stays in `db::alert_channels`.
pub async fn list_enabled_channels(pool: &SqlitePool) -> Result<Vec<ChannelRow>, AppError> {
    sqlx::query_as!(
        ChannelRow,
        r#"SELECT id AS "id!", kind AS "kind!", config_encrypted AS "config_encrypted!",
                  enabled AS "enabled!: bool", created_at AS "created_at!: i64",
                  updated_at AS "updated_at!: i64"
           FROM alert_channels WHERE enabled = 1
           ORDER BY created_at ASC, id ASC"#
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}
