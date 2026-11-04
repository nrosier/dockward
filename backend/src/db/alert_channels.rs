//! SQL for the `alert_channels` table. Business rules live in `services::alert_channels`.
//! `config_encrypted` is the `v1:` ciphertext of the whole channel config. It never
//! leaves the service layer, and `Debug` does not print it.

use std::fmt;

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

/// One `alert_channels` row.
#[derive(Clone)]
pub struct ChannelRow {
    pub id: String,
    pub kind: String,
    pub config_encrypted: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl fmt::Debug for ChannelRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelRow")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("config_encrypted", &"<redacted>")
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Inserts a channel. The timestamps come from the column defaults.
pub async fn insert(
    conn: &mut SqliteConnection,
    id: &str,
    kind: &str,
    config_encrypted: &str,
    enabled: bool,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO alert_channels (id, kind, config_encrypted, enabled) VALUES (?, ?, ?, ?)",
        id,
        kind,
        config_encrypted,
        enabled
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Finds one channel by id.
pub async fn find(conn: &mut SqliteConnection, id: &str) -> Result<Option<ChannelRow>, AppError> {
    sqlx::query_as!(
        ChannelRow,
        r#"SELECT id AS "id!", kind AS "kind!", config_encrypted AS "config_encrypted!",
                  enabled AS "enabled!: bool", created_at AS "created_at!: i64",
                  updated_at AS "updated_at!: i64"
           FROM alert_channels WHERE id = ?"#,
        id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Counts every channel.
pub async fn count(pool: &SqlitePool) -> Result<i64, AppError> {
    let row = sqlx::query!(r#"SELECT COUNT(*) AS "n: i64" FROM alert_channels"#)
        .fetch_one(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// One page of channels ordered by `created_at`. `sort_sign` is `1` for ascending and
/// `-1` for descending. The id breaks ties so paging is stable.
pub async fn list(
    pool: &SqlitePool,
    sort_sign: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<ChannelRow>, AppError> {
    sqlx::query_as!(
        ChannelRow,
        r#"SELECT id AS "id!", kind AS "kind!", config_encrypted AS "config_encrypted!",
                  enabled AS "enabled!: bool", created_at AS "created_at!: i64",
                  updated_at AS "updated_at!: i64"
           FROM alert_channels
           ORDER BY CASE WHEN ? = 1 THEN created_at END ASC,
                    CASE WHEN ? = -1 THEN created_at END DESC,
                    id ASC
           LIMIT ? OFFSET ?"#,
        sort_sign,
        sort_sign,
        limit,
        offset
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Sets `enabled` and, when given, replaces the encrypted config. Bumps `updated_at`.
/// Returns false when no row has this id.
pub async fn update(
    conn: &mut SqliteConnection,
    id: &str,
    enabled: bool,
    config_encrypted: Option<&str>,
) -> Result<bool, AppError> {
    sqlx::query!(
        "UPDATE alert_channels
         SET enabled = ?, config_encrypted = COALESCE(?, config_encrypted),
             updated_at = unixepoch()
         WHERE id = ?",
        enabled,
        config_encrypted,
        id
    )
    .execute(&mut *conn)
    .await
    .map(|done| done.rows_affected() > 0)
    .map_err(|_| AppError::InternalError)
}
