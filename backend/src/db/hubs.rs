//! SQL for `hubs` (`specs/spinoff-local-scan.md`, sections 2 and 9). A hub is a registry host;
//! the host is its only name. Rows hold no secret.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// One hub as the API returns it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HubRow {
    pub id: String,
    pub host: String,
    pub pull_endpoint: Option<String>,
    /// `default` or `custom`.
    pub kind: String,
}

/// One page of hubs: defaults first, then by host.
pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<HubRow>, AppError> {
    sqlx::query_as!(
        HubRow,
        r#"SELECT id AS "id!", host AS "host!", pull_endpoint, kind AS "kind!"
           FROM hubs
           ORDER BY (kind = 'default') DESC, host ASC
           LIMIT ? OFFSET ?"#,
        limit,
        offset
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// The number of hubs.
pub async fn count(pool: &SqlitePool) -> Result<i64, AppError> {
    sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n!: i64" FROM hubs"#)
        .fetch_one(pool)
        .await
        .map_err(db_err)
}

/// One hub by id.
pub async fn find(conn: &mut SqliteConnection, id: &str) -> Result<Option<HubRow>, AppError> {
    sqlx::query_as!(
        HubRow,
        r#"SELECT id AS "id!", host AS "host!", pull_endpoint, kind AS "kind!"
           FROM hubs WHERE id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// Inserts a custom hub. A host that is already a hub is `409`.
pub async fn insert_custom(
    conn: &mut SqliteConnection,
    id: &str,
    host: &str,
    pull_endpoint: Option<&str>,
    created_by: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO hubs (id, host, pull_endpoint, kind, created_by)
         VALUES (?, ?, ?, 'custom', ?)",
        id,
        host,
        pull_endpoint,
        created_by
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|err| match err {
        sqlx::Error::Database(ref found) if found.is_unique_violation() => {
            AppError::Conflict("this hub already exists.".to_owned())
        }
        _ => AppError::InternalError,
    })
}

/// True when an image source uses the hub.
pub async fn used_by_source(conn: &mut SqliteConnection, id: &str) -> Result<bool, AppError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS (SELECT 1 FROM image_sources WHERE hub_id = ?) AS "used!: bool""#,
        id
    )
    .fetch_one(conn)
    .await
    .map_err(db_err)?;
    Ok(row.used)
}

/// Deletes a custom hub. Images that still name the hub keep it (`RESTRICT`), which is `409`.
pub async fn delete_custom(conn: &mut SqliteConnection, id: &str) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM hubs WHERE id = ? AND kind = 'custom'", id)
        .execute(conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(|err| match err {
            sqlx::Error::Database(ref found) if found.is_foreign_key_violation() => {
                AppError::Conflict("images of this hub are still recorded.".to_owned())
            }
            _ => AppError::InternalError,
        })
}
