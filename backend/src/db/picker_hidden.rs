//! SQL for `picker_hidden_items`, the per-user hide list of the mapping pickers
//! (`specs/database.md`). Every query is scoped to one user, so another user's row is
//! indistinguishable from a missing one.

use sqlx::SqlitePool;

use crate::error::AppError;

/// One stored hidden item. `harbor_base_url` is set for `harbor` rows and `None` for `github`.
#[derive(Debug, Clone)]
pub struct HiddenRow {
    pub id: String,
    pub source: String,
    pub harbor_base_url: Option<String>,
    pub full_name: String,
    pub created_at: i64,
}

/// The row of `user_id` with this key, if there is one. `harbor_base_url` is `None` for
/// `github` (`IS` matches two NULLs).
pub async fn find(
    pool: &SqlitePool,
    user_id: &str,
    source: &str,
    harbor_base_url: Option<&str>,
    full_name: &str,
) -> Result<Option<HiddenRow>, AppError> {
    sqlx::query_as!(
        HiddenRow,
        r#"SELECT id AS "id!", source, harbor_base_url, full_name, created_at
           FROM picker_hidden_items
           WHERE user_id = ? AND source = ? AND harbor_base_url IS ? AND full_name = ?"#,
        user_id,
        source,
        harbor_base_url,
        full_name
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Inserts a row unless the user already holds `cap` rows or the key exists. Returns
/// whether a row was written. One statement, so concurrent hides cannot pass the cap.
#[allow(clippy::too_many_arguments)]
pub async fn insert_capped(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    source: &str,
    harbor_base_url: Option<&str>,
    full_name: &str,
    created_at: i64,
    cap: i64,
) -> Result<bool, AppError> {
    let result = sqlx::query!(
        "INSERT INTO picker_hidden_items (id, user_id, source, harbor_base_url, full_name, created_at)
         SELECT CAST(? AS TEXT), CAST(? AS TEXT), CAST(? AS TEXT), CAST(? AS TEXT),
                CAST(? AS TEXT), CAST(? AS INTEGER)
         WHERE (SELECT COUNT(*) FROM picker_hidden_items WHERE user_id = ?) < ?
         ON CONFLICT DO NOTHING",
        id,
        user_id,
        source,
        harbor_base_url,
        full_name,
        created_at,
        user_id,
        cap
    )
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(result.rows_affected() > 0)
}

/// The filter and page of a hidden-item list. `sort` is `created_at` or `full_name`;
/// `sort_sign` is `1` (ascending) or `-1`.
pub struct ListFilter<'a> {
    pub user_id: &'a str,
    pub source: Option<&'a str>,
    pub sort: &'a str,
    pub sort_sign: i64,
    pub limit: i64,
    pub offset: i64,
}

/// One page of the user's hidden items. `ORDER BY` uses CASE terms so every sort key
/// stays a compile-checked query.
pub async fn list(pool: &SqlitePool, filter: &ListFilter<'_>) -> Result<Vec<HiddenRow>, AppError> {
    sqlx::query_as!(
        HiddenRow,
        r#"SELECT id AS "id!", source, harbor_base_url, full_name, created_at
           FROM picker_hidden_items
           WHERE user_id = ? AND (? IS NULL OR source = ?)
           ORDER BY
             CASE WHEN ? = 'created_at' AND ? = 1 THEN created_at END ASC,
             CASE WHEN ? = 'created_at' AND ? = -1 THEN created_at END DESC,
             CASE WHEN ? = 'full_name' AND ? = 1 THEN full_name END ASC,
             CASE WHEN ? = 'full_name' AND ? = -1 THEN full_name END DESC,
             id ASC
           LIMIT ? OFFSET ?"#,
        filter.user_id,
        filter.source,
        filter.source,
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

/// Counts the user's hidden items for the same filter as [`list`].
pub async fn count(
    pool: &SqlitePool,
    user_id: &str,
    source: Option<&str>,
) -> Result<i64, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS n FROM picker_hidden_items
          WHERE user_id = ? AND (? IS NULL OR source = ?)",
        user_id,
        source,
        source
    )
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// The full names the user hid for one list: Harbor items on `harbor_base_url`, or GitHub
/// items when `harbor_base_url` is `None`. At most 1,000 rows by the per-user cap.
pub async fn names(
    pool: &SqlitePool,
    user_id: &str,
    source: &str,
    harbor_base_url: Option<&str>,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        "SELECT full_name FROM picker_hidden_items
          WHERE user_id = ? AND source = ? AND harbor_base_url IS ?",
        user_id,
        source,
        harbor_base_url
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(rows.into_iter().map(|row| row.full_name).collect())
}

/// Deletes one row of `user_id`. Returns the number of rows removed (0 or 1).
pub async fn delete_owned(pool: &SqlitePool, user_id: &str, id: &str) -> Result<u64, AppError> {
    let result = sqlx::query!(
        "DELETE FROM picker_hidden_items WHERE id = ? AND user_id = ?",
        id,
        user_id
    )
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(result.rows_affected())
}
