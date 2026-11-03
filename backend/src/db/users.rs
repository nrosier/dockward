//! SQL for the `users` table used by per-request authentication.

use sqlx::SqlitePool;

use crate::error::AppError;

/// The columns the per-request lookup needs. `role` is read from here on every
/// request, so a demotion takes effect immediately.
#[derive(Debug, Clone)]
pub struct UserAuthRow {
    pub id: String,
    pub username: String,
    pub role: String,
    pub token_version: i64,
}

/// Finds a user by id for session validation. Returns `None` when the row is gone.
pub async fn find_auth(pool: &SqlitePool, user_id: &str) -> Result<Option<UserAuthRow>, AppError> {
    sqlx::query_as!(
        UserAuthRow,
        r#"SELECT id AS "id!", username, role, token_version
           FROM users WHERE id = ?"#,
        user_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Increments `token_version`, which revokes every session of the user.
/// Returns the number of rows changed (0 when the user does not exist).
pub async fn bump_token_version(pool: &SqlitePool, user_id: &str) -> Result<u64, AppError> {
    sqlx::query!(
        "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
        user_id
    )
    .execute(pool)
    .await
    .map(|done| done.rows_affected())
    .map_err(|_| AppError::InternalError)
}

/// Sets a user's role. Test helper for demotion; the admin route owns this in #19.
#[cfg(test)]
pub async fn set_role(pool: &SqlitePool, user_id: &str, role: &str) -> Result<(), AppError> {
    sqlx::query!("UPDATE users SET role = ? WHERE id = ?", role, user_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
}

/// Full row for login and the `User` response.
#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub role: String,
    pub auth_provider: String,
    pub token_version: i64,
    pub created_at: Option<i64>,
}

/// Finds a user by username for login. Returns `None` when no such user exists.
pub async fn find_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<UserRow>, AppError> {
    sqlx::query_as!(
        UserRow,
        r#"SELECT id AS "id!", username, email, password_hash, role,
                  auth_provider, token_version, created_at
           FROM users WHERE username = ?"#,
        username
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Finds a user by id for the `User` response.
pub async fn find_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<UserRow>, AppError> {
    sqlx::query_as!(
        UserRow,
        r#"SELECT id AS "id!", username, email, password_hash, role,
                  auth_provider, token_version, created_at
           FROM users WHERE id = ?"#,
        user_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalError)
}
