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

/// Counts local admins. The last-local-admin rule uses this inside the write transaction.
pub async fn count_local_admins(conn: &mut sqlx::SqliteConnection) -> Result<i64, AppError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "n: i64" FROM users WHERE role = 'admin' AND auth_provider = 'local'"#
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.n)
}

/// Reads one user's role and provider inside a transaction. `None` when the row is gone.
pub async fn role_and_provider(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
) -> Result<Option<(String, String, String)>, AppError> {
    let row = sqlx::query!(
        r#"SELECT role, auth_provider, username FROM users WHERE id = ?"#,
        user_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(row.map(|r| (r.role, r.auth_provider, r.username)))
}

/// Deletes a user's mappings. Step one of the user-deletion order in `specs/database.md`.
pub async fn delete_mappings(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM repo_mappings WHERE user_id = ?", user_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
}

/// Deletes a user's credentials. Step two of the user-deletion order.
pub async fn delete_credentials(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query!("DELETE FROM user_credentials WHERE user_id = ?", user_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
}

/// Deletes the `users` row. Step three. Acceptances and audit rows keep their
/// username snapshots, and their user references become NULL.
pub async fn delete_user_row(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
) -> Result<u64, AppError> {
    sqlx::query!("DELETE FROM users WHERE id = ?", user_id)
        .execute(&mut *conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(|_| AppError::InternalError)
}

/// Sets a user's role inside a transaction.
pub async fn update_role(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    role: &str,
) -> Result<(), AppError> {
    sqlx::query!("UPDATE users SET role = ? WHERE id = ?", role, user_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
}

/// Inserts a new local user. The caller has checked the password length.
pub async fn insert_local(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    username: &str,
    email: Option<&str>,
    password_hash: &str,
    role: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash, role, auth_provider)
         VALUES (?, ?, ?, ?, ?, 'local')",
        id,
        username,
        email,
        password_hash,
        role
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}

/// Finds a user by username inside a transaction. Used by the create check.
pub async fn find_by_username_tx(
    conn: &mut sqlx::SqliteConnection,
    username: &str,
) -> Result<Option<UserRow>, AppError> {
    sqlx::query_as!(
        UserRow,
        r#"SELECT id AS "id!", username, email, password_hash, role,
                  auth_provider, token_version, created_at
           FROM users WHERE username = ?"#,
        username
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Lists all users, oldest first. Used by the admin list route.
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<UserRow>, AppError> {
    sqlx::query_as!(
        UserRow,
        r#"SELECT id AS "id!", username, email, password_hash, role,
                  auth_provider, token_version, created_at
           FROM users ORDER BY created_at, username"#
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalError)
}

/// Replaces a user's password hash. The caller hashes the new password first.
pub async fn set_password_hash(
    pool: &SqlitePool,
    user_id: &str,
    password_hash: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        password_hash,
        user_id
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AppError::InternalError)
}
