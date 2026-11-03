//! First-run setup SQL. The insert runs only while `users` is empty, in one
//! statement, so concurrent setup requests cannot create two first admins.

use sqlx::SqlitePool;

use crate::error::AppError;

/// Inserts the first admin only if `users` is empty. Returns `true` when this call
/// created the account. A `false` result means setup was already done.
pub async fn insert_first_admin(
    pool: &SqlitePool,
    id: &str,
    username: &str,
    email: Option<&str>,
    password_hash: &str,
) -> Result<bool, AppError> {
    let done = sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash, role, auth_provider)
         SELECT ?, ?, ?, ?, 'admin', 'local'
         WHERE NOT EXISTS (SELECT 1 FROM users)",
        id,
        username,
        email,
        password_hash
    )
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalError)?;
    Ok(done.rows_affected() == 1)
}

/// Whether any user exists. Setup is open only while this is `false`.
pub async fn any_user_exists(pool: &SqlitePool) -> Result<bool, AppError> {
    let row = sqlx::query!(r#"SELECT EXISTS (SELECT 1 FROM users) AS "exists_flag: i64""#)
        .fetch_one(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
    Ok(row.exists_flag != 0)
}
