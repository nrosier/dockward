//! Backup SQL. The consistent copy is made with `VACUUM INTO` (`specs/security.md`,
//! Backup and restore). The target path is the only dynamic part, so the caller
//! validates it first. See `services::backup::create`.

use sqlx::SqlitePool;

use crate::error::AppError;

/// Writes a consistent copy of the database to `target`, which must not exist.
///
/// SQLite cannot bind a value for the `VACUUM INTO` target, so the path is written
/// into the statement. `target` must already be validated to contain only ASCII
/// letters, digits, `.`, `_`, `-`, and `/`, with no quote. A caller that breaks this
/// rule would open the statement to injection. `services::backup::create` checks it.
pub async fn vacuum_into(pool: &SqlitePool, target: &str) -> Result<(), AppError> {
    let statement = format!("VACUUM INTO '{target}'");
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
}
