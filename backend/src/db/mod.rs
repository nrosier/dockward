use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

#[allow(dead_code)] // Used by the audit writer and the admin audit list.
pub mod audit;
#[allow(dead_code)] // Used by the login service and the OIDC settings in #18.
pub mod config;
pub mod credentials;
#[allow(dead_code)] // Used by the setup and login services.
pub mod setup;
#[allow(dead_code)] // Used by the session service and the account and admin routes.
pub mod users;

use crate::error::AppError;

/// File name of the SQLite database inside `HARBORGATE_DATA_DIR`.
pub const DB_FILE_NAME: &str = "harborgate.db";

/// Connection options for the database at `path`. Foreign keys are enforced on
/// every connection, and WAL is set. Both are set explicitly so a change in the
/// library default cannot switch enforcement off.
pub fn connect_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
}

/// Full path of the database file for a data directory.
pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_FILE_NAME)
}

/// Opens the pool for the database in `data_dir` and applies the schema migrations.
pub async fn open(data_dir: &Path) -> Result<SqlitePool, AppError> {
    let pool = SqlitePoolOptions::new()
        .connect_with(connect_options(&database_path(data_dir)))
        .await
        .map_err(|_| AppError::InternalError)?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Applies the embedded migrations in `backend/migrations/`.
pub async fn migrate(pool: &SqlitePool) -> Result<(), AppError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|_| AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single-connection in-memory pool with the same foreign key setting.
    async fn test_pool() -> Result<SqlitePool, AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        migrate(&pool).await?;
        Ok(pool)
    }

    /// One user, a Harbor and a GitHub credential, and one mapping that uses both.
    /// Test values only.
    async fn seed_mapping(pool: &SqlitePool) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider)
             VALUES ('user-1', 'test-user', 'user', 'local')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, encrypted_token)
             VALUES ('cred-harbor', 'user-1', 'harbor', 'harbor', 'https://harbor.example.com', 'v1:test')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, service_type, label, encrypted_token)
             VALUES ('cred-gh', 'user-1', 'github', 'github', 'v1:test')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO repo_mappings (
                id, user_id, harbor_cred_id, github_cred_id, harbor_base_url,
                harbor_project, harbor_repository, github_owner, github_repo,
                webhook_token_hash, webhook_auth_secret_hash)
             VALUES ('map-1', 'user-1', 'cred-harbor', 'cred-gh', 'https://harbor.example.com',
                'project', 'repo', 'owner', 'repo', 'hash-token-test', 'hash-secret-test')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        Ok(())
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced_on_the_pool() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let row = sqlx::query!("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(row.foreign_keys, Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn orphan_insert_is_rejected() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let result = sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, service_type, label, encrypted_token)
             VALUES ('cred-x', 'no-such-user', 'github', 'label', 'v1:test')"
        )
        .execute(&pool)
        .await;
        assert!(result.is_err(), "orphan credential was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn restrict_blocks_deleting_a_credential_in_use() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_mapping(&pool).await?;

        let deleted = sqlx::query!("DELETE FROM user_credentials WHERE id = 'cred-gh'")
            .execute(&pool)
            .await;
        assert!(deleted.is_err(), "RESTRICT did not block the delete");

        let remaining = sqlx::query!("SELECT COUNT(*) AS n FROM user_credentials")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(remaining.n, 2);
        Ok(())
    }

    #[tokio::test]
    async fn file_database_uses_wal() -> Result<(), AppError> {
        let dir = std::env::temp_dir().join(format!("harborgate-db-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| AppError::InternalError)?;
        let pool = open(&dir).await?;
        // PRAGMA results have no column type the macro can infer, so this read is
        // the one runtime query in the module.
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, "wal");
        Ok(())
    }
}
