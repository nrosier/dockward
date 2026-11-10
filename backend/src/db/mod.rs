use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

pub mod acceptances;
pub mod alert_channels;
pub mod alert_deliveries;
#[allow(dead_code)] // Used by the audit writer and the admin audit list.
pub mod audit;
pub mod backup;
#[allow(dead_code)] // Used by the login service and the OIDC settings in #18.
pub mod config;
pub mod credentials;
pub mod dashboard;
pub mod db_refresh;
pub mod discovery;
pub mod findings;
pub mod github_issues;
pub mod hubs;
pub mod image_sources;
pub mod job_runs;
pub mod key_rotation;
pub mod publish;
pub mod retention;
pub mod scan_runs;
pub mod scans;
#[allow(dead_code)] // Used by the setup and login services.
pub mod setup;
pub mod sources;
#[allow(dead_code)] // Used by the pull and eviction jobs (Steps 4 and 5).
pub mod storage;
#[allow(dead_code)] // Used by the job worker and the retry route.
pub mod sync_jobs;
pub mod sync_reports;
#[allow(dead_code)] // Used by the session service and the account and admin routes.
pub mod users;

use crate::error::AppError;

/// File name of the SQLite database inside `DOCKWARD_DATA_DIR`.
pub const DB_FILE_NAME: &str = "harborgate.db";

/// Table that marks a Dockward `main` database. Its presence refuses the file (decision 21).
pub const LEGACY_TABLE: &str = "repo_mappings";

/// The fixed refusal text for a legacy database (specs/spinoff-local-scan.md, section 9).
pub const LEGACY_DATABASE_ERROR: &str =
    "this database was created by HarborGate and cannot be used by this version";

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

/// Opens the pool for the database in `data_dir`. A legacy database is refused before any
/// migration runs. Then the embedded schema is applied.
pub async fn open(data_dir: &Path) -> Result<SqlitePool, AppError> {
    let pool = SqlitePoolOptions::new()
        .connect_with(connect_options(&database_path(data_dir)))
        .await
        .map_err(|_| AppError::InternalError)?;
    refuse_legacy(&pool).await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Refuses a database that holds the `repo_mappings` table. The check runs before the
/// migrator, because a legacy file would otherwise be left at its old schema.
pub async fn refuse_legacy(pool: &SqlitePool) -> Result<(), AppError> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(LEGACY_TABLE)
            .fetch_optional(pool)
            .await
            .map_err(|_| AppError::InternalError)?;
    if found.is_some() {
        return Err(AppError::LegacyDatabase);
    }
    Ok(())
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
    pub(crate) async fn test_pool() -> Result<SqlitePool, AppError> {
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

    /// Names of every table in the database, sorted. Test helper.
    async fn table_names(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations'
             ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// One user, a GitHub credential, and one source that uses it. Test values only.
    async fn seed_source(pool: &SqlitePool) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider)
             VALUES ('user-1', 'test-user', 'user', 'local')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('cred-gh', 'user-1', 'github', 'v1:test')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO image_sources (
                id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('src-1', 'user-1', 'hub-default-ghcr', 'nrosier/walley', 'latest',
                'cred-gh', 'owner', 'repo')"
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
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('cred-x', 'no-such-user', 'label', 'v1:test')"
        )
        .execute(&pool)
        .await;
        assert!(result.is_err(), "orphan credential was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn restrict_blocks_deleting_a_credential_in_use() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_source(&pool).await?;

        let deleted = sqlx::query!("DELETE FROM user_credentials WHERE id = 'cred-gh'")
            .execute(&pool)
            .await;
        assert!(deleted.is_err(), "RESTRICT did not block the delete");

        let remaining = sqlx::query!("SELECT COUNT(*) AS n FROM user_credentials")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(remaining.n, 1);
        Ok(())
    }

    /// The fresh migration creates exactly the spinoff tables of section 9 and none of the
    /// removed Harbor tables.
    #[tokio::test]
    async fn migration_creates_exactly_the_spinoff_tables() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let tables = table_names(&pool).await?;
        let expected = [
            "alert_channels",
            "alert_deliveries",
            "audit_log",
            "cve_acceptances",
            "cve_findings",
            "github_issues",
            "hubs",
            "image_platforms",
            "image_sources",
            "images",
            "job_runs",
            "publish_reports",
            "scan_runs",
            "scanner_databases",
            "scanner_findings",
            "source_credentials",
            "sync_jobs",
            "system_config",
            "tag_observations",
            "user_credentials",
            "users",
        ];
        assert_eq!(tables, expected);
        Ok(())
    }

    /// Section 2: a default install has ghcr.io and docker.io, both of kind default.
    #[tokio::test]
    async fn default_hubs_are_seeded() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let rows: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT host, kind, pull_endpoint FROM hubs ORDER BY host")
                .fetch_all(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        assert_eq!(
            rows,
            vec![
                ("docker.io".to_owned(), "default".to_owned(), None),
                ("ghcr.io".to_owned(), "default".to_owned(), None),
            ]
        );
        Ok(())
    }

    /// Section 9: a database that holds `repo_mappings` is refused before the migrator runs,
    /// and no migration is applied to it.
    #[tokio::test]
    async fn legacy_repo_mappings_database_is_refused_before_migration() -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query("CREATE TABLE repo_mappings (id TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let refused = refuse_legacy(&pool).await;
        assert!(matches!(refused, Err(AppError::LegacyDatabase)));
        let names = table_names(&pool).await?;
        assert_eq!(names, vec!["repo_mappings".to_owned()], "no migration ran");
        assert_eq!(
            LEGACY_DATABASE_ERROR,
            "this database was created by HarborGate and cannot be used by this version"
        );
        Ok(())
    }

    /// `open` refuses a file that holds `repo_mappings` at pool open, before the spinoff
    /// schema is created in it.
    #[tokio::test]
    async fn open_refuses_a_legacy_file_and_creates_no_tables() -> Result<(), AppError> {
        let dir = std::env::temp_dir().join(format!("dockward-legacy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| AppError::InternalError)?;
        let legacy = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options(&database_path(&dir)))
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query("CREATE TABLE repo_mappings (id TEXT PRIMARY KEY)")
            .execute(&legacy)
            .await
            .map_err(|_| AppError::InternalError)?;
        legacy.close().await;

        let opened = open(&dir).await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(opened, Err(AppError::LegacyDatabase)));
        Ok(())
    }

    #[tokio::test]
    async fn file_database_uses_wal() -> Result<(), AppError> {
        let dir = std::env::temp_dir().join(format!("dockward-db-test-{}", std::process::id()));
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
