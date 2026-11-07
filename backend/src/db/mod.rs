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
pub mod findings;
pub mod github_issues;
pub mod job_runs;
pub mod key_rotation;
pub mod mappings;
pub mod picker_hidden;
pub mod project_webhooks;
pub mod retention;
#[allow(dead_code)] // Used by the scanner services added in later parts of #224.
pub mod scanner_reports;
#[allow(dead_code)] // Used by the setup and login services.
pub mod setup;
#[allow(dead_code)] // Used by the job worker and the retry route.
pub mod sync_jobs;
pub mod sync_reports;
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

    /// Migration 0005 rebuilds `project_webhooks` without the `rotated_at` default. Rows and
    /// their unmatched counts written under 0004 survive, and a new row has `rotated_at` NULL.
    #[tokio::test]
    async fn migration_0005_keeps_rows_and_drops_the_rotated_at_default() -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        let migrator = sqlx::migrate!("./migrations");
        migrator
            .run_to(4, &pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query(
            "INSERT INTO users (id, username, role, auth_provider)
             VALUES ('u1', 'u1', 'user', 'local')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        // Written under 0004, so rotated_at took the old default.
        sqlx::query(
            "INSERT INTO project_webhooks (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash)
             VALUES ('pw1', 'u1', 'https://harbor.example.com', 'proj', 'th', 'sh')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query(
            "INSERT INTO project_webhook_unmatched (project_webhook_id, repository, count, last_seen_at)
             VALUES ('pw1', 'proj/x', 3, 100)",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let (before,): (Option<i64>,) =
            sqlx::query_as("SELECT rotated_at FROM project_webhooks WHERE id = 'pw1'")
                .fetch_one(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;

        migrator
            .run(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;

        let (id, token_hash, rotated): (String, String, Option<i64>) = sqlx::query_as(
            "SELECT id, token_hash, rotated_at FROM project_webhooks WHERE id = 'pw1'",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!((id.as_str(), token_hash.as_str()), ("pw1", "th"));
        assert_eq!(rotated, before, "the existing value is copied unchanged");
        let (kept,): (i64,) = sqlx::query_as(
            "SELECT count FROM project_webhook_unmatched WHERE project_webhook_id = 'pw1'",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(kept, 3);
        sqlx::query(
            "INSERT INTO project_webhooks (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash)
             VALUES ('pw2', 'u1', 'https://harbor.example.com', 'proj2', 'th2', 'sh2')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let (fresh,): (Option<i64>,) =
            sqlx::query_as("SELECT rotated_at FROM project_webhooks WHERE id = 'pw2'")
                .fetch_one(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        assert_eq!(fresh, None);
        // The constraints survive: duplicate token and duplicate project are refused, and
        // deleting the user still cascades to the webhook and its counts.
        let dup_token = sqlx::query(
            "INSERT INTO project_webhooks (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash)
             VALUES ('pw3', 'u1', 'https://harbor.example.com', 'proj3', 'th', 'sh')",
        )
        .execute(&pool)
        .await;
        let dup_project = sqlx::query(
            "INSERT INTO project_webhooks (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash)
             VALUES ('pw4', 'u1', 'https://harbor.example.com', 'proj', 'th4', 'sh')",
        )
        .execute(&pool)
        .await;
        assert!(dup_token.is_err() && dup_project.is_err());
        sqlx::query("DELETE FROM users WHERE id = 'u1'")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let (left,): (i64,) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM project_webhooks) + (SELECT COUNT(*) FROM project_webhook_unmatched)",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(left, 0);
        Ok(())
    }

    /// Migration 0007 (#185) rebuilds `repo_mappings` without `UNIQUE (github_owner,
    /// github_repo)`. Rows written under 0006 and their child rows survive, a second mapping
    /// with the same GitHub target is accepted, and the Harbor uniqueness and the cascades
    /// still hold.
    #[tokio::test]
    async fn migration_0007_keeps_rows_and_drops_the_github_uniqueness() -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        let migrator = sqlx::migrate!("./migrations");
        migrator
            .run_to(6, &pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        seed_mapping(&pool).await?;
        let insert = |id: &'static str, harbor_repo: &'static str| {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
                 VALUES (?, 'user-1', 'cred-harbor', 'cred-gh', 'https://harbor.example.com', 'proj', ?, 'shared-owner', 'shared-repo', ?, 'sh')",
            )
            .bind(id)
            .bind(harbor_repo)
            .bind(format!("th-{id}"))
        };
        insert("mx1", "one")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        // Under 0006 the GitHub target is still unique.
        assert!(insert("mx2", "two").execute(&pool).await.is_err());
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, payload) VALUES ('job-1', 'mx1', '{}')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let (mappings_before,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_mappings")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;

        migrator
            .run(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;

        let (mappings_after,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_mappings")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(mappings_after, mappings_before, "every mapping row is kept");
        let (jobs,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sync_jobs")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(jobs, 1, "the rebuild did not cascade into child rows");
        let (fk,): (i64,) = sqlx::query_as("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(fk, 1, "foreign keys are back on");
        // The second GitHub target now succeeds; the Harbor duplicate is still refused.
        insert("mx2", "two")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert!(insert("mx3", "one").execute(&pool).await.is_err());
        // The cascade still works on the rebuilt table.
        sqlx::query("DELETE FROM repo_mappings WHERE id = 'mx1'")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let (jobs_left,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sync_jobs")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(jobs_left, 0);
        Ok(())
    }

    /// Migration 0008 (#191) gives every existing mapping the schedule off, and the CHECK
    /// constraints refuse values outside the allowed ranges.
    #[tokio::test]
    async fn migration_0008_turns_the_scan_schedule_off_for_existing_mappings()
    -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        let migrator = sqlx::migrate!("./migrations");
        migrator
            .run_to(7, &pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        seed_mapping(&pool).await?;
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
             VALUES ('m8', 'user-1', 'cred-harbor', 'cred-gh', 'https://harbor.example.com', 'proj', 'eight', 'o', 'r', 'th8', 'sh')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        migrator
            .run(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let (schedule, minute, weekday, last): (String, i64, i64, Option<i64>) = sqlx::query_as(
            "SELECT scan_schedule, scan_minute, scan_weekday, scan_last_slot FROM repo_mappings WHERE id = 'm8'",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(
            (schedule.as_str(), minute, weekday, last),
            ("off", 0, 1, None)
        );
        for bad in [
            "UPDATE repo_mappings SET scan_schedule = 'hourly' WHERE id = 'm8'",
            "UPDATE repo_mappings SET scan_minute = 1440 WHERE id = 'm8'",
            "UPDATE repo_mappings SET scan_weekday = 0 WHERE id = 'm8'",
        ] {
            assert!(sqlx::query(bad).execute(&pool).await.is_err(), "{bad}");
        }
        Ok(())
    }
}
