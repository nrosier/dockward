//! Age-based retention (`specs/cve-lifecycle.md`, Retention). Every 24 hours, 5 minutes
//! after start, this worker deletes rows older than their limit. Each run is recorded in
//! `job_runs` with kind `retention`, and the successful run is audited as `retention.run`.
//!
//! The deletes and the audit row share one transaction. A failed run rolls back and is
//! recorded in `job_runs` as `failed`. `github_issues`, `cve_findings` and
//! `cve_acceptances` are never deleted here.

use std::time::Duration;

use serde_json::json;
use sqlx::{SqliteConnection, SqlitePool};
use tokio::sync::watch;

use crate::db::job_runs::{self, JobRun};
use crate::db::retention as retention_db;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::ids;
use crate::worker::now_secs;

const DAY: i64 = 86_400;
// The ages below are from `specs/cve-lifecycle.md` (Retention) and `specs/database.md`
// (Retention). A row whose timestamp is NULL is never deleted, because `NULL < cutoff`
// is not true in SQL.
/// Age limit for `sync_reports`: 90 days (`specs/cve-lifecycle.md` Retention).
const SYNC_REPORT_AGE: i64 = 90 * DAY;
/// Age limit for finished `jobs`: 90 days (`specs/cve-lifecycle.md` Retention,
/// `specs/database.md` Retention).
const JOB_AGE: i64 = 90 * DAY;
/// Age limit for `job_runs`: 90 days (`specs/database.md` Retention).
const JOB_RUN_AGE: i64 = 90 * DAY;
/// Age limit for `alert_deliveries`: 30 days (`specs/cve-lifecycle.md` Retention,
/// `specs/database.md` Retention).
const ALERT_DELIVERY_AGE: i64 = 30 * DAY;
/// Age limit for `audit_log`: 365 days (`specs/cve-lifecycle.md` Retention).
const AUDIT_LOG_AGE: i64 = 365 * DAY;

/// Delay before the first run after start.
const FIRST_RUN_DELAY: Duration = Duration::from_secs(300);
/// Time between runs.
const RUN_INTERVAL: Duration = Duration::from_secs(86_400);

/// Error text kept in `job_runs` for a failed run. It names no table, row, or value.
const FAILED_SUMMARY: &str = "retention deletes failed; no rows were removed";

/// Rows deleted per table in one run.
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    sync_reports: u64,
    jobs: u64,
    job_runs: u64,
    alert_deliveries: u64,
    audit_log: u64,
}

impl Counts {
    /// The sum of all tables. Refuses an overflow.
    fn total(&self) -> Result<u64, AppError> {
        [
            self.sync_reports,
            self.jobs,
            self.job_runs,
            self.alert_deliveries,
            self.audit_log,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, count| {
            sum.checked_add(count).ok_or(AppError::InternalError)
        })
    }

    /// The per-table counts for the audit `details`.
    fn details(&self) -> serde_json::Value {
        json!({
            "sync_reports": self.sync_reports,
            "sync_jobs": self.jobs,
            "job_runs": self.job_runs,
            "alert_deliveries": self.alert_deliveries,
            "audit_log": self.audit_log,
        })
    }
}

/// Runs one retention pass at `now` (Unix seconds). Returns the number of rows deleted.
/// On success the `job_runs` row is `done` and the audit row is written. On failure the
/// deletes roll back, a `failed` `job_runs` row is written, and the error is returned.
pub async fn run_once(pool: &SqlitePool, now: i64) -> Result<u64, AppError> {
    match delete_expired(pool, now).await {
        Ok(counts) => {
            let total = counts.total()?;
            let processed = i64::try_from(total).map_err(|_| AppError::InternalError)?;
            record_run(pool, now, "done", processed, None).await?;
            Ok(total)
        }
        Err(error) => {
            record_run(pool, now, "failed", 0, Some(FAILED_SUMMARY)).await?;
            Err(error)
        }
    }
}

/// Deletes the expired rows and writes the audit row in one transaction. Commits only
/// when every step succeeds.
async fn delete_expired(pool: &SqlitePool, now: i64) -> Result<Counts, AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    match delete_and_audit(&mut tx, now).await {
        Ok(counts) => {
            tx.commit().await.map_err(|_| AppError::InternalError)?;
            Ok(counts)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

async fn delete_and_audit(conn: &mut SqliteConnection, now: i64) -> Result<Counts, AppError> {
    let counts = Counts {
        sync_reports: retention_db::delete_sync_reports(conn, now - SYNC_REPORT_AGE).await?,
        jobs: retention_db::delete_jobs(conn, now - JOB_AGE).await?,
        job_runs: retention_db::delete_job_runs(conn, now - JOB_RUN_AGE).await?,
        alert_deliveries: retention_db::delete_alert_deliveries(conn, now - ALERT_DELIVERY_AGE)
            .await?,
        audit_log: retention_db::delete_audit_log(conn, now - AUDIT_LOG_AGE).await?,
    };
    audit::record(
        conn,
        &Actor::system(),
        "retention.run",
        "retention",
        Some(&counts.details()),
    )
    .await?;
    Ok(counts)
}

/// Appends one `retention` row to `job_runs`.
async fn record_run(
    pool: &SqlitePool,
    now: i64,
    status: &str,
    processed: i64,
    error_summary: Option<&str>,
) -> Result<(), AppError> {
    job_runs::insert(
        pool,
        &JobRun {
            id: ids::new_id()?,
            job_kind: "retention".to_owned(),
            started_at: now,
            // The real finish time, never before the start.
            finished_at: Some(now_secs().max(now)),
            status: status.to_owned(),
            processed_count: processed,
            error_summary: error_summary.map(str::to_owned),
            scanner: None,
        },
    )
    .await
}

/// Runs the retention pass 5 minutes after start and then every 24 hours, until `stop`
/// turns true. A pass that is running when the signal arrives finishes first.
pub async fn run(pool: SqlitePool, mut stop: watch::Receiver<bool>) {
    let mut delay = FIRST_RUN_DELAY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        match run_once(&pool, now_secs()).await {
            Ok(deleted) => tracing::info!(deleted, "retention run finished"),
            Err(error) => tracing::warn!(?error, "retention run failed"),
        }
        delay = RUN_INTERVAL;
    }
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;
    use crate::db;

    /// A fixed instant for the tests. Values are test-only.
    const NOW: i64 = 1_800_000_000;

    /// A migrated single-connection in-memory pool with foreign keys on.
    async fn test_pool() -> Result<SqlitePool, AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        db::migrate(&pool).await?;
        Ok(pool)
    }

    /// One user, two credentials, one mapping and one alert channel, so the rows under
    /// test have their parents. Test values only.
    async fn seed_parents(pool: &SqlitePool) -> Result<(), AppError> {
        for sql in [
            "INSERT INTO users (id, username, role, auth_provider)
             VALUES ('user-1', 'test-user', 'user', 'local')",
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('cred-gh', 'user-1', 'github', 'v1:test')",
            "INSERT INTO image_sources (
                id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('map-1', 'user-1', 'hub-default-ghcr', 'project/repo', '*', 'cred-gh',
                'owner', 'repo')",
            "INSERT INTO alert_channels (id, kind, config_encrypted, enabled)
             VALUES ('chan-1', 'webhook', 'v1:test', FALSE)",
        ] {
            sqlx::query(sql)
                .execute(pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        }
        Ok(())
    }

    async fn insert_sync_report(
        pool: &SqlitePool,
        id: &str,
        synced_at: i64,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO publish_reports (id, source_id, image_tag, image_digest,
                vulnerability_summary, sarif_status, synced_at)
             VALUES (?, 'map-1', 'v1', 'sha256:aa', '{}', 'success', ?)",
        )
        .bind(id)
        .bind(synced_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
    }

    async fn insert_job(
        pool: &SqlitePool,
        id: &str,
        status: &str,
        updated_at: i64,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, payload, updated_at)
             VALUES (?, 'map-1', ?, '{}', ?)",
        )
        .bind(id)
        .bind(status)
        .bind(updated_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
    }

    async fn insert_job_run(pool: &SqlitePool, id: &str, started_at: i64) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO job_runs (id, job_kind, started_at, status, processed_count)
             VALUES (?, 'discover', ?, 'done', 0)",
        )
        .bind(id)
        .bind(started_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
    }

    async fn insert_alert_delivery(
        pool: &SqlitePool,
        id: &str,
        sent_at: i64,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO alert_deliveries (id, channel_id, dedupe_key, sent_at)
             VALUES (?, 'chan-1', ?, ?)",
        )
        .bind(id)
        .bind(id)
        .bind(sent_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
    }

    async fn insert_audit(pool: &SqlitePool, id: &str, created_at: i64) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO audit_log (id, actor_username, action, target, created_at)
             VALUES (?, 'test-user', 'user.create', 'user:x', ?)",
        )
        .bind(id)
        .bind(created_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| AppError::InternalError)
    }

    /// How many rows with this id the given `SELECT COUNT(*)` finds.
    async fn count(pool: &SqlitePool, sql: &'static str, id: &str) -> Result<i64, AppError> {
        sqlx::query_scalar::<_, i64>(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|_| AppError::InternalError)
    }

    #[tokio::test]
    async fn rows_on_each_side_of_every_boundary() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_parents(&pool).await?;
        // Each table gets one row 1 s older than its limit and one row 1 s newer.
        insert_sync_report(&pool, "sync_reports-old", NOW - SYNC_REPORT_AGE - 1).await?;
        insert_sync_report(&pool, "sync_reports-new", NOW - SYNC_REPORT_AGE + 1).await?;
        insert_job_done(&pool, "jobs-old", NOW - JOB_AGE - 1).await?;
        insert_job_done(&pool, "jobs-new", NOW - JOB_AGE + 1).await?;
        insert_job_run(&pool, "job_runs-old", NOW - JOB_RUN_AGE - 1).await?;
        insert_job_run(&pool, "job_runs-new", NOW - JOB_RUN_AGE + 1).await?;
        insert_alert_delivery(&pool, "alert_deliveries-old", NOW - ALERT_DELIVERY_AGE - 1).await?;
        insert_alert_delivery(&pool, "alert_deliveries-new", NOW - ALERT_DELIVERY_AGE + 1).await?;
        insert_audit(&pool, "audit_log-old", NOW - AUDIT_LOG_AGE - 1).await?;
        insert_audit(&pool, "audit_log-new", NOW - AUDIT_LOG_AGE + 1).await?;

        run_once(&pool, NOW).await?;

        let checks = [
            (
                "sync_reports",
                "SELECT COUNT(*) FROM publish_reports WHERE id = ?",
            ),
            ("jobs", "SELECT COUNT(*) FROM jobs WHERE id = ?"),
            ("job_runs", "SELECT COUNT(*) FROM job_runs WHERE id = ?"),
            (
                "alert_deliveries",
                "SELECT COUNT(*) FROM alert_deliveries WHERE id = ?",
            ),
            ("audit_log", "SELECT COUNT(*) FROM audit_log WHERE id = ?"),
        ];
        for (table, sql) in checks {
            let old = count(&pool, sql, &format!("{table}-old")).await?;
            let new = count(&pool, sql, &format!("{table}-new")).await?;
            assert_eq!(old, 0, "{table}: the row 1 s older than the limit was kept");
            assert_eq!(
                new, 1,
                "{table}: the row 1 s newer than the limit was deleted"
            );
        }
        pool.close().await;
        Ok(())
    }

    /// `jobs` rows in `done` for the boundary test. Queued and running rows are
    /// covered by the next test.
    async fn insert_job_done(pool: &SqlitePool, id: &str, updated_at: i64) -> Result<(), AppError> {
        insert_job(pool, id, "done", updated_at).await
    }

    #[tokio::test]
    async fn a_row_at_exactly_the_cutoff_is_kept() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_parents(&pool).await?;
        insert_sync_report(&pool, "sync_reports-edge", NOW - SYNC_REPORT_AGE).await?;
        insert_job(&pool, "jobs-edge", "done", NOW - JOB_AGE).await?;
        insert_job_run(&pool, "job_runs-edge", NOW - JOB_RUN_AGE).await?;
        insert_alert_delivery(&pool, "alert_deliveries-edge", NOW - ALERT_DELIVERY_AGE).await?;
        insert_audit(&pool, "audit_log-edge", NOW - AUDIT_LOG_AGE).await?;

        run_once(&pool, NOW).await?;

        let checks = [
            (
                "sync_reports",
                "SELECT COUNT(*) FROM publish_reports WHERE id = ?",
            ),
            ("jobs", "SELECT COUNT(*) FROM jobs WHERE id = ?"),
            ("job_runs", "SELECT COUNT(*) FROM job_runs WHERE id = ?"),
            (
                "alert_deliveries",
                "SELECT COUNT(*) FROM alert_deliveries WHERE id = ?",
            ),
            ("audit_log", "SELECT COUNT(*) FROM audit_log WHERE id = ?"),
        ];
        for (table, sql) in checks {
            let edge = count(&pool, sql, &format!("{table}-edge")).await?;
            assert_eq!(edge, 1, "{table}: a row exactly at the cutoff was deleted");
        }
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_job_keeps_its_report_with_a_null_job_id() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_parents(&pool).await?;
        insert_job(&pool, "job-old", "done", NOW - JOB_AGE - 1).await?;
        // The report is recent, so only the job is expired.
        insert_sync_report(&pool, "report-recent", NOW).await?;
        sqlx::query("UPDATE publish_reports SET job_id = 'job-old' WHERE id = 'report-recent'")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;

        run_once(&pool, NOW).await?;

        let jobs = count(&pool, "SELECT COUNT(*) FROM jobs WHERE id = ?", "job-old").await?;
        assert_eq!(jobs, 0, "the expired job was kept");
        let linked = count(
            &pool,
            "SELECT COUNT(*) FROM publish_reports WHERE id = ? AND job_id IS NULL",
            "report-recent",
        )
        .await?;
        assert_eq!(
            linked, 1,
            "the report was deleted or still points at the job"
        );
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn queued_and_running_jobs_are_never_deleted() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_parents(&pool).await?;
        // Far older than the limit, so only the status can keep them.
        let long_ago = NOW - JOB_AGE - DAY;
        insert_job(&pool, "job-queued", "queued", long_ago).await?;
        insert_job(&pool, "job-running", "running", long_ago).await?;
        insert_job(&pool, "job-done", "done", long_ago).await?;
        insert_job(&pool, "job-failed", "failed", long_ago).await?;

        run_once(&pool, NOW).await?;

        let sql = "SELECT COUNT(*) FROM jobs WHERE id = ?";
        assert_eq!(
            count(&pool, sql, "job-queued").await?,
            1,
            "a queued job was deleted"
        );
        assert_eq!(
            count(&pool, sql, "job-running").await?,
            1,
            "a running job was deleted"
        );
        assert_eq!(
            count(&pool, sql, "job-done").await?,
            0,
            "an old done job was kept"
        );
        assert_eq!(
            count(&pool, sql, "job-failed").await?,
            0,
            "an old failed job was kept"
        );
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn run_is_recorded_in_job_runs_and_audit() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_parents(&pool).await?;
        insert_sync_report(&pool, "sync_reports-old", NOW - SYNC_REPORT_AGE - 1).await?;

        let deleted = run_once(&pool, NOW).await?;
        assert_eq!(deleted, 1, "run_once returned the wrong total");

        let runs: Vec<(String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT job_kind, status, processed_count, error_summary
             FROM job_runs WHERE job_kind = 'retention'",
        )
        .fetch_all(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(
            runs,
            vec![("retention".to_owned(), "done".to_owned(), 1, None)],
            "job_runs did not record one done retention run"
        );

        let audits: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT actor_username, actor_user_id, details
             FROM audit_log WHERE action = 'retention.run'",
        )
        .fetch_all(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(audits.len(), 1, "expected one retention.run audit row");
        let (username, user_id, details) = &audits[0];
        assert_eq!(username, "system");
        assert_eq!(user_id, &None);
        let details: serde_json::Value =
            serde_json::from_str(details.as_deref().ok_or(AppError::InternalError)?)
                .map_err(|_| AppError::InternalError)?;
        assert_eq!(details["sync_reports"], 1);
        assert_eq!(details["audit_log"], 0);
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn failure_rolls_back_and_records_failed() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_parents(&pool).await?;
        // The sync_reports delete runs first and would succeed. The audit_log delete runs
        // last, and this trigger makes it fail, so the run must roll back.
        insert_sync_report(&pool, "sync_reports-old", NOW - SYNC_REPORT_AGE - 1).await?;
        insert_audit(&pool, "audit_log-old", NOW - AUDIT_LOG_AGE - 1).await?;
        sqlx::query(
            "CREATE TRIGGER retention_test_block_audit_delete BEFORE DELETE ON audit_log
             BEGIN SELECT RAISE(ABORT, 'blocked for test'); END",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;

        let result = run_once(&pool, NOW).await;
        assert!(
            result.is_err(),
            "a failing delete was reported as a success"
        );

        let kept = count(
            &pool,
            "SELECT COUNT(*) FROM publish_reports WHERE id = ?",
            "sync_reports-old",
        )
        .await?;
        assert_eq!(kept, 1, "the earlier delete was not rolled back");

        let runs: Vec<(String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT job_kind, status, processed_count, error_summary
             FROM job_runs WHERE job_kind = 'retention'",
        )
        .fetch_all(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(
            runs,
            vec![(
                "retention".to_owned(),
                "failed".to_owned(),
                0,
                Some(FAILED_SUMMARY.to_owned())
            )],
            "job_runs did not record one failed retention run"
        );

        let audited = count(
            &pool,
            "SELECT COUNT(*) FROM audit_log WHERE action = ?",
            "retention.run",
        )
        .await?;
        assert_eq!(audited, 0, "a failed run wrote a retention.run audit row");
        pool.close().await;
        Ok(())
    }
}
