//! Tests of the `db_update` job against the real migrated schema. The scanners are shell scripts
//! that stand in for the pinned executables: they write the cache files and print the status
//! the real tools do (captured 2026-11-10 from Trivy v0.76.2 and Grype v0.121.2).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::SqlitePool;

use super::*;
use crate::db;
use crate::db::jobs::ClaimedJob;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A claimed `db_update` job for `payload`, on its first attempt.
fn test_job(payload: &str) -> ClaimedJob {
    ClaimedJob {
        id: "job-db-update".to_owned(),
        source_id: None,
        attempts: 0,
        payload: payload.to_owned(),
    }
}

/// 2026-11-10T13:03:09Z and one day later, as the `UpdatedAt` of Trivy's metadata.
const TRIVY_OLD: &str = "2026-11-10T13:03:09.93195248Z";
const TRIVY_NEW: &str = "2026-11-11T13:03:09.93195248Z";
const TRIVY_OLD_SECS: i64 = 1_794_315_789;
const TRIVY_NEW_SECS: i64 = TRIVY_OLD_SECS + 86_400;
/// The `built` time of `grype db status -o json`.
const GRYPE_BUILT: &str = "2026-11-10T06:21:20Z";
const GRYPE_BUILT_SECS: i64 = 1_794_291_680;

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
    env: ScanEnv,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write_script(path: &Path, body: &str) {
    if let Err(err) = std::fs::write(path, format!("#!/bin/sh\n{body}\n")) {
        panic!("script: {err}");
    }
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)) {
        panic!("chmod: {err}");
    }
}

async fn exec(pool: &SqlitePool, sql: &'static str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    if let Err(err) = query.execute(pool).await {
        panic!("test sql: {err}");
    }
}

async fn count(pool: &SqlitePool, sql: &'static str, binds: &[&str]) -> i64 {
    let mut query = sqlx::query_scalar::<_, i64>(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    match query.fetch_one(pool).await {
        Ok(n) => n,
        Err(err) => panic!("test count: {err}"),
    }
}

impl Fx {
    /// A fresh database and scanner scripts. Trivy's update writes `trivy_updated_at` into its
    /// metadata; Grype's `db status` prints `GRYPE_BUILT`. Each script appends its arguments and
    /// the cache variable it saw to `calls.log`.
    async fn new(name: &str, trivy_updated_at: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dockward-dbupdate-{name}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let bin = dir.join("bin");
        if let Err(err) = std::fs::create_dir_all(&bin) {
            panic!("dir: {err}");
        }
        let pool = match db::open(&dir).await {
            Ok(pool) => pool,
            Err(err) => panic!("db: {err:?}"),
        };
        let log = dir.join("calls.log");
        let trivy = bin.join("trivy");
        write_script(
            &trivy,
            &format!(
                "echo \"trivy $* cache=$TRIVY_CACHE_DIR\" >> '{log}'\n\
                 mkdir -p \"$TRIVY_CACHE_DIR/db\"\n\
                 printf '{{\"Version\":2,\"UpdatedAt\":\"{trivy_updated_at}\"}}' \
                 > \"$TRIVY_CACHE_DIR/db/metadata.json\"",
                log = log.display()
            ),
        );
        let grype = bin.join("grype");
        write_script(
            &grype,
            &format!(
                "echo \"grype $* cache=$GRYPE_DB_CACHE_DIR\" >> '{log}'\n\
                 if [ \"$1 $2\" = \"db status\" ]; then\n\
                 printf '{{\"schemaVersion\":\"v6.1.10\",\"built\":\"{GRYPE_BUILT}\",\"valid\":true}}'\n\
                 fi",
                log = log.display()
            ),
        );
        let env = ScanEnv::with_programs(dir.join("scanner-cache"), trivy, grype);
        Self { pool, dir, env }
    }

    async fn image(&self, id: &str) {
        exec(
            &self.pool,
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES (?, 'hub-default-ghcr', 'o/app', ?, 1)",
            &[id, &format!("sha256:i{id}")],
        )
        .await;
    }

    async fn platform(&self, id: &str, image: &str, state: &str) {
        exec(
            &self.pool,
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
             VALUES (?, ?, 'linux/amd64', ?, ?, 1)",
            &[id, image, &format!("sha256:{id}"), state],
        )
        .await;
    }

    async fn store_built_at(&self, scanner: &str, built_at: i64) {
        exec(
            &self.pool,
            "INSERT INTO scanner_databases (scanner, built_at, checked_at) VALUES (?, ?, 1)",
            &[scanner, &built_at.to_string()],
        )
        .await;
    }

    async fn run(&self, scanner: Scanner) -> JobOutcome {
        let payload = match DbUpdatePayload::new(scanner).to_text() {
            Ok(text) => text,
            Err(err) => panic!("payload: {err:?}"),
        };
        // The job the run is recorded for. A `job_runs` row links to it (migration 0004).
        // It is inserted here, so the tests that count jobs see only the rows they make.
        exec(
            &self.pool,
            "INSERT OR IGNORE INTO jobs (id, source_id, status, attempts, payload)
             VALUES ('job-db-update', NULL, 'running', 0, ?)",
            &[&payload],
        )
        .await;
        run_db_update(&self.pool, &self.env, &test_job(&payload)).await
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
    }

    async fn rescans(&self, scanner: &str) -> i64 {
        count(
            &self.pool,
            "SELECT COUNT(*) FROM scan_runs WHERE trigger = 'db_update' AND scanner = ?",
            &[scanner],
        )
        .await
    }
}

#[tokio::test]
async fn an_unchanged_database_queues_nothing() {
    let fx = Fx::new("unchanged", TRIVY_OLD).await;
    fx.image("a1").await;
    fx.platform("b1", "a1", "stored").await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));

    assert_eq!(fx.rescans("trivy").await, 0);
    // Only the db_update job the run records for exists; no scan job is queued.
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM jobs WHERE json_extract(payload, '$.kind') = 'scan'",
            &[]
        )
        .await,
        0
    );
}

#[tokio::test]
async fn a_newer_database_queues_one_rescan_per_stored_platform_image() {
    let fx = Fx::new("newer", TRIVY_NEW).await;
    fx.image("a1").await;
    fx.image("a2").await;
    fx.platform("b1", "a1", "stored").await;
    fx.platform("b2", "a2", "stored").await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));

    // One scan per stored image for the scanner whose database changed, and none for the other.
    assert_eq!(fx.rescans("trivy").await, 2);
    assert_eq!(fx.rescans("grype").await, 0);
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM jobs WHERE source_id IS NULL AND status = 'queued'
             AND payload LIKE '%\"scan\"%'",
            &[]
        )
        .await,
        2
    );
    // The new build time is stored in the same step.
    assert_eq!(
        count(
            &fx.pool,
            "SELECT built_at FROM scanner_databases WHERE scanner = 'trivy'",
            &[]
        )
        .await,
        TRIVY_NEW_SECS
    );
    // A second run of the same database queues nothing more.
    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));
    assert_eq!(fx.rescans("trivy").await, 2);
}

#[tokio::test]
async fn an_evicted_image_is_not_rescanned() {
    let fx = Fx::new("evicted", TRIVY_NEW).await;
    fx.image("a1").await;
    fx.platform("b1", "a1", "stored").await;
    fx.platform("b2", "a1", "evicted").await;
    fx.platform("b3", "a1", "failed").await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));

    assert_eq!(fx.rescans("trivy").await, 1);
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM scan_runs WHERE trigger = 'db_update' AND image_platform_id = 'b1'",
            &[]
        )
        .await,
        1
    );
}

#[tokio::test]
async fn the_first_grype_database_is_stored_and_rescans_through_its_status_time() {
    let fx = Fx::new("grype", TRIVY_OLD).await;
    fx.image("a1").await;
    fx.platform("b1", "a1", "stored").await;

    assert!(matches!(fx.run(Scanner::Grype).await, JobOutcome::Done));

    assert_eq!(fx.rescans("grype").await, 1);
    assert_eq!(fx.rescans("trivy").await, 0);
    assert_eq!(
        count(
            &fx.pool,
            "SELECT built_at FROM scanner_databases WHERE scanner = 'grype'",
            &[]
        )
        .await,
        GRYPE_BUILT_SECS
    );
}

#[tokio::test]
async fn a_refresh_records_a_db_update_job_run_and_uses_the_verified_commands() {
    let fx = Fx::new("record", TRIVY_NEW).await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));
    assert!(matches!(fx.run(Scanner::Grype).await, JobOutcome::Done));

    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM job_runs WHERE job_kind = 'db_update' AND status = 'done'
             AND error_summary IS NULL",
            &[]
        )
        .await,
        2
    );
    let calls = fx.calls();
    let cache = fx.dir.join("scanner-cache");
    assert!(calls.contains(&format!(
        "trivy image --download-db-only cache={}",
        cache.join("trivy").display()
    )));
    assert!(calls.contains("trivy image --download-java-db-only"));
    assert!(calls.contains(&format!(
        "grype db update cache={}",
        cache.join("grype").display()
    )));
}

#[tokio::test]
async fn a_failed_update_records_the_fixed_error_and_changes_nothing() {
    let fx = Fx::new("fail", TRIVY_NEW).await;
    fx.image("a1").await;
    fx.platform("b1", "a1", "stored").await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;
    // The scanner prints a secret-looking message to stderr and exits 1.
    write_script(
        &fx.dir.join("bin/trivy"),
        "echo 'token=secret-from-the-tool' 1>&2\nexit 1",
    );

    let outcome = fx.run(Scanner::Trivy).await;

    assert!(
        matches!(&outcome, JobOutcome::Failed(text) if text == "scanner failed"),
        "got {outcome:?}"
    );
    assert_eq!(fx.rescans("trivy").await, 0);
    assert_eq!(
        count(
            &fx.pool,
            "SELECT built_at FROM scanner_databases WHERE scanner = 'trivy'",
            &[]
        )
        .await,
        TRIVY_OLD_SECS,
        "the old database time is kept"
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM job_runs WHERE job_kind = 'db_update' AND status = 'failed'
             AND error_summary = 'scanner failed'",
            &[]
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_timeout_is_permanent_with_the_fixed_text() {
    let fx = Fx::new("timeout", TRIVY_NEW).await;
    exec(
        &fx.pool,
        "INSERT INTO system_config (key, value) VALUES ('scanner.timeout_s', '1')",
        &[],
    )
    .await;
    write_script(&fx.dir.join("bin/trivy"), "/bin/sleep 30");

    let outcome = fx.run(Scanner::Trivy).await;

    assert!(
        matches!(&outcome, JobOutcome::Permanent(text) if text == "scanner timed out"),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn a_run_records_the_scanner_it_refreshed() {
    let fx = Fx::new("run-scanner", TRIVY_NEW).await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));

    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM job_runs WHERE job_kind = 'db_update' AND scanner = 'trivy'",
            &[]
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_run_records_its_real_start_and_finish() {
    let fx = Fx::new("run-timing", TRIVY_NEW).await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;
    // The update takes at least a second, so the finish time must be later than the start.
    write_script(
        &fx.dir.join("bin/trivy"),
        &format!(
            "/bin/sleep 1.2\nmkdir -p \"$TRIVY_CACHE_DIR/db\"\n\
             printf '{{\"Version\":2,\"UpdatedAt\":\"{TRIVY_NEW}\"}}' \
             > \"$TRIVY_CACHE_DIR/db/metadata.json\""
        ),
    );

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));

    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM job_runs WHERE job_kind = 'db_update'
             AND finished_at > started_at",
            &[]
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_non_scanner_error_has_the_same_text_on_the_job_and_the_run() {
    let fx = Fx::new("non-scanner-error", TRIVY_NEW).await;
    // The update succeeds, then reading the stored build time fails inside the store.
    exec(&fx.pool, "DROP TABLE scanner_databases", &[]).await;

    let outcome = fx.run(Scanner::Trivy).await;

    // The job's last_error and the run's error_summary are the same fixed text.
    assert!(
        matches!(&outcome, JobOutcome::Failed(text) if text == "scanner failed"),
        "got {outcome:?}"
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM job_runs WHERE job_kind = 'db_update' AND status = 'failed'
             AND error_summary = 'scanner failed'",
            &[]
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_stored_timeout_is_clamped_to_the_settings_range() {
    let fx = Fx::new("clamp", TRIVY_NEW).await;
    for (stored, expected) in [("1", 10), ("999999", 86_400), ("600", 600)] {
        exec(
            &fx.pool,
            "INSERT OR REPLACE INTO system_config (key, value) VALUES ('scanner.timeout_s', ?)",
            &[stored],
        )
        .await;
        let limits = match process_limits(&SqlStoreRepository::new(fx.pool.clone())).await {
            Ok(limits) => limits,
            Err(err) => panic!("limits: {err:?}"),
        };
        assert_eq!(
            limits.timeout,
            Duration::from_secs(expected),
            "stored {stored}"
        );
    }
}

#[test]
fn the_child_sees_the_cache_path_and_no_secret() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => panic!("runtime: {err}"),
    };
    let fx = runtime.block_on(Fx::new("env", TRIVY_NEW));
    write_script(
        &fx.dir.join("bin/trivy"),
        &format!(
            "export -p > '{}/env.txt'\nmkdir -p \"$TRIVY_CACHE_DIR/db\"\n\
             printf '{{\"UpdatedAt\":\"{TRIVY_NEW}\"}}' > \"$TRIVY_CACHE_DIR/db/metadata.json\"",
            fx.dir.display()
        ),
    );
    let _guard = match crate::services::scanner::process::tests::ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poison) => poison.into_inner(),
    };
    // SAFETY: ENV_LOCK serialises environment access in this test binary; removed below.
    unsafe { std::env::set_var("DOCKWARD_ENCRYPTION_KEY", "canary-key-5d2") };

    let outcome = runtime.block_on(fx.run(Scanner::Trivy));

    // SAFETY: as above; the lock is still held.
    unsafe { std::env::remove_var("DOCKWARD_ENCRYPTION_KEY") };
    assert!(matches!(outcome, JobOutcome::Done), "got {outcome:?}");
    let listing = std::fs::read_to_string(fx.dir.join("env.txt")).unwrap_or_default();
    assert!(listing.contains("TRIVY_CACHE_DIR"));
    assert!(!listing.contains("canary-key-5d2"));
    assert!(!listing.contains("DOCKWARD_ENCRYPTION_KEY"));
    assert!(!listing.contains("PATH="));
}

#[tokio::test]
async fn a_bad_payload_fails_once_with_the_fixed_text() {
    let fx = Fx::new("payload", TRIVY_OLD).await;
    for payload in [
        "not json",
        r#"{"kind":"db_update"}"#,
        r#"{"kind":"db_update","scanner":"../etc"}"#,
    ] {
        let outcome = run_db_update(&fx.pool, &fx.env, &test_job(payload)).await;
        assert!(matches!(outcome, JobOutcome::Permanent(_)), "{payload}");
    }
    assert_eq!(fx.calls(), "", "no process starts for a bad payload");
}

#[tokio::test]
async fn the_schedule_queues_one_job_per_scanner_and_skips_an_open_one() {
    let fx = Fx::new("sched", TRIVY_OLD).await;

    assert_eq!(schedule_once(&fx.pool, 1_000).await.ok(), Some(2));
    // Both are still queued, so a second pass adds nothing.
    assert_eq!(schedule_once(&fx.pool, 2_000).await.ok(), Some(0));
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM jobs WHERE source_id IS NULL
             AND payload LIKE '%\"db_update\"%'",
            &[]
        )
        .await,
        2
    );
    // Once the jobs are done (or failed), the next pass queues them again.
    exec(&fx.pool, "UPDATE jobs SET status = 'done'", &[]).await;
    assert_eq!(schedule_once(&fx.pool, 3_000).await.ok(), Some(2));
    exec(&fx.pool, "UPDATE jobs SET status = 'failed'", &[]).await;
    assert_eq!(schedule_once(&fx.pool, 4_000).await.ok(), Some(2));
}

#[test]
fn the_interval_is_twenty_four_hours() {
    assert_eq!(INTERVAL, Duration::from_secs(24 * 60 * 60));
}

#[tokio::test(start_paused = true)]
async fn the_schedule_runs_once_per_twenty_four_hours() {
    use std::sync::atomic::AtomicUsize;

    let passes = Arc::new(AtomicUsize::new(0));
    let (stop_tx, stop_rx) = watch::channel(false);
    let counter = passes.clone();
    let task = tokio::spawn(run_every(FIRST_DELAY, INTERVAL, stop_rx, move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let seen = || passes.load(Ordering::SeqCst);

    // Nothing before the first delay.
    tokio::time::sleep(FIRST_DELAY - Duration::from_secs(1)).await;
    assert_eq!(seen(), 0);
    // The first pass runs at the first delay.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(seen(), 1);
    // Not again within the day.
    tokio::time::sleep(INTERVAL - Duration::from_secs(60)).await;
    assert_eq!(seen(), 1);
    // The next pass comes 24 hours after the first.
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(seen(), 2);
    // And one more a day later, never twice in a day.
    tokio::time::sleep(INTERVAL).await;
    assert_eq!(seen(), 3);

    let _ = stop_tx.send(true);
    let _ = task.await;
}

#[test]
fn the_build_time_is_read_from_each_scanners_own_document() {
    assert_eq!(
        parse_built_at(Scanner::Trivy, &format!(r#"{{"UpdatedAt":"{TRIVY_OLD}"}}"#)),
        Some(TRIVY_OLD_SECS)
    );
    assert_eq!(
        parse_built_at(Scanner::Grype, &format!(r#"{{"built":"{GRYPE_BUILT}"}}"#)),
        Some(GRYPE_BUILT_SECS)
    );
    assert_eq!(parse_built_at(Scanner::Trivy, r#"{"built":"x"}"#), None);
    assert_eq!(parse_built_at(Scanner::Grype, "not json"), None);
    assert_eq!(
        parse_built_at(Scanner::Trivy, r#"{"UpdatedAt":"yesterday"}"#),
        None
    );
}

/// Writes a step log for one scanner step: the steps that ran for the test job, with their
/// outcome text, read back from `job_log_steps`.
async fn step_outcomes(pool: &SqlitePool, job_id: &str) -> Vec<(i64, String, String)> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT seq, command, outcome FROM job_log_steps WHERE job_id = ? ORDER BY seq",
    )
    .bind(job_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    rows
}

#[tokio::test]
async fn a_trivy_update_records_one_step_per_download_with_its_command_and_outcome() {
    let fx = Fx::new("steps-ok", TRIVY_NEW).await;
    fx.store_built_at("trivy", TRIVY_OLD_SECS).await;

    assert!(matches!(fx.run(Scanner::Trivy).await, JobOutcome::Done));

    let steps = step_outcomes(&fx.pool, "job-db-update").await;
    assert_eq!(
        steps,
        vec![
            (
                0,
                "trivy image --download-db-only".to_owned(),
                "ok".to_owned()
            ),
            (
                1,
                "trivy image --download-java-db-only".to_owned(),
                "ok".to_owned()
            ),
        ]
    );
    // The job's latest attempt is the one the steps were written under (attempts 0 + 1).
    let attempts: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT attempt FROM job_log_steps WHERE job_id = 'job-db-update'",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap_or_default();
    assert_eq!(attempts, vec![1]);
}

#[tokio::test]
async fn a_failed_update_step_stores_its_stderr_tail_redacted_and_the_run_links_the_job() {
    let dir_marker = "robot:s3cret@registry.example.com";
    let fx = Fx::new("steps-fail", TRIVY_NEW).await;
    // Rewrite the trivy stub so the download fails and prints a credential on stderr.
    write_script(
        &fx.dir.join("bin").join("trivy"),
        &format!("echo 'pull https://{dir_marker}/db' >&2\nexit 1"),
    );

    let outcome = fx.run(Scanner::Trivy).await;
    assert!(matches!(outcome, JobOutcome::Failed(_)), "{outcome:?}");

    let outcome_text: String = sqlx::query_scalar(
        "SELECT outcome FROM job_log_steps WHERE job_id = 'job-db-update' AND seq = 0",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap_or_default();
    assert_eq!(outcome_text, "failed");

    let lines: Vec<String> = sqlx::query_scalar(
        "SELECT l.text FROM job_log_lines l JOIN job_log_steps s ON s.id = l.step_id
         WHERE s.job_id = 'job-db-update' AND s.seq = 0",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap_or_default();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("registry.example.com")),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains("s3cret")),
        "{lines:?}"
    );

    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM job_runs WHERE job_id = 'job-db-update' AND status = 'failed'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap_or_default();
    assert_eq!(linked, 1);
}

/// Reads the job's log the way `GET /jobs/:id/log` does, as an admin.
async fn log_of(pool: &SqlitePool) -> crate::services::job_log::JobLog {
    let query = crate::services::job_log::LogQuery::default();
    match crate::services::job_log::get(pool, "admin", true, "job-db-update", &query).await {
        Ok(log) => log,
        Err(err) => panic!("job log: {err:?}"),
    }
}

#[tokio::test]
async fn log_lines_carry_a_timestamp_and_the_scanner_name() {
    for (scanner, name) in [(Scanner::Trivy, "trivy"), (Scanner::Grype, "grype")] {
        let fx = Fx::new(&format!("log-meta-{name}"), TRIVY_NEW).await;
        write_script(
            &fx.dir.join("bin").join(name),
            &format!(
                "echo '{name} progress' >&2\necho \"{name} $*\" >> '{}'",
                fx.dir.join("calls.log").display()
            ),
        );
        // Grype's update is followed by a status read; its output is not JSON here, so the run
        // may fail after the update step. The step log is what this test reads.
        let _ = fx.run(scanner).await;

        let log = log_of(&fx.pool).await;
        assert_eq!(log.scanner.as_deref(), Some(name));
        assert!(!log.steps.is_empty(), "{name} has a step");
        assert!(
            log.steps.iter().all(|s| !s.started_at.is_empty()),
            "{:?}",
            log.steps
        );
        let progress: Vec<_> = log
            .lines
            .iter()
            .filter(|l| l.text == format!("{name} progress"))
            .collect();
        assert!(!progress.is_empty(), "{name} lines: {:?}", log.lines);
        for line in &log.lines {
            assert!(
                line.at.len() >= 20 && line.at.contains('T') && line.at.ends_with('Z'),
                "an RFC 3339 timestamp, got {:?}",
                line.at
            );
        }
        let stored_at: Vec<i64> = sqlx::query_scalar("SELECT at FROM job_log_lines")
            .fetch_all(&fx.pool)
            .await
            .unwrap_or_default();
        assert!(stored_at.iter().all(|at| *at > 0), "{stored_at:?}");
    }
}

#[tokio::test]
async fn log_output_is_capped_at_500_lines() {
    let fx = Fx::new("log-cap", TRIVY_NEW).await;
    write_script(
        &fx.dir.join("bin").join("trivy"),
        "i=0\nwhile [ $i -lt 650 ]; do echo \"line $i\" >&2; i=$((i+1)); done\nexit 1",
    );

    let outcome = fx.run(Scanner::Trivy).await;
    assert!(matches!(outcome, JobOutcome::Failed(_)), "{outcome:?}");

    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT l.text FROM job_log_lines l JOIN job_log_steps s ON s.id = l.step_id
         WHERE s.job_id = 'job-db-update' AND s.seq = 0 ORDER BY l.id",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap_or_default();
    assert_eq!(stored.len(), 500, "the stored tail is capped");
    assert_eq!(stored.last().map(String::as_str), Some("line 649"));
    assert_eq!(stored.first().map(String::as_str), Some("line 150"));
    let log = log_of(&fx.pool).await;
    assert!(log.steps[0].truncated, "the step is flagged truncated");
}
