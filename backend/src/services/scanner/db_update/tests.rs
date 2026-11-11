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

static COUNTER: AtomicU64 = AtomicU64::new(0);

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
        run_db_update(&self.pool, &self.env, &payload).await
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
    assert_eq!(count(&fx.pool, "SELECT COUNT(*) FROM jobs", &[]).await, 0);
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
        let outcome = run_db_update(&fx.pool, &fx.env, payload).await;
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
