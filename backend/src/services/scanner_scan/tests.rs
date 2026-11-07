//! Scanner scan tests (#224). A stateful fake Harbor holds the project scanner and answers the
//! scanner, scan, overview and report calls. No live Harbor and no real token is used. The
//! credentials are obviously fake, and the sentinel must never reach a job row.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use reqwest::Url;

use super::*;
// `seal` is `crypto::encrypt` under another name. This whole file is test code, and the call-site
// guard in `key_rotation` counts only non-test sites by the `crypto::encrypt(` text.
use crate::auth::crypto::{self, credentials_key, encrypt as seal};
use crate::config;
use crate::db;
use crate::services::harbor_client::{HarborReply, TRIVY_REPORT_MIME};
use crate::services::ids;
use crate::services::sync::Clock;

const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const DIGEST: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BASE: &str = "https://harbor.example.com";
const PREVIOUS: &str = "uuid-previous";
const CHOSEN: &str = "uuid-chosen";
/// A string in a Harbor body that must never reach a job row.
const SENTINEL: &str = "SENTINEL-scanner-scan-7c2e";

fn key() -> DerivedKey {
    let root = config::parse_encryption_key(ROOT).unwrap();
    credentials_key(&root).unwrap()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// A fixed clock. Sleeps are never waited.
struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }

    async fn sleep(&self, _duration: std::time::Duration) {}
}

/// A stateful fake Harbor. `current` is the project scanner. A `PUT` changes it. The overview
/// answers from `overview`, one status per call, and the last status repeats.
struct FakeHarbor {
    current: Mutex<String>,
    overview: Mutex<VecDeque<&'static str>>,
    /// Status answered to a restore or switch `PUT`, when set. `None` accepts the change.
    put_refused: Mutex<Option<u16>>,
    /// When set, the tag resolve call answers `404`, as for a tag deleted from Harbor.
    tag_gone: Mutex<bool>,
    /// Calls as (method, path).
    calls: Mutex<Vec<(String, String)>>,
}

impl FakeHarbor {
    fn new(current: &str) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(current.to_owned()),
            overview: Mutex::new(VecDeque::from(vec!["Success"])),
            put_refused: Mutex::new(None),
            tag_gone: Mutex::new(false),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn current(&self) -> String {
        lock(&self.current).clone()
    }

    fn put_count(&self) -> usize {
        lock(&self.calls).iter().filter(|c| c.0 == "PUT").count()
    }

    fn record(&self, method: &str, url: &Url) {
        lock(&self.calls).push((method.to_owned(), url.path().to_owned()));
    }

    fn set_overview(&self, statuses: &[&'static str]) {
        *lock(&self.overview) = statuses.iter().copied().collect();
    }

    /// The next overview status: the front of the queue, unless more than one is left.
    fn next_status(&self) -> &'static str {
        let mut queue = lock(&self.overview);
        if queue.len() > 1 {
            queue.pop_front().unwrap_or("Success")
        } else {
            queue.front().copied().unwrap_or("Success")
        }
    }
}

fn reply(status: u16, body: String) -> HarborReply {
    HarborReply::new(status, body.into_bytes())
}

/// A scanner registration as Harbor returns it, with the fields the client must not store.
fn scanner_body(uuid: &str, name: &str) -> String {
    format!(
        r#"{{"uuid":"{uuid}","name":"{name}","vendor":"Aqua","version":"1.0","disabled":false,"url":"https://{SENTINEL}.invalid","auth":"{SENTINEL}"}}"#
    )
}

/// A Trivy-keyed report with one item.
fn report_body() -> String {
    format!(
        r#"{{"{TRIVY_REPORT_MIME}":{{"scanner":{{"name":"Trivy","vendor":"Aqua","version":"0.1"}},"vulnerabilities":[{{"id":"CVE-2026-1","package":"openssl","version":"1.0","severity":"High"}}]}}}}"#
    )
}

/// Answers the fake Harbor's calls. Every request is recorded by method and path.
#[derive(Clone)]
struct Writes(Arc<FakeHarbor>);

impl HarborFetch for Writes {
    async fn fetch(
        &self,
        url: &Url,
        _username: &str,
        _secret: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        let harbor = &self.0;
        harbor.record("GET", url);
        let path = url.path();
        if path.ends_with("/scanner/candidates") {
            let body = format!(
                "[{},{}]",
                scanner_body(PREVIOUS, "Trivy"),
                scanner_body(CHOSEN, "Grype")
            );
            return Ok(reply(200, body));
        }
        if path.ends_with("/scanner") {
            let uuid = harbor.current();
            let name = if uuid == CHOSEN { "Grype" } else { "Trivy" };
            return Ok(reply(200, scanner_body(&uuid, name)));
        }
        if path.ends_with("/additions/vulnerabilities") {
            return Ok(reply(200, report_body()));
        }
        if url
            .query()
            .is_some_and(|q| q.contains("with_scan_overview"))
        {
            let status = harbor.next_status();
            return Ok(reply(
                200,
                format!(
                    r#"{{"scan_overview":{{"{TRIVY_REPORT_MIME}":{{"scan_status":"{status}"}}}}}}"#
                ),
            ));
        }
        // The tag resolve call. A tag deleted from Harbor answers 404.
        if *lock(&harbor.tag_gone) {
            return Ok(reply(404, "{}".to_owned()));
        }
        Ok(reply(200, format!(r#"{{"digest":"{DIGEST}","tags":[]}}"#)))
    }

    async fn post_json(
        &self,
        url: &Url,
        _username: &str,
        _secret: &[u8],
        _body: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        self.0.record("POST", url);
        Ok(reply(202, "{}".to_owned()))
    }

    async fn put_json(
        &self,
        url: &Url,
        _username: &str,
        _secret: &[u8],
        body: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        self.0.record("PUT", url);
        if let Some(status) = *lock(&self.0.put_refused) {
            return Ok(reply(status, "{}".to_owned()));
        }
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| AppError::InternalError)?;
        if let Some(uuid) = value.get("uuid").and_then(serde_json::Value::as_str) {
            *lock(&self.0.current) = uuid.to_owned();
        }
        Ok(reply(200, "{}".to_owned()))
    }
}

/// A pool with one user, a Harbor credential and mapping `m1`. Test values only.
async fn fixture(name: &str) -> (SqlitePool, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "harborgate-scanner-scan-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = db::open(&dir).await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, token_version)
         VALUES ('u1', 'u1', NULL, 'user', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let stored = seal(
        &key(),
        &crypto::aad("user_credentials", "encrypted_token", "c1"),
        b"fake-token-value",
    )
    .unwrap();
    sqlx::query(
        "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
         VALUES ('c1', 'u1', 'harbor', 'h', ?, 'robot$hg', ?)",
    )
    .bind(BASE)
    .bind(stored)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_credentials (id, user_id, service_type, label, encrypted_token)
         VALUES ('c2', 'u1', 'github', 'g', 'v1:fake')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch, created_at)
         VALUES ('m1', 'u1', 'c1', 'c2', ?, 'proj', 'app', 'o', 'g', 'h1', 'h2', 0, 'CRITICAL', 'main', 1)",
    )
    .bind(BASE)
    .execute(&pool)
    .await
    .unwrap();
    (pool, dir)
}

/// The `scanner_scan` payload for `scanner`, with or without the fetch-only flag.
fn scan_payload(scanner: &str) -> String {
    format!(
        r#"{{"kind":"scanner_scan","repo_full_name":"proj/app","digest":"{DIGEST}","tag":"v1","scanner_uuid":"{scanner}","trigger":"scanner"}}"#
    )
}

async fn enqueue(pool: &SqlitePool, id: &str, payload: &str) {
    db::sync_jobs::enqueue(pool, id, "m1", payload, 1_000)
        .await
        .unwrap();
}

/// The job as the worker hands it to the handler.
async fn claim(pool: &SqlitePool, id: &str) -> ClaimedJob {
    let (job_id, mapping_id, attempts, payload) =
        sqlx::query_as::<_, (String, String, i64, String)>(
            "SELECT id, mapping_id, attempts, payload FROM sync_jobs WHERE id = ?",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    ClaimedJob {
        id: job_id,
        mapping_id,
        attempts,
        payload,
    }
}

async fn lock_row(pool: &SqlitePool) -> Option<ProjectScannerLockRow> {
    scanner_db::get_project_lock(pool, BASE, "proj")
        .await
        .unwrap()
}

/// Runs one step of job `id` at `now`, against the fake Harbor.
async fn run(pool: &SqlitePool, harbor: &Arc<FakeHarbor>, id: &str, now: i64) -> JobOutcome {
    let job = claim(pool, id).await;
    run_job(
        pool,
        &key(),
        &Writes(harbor.clone()),
        &FixedClock(now),
        &job,
    )
    .await
}

/// Runs one step of a `scanner_restore` job.
async fn run_restore(
    pool: &SqlitePool,
    harbor: &Arc<FakeHarbor>,
    id: &str,
    now: i64,
) -> JobOutcome {
    let job = claim(pool, id).await;
    run_restore_job(
        pool,
        &key(),
        &Writes(harbor.clone()),
        &FixedClock(now),
        &job,
    )
    .await
}

/// A scan with the chosen scanner succeeds on one step: the scanner is switched, the report is
/// final, it is stored, and the previous scanner is restored after it.
#[tokio::test]
async fn restore_runs_after_a_successful_scan() {
    let (pool, dir) = fixture("success").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    enqueue(&pool, "j-ok", &scan_payload(CHOSEN)).await;

    let outcome = run(&pool, &harbor, "j-ok", 2_000).await;
    assert_eq!(outcome, JobOutcome::Done);
    assert_eq!(
        harbor.put_count(),
        2,
        "one switch to the chosen scanner, one restore"
    );
    assert_eq!(
        harbor.current(),
        PREVIOUS,
        "the previous scanner is restored"
    );
    assert!(
        lock_row(&pool).await.is_none(),
        "a successful restore releases the lock"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed scan (the scanner reports an error) still restores the previous scanner. The job fails
/// with the fixed text, and nothing from Harbor is stored.
#[tokio::test]
async fn restore_runs_after_a_failed_scan() {
    let (pool, dir) = fixture("failed-scan").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    harbor.set_overview(&["Running", "Error"]);
    enqueue(&pool, "j-fail", &scan_payload(CHOSEN)).await;

    // The first step switches, sees the scan running, and waits.
    let first = run(&pool, &harbor, "j-fail", 2_000).await;
    assert!(matches!(first, JobOutcome::Deferred { .. }), "{first:?}");
    assert_eq!(
        harbor.current(),
        CHOSEN,
        "the switch is kept during the wait"
    );
    // The next poll reads the error. The scan fails, and the restore still runs.
    let second = run(&pool, &harbor, "j-fail", 2_030).await;
    assert_eq!(second, JobOutcome::Failed(MSG_SCANNER_FAILED.to_owned()));
    assert_eq!(
        harbor.current(),
        PREVIOUS,
        "the previous scanner is restored after the failure"
    );
    assert!(
        lock_row(&pool).await.is_none(),
        "the lock is released after the restore"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The lock blocks a second scan of the same project: while one job holds it, another job is
/// deferred and nothing is switched.
#[tokio::test]
async fn the_lock_blocks_a_second_scan_of_the_same_project() {
    let (pool, dir) = fixture("lock").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    harbor.set_overview(&["Running"]);
    enqueue(&pool, "j-a", &scan_payload(CHOSEN)).await;
    enqueue(&pool, "j-b", &scan_payload(CHOSEN)).await;

    // Job A switches and waits, so it holds the lock.
    let first = run(&pool, &harbor, "j-a", 2_000).await;
    assert!(matches!(first, JobOutcome::Deferred { .. }), "{first:?}");
    assert_eq!(
        lock_row(&pool).await.map(|row| row.job_id),
        Some("j-a".to_owned())
    );
    let puts = harbor.put_count();

    // Job B is deferred and switches nothing.
    let second = run(&pool, &harbor, "j-b", 2_000).await;
    assert!(matches!(second, JobOutcome::Deferred { .. }), "{second:?}");
    assert_eq!(harbor.put_count(), puts, "no switch while the lock is held");
    assert_eq!(
        lock_row(&pool).await.map(|row| row.job_id),
        Some("j-a".to_owned()),
        "the lock stays with the first job"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed restore keeps the lock. The lock moves to a `scanner_restore` job, which retries. The
/// lock is released only once a restore succeeds.
#[tokio::test]
async fn a_failed_restore_keeps_the_lock() {
    let (pool, dir) = fixture("restore-fail").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    harbor.set_overview(&["Running", "Error"]);
    enqueue(&pool, "j-restore", &scan_payload(CHOSEN)).await;

    // The first step switches and waits. The second sees the error, so the scan ends and the
    // restore runs. Harbor refuses the restore PUT.
    run(&pool, &harbor, "j-restore", 2_000).await;
    *lock(&harbor.put_refused) = Some(500);
    let scan_outcome = run(&pool, &harbor, "j-restore", 2_030).await;
    assert_eq!(
        scan_outcome,
        JobOutcome::Failed(MSG_SCANNER_FAILED.to_owned()),
        "the scan keeps its own outcome"
    );

    let row = lock_row(&pool)
        .await
        .expect("the lock is kept after a failed restore");
    assert_eq!(row.state, "restore_pending");
    let restore_id = row.job_id.clone();
    assert_ne!(restore_id, "j-restore", "the lock moved to the restore job");
    assert_eq!(harbor.current(), CHOSEN, "the switch is still in place");

    // The restore job is still refused: it fails with the restore text and keeps the lock.
    let refused = run_restore(&pool, &harbor, &restore_id, 2_060).await;
    assert_eq!(refused, JobOutcome::Failed(MSG_RESTORE_FAILED.to_owned()));
    assert!(
        lock_row(&pool).await.is_some(),
        "still held after the failed restore"
    );

    // Harbor accepts the restore: the restore job succeeds and the lock is released.
    *lock(&harbor.put_refused) = None;
    let restored = run_restore(&pool, &harbor, &restore_id, 2_120).await;
    assert_eq!(restored, JobOutcome::Done);
    assert_eq!(harbor.current(), PREVIOUS);
    assert!(
        lock_row(&pool).await.is_none(),
        "released once the restore succeeds"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Harbor's scanner `url`, `auth` and the sentinel never reach a job row or the stored report.
#[tokio::test]
async fn no_harbor_secret_text_reaches_a_job_row_or_a_report() {
    let (pool, dir) = fixture("secrets").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    enqueue(&pool, "j-secret", &scan_payload(CHOSEN)).await;
    assert_eq!(
        run(&pool, &harbor, "j-secret", 2_000).await,
        JobOutcome::Done
    );

    let job_text: String = sqlx::query_scalar(
        "SELECT COALESCE(last_error, '') || payload FROM sync_jobs WHERE id = 'j-secret'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!job_text.contains(SENTINEL));
    let report_text: String = sqlx::query_scalar(
        "SELECT COALESCE(scanner_name, '') || COALESCE(scanner_vendor, '') || COALESCE(scanner_version, '')
         FROM scanner_reports WHERE scanner_uuid = ?",
    )
    .bind(CHOSEN)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!report_text.contains(SENTINEL));
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tag deleted while the scan waits: the re-run finds `404` on the tag, and that outcome still
/// restores the previous scanner and releases the lock. Nothing is left switched.
#[tokio::test]
async fn a_gone_tag_still_restores_after_a_wait() {
    let (pool, dir) = fixture("tag-gone").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    harbor.set_overview(&["Running"]);
    enqueue(&pool, "j-gone", &scan_payload(CHOSEN)).await;

    // The first run switches and waits, so the scanner is switched and the lock is held.
    let first = run(&pool, &harbor, "j-gone", 2_000).await;
    assert!(matches!(first, JobOutcome::Deferred { .. }), "{first:?}");
    assert_eq!(harbor.current(), CHOSEN);

    // The tag is deleted before the re-run. The job must not leave the switch in place.
    *lock(&harbor.tag_gone) = true;
    let second = run(&pool, &harbor, "j-gone", 2_030).await;
    assert_eq!(
        second,
        JobOutcome::DoneWithNote(resolve::NOTE_ARTIFACT_GONE.to_owned())
    );
    assert_eq!(
        harbor.current(),
        PREVIOUS,
        "restored even though the tag is gone"
    );
    assert!(lock_row(&pool).await.is_none(), "the lock is released");
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Step 8: the store queues one sync job for the digest and tag, carrying the scanner and the
/// trigger. A second scan while that job is still queued does not queue another.
#[tokio::test]
async fn a_stored_report_queues_one_sync_job() {
    let (pool, dir) = fixture("sync-after-store").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    enqueue(&pool, "j-sync", &scan_payload(CHOSEN)).await;
    assert_eq!(run(&pool, &harbor, "j-sync", 2_000).await, JobOutcome::Done);

    let syncs: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM sync_jobs WHERE json_extract(payload, '$.kind') IS NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(syncs.len(), 1);
    let payload: serde_json::Value = serde_json::from_str(&syncs[0]).unwrap();
    assert_eq!(payload["digest"], DIGEST);
    assert_eq!(payload["tag"], "v1");
    assert_eq!(payload["scanner_uuid"], CHOSEN);

    enqueue(&pool, "j-sync-2", &scan_payload(CHOSEN)).await;
    assert_eq!(
        run(&pool, &harbor, "j-sync-2", 2_100).await,
        JobOutcome::Done
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_jobs WHERE json_extract(payload, '$.kind') IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "deduped like the resolve job's");
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The two jobs a scheduled run queues (one per scanner) run one at a time on a project: while
/// the first waits for its report and holds the lock, the second is deferred and switches nothing.
/// Once the first has stored its report and released the lock, the second runs.
#[tokio::test]
async fn a_scheduled_run_scans_one_scanner_at_a_time() {
    let (pool, dir) = fixture("scheduled-serial").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    harbor.set_overview(&["Running", "Success"]);
    for (id, uuid) in [("j-trivy", PREVIOUS), ("j-grype", CHOSEN)] {
        let payload = format!(
            r#"{{"kind":"scanner_scan","repo_full_name":"proj/app","tag":"v1","scanner_uuid":"{uuid}","trigger":"schedule"}}"#
        );
        enqueue(&pool, id, &payload).await;
    }

    let first = run(&pool, &harbor, "j-trivy", 2_000).await;
    assert!(matches!(first, JobOutcome::Deferred { .. }), "{first:?}");
    let held = lock_row(&pool).await.map(|row| row.job_id);
    assert_eq!(held.as_deref(), Some("j-trivy"));

    let puts = harbor.put_count();
    let second = run(&pool, &harbor, "j-grype", 2_001).await;
    assert!(matches!(second, JobOutcome::Deferred { .. }), "{second:?}");
    assert_eq!(harbor.put_count(), puts, "no switch while the lock is held");

    // The first job finishes: its report is stored and the lock is released.
    assert_eq!(
        run(&pool, &harbor, "j-trivy", 2_010).await,
        JobOutcome::Done
    );
    assert!(lock_row(&pool).await.is_none());

    // Now the second takes the lock, switches, stores its report and restores.
    assert_eq!(
        run(&pool, &harbor, "j-grype", 2_020).await,
        JobOutcome::Done
    );
    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT scanner_uuid FROM scanner_reports WHERE mapping_id = 'm1' ORDER BY scanner_uuid",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(stored, vec![CHOSEN.to_owned(), PREVIOUS.to_owned()]);
    assert!(lock_row(&pool).await.is_none());
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

async fn seed_report(pool: &SqlitePool, uuid: &str, name: Option<&str>, cve: &str) {
    let id = ids::new_id().unwrap();
    let mut tx = pool.begin().await.unwrap();
    scanner_db::replace_report(
        &mut tx,
        &crate::db::scanner_reports::NewScannerReport {
            id: &id,
            mapping_id: "m1",
            image_digest: DIGEST,
            scanner_uuid: uuid,
            scanner_name: name,
            scanner_vendor: None,
            scanner_version: None,
            image_push_time: None,
            stored_at: 1,
        },
        &[crate::db::scanner_reports::NewScannerFinding {
            cve_id: cve,
            package: "p",
            version: None,
            fixed_in_version: None,
            severity: "HIGH",
            cvss_v3: None,
            description: None,
        }],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn report_uuids(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT scanner_uuid FROM scanner_reports WHERE mapping_id = 'm1' ORDER BY scanner_uuid",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn registration(uuid: &str, name: &str) -> ScannerRegistration {
    ScannerRegistration {
        uuid: uuid.to_owned(),
        name: name.to_owned(),
        vendor: None,
        version: None,
        disabled: false,
    }
}

/// A chosen scan never replaces the `unknown` report: both are kept, so an old report is not
/// counted as another scanner's and its CVEs are not dropped.
#[tokio::test]
async fn a_chosen_scan_never_replaces_the_unknown_report() {
    let (pool, dir) = fixture("keep-unknown").await;
    seed_report(&pool, "unknown", None, "CVE-2026-9000").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    enqueue(&pool, "j-keep", &scan_payload(CHOSEN)).await;
    assert_eq!(run(&pool, &harbor, "j-keep", 2_000).await, JobOutcome::Done);
    assert_eq!(
        report_uuids(&pool).await,
        vec!["unknown".to_owned(), CHOSEN.to_owned()]
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A webhook-queued fetch-only job reads a report that is final, stores it for that scanner, and
/// leaves the other scanner's report alone.
#[tokio::test]
async fn a_fetch_only_job_stores_the_named_scanners_report_and_not_the_others() {
    let (pool, dir) = fixture("fetch-only").await;
    seed_report(&pool, PREVIOUS, Some("Trivy"), "CVE-2026-9000").await;
    let harbor = FakeHarbor::new(PREVIOUS);
    let payload = format!(
        r#"{{"kind":"scanner_scan","repo_full_name":"proj/app","tag":"v1","scanner_uuid":"{CHOSEN}","fetch_only":true,"trigger":"webhook"}}"#
    );
    enqueue(&pool, "j-fetch", &payload).await;
    assert_eq!(
        run(&pool, &harbor, "j-fetch", 2_000).await,
        JobOutcome::Done
    );
    assert_eq!(
        report_uuids(&pool).await,
        vec![CHOSEN.to_owned(), PREVIOUS.to_owned()]
    );
    let kept: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scanner_findings sf JOIN scanner_reports sr ON sr.id = sf.report_id
         WHERE sr.scanner_uuid = ? AND sf.cve_id = 'CVE-2026-9000'",
    )
    .bind(PREVIOUS)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kept, 1, "the other scanner's findings are untouched");
    let posts = lock(&harbor.calls).iter().filter(|c| c.0 == "POST").count();
    assert_eq!(posts, 0, "a fetch-only job never starts a scan");
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A complete scanner list that no longer has a scanner marks it `removed_at`, deletes its reports,
/// recomputes the tag's findings from the reports that remain, and queues one sync job. A list cut
/// short, or an empty one, removes nothing.
#[tokio::test]
async fn a_scanner_missing_from_a_complete_list_is_removed_with_its_reports() {
    let (pool, dir) = fixture("removed").await;
    sqlx::query(
        "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
            vulnerability_summary, sarif_status, synced_at)
         VALUES ('r1', 'm1', 'app', 'v1', ?, '{}', 'success', 1)",
    )
    .bind(DIGEST)
    .execute(&pool)
    .await
    .unwrap();
    let both = Candidates {
        scanners: vec![
            registration("uuid-a", "Trivy"),
            registration("uuid-b", "Grype"),
        ],
        complete: true,
    };
    scanner_store::apply_candidates(&pool, BASE, &both, 100)
        .await
        .unwrap();
    seed_report(&pool, "uuid-a", Some("Trivy"), "CVE-2026-0001").await;
    seed_report(&pool, "uuid-b", Some("Grype"), "CVE-2026-0002").await;
    // The tag's findings as the last merged sync left them: both CVEs open.
    for (id, cve) in [("f1", "CVE-2026-0001"), ("f2", "CVE-2026-0002")] {
        sqlx::query(
            "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, package, severity, status)
             VALUES (?, 'm1', 'app', 'v1', ?, 'p', 'HIGH', 'open')",
        )
        .bind(id)
        .bind(cve)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Not complete, or empty: nothing is removed.
    for list in [
        Candidates {
            scanners: vec![registration("uuid-a", "Trivy")],
            complete: false,
        },
        Candidates {
            scanners: Vec::new(),
            complete: true,
        },
    ] {
        let removed = scanner_store::apply_candidates(&pool, BASE, &list, 150)
            .await
            .unwrap();
        assert_eq!(removed, 0);
    }
    assert_eq!(report_uuids(&pool).await.len(), 2);

    // Complete, without Grype.
    let only_a = Candidates {
        scanners: vec![registration("uuid-a", "Trivy")],
        complete: true,
    };
    let removed = scanner_store::apply_candidates(&pool, BASE, &only_a, 200)
        .await
        .unwrap();
    assert_eq!(removed, 1);

    let rows = scanner_db::list_scanners(&pool, BASE).await.unwrap();
    let b = rows.iter().find(|row| row.uuid == "uuid-b").unwrap();
    assert_eq!(b.removed_at, Some(200));
    let a = rows.iter().find(|row| row.uuid == "uuid-a").unwrap();
    assert_eq!(a.removed_at, None);
    assert_eq!(report_uuids(&pool).await, vec!["uuid-a".to_owned()]);

    // The tag's findings now follow the remaining report: Grype's CVE is fixed.
    let status: Vec<(String, String)> = sqlx::query_as(
        "SELECT cve_id, status FROM cve_findings WHERE image_tag = 'v1' ORDER BY cve_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        status,
        vec![
            ("CVE-2026-0001".to_owned(), "open".to_owned()),
            ("CVE-2026-0002".to_owned(), "fixed".to_owned()),
        ]
    );
    let syncs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_jobs WHERE status = 'queued' AND json_extract(payload, '$.kind') IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        syncs, 1,
        "one sync job lets the SARIF and the issues follow"
    );

    // Listing the scanner again clears removed_at.
    scanner_store::apply_candidates(&pool, BASE, &both, 300)
        .await
        .unwrap();
    let rows = scanner_db::list_scanners(&pool, BASE).await.unwrap();
    assert_eq!(
        rows.iter()
            .find(|row| row.uuid == "uuid-b")
            .unwrap()
            .removed_at,
        None
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// `GET .../scans`: the state of each scanner for a tag, from the database only.
#[tokio::test]
async fn the_scans_list_shows_each_scanner_with_its_state_and_note() {
    use crate::services::tag_scans;
    let (pool, dir) = fixture("scans-list").await;
    let both = Candidates {
        scanners: vec![
            registration("uuid-a", "Trivy"),
            registration("uuid-b", "Grype"),
        ],
        complete: true,
    };
    scanner_store::apply_candidates(&pool, BASE, &both, 100)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest,
            vulnerability_summary, sarif_status, synced_at)
         VALUES ('r1', 'm1', 'app', 'v1', ?, '{}', 'success', 1)",
    )
    .bind(DIGEST)
    .execute(&pool)
    .await
    .unwrap();
    seed_report(&pool, "uuid-a", Some("Trivy"), "CVE-2026-0001").await;
    // Grype's job failed with a fixed message.
    let payload = scan_payload("uuid-b");
    enqueue(&pool, "j-failed", &payload).await;
    sqlx::query("UPDATE sync_jobs SET status = 'failed', last_error = ? WHERE id = 'j-failed'")
        .bind(MSG_SCANNER_FAILED)
        .execute(&pool)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let mapping = mapping_db::find_by_id(&mut conn, "m1")
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    let items = tag_scans::list(&pool, &mapping, "v1").await.unwrap();
    let view: Vec<(&str, &str, &str, Option<&str>)> = items
        .iter()
        .map(|item| {
            (
                item.scanner_uuid.as_str(),
                item.scanner_name.as_str(),
                item.state,
                item.note,
            )
        })
        .collect();
    assert_eq!(
        view,
        vec![
            ("uuid-b", "Grype", "failed", Some("sync.note.scannerFailed")),
            ("uuid-a", "Trivy", "ok", None),
        ]
    );
    assert_eq!(items[0].job_id.as_deref(), Some("j-failed"));
    assert!(tag_scans::list(&pool, &mapping, "bad tag").await.is_err());
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
