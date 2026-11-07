//! Scheduled scan tests (#191). Harbor is a fake that records every call and answers from
//! recorded bodies, so no live Harbor and no real token is used. Credentials are obviously fake.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;

use super::*;
use crate::auth::crypto::{self, credentials_key, encrypt as seal};
use crate::config;
use crate::db;
use crate::services::harbor_client::HarborReply;
use crate::services::sync::Clock;

const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const DIGEST: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A string in Harbor bodies that must never reach a job row.
const SENTINEL: &str = "SENTINEL-harbor-scan-91af";
/// 2026-11-05 (a Thursday) 00:00:00 UTC.
const THU: i64 = 1_793_836_800;

fn key() -> DerivedKey {
    let root = config::parse_encryption_key(ROOT).unwrap();
    credentials_key(&root).unwrap()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Answers the newest-artifact list and the scan request, and records each call as
/// `(method, path, query)`.
struct FakeHarbor {
    list: Mutex<(u16, String)>,
    scan: Mutex<Result<u16, ()>>,
    calls: Mutex<Vec<(String, String, String)>>,
}

impl FakeHarbor {
    fn new(list_status: u16, list_body: &str, scan_status: u16) -> Arc<Self> {
        Arc::new(Self {
            list: Mutex::new((list_status, list_body.to_owned())),
            scan: Mutex::new(Ok(scan_status)),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, String, String)> {
        lock(&self.calls).clone()
    }

    fn posts(&self) -> usize {
        self.calls().iter().filter(|c| c.0 == "POST").count()
    }
}

impl HarborFetch for Arc<FakeHarbor> {
    async fn fetch(
        &self,
        url: &Url,
        _username: &str,
        _secret: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        lock(&self.calls).push((
            "GET".to_owned(),
            url.path().to_owned(),
            url.query().unwrap_or("").to_owned(),
        ));
        let (status, body) = lock(&self.list).clone();
        Ok(HarborReply::new(status, body.into_bytes()))
    }

    async fn post_json(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        body: &[u8],
    ) -> Result<HarborReply, AppError> {
        assert_eq!(username, "robot$one");
        assert_eq!(secret, b"secret-one");
        assert_eq!(body, SCAN_REQUEST_BODY);
        lock(&self.calls).push((
            "POST".to_owned(),
            url.path().to_owned(),
            url.query().unwrap_or("").to_owned(),
        ));
        match *lock(&self.scan) {
            Ok(status) => Ok(HarborReply::new(
                status,
                format!(r#"{{"errors":[{{"message":"{SENTINEL}"}}]}}"#).into_bytes(),
            )),
            Err(()) => Err(AppError::UpstreamUnreachable),
        }
    }
}

#[derive(Clone)]
struct FixedClock(Arc<AtomicI64>);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    async fn sleep(&self, _duration: Duration) {}
}

fn clock() -> FixedClock {
    FixedClock(Arc::new(AtomicI64::new(THU)))
}

struct Fixture {
    pool: SqlitePool,
    dir: std::path::PathBuf,
}

impl Fixture {
    /// User `u1` with Harbor credential `c1` and GitHub credential `c2`, and mapping `m1`
    /// (`proj/app`) with the schedule off.
    async fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("harborgate-schedule-{name}-{}", std::process::id()));
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
        let key = key();
        for (id, service, username, secret) in [
            ("c1", "harbor", Some("robot$one"), "secret-one"),
            ("c2", "github", None, "gh-one"),
        ] {
            let stored = seal(
                &key,
                &crypto::aad("user_credentials", "encrypted_token", id),
                secret.as_bytes(),
            )
            .unwrap();
            sqlx::query(
                "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
                 VALUES (?, 'u1', ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(service)
            .bind(id)
            .bind((service == "harbor").then_some("https://harbor.example.com"))
            .bind(username)
            .bind(stored)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, default_branch)
             VALUES ('m1', 'u1', 'c1', 'c2', 'https://harbor.example.com', 'proj', 'app', 'octo', 'app', 'h1', 's1', 'main')",
        )
        .execute(&pool)
        .await
        .unwrap();
        Self { pool, dir }
    }

    async fn set_schedule(&self, schedule: &str, minute: i64, weekday: i64, last: Option<i64>) {
        sqlx::query(
            "UPDATE repo_mappings SET scan_schedule = ?, scan_minute = ?, scan_weekday = ?, scan_last_slot = ? WHERE id = 'm1'",
        )
        .bind(schedule)
        .bind(minute)
        .bind(weekday)
        .bind(last)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn payloads(&self) -> Vec<(String, Value)> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT status, payload FROM sync_jobs ORDER BY rowid")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        rows.into_iter()
            .map(|(status, payload)| (status, serde_json::from_str(&payload).unwrap()))
            .collect()
    }

    async fn scan_job(&self, id: &str) -> ClaimedJob {
        let payload = r#"{"kind":"scan","repo_full_name":"proj/app","trigger":"schedule"}"#;
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, next_attempt_at, payload, created_at, updated_at)
             VALUES (?, 'm1', 'running', 0, 1000, ?, 1000, 1000)",
        )
        .bind(id)
        .bind(payload)
        .execute(&self.pool)
        .await
        .unwrap();
        ClaimedJob {
            id: id.to_owned(),
            mapping_id: "m1".to_owned(),
            attempts: 0,
            payload: payload.to_owned(),
        }
    }

    async fn run(&self, harbor: &Arc<FakeHarbor>, job: &ClaimedJob) -> JobOutcome {
        run_job(&self.pool, &key(), harbor, &clock(), job).await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One tagged artifact with two tags, the newer `v2`, and a sentinel in a field never read.
fn newest_body() -> String {
    json!([{
        "digest": DIGEST,
        "tags": [
            {"name": "v1", "push_time": "2026-11-05T10:00:01.000Z"},
            {"name": "v2", "push_time": "2026-11-05T10:00:09.000Z"}
        ],
        "extra_attrs": {"note": SENTINEL}
    }])
    .to_string()
}

// ---- slots ------------------------------------------------------------------------------

#[test]
fn daily_slot_is_today_once_the_time_has_passed_and_yesterday_before() {
    // 02:30 UTC.
    assert_eq!(
        latest_slot("daily", 150, 1, THU + 3 * 3600),
        Some(THU + 150 * 60)
    );
    assert_eq!(
        latest_slot("daily", 150, 1, THU + 3600),
        Some(THU - 86_400 + 150 * 60)
    );
    // Exactly at the slot it is due.
    assert_eq!(
        latest_slot("daily", 150, 1, THU + 150 * 60),
        Some(THU + 150 * 60)
    );
}

#[test]
fn weekly_slot_is_the_latest_chosen_weekday_at_the_time() {
    // THU is ISO weekday 4. Monday 01:00 is three days back.
    assert_eq!(
        latest_slot("weekly", 60, 1, THU + 12 * 3600),
        Some(THU - 3 * 86_400 + 3600)
    );
    // Thursday 13:00 on Thursday at 12:00 is a week back.
    assert_eq!(
        latest_slot("weekly", 13 * 60, 4, THU + 12 * 3600),
        Some(THU - 7 * 86_400 + 13 * 3600)
    );
    // Thursday 11:00 on Thursday at 12:00 is today.
    assert_eq!(
        latest_slot("weekly", 11 * 60, 4, THU + 12 * 3600),
        Some(THU + 11 * 3600)
    );
    // Sunday (7).
    assert_eq!(latest_slot("weekly", 0, 7, THU), Some(THU - 4 * 86_400));
}

#[test]
fn off_and_unknown_schedules_have_no_slot() {
    assert_eq!(latest_slot("off", 0, 1, THU), None);
    assert_eq!(latest_slot("hourly", 0, 1, THU), None);
}

// ---- scheduler --------------------------------------------------------------------------

#[tokio::test]
async fn an_off_schedule_queues_nothing() {
    let fx = Fixture::new("off").await;
    assert_eq!(tick(&fx.pool, THU + 86_400).await.unwrap(), 0);
    assert!(fx.payloads().await.is_empty());
}

#[tokio::test]
async fn a_due_slot_queues_one_scan_job_once() {
    let fx = Fixture::new("due").await;
    // Saved at 00:00, daily at 02:00.
    fx.set_schedule("daily", 120, 1, Some(THU)).await;
    // Before the slot: nothing.
    assert_eq!(tick(&fx.pool, THU + 3600).await.unwrap(), 0);
    // At 02:01 the slot is due.
    assert_eq!(tick(&fx.pool, THU + 121 * 60).await.unwrap(), 1);
    // The next tick in the same slot queues nothing.
    assert_eq!(tick(&fx.pool, THU + 122 * 60).await.unwrap(), 0);
    let jobs = fx.payloads().await;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].0, "queued");
    assert_eq!(
        jobs[0].1,
        json!({"kind": "scan", "repo_full_name": "proj/app", "trigger": "schedule"})
    );
}

#[tokio::test]
async fn a_slot_before_the_save_never_fires_and_missed_slots_fire_once() {
    let fx = Fixture::new("missed").await;
    // Saved at 03:00, daily at 02:00: today's slot is already past.
    fx.set_schedule("daily", 120, 1, Some(THU + 3 * 3600)).await;
    assert_eq!(tick(&fx.pool, THU + 4 * 3600).await.unwrap(), 0);
    // Three days later (the server was down), one job, not three.
    assert_eq!(
        tick(&fx.pool, THU + 3 * 86_400 + 5 * 3600).await.unwrap(),
        1
    );
    assert_eq!(fx.payloads().await.len(), 1);
}

#[tokio::test]
async fn a_pending_scan_job_is_not_doubled_by_the_next_slot() {
    let fx = Fixture::new("pending").await;
    fx.set_schedule("daily", 0, 1, Some(THU - 1)).await;
    assert_eq!(tick(&fx.pool, THU + 60).await.unwrap(), 1);
    // The job is still queued a day later: the next slot is recorded but queues nothing.
    assert_eq!(tick(&fx.pool, THU + 86_400 + 60).await.unwrap(), 0);
    assert_eq!(fx.payloads().await.len(), 1);
    let last: Option<i64> =
        sqlx::query_scalar("SELECT scan_last_slot FROM repo_mappings WHERE id = 'm1'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(last, Some(THU + 86_400));
}

// ---- scan job ---------------------------------------------------------------------------

#[tokio::test]
async fn the_job_scans_the_newest_tagged_image_and_queues_one_scheduled_sync() {
    let fx = Fixture::new("scan").await;
    let harbor = FakeHarbor::new(200, &newest_body(), 202);
    let job = fx.scan_job("s1").await;
    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    let calls = harbor.calls();
    assert_eq!(calls.len(), 2);
    // The newest tagged artifact, the source-suggestion query.
    assert_eq!(calls[0].0, "GET");
    assert_eq!(
        calls[0].1,
        "/api/v2.0/projects/proj/repositories/app/artifacts"
    );
    assert_eq!(calls[0].2, "page=1&page_size=1&sort=-push_time&q=tags%3D*");
    // The scan call on the digest.
    assert_eq!(calls[1].0, "POST");
    assert_eq!(
        calls[1].1,
        // The digest is one encoded path segment, as in every other artifact URL.
        format!(
            "/api/v2.0/projects/proj/repositories/app/artifacts/{}/scan",
            DIGEST.replace(':', "%3A")
        )
    );

    let jobs = fx.payloads().await;
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].0, "done");
    assert_eq!(jobs[1].0, "queued");
    assert_eq!(
        jobs[1].1,
        json!({"repo_full_name": "proj/app", "digest": DIGEST, "tag": "v2", "trigger": "schedule"})
    );
}

#[tokio::test]
async fn a_second_run_does_not_scan_a_digest_already_scanning() {
    let fx = Fixture::new("twice").await;
    let harbor = FakeHarbor::new(200, &newest_body(), 202);
    let first = fx.scan_job("s1").await;
    assert_eq!(fx.run(&harbor, &first).await, JobOutcome::Done);
    // The scheduled sync is still queued (waiting for Harbor's report).
    let second = fx.scan_job("s2").await;
    assert_eq!(
        fx.run(&harbor, &second).await,
        JobOutcome::DoneWithNote(NOTE_SCAN_RUNNING.to_owned())
    );
    assert_eq!(harbor.posts(), 1, "no second scan request");
    // No second sync job either.
    let syncs = fx
        .payloads()
        .await
        .into_iter()
        .filter(|(_, p)| p.get("kind").is_none())
        .count();
    assert_eq!(syncs, 1);
}

#[tokio::test]
async fn harbor_running_its_own_scan_skips_the_run() {
    let fx = Fixture::new("conflict").await;
    let harbor = FakeHarbor::new(200, &newest_body(), 409);
    let job = fx.scan_job("s1").await;
    assert_eq!(
        fx.run(&harbor, &job).await,
        JobOutcome::DoneWithNote(NOTE_SCAN_RUNNING.to_owned())
    );
    assert_eq!(fx.payloads().await.len(), 1, "no sync job queued");
}

#[tokio::test]
async fn a_refused_scan_fails_with_fixed_text_for_the_backoff() {
    for (status, message) in [
        (403u16, MSG_SCAN_FORBIDDEN),
        (401, "Harbor rejected the robot account credentials"),
    ] {
        let fx = Fixture::new(&format!("refused-{status}")).await;
        let harbor = FakeHarbor::new(200, &newest_body(), status);
        let job = fx.scan_job("s1").await;
        assert_eq!(
            fx.run(&harbor, &job).await,
            JobOutcome::Failed(message.to_owned())
        );
    }
    let fx = Fixture::new("refused-500").await;
    let harbor = FakeHarbor::new(200, &newest_body(), 500);
    let job = fx.scan_job("s1").await;
    let outcome = fx.run(&harbor, &job).await;
    assert_eq!(
        outcome,
        JobOutcome::Failed("Harbor refused to start the scan (status 500)".to_owned())
    );
    if let JobOutcome::Failed(text) = outcome {
        assert!(!text.contains(SENTINEL));
        assert!(!text.contains("harbor.example.com"));
    }
}

#[tokio::test]
async fn a_refused_scan_uses_the_existing_backoff_and_alert() {
    use crate::worker::{self, JobHandler, Step};

    struct Handler {
        pool: SqlitePool,
        harbor: Arc<FakeHarbor>,
        gave_up: std::sync::atomic::AtomicUsize,
    }
    impl JobHandler for Handler {
        async fn run(&self, job: ClaimedJob) -> JobOutcome {
            run_job(&self.pool, &key(), &self.harbor, &clock(), &job).await
        }
        fn on_give_up(&self, _job: &ClaimedJob, _now: i64) {
            self.gave_up.fetch_add(1, Ordering::SeqCst);
        }
    }

    let fx = Fixture::new("backoff").await;
    let handler = Arc::new(Handler {
        pool: fx.pool.clone(),
        harbor: FakeHarbor::new(200, &newest_body(), 403),
        gave_up: Default::default(),
    });
    sqlx::query(
        "INSERT INTO sync_jobs (id, mapping_id, status, attempts, next_attempt_at, payload, created_at, updated_at)
         VALUES ('s1', 'm1', 'queued', 0, 0, '{\"kind\":\"scan\",\"trigger\":\"schedule\"}', 0, 0)",
    )
    .execute(&fx.pool)
    .await
    .unwrap();
    let mut now = 1_000;
    let mut delays = Vec::new();
    loop {
        match worker::step(&fx.pool, &handler, now).await.unwrap() {
            Step::Retry { next_attempt_at } => {
                delays.push(next_attempt_at - now);
                now = next_attempt_at;
            }
            Step::GaveUp => break,
            other => panic!("unexpected step {other:?}"),
        }
    }
    assert_eq!(delays, vec![30, 60, 120, 240, 480, 960, 1920]);
    assert_eq!(
        handler.gave_up.load(Ordering::SeqCst),
        1,
        "sync-failed alert"
    );
    let (status, error): (String, String) =
        sqlx::query_as("SELECT status, last_error FROM sync_jobs WHERE id = 's1'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(error, MSG_SCAN_FORBIDDEN);
}

#[tokio::test]
async fn a_repository_with_no_tagged_image_is_done_with_a_note() {
    let fx = Fixture::new("empty").await;
    let harbor = FakeHarbor::new(200, "[]", 202);
    let job = fx.scan_job("s1").await;
    assert_eq!(
        fx.run(&harbor, &job).await,
        JobOutcome::DoneWithNote(NOTE_NO_TAGGED_IMAGE.to_owned())
    );
    assert_eq!(harbor.posts(), 0);
}

#[tokio::test]
async fn a_harbor_rate_limit_defers_and_an_unreachable_harbor_fails() {
    let fx = Fixture::new("limits").await;
    let harbor = FakeHarbor::new(200, &newest_body(), 429);
    let job = fx.scan_job("s1").await;
    assert!(matches!(
        fx.run(&harbor, &job).await,
        JobOutcome::Deferred { .. }
    ));
    let harbor = FakeHarbor::new(200, &newest_body(), 202);
    *lock(&harbor.scan) = Err(());
    let job = fx.scan_job("s2").await;
    assert_eq!(
        fx.run(&harbor, &job).await,
        JobOutcome::Failed("Harbor could not be reached".to_owned())
    );
}

// ---- new ids ----------------------------------------------------------------------------

#[test]
fn new_ids_are_those_not_in_the_last_result_for_the_digest() {
    let report = json!({"vulnerabilities": [
        {"id": "CVE-2"}, {"id": "CVE-1"}, {"id": "CVE-2"}, {"id": ""}, {"id": "CVE-3"}
    ]});
    let ids = report_cve_ids(&report);
    assert_eq!(ids, vec!["CVE-1", "CVE-2", "CVE-3"]);
    assert_eq!(
        new_cve_ids(&ids, Some(r#"["CVE-1","CVE-9"]"#)),
        vec!["CVE-2", "CVE-3"]
    );
    // No previous result: every id is new.
    assert_eq!(new_cve_ids(&ids, None), ids);
    // A clean scan reports nothing new.
    assert!(new_cve_ids(&[], Some(r#"["CVE-1"]"#)).is_empty());
    // An unchanged scan reports nothing new.
    assert!(new_cve_ids(&ids, Some(r#"["CVE-1","CVE-2","CVE-3"]"#)).is_empty());
}
