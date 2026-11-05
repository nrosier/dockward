//! Resolve job tests (#132). Harbor is a fake that records every call and answers from a
//! recorded body, so no live Harbor and no real token is used. The credentials are obviously
//! fake test values.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;

use super::*;
// `seal` is `crypto::encrypt` under another name. This whole file is test code, and the call-site
// guard in `key_rotation` counts only non-test sites by the `crypto::encrypt(` text.
use crate::auth::crypto::{self, credentials_key, encrypt as seal};
use crate::config;
use crate::db;
use crate::services::sync::Clock;
use crate::worker::{self, JobHandler, Step};

const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// A valid digest: `sha256:` and 64 lowercase hex characters.
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A string that must never reach `sync_jobs.payload` or `last_error`.
const SENTINEL: &str = "SENTINEL-harbor-body-5d1e";

fn key() -> DerivedKey {
    let root = config::parse_encryption_key(ROOT).unwrap();
    credentials_key(&root).unwrap()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// What the fake Harbor answers.
#[derive(Clone)]
enum Answer {
    Reply {
        status: u16,
        body: String,
        retry_after: Option<u64>,
    },
    Unreachable,
}

/// One recorded call: URL path, username, secret.
type Call = (String, String, String);

struct FakeHarbor {
    answer: Mutex<Answer>,
    calls: Mutex<Vec<Call>>,
    /// Runs inside the fetch, to model a change that lands while the lookup is in flight.
    during_fetch: Mutex<Option<(SqlitePool, &'static str)>>,
}

impl FakeHarbor {
    fn answering(status: u16, body: &str) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Answer::Reply {
                status,
                body: body.to_owned(),
                retry_after: None,
            }),
            calls: Mutex::new(Vec::new()),
            during_fetch: Mutex::new(None),
        })
    }

    fn set(&self, answer: Answer) {
        *lock(&self.answer) = answer;
    }

    fn calls(&self) -> Vec<Call> {
        lock(&self.calls).clone()
    }
}

impl HarborFetch for Arc<FakeHarbor> {
    async fn fetch(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        lock(&self.calls).push((
            url.path().to_owned(),
            username.to_owned(),
            String::from_utf8_lossy(secret).into_owned(),
        ));
        let hook = lock(&self.during_fetch).clone();
        if let Some((pool, sql)) = hook {
            sqlx::query(sql).execute(&pool).await.unwrap();
        }
        match lock(&self.answer).clone() {
            Answer::Unreachable => Err(AppError::UpstreamUnreachable),
            Answer::Reply {
                status,
                body,
                retry_after,
            } => Ok(HarborReply {
                status,
                body: body.into_bytes(),
                retry_after,
            }),
        }
    }
}

/// A clock the test sets. `step_once` sets the handler's clock to the `now` it passes to the
/// worker, so the handler and the worker agree on the time as they do in production.
#[derive(Clone)]
struct FixedClock(Arc<AtomicI64>);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    async fn sleep(&self, _duration: Duration) {}
}

fn clock() -> FixedClock {
    FixedClock(Arc::new(AtomicI64::new(1_000)))
}

/// A handler that runs only resolve jobs and counts `on_give_up` calls.
struct TestHandler {
    pool: SqlitePool,
    key: DerivedKey,
    harbor: Arc<FakeHarbor>,
    clock: FixedClock,
    gave_up: AtomicUsize,
}

impl JobHandler for TestHandler {
    async fn run(&self, job: ClaimedJob) -> JobOutcome {
        run(&self.pool, &self.key, &self.harbor, &self.clock, &job).await
    }

    fn on_give_up(&self, _job: &ClaimedJob, _now: i64) {
        self.gave_up.fetch_add(1, Ordering::SeqCst);
    }
}

struct Fixture {
    pool: SqlitePool,
    dir: std::path::PathBuf,
}

impl Fixture {
    /// Users `u1` and `u2`. `m1` is `proj/app` for `u1` with credential `c1`. `m2` is
    /// `proj2/other` for `u2` with credential `c3`. `m3` is `u2`'s mapping that wrongly points
    /// at `u1`'s credential `c1`.
    async fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("harborgate-resolve-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        for user in ["u1", "u2"] {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, token_version)
                 VALUES (?, ?, NULL, 'user', 0)",
            )
            .bind(user)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        }
        let key = key();
        for (id, user, service, username, secret) in [
            ("c1", "u1", "harbor", Some("robot$one"), "secret-one"),
            ("c2", "u1", "github", None, "gh-one"),
            ("c3", "u2", "harbor", Some("robot$two"), "secret-two"),
            ("c4", "u2", "github", None, "gh-two"),
        ] {
            let stored = seal(
                &key,
                &crypto::aad("user_credentials", "encrypted_token", id),
                secret.as_bytes(),
            )
            .unwrap();
            sqlx::query(
                "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(user)
            .bind(service)
            .bind(id)
            .bind((service == "harbor").then_some("https://harbor.example.com"))
            .bind(username)
            .bind(stored)
            .execute(&pool)
            .await
            .unwrap();
        }
        for (id, user, harbor_cred, github_cred, project, repository, n) in [
            ("m1", "u1", "c1", "c2", "proj", "app", 1),
            ("m2", "u2", "c3", "c4", "proj2", "other", 2),
            ("m3", "u2", "c1", "c4", "proj3", "third", 3),
        ] {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, default_branch)
                 VALUES (?, ?, ?, ?, 'https://harbor.example.com', ?, ?, 'octo', ?, ?, ?, 'main')",
            )
            .bind(id)
            .bind(user)
            .bind(harbor_cred)
            .bind(github_cred)
            .bind(project)
            .bind(repository)
            .bind(repository)
            .bind(format!("h{n}"))
            .bind(format!("s{n}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        Self { pool, dir }
    }

    fn handler(&self, harbor: &Arc<FakeHarbor>) -> Arc<TestHandler> {
        Arc::new(TestHandler {
            pool: self.pool.clone(),
            key: key(),
            harbor: harbor.clone(),
            clock: clock(),
            gave_up: AtomicUsize::new(0),
        })
    }

    /// Stores a resolve job in the given status and returns it as the worker would claim it.
    async fn resolve_job(&self, id: &str, mapping: &str, status: &str) -> ClaimedJob {
        let payload = format!(r#"{{"kind":"resolve","repo_full_name":"x/y","digest":"{DIGEST}"}}"#);
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, next_attempt_at, payload, created_at, updated_at)
             VALUES (?, ?, ?, 0, 1000, ?, 1000, 1000)",
        )
        .bind(id)
        .bind(mapping)
        .bind(status)
        .bind(&payload)
        .execute(&self.pool)
        .await
        .unwrap();
        ClaimedJob {
            id: id.to_owned(),
            mapping_id: mapping.to_owned(),
            attempts: 0,
            payload,
        }
    }

    async fn run(&self, harbor: &Arc<FakeHarbor>, job: &ClaimedJob) -> JobOutcome {
        run(&self.pool, &key(), harbor, &clock(), job).await
    }

    /// The payloads of the sync jobs (those with no `kind`), in insertion order.
    async fn children(&self) -> Vec<serde_json::Value> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT payload FROM sync_jobs WHERE json_extract(payload, '$.kind') IS NULL ORDER BY rowid",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        rows.iter()
            .map(|payload| serde_json::from_str(payload).unwrap())
            .collect()
    }

    async fn tags_queued(&self) -> Vec<String> {
        self.children()
            .await
            .iter()
            .map(|payload| payload["tag"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn status(&self, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM sync_jobs WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn insert_child(&self, id: &str, mapping: &str, tag: &str, status: &str) {
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
             VALUES (?, ?, ?, 0, ?, 500, 500)",
        )
        .bind(id)
        .bind(mapping)
        .bind(status)
        .bind(format!(
            r#"{{"repo_full_name":"proj/app","digest":"{DIGEST}","tag":"{tag}"}}"#
        ))
        .execute(&self.pool)
        .await
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `n` is the second of `2026-11-05T10:00:nn.000Z`, so a larger `n` is a newer push.
fn at(n: u32) -> Option<String> {
    Some(format!("2026-11-05T10:00:{n:02}.000Z"))
}

/// An artifact body with these tags. It also carries a sentinel in fields the resolve never
/// reads, so a leak of the body shows.
fn artifact_body(tags: &[(&str, Option<String>)]) -> String {
    let tags: Vec<serde_json::Value> = tags
        .iter()
        .map(|(name, push_time)| match push_time {
            Some(time) => serde_json::json!({"name": name, "push_time": time, "id": 1}),
            None => serde_json::json!({"name": name, "id": 1}),
        })
        .collect();
    serde_json::json!({
        "digest": DIGEST,
        "tags": tags,
        "extra_attrs": {"config": {"Labels": {"note": SENTINEL}}},
    })
    .to_string()
}

fn tag(name: &str, n: u32) -> ArtifactTag {
    ArtifactTag {
        name: name.to_owned(),
        push_time: at(n),
    }
}

// ---- kind ------------------------------------------------------------------------------

#[test]
fn job_kind_reads_the_payload_leniently() {
    assert_eq!(job_kind(r#"{"digest":"d","tag":"t"}"#), JobKind::Sync);
    assert_eq!(job_kind(r#"{"kind":"sync","tag":"t"}"#), JobKind::Sync);
    assert_eq!(job_kind(r#"{"kind":"resolve"}"#), JobKind::Resolve);
    // Members the resolve job does not know do not matter.
    assert_eq!(
        job_kind(r#"{"kind":"resolve","extra":[1,2],"trigger":"poll"}"#),
        JobKind::Resolve
    );
    assert_eq!(job_kind(r#"{"kind":"refresh"}"#), JobKind::Unknown);
    assert_eq!(job_kind(r#"{"kind":null}"#), JobKind::Unknown);
    assert_eq!(job_kind(r#"{"kind":7}"#), JobKind::Unknown);
    // Not an object: left to the sync handler, which reports the bad payload.
    assert_eq!(job_kind("not json"), JobKind::Sync);
    assert_eq!(job_kind("[1]"), JobKind::Sync);
}

// ---- ordering --------------------------------------------------------------------------

#[test]
fn a_missing_push_time_sorts_last_and_ties_break_by_name() {
    let tags = vec![
        ArtifactTag {
            name: "nodate".to_owned(),
            push_time: None,
        },
        tag("b", 5),
        tag("a", 5),
        tag("newest", 9),
        ArtifactTag {
            name: "badtime".to_owned(),
            push_time: Some("yesterday".to_owned()),
        },
        ArtifactTag {
            name: "aaa-nodate".to_owned(),
            push_time: None,
        },
    ];
    assert_eq!(
        newest_tags(tags, 10),
        vec!["newest", "a", "b", "aaa-nodate", "badtime", "nodate"]
    );
}

#[test]
fn fractions_order_tags_pushed_in_one_second() {
    let tags = vec![
        ArtifactTag {
            name: "early".to_owned(),
            push_time: Some("2026-11-05T10:00:01.100Z".to_owned()),
        },
        ArtifactTag {
            name: "late".to_owned(),
            push_time: Some("2026-11-05T10:00:01.900Z".to_owned()),
        },
        ArtifactTag {
            name: "whole".to_owned(),
            push_time: Some("2026-11-05T10:00:01Z".to_owned()),
        },
    ];
    assert_eq!(newest_tags(tags, 10), vec!["late", "early", "whole"]);
}

#[test]
fn invalid_names_are_dropped_and_duplicates_collapse() {
    let tags = vec![
        tag("ok", 1),
        tag("has space", 9),
        tag("", 8),
        tag("-dash", 7),
        tag("team/app", 6),
        tag("ok", 5),
    ];
    // The duplicate keeps its newest time, so `ok` is the one entry.
    assert_eq!(newest_tags(tags, 10), vec!["ok"]);
}

// ---- fan-out ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_with_three_tags_queues_three_sync_children_equal_to_webhook_jobs() {
    let fx = Fixture::new("three").await;
    let harbor = FakeHarbor::answering(
        200,
        &artifact_body(&[("v1", at(1)), ("v2", at(2)), ("v3", at(3))]),
    );
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    assert_eq!(fx.status("r1").await, "done");
    let children = fx.children().await;
    assert_eq!(children.len(), 3);
    for child in &children {
        // The same payload a webhook sync job stores: no `kind`, no `trigger`.
        let tag = child["tag"].as_str().unwrap();
        let expected = serde_json::to_value(ScanEvent {
            repo_full_name: "proj/app".to_owned(),
            digest: DIGEST.to_owned(),
            tag: tag.to_owned(),
        })
        .unwrap();
        assert_eq!(child, &expected);
        assert!(child.get("kind").is_none());
    }
    assert_eq!(fx.tags_queued().await, vec!["v3", "v2", "v1"]);
    // The rows are queued sync jobs of the mapping.
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_jobs WHERE status = 'queued' AND mapping_id = 'm1'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(queued, 3);
}

#[tokio::test]
async fn resolve_with_twelve_tags_queues_the_newest_ten() {
    let fx = Fixture::new("twelve").await;
    let names: Vec<String> = (0..12).map(|n| format!("t{n:02}")).collect();
    let tags: Vec<(&str, Option<String>)> = names
        .iter()
        .enumerate()
        .map(|(n, name)| (name.as_str(), at(n as u32)))
        .collect();
    let harbor = FakeHarbor::answering(200, &artifact_body(&tags));
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    let queued = fx.tags_queued().await;
    assert_eq!(queued.len(), MAX_TAGS_PER_DIGEST);
    let expected: Vec<String> = (2..12).rev().map(|n| format!("t{n:02}")).collect();
    assert_eq!(queued, expected);
    assert!(!queued.contains(&"t00".to_owned()) && !queued.contains(&"t01".to_owned()));
}

#[tokio::test]
async fn resolve_keeps_a_missing_push_time_last_and_breaks_ties_by_name_in_the_cut() {
    let fx = Fixture::new("cut").await;
    // Ten dated tags fill the cut, so the undated tag and the late name are cut.
    let mut tags: Vec<(String, Option<String>)> = (0..9)
        .map(|n| (format!("d{n}"), at(10 + n as u32)))
        .collect();
    tags.push(("tie-b".to_owned(), at(1)));
    tags.push(("tie-a".to_owned(), at(1)));
    tags.push(("undated".to_owned(), None));
    let borrowed: Vec<(&str, Option<String>)> = tags
        .iter()
        .map(|(name, time)| (name.as_str(), time.clone()))
        .collect();
    let harbor = FakeHarbor::answering(200, &artifact_body(&borrowed));
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    let queued = fx.tags_queued().await;
    assert_eq!(queued.len(), 10);
    assert_eq!(queued.last().map(String::as_str), Some("tie-a"));
    assert!(!queued.contains(&"tie-b".to_owned()));
    assert!(!queued.contains(&"undated".to_owned()));
}

#[tokio::test]
async fn a_queued_or_running_child_for_the_same_pair_blocks_a_duplicate() {
    let fx = Fixture::new("blocks").await;
    fx.insert_child("c-queued", "m1", "v1", "queued").await;
    fx.insert_child("c-running", "m1", "v2", "running").await;
    let harbor = FakeHarbor::answering(
        200,
        &artifact_body(&[("v1", at(1)), ("v2", at(2)), ("v3", at(3))]),
    );
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    // Only v3 is new. The two existing children are the only rows for v1 and v2.
    let new: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM sync_jobs WHERE json_extract(payload,'$.tag') IN ('v1','v2')",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(new.len(), 2);
    assert_eq!(fx.children().await.len(), 3);
}

#[tokio::test]
async fn a_done_failed_or_synced_pair_does_not_block_a_rescan() {
    let fx = Fixture::new("rescan").await;
    fx.insert_child("c-done", "m1", "v1", "done").await;
    fx.insert_child("c-failed", "m1", "v2", "failed").await;
    // A pair with a successful report: a rescan means the report changed, so it syncs again.
    fx.insert_child("c-synced", "m1", "v3", "done").await;
    sqlx::query(
        "INSERT INTO sync_reports (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status)
         VALUES ('rep1', 'm1', 'c-synced', 'app', 'v3', ?, '{}', 'success')",
    )
    .bind(DIGEST)
    .execute(&fx.pool)
    .await
    .unwrap();
    let harbor = FakeHarbor::answering(
        200,
        &artifact_body(&[("v1", at(1)), ("v2", at(2)), ("v3", at(3))]),
    );
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_jobs WHERE status = 'queued'")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(queued, 3, "each rescanned tag is queued again");
}

#[tokio::test]
async fn a_pair_of_another_mapping_does_not_block() {
    let fx = Fixture::new("other-mapping").await;
    fx.insert_child("c-other", "m2", "v1", "queued").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    let for_m1: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_jobs WHERE mapping_id = 'm1' AND status = 'queued'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(for_m1, 1);
}

#[tokio::test]
async fn a_guarded_update_that_affects_zero_rows_inserts_no_children() {
    let fx = Fixture::new("guard").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1)), ("v2", at(2))]));
    // The job is no longer running: it was re-queued (for example by a restart) before the
    // fan-out. Its claim is stale.
    let job = fx.resolve_job("r1", "m1", "queued").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    assert!(fx.children().await.is_empty());
    assert_eq!(fx.status("r1").await, "queued", "the guard changed nothing");
}

#[tokio::test]
async fn a_retry_after_a_rollback_leaves_no_children_and_the_rerun_yields_exactly_n() {
    let fx = Fixture::new("rollback").await;
    let harbor = FakeHarbor::answering(
        200,
        &artifact_body(&[("t1", at(1)), ("t2", at(2)), ("t3", at(3))]),
    );
    let job = fx.resolve_job("r1", "m1", "running").await;
    // Inject a failure on the second insert. Tags are inserted newest first: t3, t2, t1.
    sqlx::query(
        "CREATE TRIGGER fail_second BEFORE INSERT ON sync_jobs
         WHEN json_extract(NEW.payload, '$.tag') = 't2'
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .execute(&fx.pool)
    .await
    .unwrap();

    let outcome = fx.run(&harbor, &job).await;

    assert_eq!(outcome, JobOutcome::Failed(MSG_DATABASE.to_owned()));
    assert!(
        fx.children().await.is_empty(),
        "the first insert rolled back"
    );
    assert_eq!(
        fx.status("r1").await,
        "running",
        "the done mark rolled back"
    );

    sqlx::query("DROP TRIGGER fail_second")
        .execute(&fx.pool)
        .await
        .unwrap();
    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);
    assert_eq!(fx.tags_queued().await, vec!["t3", "t2", "t1"]);
    assert_eq!(fx.status("r1").await, "done");
}

#[tokio::test]
async fn running_the_same_claimed_resolve_job_twice_inserts_nothing_the_second_time() {
    let fx = Fixture::new("twice").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1)), ("v2", at(2))]));
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);
    assert_eq!(fx.children().await.len(), 2);
    // A done child must not matter: the second run is stopped by the guard, not the dedupe.
    sqlx::query(
        "UPDATE sync_jobs SET status = 'done' WHERE json_extract(payload,'$.kind') IS NULL",
    )
    .execute(&fx.pool)
    .await
    .unwrap();
    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    assert_eq!(fx.children().await.len(), 2);
}

#[tokio::test]
async fn a_mapping_deleted_mid_flight_gives_no_children_and_no_error() {
    let fx = Fixture::new("deleted-mid").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));
    // The mapping is deleted while Harbor is being read. The job row cascades away with it.
    *lock(&harbor.during_fetch) =
        Some((fx.pool.clone(), "DELETE FROM repo_mappings WHERE id = 'm1'"));
    let job = fx.resolve_job("r1", "m1", "running").await;

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    assert!(fx.children().await.is_empty());
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_jobs")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(jobs, 0);
}

#[tokio::test]
async fn a_mapping_gone_before_the_run_fails_with_the_gone_message_and_no_call() {
    let fx = Fixture::new("deleted-before").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));
    let job = ClaimedJob {
        id: "r1".to_owned(),
        mapping_id: "no-such-mapping".to_owned(),
        attempts: 0,
        payload: format!(r#"{{"kind":"resolve","repo_full_name":"x/y","digest":"{DIGEST}"}}"#),
    };

    assert_eq!(
        fx.run(&harbor, &job).await,
        JobOutcome::Failed(MSG_GONE.to_owned())
    );
    assert!(harbor.calls().is_empty());
}

// ---- failures --------------------------------------------------------------------------

/// Runs a queued resolve job to a result through the worker and returns the step.
async fn step_once(fx: &Fixture, handler: &Arc<TestHandler>, now: i64) -> Step {
    handler.clock.0.store(now, Ordering::SeqCst);
    worker::step(&fx.pool, handler, now).await.unwrap()
}

async fn last_error(fx: &Fixture, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT last_error FROM sync_jobs WHERE id = ?")
        .bind(id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
}

async fn queued_resolve(fx: &Fixture) {
    fx.resolve_job("r1", "m1", "queued").await;
}

#[tokio::test]
async fn a_5xx_fails_with_its_fixed_text_and_follows_the_backoff_until_the_eighth_failure() {
    let fx = Fixture::new("backoff-5xx").await;
    let harbor = FakeHarbor::answering(503, SENTINEL);
    let handler = fx.handler(&harbor);
    queued_resolve(&fx).await;

    let mut now = 1_000;
    for delay in [30, 60, 120, 240, 480, 960, 1920] {
        let step = step_once(&fx, &handler, now).await;
        assert_eq!(
            step,
            Step::Retry {
                next_attempt_at: now + delay
            }
        );
        assert_eq!(
            last_error(&fx, "r1").await.as_deref(),
            Some("Harbor returned status 503")
        );
        now += delay;
    }
    // 30 + 60 + 120 + 240 + 480 + 960 + 1920 s = 63 min 30 s after the first attempt.
    assert_eq!(now - 1_000, 3_810);
    assert_eq!(handler.gave_up.load(Ordering::SeqCst), 0);

    assert_eq!(step_once(&fx, &handler, now).await, Step::GaveUp);

    assert_eq!(fx.status("r1").await, "failed");
    assert_eq!(
        handler.gave_up.load(Ordering::SeqCst),
        1,
        "on_give_up fires once"
    );
    assert_eq!(harbor.calls().len(), 8);
    let error = last_error(&fx, "r1").await.unwrap();
    assert_eq!(error, "Harbor returned status 503");
    assert!(!error.contains(SENTINEL));
}

#[tokio::test]
async fn a_fetch_error_fails_with_its_fixed_text_and_the_eighth_failure_gives_up() {
    let fx = Fixture::new("backoff-fetch").await;
    let harbor = FakeHarbor::answering(200, "");
    harbor.set(Answer::Unreachable);
    let handler = fx.handler(&harbor);
    queued_resolve(&fx).await;

    let mut now = 1_000;
    for delay in [30, 60, 120, 240, 480, 960, 1920] {
        assert_eq!(
            step_once(&fx, &handler, now).await,
            Step::Retry {
                next_attempt_at: now + delay
            }
        );
        now += delay;
    }
    assert_eq!(step_once(&fx, &handler, now).await, Step::GaveUp);

    assert_eq!(
        last_error(&fx, "r1").await.as_deref(),
        Some("Harbor could not be reached")
    );
    assert_eq!(handler.gave_up.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_404_a_401_a_403_and_an_unreadable_200_each_fail_with_their_fixed_text() {
    let cases: [(u16, &str, &str); 5] = [
        (404, SENTINEL, "digest not found in Harbor"),
        (
            401,
            SENTINEL,
            "Harbor rejected the robot account credentials",
        ),
        (
            403,
            SENTINEL,
            "Harbor rejected the robot account credentials",
        ),
        (
            200,
            SENTINEL,
            "Harbor returned an artifact that could not be read",
        ),
        (
            200,
            r#"{"tags":"not a list"}"#,
            "Harbor returned an artifact that could not be read",
        ),
    ];
    for (n, (status, body, expected)) in cases.into_iter().enumerate() {
        let fx = Fixture::new(&format!("text-{n}")).await;
        let harbor = FakeHarbor::answering(status, body);
        let handler = fx.handler(&harbor);
        queued_resolve(&fx).await;

        // A failure retries (it is not permanent) and stores the fixed text.
        let step = step_once(&fx, &handler, 1_000).await;
        assert_eq!(
            step,
            Step::Retry {
                next_attempt_at: 1_030
            },
            "{status} is retried"
        );
        let error = last_error(&fx, "r1").await.unwrap();
        assert_eq!(error, expected, "status {status}");
        assert!(!error.contains(SENTINEL));
        assert!(fx.children().await.is_empty());
    }
}

#[tokio::test]
async fn a_digest_with_no_tags_fails_after_the_attempts_with_the_zero_tags_message() {
    for body in [
        r#"{"digest":"x","tags":null}"#,
        r#"{"digest":"x"}"#,
        r#"{"digest":"x","tags":[]}"#,
        r#"{"digest":"x","tags":[{"name":"bad tag"}]}"#,
    ] {
        let fx = Fixture::new("no-tags").await;
        let harbor = FakeHarbor::answering(200, body);
        let handler = fx.handler(&harbor);
        queued_resolve(&fx).await;

        let mut now = 1_000;
        for delay in [30, 60, 120, 240, 480, 960, 1920] {
            assert_eq!(
                step_once(&fx, &handler, now).await,
                Step::Retry {
                    next_attempt_at: now + delay
                },
                "{body}"
            );
            // Not done while attempts remain: a tag may still be added.
            assert_eq!(fx.status("r1").await, "queued");
            now += delay;
        }
        assert_eq!(step_once(&fx, &handler, now).await, Step::GaveUp);

        assert_eq!(fx.status("r1").await, "failed");
        assert_eq!(
            last_error(&fx, "r1").await.as_deref(),
            Some("digest has no tags to sync")
        );
        assert_eq!(handler.gave_up.load(Ordering::SeqCst), 1);
        assert!(fx.children().await.is_empty());
    }
}

/// A digest that had no tags when it was scanned and gets one later is not lost: the resolve
/// job fails visibly, and the next poll queues the new pair (`specs/integrations.md`, Polling).
#[tokio::test]
async fn after_a_zero_tag_failure_a_tag_added_later_is_queued_by_the_poller() {
    let fx = Fixture::new("zero-then-poll").await;
    let harbor = FakeHarbor::answering(200, r#"{"digest":"x","tags":[]}"#);
    let job = fx.resolve_job("r1", "m1", "running").await;
    assert_eq!(
        fx.run(&harbor, &job).await,
        JobOutcome::Failed(MSG_NO_TAGS.to_owned())
    );
    assert!(fx.children().await.is_empty());

    // The tag is added. The poller lists the artifact with it (later pages are empty).
    let list = format!(
        r#"[{{"digest":"{DIGEST}","tags":[{{"name":"late","push_time":"2026-11-05T12:00:00Z"}}]}}]"#
    );
    struct ListHarbor(String);
    impl HarborFetch for ListHarbor {
        async fn fetch(
            &self,
            url: &Url,
            _username: &str,
            _secret: &[u8],
            _extra_headers: &[(&str, &str)],
        ) -> Result<HarborReply, AppError> {
            let first = url.query().unwrap_or_default().starts_with("page=1&");
            let body = if first {
                self.0.clone()
            } else {
                "[]".to_owned()
            };
            Ok(HarborReply::new(200, body.into_bytes()))
        }
    }
    crate::services::poller::poll_once(&fx.pool, &key(), &ListHarbor(list), 2_000)
        .await
        .unwrap();

    let queued: Vec<(String, String)> = sqlx::query_as(
        "SELECT mapping_id, payload FROM sync_jobs WHERE json_extract(payload, '$.tag') = 'late'",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    let for_m1: Vec<&(String, String)> = queued.iter().filter(|(m, _)| m == "m1").collect();
    assert_eq!(for_m1.len(), 1);
    let payload: serde_json::Value = serde_json::from_str(&for_m1[0].1).unwrap();
    assert_eq!(payload["digest"], DIGEST);
    assert_eq!(payload["trigger"], "poll");
}

#[tokio::test]
async fn a_bad_digest_in_a_resolve_payload_is_permanent_with_no_harbor_or_credential_use() {
    let fx = Fixture::new("bad-digest").await;
    // Make the credential unusable: if the handler decrypted it, the outcome would be a
    // retryable failure, not Permanent. A digest that is bad never gets that far.
    sqlx::query("UPDATE user_credentials SET encrypted_token = 'v1:garbage' WHERE id = 'c1'")
        .execute(&fx.pool)
        .await
        .unwrap();
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));
    let upper = format!("sha256:{}", "A".repeat(64));
    for bad in [
        "sha256:aaaa",
        upper.as_str(),
        "../../etc/passwd",
        "sha256:",
        "",
    ] {
        for mapping in ["m1", "no-such-mapping"] {
            let job = ClaimedJob {
                id: "r1".to_owned(),
                mapping_id: mapping.to_owned(),
                attempts: 0,
                payload: serde_json::json!({"kind":"resolve","digest":bad}).to_string(),
            };
            assert_eq!(
                fx.run(&harbor, &job).await,
                JobOutcome::Permanent(MSG_BAD_DIGEST.to_owned()),
                "{bad}"
            );
        }
    }
    // No digest at all, and a payload that is not JSON, are permanent too.
    for payload in [r#"{"kind":"resolve"}"#, "not json", r#"{"digest":5}"#] {
        let job = ClaimedJob {
            id: "r1".to_owned(),
            mapping_id: "m1".to_owned(),
            attempts: 0,
            payload: payload.to_owned(),
        };
        assert_eq!(
            fx.run(&harbor, &job).await,
            JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned())
        );
    }
    assert!(harbor.calls().is_empty(), "no Harbor call");
}

#[tokio::test]
async fn a_sentinel_in_the_harbor_body_never_reaches_a_payload_or_last_error() {
    let fx = Fixture::new("sentinel").await;
    // A success whose body carries the sentinel in a tag name that is dropped and in fields the
    // resolve does not read.
    let harbor = FakeHarbor::answering(
        200,
        &artifact_body(&[("ok", at(1)), (&format!("{SENTINEL} bad"), at(2))]),
    );
    let job = fx.resolve_job("r1", "m1", "running").await;
    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);
    // Each failure path with the sentinel in the body.
    for status in [500, 404, 401, 429, 302] {
        harbor.set(Answer::Reply {
            status,
            body: SENTINEL.to_owned(),
            retry_after: None,
        });
        let _ = fx
            .run(
                &harbor,
                &fx.resolve_job(&format!("f{status}"), "m1", "running").await,
            )
            .await;
    }
    let handler = fx.handler(&harbor);
    harbor.set(Answer::Reply {
        status: 500,
        body: SENTINEL.to_owned(),
        retry_after: None,
    });
    fx.resolve_job("r9", "m1", "queued").await;
    let _ = step_once(&fx, &handler, 1_000).await;

    let stored: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT payload, last_error FROM sync_jobs")
            .fetch_all(&fx.pool)
            .await
            .unwrap();
    assert!(!stored.is_empty());
    for (payload, error) in stored {
        assert!(!payload.contains(SENTINEL));
        assert!(!error.unwrap_or_default().contains(SENTINEL));
    }
    assert_eq!(fx.tags_queued().await, vec!["ok"]);
}

// ---- tenancy and the URL ---------------------------------------------------------------

#[tokio::test]
async fn the_resolve_job_reads_only_its_own_mappings_credential() {
    let fx = Fixture::new("tenancy").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));

    let one = fx.resolve_job("r1", "m1", "running").await;
    assert_eq!(fx.run(&harbor, &one).await, JobOutcome::Done);
    let two = fx.resolve_job("r2", "m2", "running").await;
    assert_eq!(fx.run(&harbor, &two).await, JobOutcome::Done);

    let calls = harbor.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (calls[0].1.as_str(), calls[0].2.as_str()),
        ("robot$one", "secret-one")
    );
    assert_eq!(
        (calls[1].1.as_str(), calls[1].2.as_str()),
        ("robot$two", "secret-two")
    );
}

#[tokio::test]
async fn a_mapping_whose_credential_belongs_to_another_user_gives_the_gone_message_and_no_call() {
    let fx = Fixture::new("tenancy-foreign").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));
    // m3 belongs to u2 but points at u1's credential c1.
    let job = fx.resolve_job("r3", "m3", "running").await;

    assert_eq!(
        fx.run(&harbor, &job).await,
        JobOutcome::Failed(MSG_GONE.to_owned())
    );
    assert!(harbor.calls().is_empty(), "u1's secret was never used");
    assert!(fx.children().await.is_empty());
}

#[tokio::test]
async fn the_url_comes_from_the_mapping_never_from_the_payload_repository() {
    let fx = Fixture::new("url").await;
    let harbor = FakeHarbor::answering(200, &artifact_body(&[("v1", at(1))]));
    let payload = format!(
        r#"{{"kind":"resolve","repo_full_name":"evil/elsewhere","digest":"{DIGEST}","harbor_project":"evil"}}"#
    );
    sqlx::query(
        "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
         VALUES ('r1', 'm1', 'running', 0, ?, 1000, 1000)",
    )
    .bind(&payload)
    .execute(&fx.pool)
    .await
    .unwrap();
    let job = ClaimedJob {
        id: "r1".to_owned(),
        mapping_id: "m1".to_owned(),
        attempts: 0,
        payload,
    };

    assert_eq!(fx.run(&harbor, &job).await, JobOutcome::Done);

    let calls = harbor.calls();
    assert_eq!(
        calls[0].0,
        format!(
            "/api/v2.0/projects/proj/repositories/app/artifacts/{}",
            DIGEST.replace(':', "%3A")
        )
    );
    // The children name the mapping's repository too.
    assert_eq!(fx.children().await[0]["repo_full_name"], "proj/app");
}

// ---- rate limit ------------------------------------------------------------------------

#[tokio::test]
async fn a_429_with_retry_after_defers_the_job_by_that_many_seconds_without_using_an_attempt() {
    let fx = Fixture::new("rate-header").await;
    let harbor = FakeHarbor::answering(200, "");
    harbor.set(Answer::Reply {
        status: 429,
        body: SENTINEL.to_owned(),
        retry_after: Some(252),
    });
    let handler = fx.handler(&harbor);
    queued_resolve(&fx).await;

    let step = step_once(&fx, &handler, 1_000).await;

    assert_eq!(
        step,
        Step::Deferred {
            next_attempt_at: 1_252
        }
    );
    let (status, attempts, error): (String, i64, Option<String>) =
        sqlx::query_as("SELECT status, attempts, last_error FROM sync_jobs WHERE id = 'r1'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(status, "queued");
    assert_eq!(attempts, 0, "a deferral does not count");
    assert_eq!(error, None);
    assert_eq!(handler.gave_up.load(Ordering::SeqCst), 0);
    // Not due before the wait ends, due after.
    assert_eq!(step_once(&fx, &handler, 1_251).await, Step::Idle);
    assert_eq!(
        step_once(&fx, &handler, 1_252).await,
        Step::Deferred {
            next_attempt_at: 1_252 + 252
        }
    );
}

#[tokio::test]
async fn a_429_with_no_retry_after_defers_five_minutes() {
    let fx = Fixture::new("rate-no-header").await;
    let harbor = FakeHarbor::answering(429, SENTINEL);
    let handler = fx.handler(&harbor);
    queued_resolve(&fx).await;

    let step = step_once(&fx, &handler, 1_000).await;

    assert_eq!(
        step,
        Step::Deferred {
            next_attempt_at: 1_300
        }
    );
    let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM sync_jobs WHERE id = 'r1'")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(attempts, 0);
}

#[tokio::test]
async fn a_retry_after_above_one_hour_is_capped_at_one_hour() {
    for seconds in [3_601u64, 7_200, u64::MAX] {
        let fx = Fixture::new("rate-cap").await;
        let harbor = FakeHarbor::answering(200, "");
        harbor.set(Answer::Reply {
            status: 429,
            body: String::new(),
            retry_after: Some(seconds),
        });
        let handler = fx.handler(&harbor);
        queued_resolve(&fx).await;

        let step = step_once(&fx, &handler, 1_000).await;

        assert_eq!(
            step,
            Step::Deferred {
                next_attempt_at: 1_000 + 3_600
            },
            "Retry-After {seconds}"
        );
    }
}

#[tokio::test]
async fn many_rate_limits_never_give_the_job_up() {
    let fx = Fixture::new("rate-many").await;
    let harbor = FakeHarbor::answering(429, "");
    let handler = fx.handler(&harbor);
    queued_resolve(&fx).await;

    let mut now = 1_000;
    for _ in 0..12 {
        let Step::Deferred { next_attempt_at } = step_once(&fx, &handler, now).await else {
            panic!("a rate limit defers");
        };
        now = next_attempt_at;
    }
    assert_eq!(fx.status("r1").await, "queued");
    assert_eq!(handler.gave_up.load(Ordering::SeqCst), 0);
}

#[test]
fn the_default_wait_is_five_minutes_and_the_cap_is_one_hour() {
    assert_eq!(DEFAULT_RATE_LIMIT_WAIT_SECS, 300);
    assert_eq!(MAX_DEFERRAL_SECS, 3_600);
    assert_eq!(MAX_TAGS_PER_DIGEST, 10);
}
