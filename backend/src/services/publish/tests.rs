//! Tests of the publish hook and the publish job against the real migrated schema
//! (`specs/spinoff-local-scan.md`, section 16: publish, SARIF and issues). GitHub is the fake of
//! the issue tests: no request leaves the process. Layouts are small directories with an
//! `index.json`, a manifest and a config holding `config.Labels`.

use std::collections::VecDeque;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sqlx::SqlitePool;

use super::*;
use crate::auth::crypto::{self, credentials_key, encrypt as seal_for_test};
use crate::config;
use crate::db;
use crate::services::issue_lifecycle::test_support::{FakeGithub, FakeIssues};
use crate::services::scan::convert;
use crate::worker::JobHandler;

const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const NOW: i64 = 1_800_000_000;
const REV_1: &str = "0123456789abcdef0123456789abcdef01234567";
const REV_2: &str = "fedcba9876543210fedcba9876543210fedcba98";

/// A GitHub token no log, job row or report may hold, and a response body no text may hold.
const CANARY_TOKEN: &str = "ghp_CANARYTOKEN_7f3a9c1d";
const CANARY_BODY: &str = "CANARY_RESPONSE_BODY_4e8b2";

const IMG_1: &str = "000000000000000000000000000000a1";
const IMG_2: &str = "000000000000000000000000000000a2";
const IMG_3: &str = "000000000000000000000000000000a3";
const P_1: &str = "000000000000000000000000000000b1";
const P_2: &str = "000000000000000000000000000000b2";
const P_3: &str = "000000000000000000000000000000b3";
const P_4: &str = "000000000000000000000000000000b4";
const P_5: &str = "000000000000000000000000000000b5";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A sleeper that returns at once.
struct NoSleep;

impl Clock for NoSleep {
    fn now(&self) -> i64 {
        NOW
    }

    async fn sleep(&self, _duration: Duration) {}
}

/// Records uploads and answers statuses from a queue; an empty queue answers `Complete`.
#[derive(Default)]
struct FakeScanning {
    uploads: Mutex<Vec<Value>>,
    upload_error: Mutex<Option<ScanError>>,
    statuses: Mutex<VecDeque<Result<Processing, ScanError>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl FakeScanning {
    fn uploads(&self) -> Vec<Value> {
        lock(&self.uploads).clone()
    }
}

impl CodeScanning for Arc<FakeScanning> {
    async fn upload(
        &self,
        token: &[u8],
        fields: &Upload<'_>,
        _now: i64,
    ) -> Result<String, ScanError> {
        assert_eq!(token, CANARY_TOKEN.as_bytes(), "the stored token is passed");
        if let Some(error) = lock(&self.upload_error).clone() {
            return Err(error);
        }
        let gz = STANDARD
            .decode(fields.sarif_b64)
            .unwrap_or_else(|err| panic!("sarif base64: {err}"));
        let mut text = String::new();
        if let Err(err) = GzDecoder::new(gz.as_slice()).read_to_string(&mut text) {
            panic!("sarif gzip: {err}");
        }
        let sarif: Value =
            serde_json::from_str(&text).unwrap_or_else(|err| panic!("sarif json: {err}"));
        let mut uploads = lock(&self.uploads);
        uploads.push(json!({
            "owner": fields.owner,
            "repo": fields.repo,
            "commit_sha": fields.commit_sha,
            "ref": fields.git_ref,
            "sarif": sarif,
        }));
        Ok(format!("sarif-{}", uploads.len()))
    }

    async fn status(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        _sarif_id: &str,
        _now: i64,
    ) -> Result<Processing, ScanError> {
        lock(&self.statuses)
            .pop_front()
            .unwrap_or(Ok(Processing::Complete))
    }
}

type TestPublisher = Publisher<Arc<FakeScanning>, FakeIssues, NoSleep>;

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
    store: StoreRoot,
    github: Arc<FakeGithub>,
    scanning: Arc<FakeScanning>,
    publisher: TestPublisher,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn key() -> Arc<DerivedKey> {
    let root = config::parse_encryption_key(ROOT).unwrap_or_else(|err| panic!("key: {err:?}"));
    Arc::new(credentials_key(&root).unwrap_or_else(|err| panic!("derive: {err:?}")))
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
    query
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("count: {err}"))
}

/// One finding of a run: CVE id, package, severity.
type Found = (&'static str, &'static str, &'static str);

impl Fx {
    /// A migrated database with user `u1`, the GitHub credential `c1` (token [`CANARY_TOKEN`]),
    /// and two sources on `ghcr.io/o/app` that target `octo/app`: `s1` (tag value `v1`) and `s2`
    /// (tag value `latest`). Neither observes an image yet.
    async fn new(name: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dockward-publish-{name}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("dir: {err}");
        }
        let pool = db::open(&dir)
            .await
            .unwrap_or_else(|err| panic!("db: {err:?}"));
        let derived = key();
        let sealed = seal_for_test(
            &derived,
            &crypto::aad("user_credentials", "encrypted_token", "c1"),
            CANARY_TOKEN.as_bytes(),
        )
        .unwrap_or_else(|err| panic!("seal: {err:?}"));
        exec(
            &pool,
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('u1', 'u1', NULL, 'user', 0)",
            &[],
        )
        .await;
        exec(
            &pool,
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('c1', 'u1', 'g', ?)",
            &[&sealed],
        )
        .await;
        for (id, tag) in [("s1", "v1"), ("s2", "latest")] {
            exec(
                &pool,
                "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value,
                     github_cred_id, github_owner, github_repo, auto_create_issues,
                     min_issue_severity)
                 VALUES (?, 'u1', 'hub-default-ghcr', 'o/app', ?, 'c1', 'octo', 'app', 1,
                         'CRITICAL')",
                &[id, tag],
            )
            .await;
        }
        let store = StoreRoot::at(dir.join("images"));
        let github = Arc::new(FakeGithub::default());
        let scanning = Arc::new(FakeScanning::default());
        let publisher = Publisher::with_parts(
            pool.clone(),
            derived,
            store.clone(),
            scanning.clone(),
            FakeIssues(github.clone()),
            NoSleep,
        );
        Self {
            pool,
            dir,
            store,
            github,
            scanning,
            publisher,
        }
    }

    async fn image(&self, id: &str) {
        exec(
            &self.pool,
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES (?, 'hub-default-ghcr', 'o/app', ?, 1)",
            &[id, &format!("sha256:{id}")],
        )
        .await;
    }

    /// A stored platform with a layout whose config holds `labels`.
    async fn platform(&self, id: &str, image: &str, platform: &str, labels: &[(&str, &str)]) {
        exec(
            &self.pool,
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
             VALUES (?, ?, ?, ?, 'stored', 1)",
            &[id, image, platform, &format!("sha256:{id}")],
        )
        .await;
        self.layout(id, labels);
    }

    fn layout(&self, id: &str, labels: &[(&str, &str)]) {
        let root = self.store.root().join(id);
        let blobs = root.join("blobs/sha256");
        if let Err(err) = std::fs::create_dir_all(&blobs) {
            panic!("layout: {err}");
        }
        let config_hex = "c".repeat(64);
        let manifest_hex = "d".repeat(64);
        let label_map: serde_json::Map<String, Value> = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), json!(v)))
            .collect();
        let files = [
            (
                blobs.join(&config_hex),
                json!({"config": {"Labels": label_map}}),
            ),
            (
                blobs.join(&manifest_hex),
                json!({"config": {"digest": format!("sha256:{config_hex}")}}),
            ),
            (
                root.join("index.json"),
                json!({"manifests": [{"digest": format!("sha256:{manifest_hex}")}]}),
            ),
        ];
        for (path, body) in files {
            if let Err(err) = std::fs::write(&path, body.to_string()) {
                panic!("layout file: {err}");
            }
        }
    }

    async fn observe(&self, source: &str, tag: &str, image: &str, first_seen: i64) {
        let at = first_seen.to_string();
        exec(
            &self.pool,
            "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?)",
            &[source, tag, image, &at, &at],
        )
        .await;
    }

    /// A scan run with its findings. A `done` run is `finished` at that time.
    async fn run(&self, platform: &str, scanner: &str, status: &str, finished: i64, f: &[Found]) {
        let id = format!("run-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
        let at = finished.to_string();
        exec(
            &self.pool,
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES (?, ?, ?, 'first_pull', ?, ?)",
            &[&id, platform, scanner, status, &at],
        )
        .await;
        for (cve, package, severity) in f {
            exec(
                &self.pool,
                "INSERT INTO scanner_findings (run_id, cve_id, package, severity)
                 VALUES (?, ?, ?, ?)",
                &[&id, cve, package, severity],
            )
            .await;
        }
    }

    /// Recomputes the merged `cve_findings` of the tags of `image`, as the scan job does.
    async fn recompute(&self, image: &str) {
        let mut conn = self
            .pool
            .acquire()
            .await
            .unwrap_or_else(|err| panic!("conn: {err}"));
        if let Err(err) = convert::recompute_image(&mut conn, image, NOW).await {
            panic!("recompute: {err:?}");
        }
    }

    /// An image with one amd64 platform on which both scanners finished, with `found`.
    async fn finished_image(
        &self,
        image: &str,
        platform: &str,
        labels: &[(&str, &str)],
        f: &[Found],
    ) {
        self.image(image).await;
        self.platform(platform, image, "linux/amd64", labels).await;
        self.run(platform, "trivy", "done", 10, f).await;
        self.run(platform, "grype", "done", 11, f).await;
    }

    async fn queue(&self, image: &str) -> usize {
        queue_publish(&self.pool, image, NOW)
            .await
            .unwrap_or_else(|err| panic!("queue: {err:?}"))
    }

    async fn publish_jobs(&self) -> i64 {
        count(
            &self.pool,
            "SELECT COUNT(*) FROM jobs WHERE json_extract(payload, '$.kind') = 'publish'",
            &[],
        )
        .await
    }

    /// Claims and runs every due job, and returns `(source, outcome)` in order.
    async fn drain(&self) -> Vec<(String, JobOutcome)> {
        let mut outcomes = Vec::new();
        loop {
            let claimed = db::jobs::claim_next(&self.pool, NOW)
                .await
                .unwrap_or_else(|err| panic!("claim: {err:?}"));
            let Some(job) = claimed else {
                break;
            };
            let outcome = self.publisher.run(&job).await;
            if let Err(err) = db::jobs::mark_done(&self.pool, &job.id, NOW).await {
                panic!("mark: {err:?}");
            }
            outcomes.push((job.source_id.clone().unwrap_or_default(), outcome));
        }
        outcomes
    }

    fn open_issues(&self) -> usize {
        self.github
            .with(|state| state.issues.iter().filter(|issue| issue.open).count())
    }

    fn all_issues(&self) -> usize {
        self.github.with(|state| state.issues.len())
    }
}

fn labels_ok() -> Vec<(&'static str, &'static str)> {
    vec![
        (labels::LABEL_REVISION, REV_1),
        (labels::LABEL_SOURCE, "https://github.com/octo/app"),
    ]
}

fn category(upload: &Value) -> String {
    let id = upload["sarif"]["runs"][0]["automationDetails"]["id"]
        .as_str()
        .unwrap_or_default();
    id.rsplit_once('/')
        .map(|(category, _)| category.to_owned())
        .unwrap_or_default()
}

/// The vendored OASIS SARIF 2.1.0 schema (errata 01), draft-04: the same check as the
/// converter's own tests (`sarif-validate`).
fn assert_schema_valid(doc: &Value) {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../tests/schemas/sarif-schema-2.1.0.json"
    ))
    .unwrap_or_else(|err| panic!("schema json: {err}"));
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft4)
        .build(&schema)
        .unwrap_or_else(|err| panic!("schema compile: {err}"));
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|err| format!("{err} (at {})", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "SARIF failed schema validation:\n{}",
        errors.join("\n")
    );
}

/// The hook queues one job when every scan and pull of the newest image has ended, never for an
/// older image, and never twice.
#[tokio::test]
async fn the_hook_queues_one_publish_job_for_the_newest_image_when_all_has_ended() {
    let fx = Fx::new("hook").await;
    fx.image(IMG_1).await;
    fx.platform(P_1, IMG_1, "linux/amd64", &labels_ok()).await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.run(P_1, "trivy", "done", 10, &[]).await;
    fx.run(P_1, "grype", "queued", 0, &[]).await;
    assert_eq!(fx.queue(IMG_1).await, 0, "a queued scan holds the publish");
    exec(
        &fx.pool,
        "UPDATE scan_runs SET status = 'done' WHERE status = 'queued'",
        &[],
    )
    .await;

    // A second platform that is still waiting to be pulled holds it too.
    exec(
        &fx.pool,
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
         VALUES (?, ?, 'linux/arm64', 'sha256:arm', 'queued')",
        &[P_2, IMG_1],
    )
    .await;
    assert_eq!(
        fx.queue(IMG_1).await,
        0,
        "a platform not yet pulled holds it"
    );
    exec(
        &fx.pool,
        "UPDATE image_platforms SET state = 'stored' WHERE id = ?",
        &[P_2],
    )
    .await;
    fx.run(P_2, "trivy", "done", 12, &[]).await;
    fx.run(P_2, "grype", "failed", 13, &[]).await;

    assert_eq!(fx.queue(IMG_1).await, 1, "a failed run does not hold it");
    assert_eq!(fx.queue(IMG_1).await, 0, "an open job is not queued twice");
    assert_eq!(fx.publish_jobs().await, 1);

    // An image the tag moved away from uploads nothing.
    fx.finished_image(IMG_2, P_3, &labels_ok(), &[]).await;
    fx.observe("s1", "v1", IMG_2, 200).await;
    assert_eq!(fx.queue(IMG_2).await, 1, "the new image is now the newest");
    assert_eq!(
        fx.queue(IMG_1).await,
        0,
        "the older image publishes nothing"
    );
}

/// Only the legacy HarborGate branch label is set: the upload goes to that branch, not to the
/// source's default branch.
#[tokio::test]
async fn the_legacy_branch_label_alone_sets_the_upload_ref() {
    let fx = Fx::new("legacy-branch").await;
    fx.image(IMG_1).await;
    fx.platform(
        P_1,
        IMG_1,
        "linux/amd64",
        &[
            (labels::LABEL_REVISION, REV_1),
            (labels::LABEL_SOURCE, "https://github.com/octo/app"),
            (labels::LEGACY_LABEL_BRANCH, "legacy-release"),
        ],
    )
    .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.run(P_1, "trivy", "done", 10, &[]).await;
    fx.run(P_1, "grype", "done", 11, &[]).await;
    fx.recompute(IMG_1).await;
    assert_eq!(fx.queue(IMG_1).await, 1);
    assert_eq!(fx.drain().await, vec![("s1".to_owned(), JobOutcome::Done)]);

    let uploads = fx.scanning.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0]["ref"], "refs/heads/legacy-release");
}

/// One merged SARIF per source: one result per (CVE id, package) with the scanner and platform
/// properties, the category and location on the hub host and the repository, valid SARIF 2.1.0,
/// and the labels read from the first scanned platform.
#[tokio::test]
async fn the_sarif_is_merged_valid_and_uploaded_under_the_hub_category() {
    let fx = Fx::new("sarif").await;
    fx.image(IMG_1).await;
    let mut second = labels_ok();
    second[0] = (labels::LABEL_REVISION, REV_2);
    fx.platform(
        P_1,
        IMG_1,
        "linux/amd64",
        &[
            (labels::LABEL_REVISION, REV_1),
            (labels::LABEL_SOURCE, "https://github.com/octo/app"),
            (labels::LABEL_BRANCH, "release"),
        ],
    )
    .await;
    fx.platform(P_2, IMG_1, "linux/arm64", &second).await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    let zlib: Found = ("CVE-2026-0001", "zlib", "CRITICAL");
    let libc: Found = ("CVE-2026-0002", "libc", "HIGH");
    fx.run(P_1, "trivy", "done", 10, &[zlib]).await;
    fx.run(P_1, "grype", "done", 11, &[zlib]).await;
    fx.run(P_2, "trivy", "done", 20, &[zlib, libc]).await;
    fx.run(P_2, "grype", "done", 21, &[]).await;
    fx.recompute(IMG_1).await;

    assert_eq!(fx.queue(IMG_1).await, 1);
    let outcomes = fx.drain().await;
    assert_eq!(outcomes, vec![("s1".to_owned(), JobOutcome::Done)]);

    let uploads = fx.scanning.uploads();
    assert_eq!(uploads.len(), 1);
    let upload = &uploads[0];
    assert_eq!(
        upload["commit_sha"], REV_1,
        "the first scanned platform's labels"
    );
    assert_eq!(upload["ref"], "refs/heads/release");
    assert_eq!(
        (upload["owner"].as_str(), upload["repo"].as_str()),
        (Some("octo"), Some("app"))
    );
    let sarif = &upload["sarif"];
    assert_schema_valid(sarif);
    assert_eq!(category(upload), "dockward/ghcr.io/o/app/v1");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "Dockward");

    let results = sarif["runs"][0]["results"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        results.len(),
        2,
        "one result per CVE and package, never per scanner"
    );
    for result in &results {
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "ghcr.io/o/app"
        );
    }
    let zlib_result = results.iter().find(|r| r["ruleId"] == "CVE-2026-0001");
    let props = zlib_result
        .map(|r| r["properties"].clone())
        .unwrap_or(Value::Null);
    assert_eq!(props[sarif::SCANNER_COUNT_KEY], 2);
    assert_eq!(props[sarif::SCANNER_NAMES_KEY], json!(["Grype", "Trivy"]));
    assert_eq!(
        props[sarif::PLATFORMS_KEY],
        json!(["linux/amd64", "linux/arm64"])
    );
    let libc_result = results.iter().find(|r| r["ruleId"] == "CVE-2026-0002");
    let props = libc_result
        .map(|r| r["properties"].clone())
        .unwrap_or(Value::Null);
    assert_eq!(props[sarif::SCANNER_COUNT_KEY], 1);
    assert_eq!(props[sarif::PLATFORMS_KEY], json!(["linux/arm64"]));

    let report: (String, Option<String>, Option<String>, String, String) = sqlx::query_as(
        "SELECT sarif_status, github_sarif_id, commit_sha, image_tag, image_digest
         FROM publish_reports WHERE source_id = 's1'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap_or_else(|err| panic!("report: {err}"));
    assert_eq!(report.0, "success");
    assert_eq!(report.1.as_deref(), Some("sarif-1"));
    assert_eq!(report.2.as_deref(), Some(REV_1));
    assert_eq!(
        (report.3.as_str(), report.4.as_str()),
        ("v1", "sha256:000000000000000000000000000000a1")
    );
    // The CRITICAL CVE got its issue with the marker.
    assert_eq!(fx.open_issues(), 1);
    let body = fx.github.with(|state| state.issues[0].body.clone());
    assert!(body.starts_with("<!-- dockward:CVE-2026-0001 -->"));
}

/// Two tags of one repository get two categories, and sources that target one GitHub repository
/// share one issue per CVE, which closes only when no source reports the CVE.
#[tokio::test]
async fn two_tags_get_two_categories_and_two_sources_share_one_issue() {
    let fx = Fx::new("shared").await;
    fx.finished_image(
        IMG_1,
        P_1,
        &labels_ok(),
        &[("CVE-2026-0001", "zlib", "CRITICAL")],
    )
    .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.observe("s2", "latest", IMG_1, 100).await;
    fx.recompute(IMG_1).await;

    assert_eq!(fx.queue(IMG_1).await, 2, "one job per source");
    let outcomes = fx.drain().await;
    assert!(
        outcomes
            .iter()
            .all(|(_, outcome)| *outcome == JobOutcome::Done)
    );
    let uploads = fx.scanning.uploads();
    let mut categories: Vec<String> = uploads.iter().map(category).collect();
    categories.sort();
    assert_eq!(
        categories,
        ["dockward/ghcr.io/o/app/latest", "dockward/ghcr.io/o/app/v1"],
        "two tags of one repository never share a category"
    );
    assert_eq!(
        fx.all_issues(),
        1,
        "one issue per GitHub repository and CVE"
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM github_issues WHERE cve_id = 'CVE-2026-0001'",
            &[]
        )
        .await,
        1
    );

    // The tag v1 moves to a clean image. The other source still reports the CVE: no close.
    fx.finished_image(IMG_2, P_2, &labels_ok(), &[]).await;
    fx.observe("s1", "v1", IMG_2, 200).await;
    fx.recompute(IMG_2).await;
    assert_eq!(fx.queue(IMG_2).await, 1);
    fx.drain().await;
    assert_eq!(
        fx.open_issues(),
        1,
        "a source that still reports the CVE keeps the issue open"
    );

    // The other tag moves to a clean image too: no source reports the CVE, the issue closes.
    fx.finished_image(IMG_3, P_3, &labels_ok(), &[]).await;
    fx.observe("s2", "latest", IMG_3, 300).await;
    fx.recompute(IMG_3).await;
    assert_eq!(fx.queue(IMG_3).await, 1);
    fx.drain().await;
    assert_eq!(
        fx.open_issues(),
        0,
        "closed when no source of the repository reports it"
    );
    assert_eq!(fx.all_issues(), 1);
}

/// A failed scanner, a failed platform and a platform that was never scanned each upload the
/// SARIF but never close an issue.
#[tokio::test]
async fn a_failed_scanner_or_platform_never_closes_an_issue() {
    let fx = Fx::new("failed").await;
    fx.finished_image(
        IMG_1,
        P_1,
        &labels_ok(),
        &[("CVE-2026-0001", "zlib", "CRITICAL")],
    )
    .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.recompute(IMG_1).await;
    fx.queue(IMG_1).await;
    fx.drain().await;
    assert_eq!(fx.open_issues(), 1);
    let uploads_before = fx.scanning.uploads().len();

    // A newer image: Trivy finds nothing and Grype failed.
    fx.image(IMG_2).await;
    fx.platform(P_3, IMG_2, "linux/amd64", &labels_ok()).await;
    fx.run(P_3, "trivy", "done", 10, &[]).await;
    fx.run(P_3, "grype", "failed", 11, &[]).await;
    fx.observe("s1", "v1", IMG_2, 200).await;
    fx.recompute(IMG_2).await;
    assert_eq!(
        fx.queue(IMG_2).await,
        1,
        "a failed run does not hold the SARIF back"
    );
    let outcomes = fx.drain().await;
    assert_eq!(outcomes, vec![("s1".to_owned(), JobOutcome::Done)]);
    assert_eq!(fx.scanning.uploads().len(), uploads_before + 1);
    assert_eq!(
        fx.open_issues(),
        1,
        "a failed scanner never closes an issue"
    );

    // A newer image of two platforms: one scanned clean by both, one whose pull failed.
    fx.image(IMG_3).await;
    fx.platform(P_4, IMG_3, "linux/amd64", &labels_ok()).await;
    fx.run(P_4, "trivy", "done", 10, &[]).await;
    fx.run(P_4, "grype", "done", 11, &[]).await;
    exec(
        &fx.pool,
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
         VALUES (?, ?, 'linux/arm64', 'sha256:arm', 'failed')",
        &[P_5, IMG_3],
    )
    .await;
    fx.observe("s1", "v1", IMG_3, 300).await;
    fx.recompute(IMG_3).await;
    assert_eq!(fx.queue(IMG_3).await, 1);
    fx.drain().await;
    assert_eq!(
        fx.open_issues(),
        1,
        "a failed platform never closes an issue"
    );

    // The same image once every platform has a result: the issue closes.
    exec(
        &fx.pool,
        "UPDATE image_platforms SET state = 'stored', pulled_at = 1 WHERE id = ?",
        &[P_5],
    )
    .await;
    fx.layout(P_5, &labels_ok());
    fx.run(P_5, "trivy", "done", 20, &[]).await;
    fx.run(P_5, "grype", "done", 21, &[]).await;
    fx.recompute(IMG_3).await;
    assert_eq!(fx.queue(IMG_3).await, 1);
    fx.drain().await;
    assert_eq!(fx.open_issues(), 0);
}

/// A missing revision label and a source label for another repository fail the publish for good
/// with the clear text, and upload nothing.
#[tokio::test]
async fn a_missing_revision_or_a_wrong_source_label_fails_the_publish() {
    let fx = Fx::new("labels").await;
    fx.finished_image(IMG_1, P_1, &[], &[("CVE-2026-0001", "zlib", "HIGH")])
        .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.recompute(IMG_1).await;
    fx.queue(IMG_1).await;
    assert_eq!(
        fx.drain().await,
        vec![(
            "s1".to_owned(),
            JobOutcome::Permanent(labels::MSG_NO_REVISION.to_owned())
        )]
    );

    fx.finished_image(
        IMG_2,
        P_2,
        &[
            (labels::LABEL_REVISION, REV_1),
            (labels::LABEL_SOURCE, "https://github.com/octo/other"),
        ],
        &[],
    )
    .await;
    fx.observe("s1", "v1", IMG_2, 200).await;
    fx.queue(IMG_2).await;
    assert_eq!(
        fx.drain().await,
        vec![(
            "s1".to_owned(),
            JobOutcome::Permanent(labels::MSG_SOURCE_MISMATCH.to_owned())
        )]
    );
    assert!(fx.scanning.uploads().is_empty());
    assert_eq!(fx.all_issues(), 0);
}

/// A job whose image stopped being the newest while it waited uploads nothing.
#[tokio::test]
async fn an_image_that_is_no_longer_the_newest_uploads_nothing() {
    let fx = Fx::new("stale").await;
    fx.finished_image(
        IMG_1,
        P_1,
        &labels_ok(),
        &[("CVE-2026-0001", "zlib", "HIGH")],
    )
    .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.recompute(IMG_1).await;
    assert_eq!(fx.queue(IMG_1).await, 1);
    fx.finished_image(IMG_2, P_2, &labels_ok(), &[]).await;
    fx.observe("s1", "v1", IMG_2, 200).await;
    assert_eq!(
        fx.drain().await,
        vec![(
            "s1".to_owned(),
            JobOutcome::DoneWithNote(messages::NOT_NEWEST.to_owned())
        )]
    );
    assert!(fx.scanning.uploads().is_empty());
}

/// A wait that ends with GitHub still processing fails the attempt, and the retry polls the same
/// upload instead of uploading again.
#[tokio::test]
async fn a_pending_upload_is_polled_again_never_uploaded_twice() {
    let fx = Fx::new("pending").await;
    fx.finished_image(
        IMG_1,
        P_1,
        &labels_ok(),
        &[("CVE-2026-0001", "zlib", "HIGH")],
    )
    .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.recompute(IMG_1).await;
    fx.queue(IMG_1).await;
    lock(&fx.scanning.statuses).extend((0..40).map(|_| Ok(Processing::Pending)));
    let job = db::jobs::claim_next(&fx.pool, NOW)
        .await
        .unwrap_or_else(|err| panic!("claim: {err:?}"))
        .unwrap_or_else(|| panic!("a publish job"));
    assert_eq!(
        fx.publisher.run(&job).await,
        JobOutcome::Failed(messages::PENDING.to_owned())
    );
    assert_eq!(fx.scanning.uploads().len(), 1);
    lock(&fx.scanning.statuses).clear();
    assert_eq!(fx.publisher.run(&job).await, JobOutcome::Done);
    assert_eq!(
        fx.scanning.uploads().len(),
        1,
        "the retry does not upload again"
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM publish_reports WHERE sarif_status = 'success'",
            &[]
        )
        .await,
        1
    );
}

/// A `JobHandler` over the publisher, so the real worker step records the outcome.
struct Handler(TestPublisher);

impl JobHandler for Handler {
    async fn run(&self, job: ClaimedJob) -> JobOutcome {
        self.0.run(&job).await
    }
}

/// A `MakeWriter` into a shared buffer.
#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl LogSink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&lock(&self.0)).into_owned()
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// No token, response body or GitHub error list reaches a log line, a job row or a report row,
/// whether GitHub refuses the upload or fails the processing. A canary token and a canary body
/// stand in for the real ones.
#[tokio::test]
async fn no_token_or_github_body_reaches_a_log_a_job_row_or_a_report() {
    let logs = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fx = Fx::new("canary").await;
    fx.finished_image(
        IMG_1,
        P_1,
        &labels_ok(),
        &[("CVE-2026-0001", "zlib", "CRITICAL")],
    )
    .await;
    fx.observe("s1", "v1", IMG_1, 100).await;
    fx.recompute(IMG_1).await;
    fx.queue(IMG_1).await;
    let publisher = Arc::new(Handler(Publisher::with_parts(
        fx.pool.clone(),
        key(),
        fx.store.clone(),
        fx.scanning.clone(),
        FakeIssues(fx.github.clone()),
        NoSleep,
    )));

    // 1. GitHub refuses the upload, with a body that holds the canary.
    let body = format!("refused: {CANARY_BODY} {CANARY_TOKEN}");
    *lock(&fx.scanning.upload_error) = Some(ScanError::Forbidden(body.clone()));
    let step = crate::worker::step(&fx.pool, &publisher, NOW).await;
    assert!(
        matches!(step, Ok(crate::worker::Step::Retry { .. })),
        "{step:?}"
    );
    let last_error: Option<String> = sqlx::query_scalar("SELECT last_error FROM jobs")
        .fetch_one(&fx.pool)
        .await
        .unwrap_or_else(|err| panic!("last_error: {err}"));
    assert_eq!(last_error.as_deref(), Some(messages::FORBIDDEN));

    // 2. GitHub accepts the upload and then fails the processing, with an error list.
    *lock(&fx.scanning.upload_error) = None;
    lock(&fx.scanning.statuses).push_back(Ok(Processing::Failed(vec![
        CANARY_BODY.to_owned(),
        CANARY_TOKEN.to_owned(),
    ])));
    exec(
        &fx.pool,
        "UPDATE jobs SET status = 'queued', next_attempt_at = 0",
        &[],
    )
    .await;
    let step = crate::worker::step(&fx.pool, &publisher, NOW).await;
    assert!(matches!(step, Ok(crate::worker::Step::GaveUp)), "{step:?}");

    // 3. A bad request, an upstream failure and a refused token: fixed text each.
    for error in [
        ScanError::Rejected(body.clone()),
        ScanError::Upstream(body.clone()),
        ScanError::Unauthorized,
    ] {
        assert!(!scan_text(error).contains(CANARY_BODY));
    }

    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT payload || ' ' || COALESCE(last_error, '') FROM jobs
         UNION ALL SELECT COALESCE(error_message, '') || ' ' || vulnerability_summary
                   FROM publish_reports",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap_or_else(|err| panic!("rows: {err}"));
    let report_error: Option<String> =
        sqlx::query_scalar("SELECT error_message FROM publish_reports")
            .fetch_one(&fx.pool)
            .await
            .unwrap_or_else(|err| panic!("report: {err}"));
    assert_eq!(report_error.as_deref(), Some(messages::PROCESSING_FAILED));
    let everything = format!("{}\n{}", stored.join("\n"), logs.text());
    for canary in [CANARY_TOKEN, CANARY_BODY, "refused:"] {
        assert!(!everything.contains(canary), "{canary} leaked");
    }
}

fn scan_text(error: ScanError) -> String {
    match scan_outcome(error) {
        JobOutcome::Failed(text) | JobOutcome::Permanent(text) => text,
        JobOutcome::Deferred { reason, .. } => reason,
        JobOutcome::Done => String::new(),
        JobOutcome::DoneWithNote(text) => text,
    }
}

/// A bad payload is refused for good and runs nothing.
#[tokio::test]
async fn a_bad_payload_is_refused() {
    let fx = Fx::new("payload").await;
    for payload in [
        r#"{"kind":"publish"}"#,
        r#"{"kind":"publish","source_id":"s1","image_id":"../x"}"#,
        r#"{"kind":"scan","source_id":"s1","image_id":"000000000000000000000000000000a1"}"#,
    ] {
        let job = ClaimedJob {
            id: "j".to_owned(),
            source_id: Some("s1".to_owned()),
            attempts: 0,
            payload: payload.to_owned(),
        };
        assert_eq!(
            fx.publisher.run(&job).await,
            JobOutcome::Permanent("job payload is not valid".to_owned()),
            "{payload}"
        );
    }
}
