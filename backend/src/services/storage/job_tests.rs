//! Tests of the `pull` job against the real migrated schema and a loopback fake registry. No
//! real registry is contacted.

use sha2::{Digest, Sha256};

use crate::db::jobs::ClaimedJob;
use crate::services::discovery::tests::{Env, Reply, env};
use crate::services::registry::manifest::OCI_MANIFEST;
use crate::services::registry::transport::sha256_digest_text;
use crate::services::storage::StoreRoot;
use crate::services::storage::job::run_pull;
use crate::services::storage::limits;
use crate::worker::JobOutcome;

const PID: &str = "0000000000000000000000000000000a";
const NOW: i64 = 1_800_000_000;

fn digest_of(bytes: &[u8]) -> String {
    sha256_digest_text(&Sha256::digest(bytes))
}

/// Publishes one image at `team/app` and returns its manifest digest. `layer_served` is what
/// the registry sends for the layer, which differs from the declared bytes to force a mismatch.
fn publish(env: &Env, layer: &[u8], layer_served: &[u8], declared_layer_size: usize) -> String {
    let config = b"{\"os\":\"linux\",\"architecture\":\"amd64\"}";
    let config_digest = digest_of(config);
    let layer_digest = digest_of(layer);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}",
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{declared_layer_size}}}]}}"#,
        config.len()
    )
    .into_bytes();
    let digest = digest_of(&manifest);
    env.script.route(
        &format!("/v2/team/app/manifests/{digest}"),
        Reply::new(200, &manifest).header("Content-Type", OCI_MANIFEST),
    );
    env.script.route(
        &format!("/v2/team/app/blobs/{config_digest}"),
        Reply::new(200, config),
    );
    env.script.route(
        &format!("/v2/team/app/blobs/{layer_digest}"),
        Reply::new(200, layer_served),
    );
    digest
}

async fn exec(env: &Env, sql: &'static str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    if let Err(err) = query.execute(&env.pool).await {
        panic!("test sql: {err}");
    }
}

async fn seed(env: &Env, digest: &str) {
    exec(
        env,
        "INSERT INTO images (id, hub_id, repository, digest, is_index, created_at)
         VALUES ('img1', 'hub-fake', 'team/app', 'sha256:aa', 0, 1)",
        &[],
    )
    .await;
    exec(
        env,
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
         VALUES (?, 'img1', 'linux/amd64', ?, 'queued')",
        &[PID, digest],
    )
    .await;
}

fn job(digest: &str) -> ClaimedJob {
    ClaimedJob {
        id: "j1".to_owned(),
        source_id: None,
        attempts: 0,
        payload: format!(
            r#"{{"kind":"pull","platform_id":"{PID}","digest":"{digest}","trigger":"first_pull"}}"#
        ),
    }
}

async fn state_of(env: &Env, id: &str) -> String {
    match sqlx::query_scalar("SELECT state FROM image_platforms WHERE id = ?")
        .bind(id)
        .fetch_one(&env.pool)
        .await
    {
        Ok(state) => state,
        Err(err) => panic!("state: {err}"),
    }
}

async fn set(env: &Env, key: &str, value: &str) {
    exec(
        env,
        "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)",
        &[key, value],
    )
    .await;
}

async fn run(env: &Env, digest: &str) -> JobOutcome {
    let store = StoreRoot::at(env.dir.join("images"));
    run_pull(&env.pool, &env.discovery, &store, &job(digest), NOW).await
}

/// True when neither a final directory nor a temporary one exists for the pull.
fn no_dirs(env: &Env) -> bool {
    let root = env.dir.join("images");
    let tmp = std::fs::read_dir(root.join(".tmp"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    !root.join(PID).exists() && tmp == 0
}

fn blob_requests(env: &Env) -> usize {
    env.script
        .hits()
        .iter()
        .filter(|hit| hit.contains("/blobs/"))
        .count()
}

#[tokio::test]
async fn a_pull_job_stores_the_image_and_reports_done() {
    let env = env("pull-job-ok").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    assert_eq!(run(&env, &digest).await, JobOutcome::Done);
    assert_eq!(state_of(&env, PID).await, "stored");
    let dir = env.dir.join("images").join(PID);
    assert!(dir.join("oci-layout").is_file() && dir.join("index.json").is_file());
    assert!(!env.dir.join("images/.tmp").join(PID).exists());
    let pulled_at: Option<i64> =
        match sqlx::query_scalar("SELECT pulled_at FROM image_platforms WHERE id = ?")
            .bind(PID)
            .fetch_one(&env.pool)
            .await
        {
            Ok(value) => value,
            Err(err) => panic!("pulled_at: {err}"),
        };
    assert_eq!(pulled_at, Some(NOW));
    // A repeated job for a stored image does nothing.
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::DoneEmpty(Some("already pulled".to_owned()))
    );
}

#[tokio::test]
async fn a_digest_mismatch_fails_with_the_fixed_text_and_leaves_no_directory() {
    let env = env("pull-job-mismatch").await;
    let digest = publish(&env, b"layer", b"LAYER", 5);
    seed(&env, &digest).await;
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::Failed("image content did not match its digest".to_owned())
    );
    assert_eq!(state_of(&env, PID).await, "failed");
    assert!(no_dirs(&env));
}

#[tokio::test]
async fn an_image_over_the_cap_is_refused_before_any_blob_is_requested() {
    let env = env("pull-job-cap").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    set(&env, limits::PULL_CAP_KEY, "100").await;
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::Permanent("image is larger than the allowed size".to_owned())
    );
    assert_eq!(state_of(&env, PID).await, "failed");
    assert_eq!(blob_requests(&env), 0);
    assert!(no_dirs(&env));
}

#[tokio::test]
async fn free_disk_below_the_minimum_is_refused_before_any_request() {
    let env = env("pull-job-disk").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    set(&env, limits::MIN_FREE_KEY, &u64::MAX.to_string()).await;
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::Failed("not enough disk space".to_owned())
    );
    // The row is unchanged and the registry saw no request.
    assert_eq!(state_of(&env, PID).await, "queued");
    assert!(env.script.hits().is_empty());
    assert!(no_dirs(&env));
}

#[tokio::test]
async fn a_pull_past_the_maximum_evicts_the_oldest_and_keeps_history() {
    let env = env("pull-job-evict").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    set(&env, limits::MAX_STORED_KEY, "1").await;
    let old = "0000000000000000000000000000000b";
    exec(
        &env,
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
         VALUES (?, 'img1', 'linux/arm64', 'sha256:bb', 'stored', 5)",
        &[old],
    )
    .await;
    exec(
        &env,
        "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status)
         VALUES ('r1', ?, 'trivy', 'first_pull', 'done')",
        &[old],
    )
    .await;
    let old_dir = env.dir.join("images").join(old);
    if let Err(err) = std::fs::create_dir_all(&old_dir) {
        panic!("old layout: {err}");
    }
    assert_eq!(run(&env, &digest).await, JobOutcome::Done);
    assert_eq!(state_of(&env, PID).await, "stored");
    assert_eq!(state_of(&env, old).await, "evicted");
    assert!(!old_dir.exists());
    // The evicted image keeps its run. The new image has its two queued scans.
    let runs: i64 =
        match sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs WHERE image_platform_id = ?")
            .bind(old)
            .fetch_one(&env.pool)
            .await
        {
            Ok(count) => count,
            Err(err) => panic!("runs: {err}"),
        };
    assert_eq!(runs, 1);
}

#[tokio::test]
async fn a_payload_digest_that_differs_from_the_row_is_not_pulled() {
    let env = env("pull-job-bad").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    assert_eq!(
        run(&env, "sha256:other").await,
        JobOutcome::Failed("internal error".to_owned())
    );
    assert_eq!(state_of(&env, PID).await, "queued");
    assert!(env.script.hits().is_empty());
}

async fn scan_jobs(env: &Env) -> Vec<(String, String)> {
    match sqlx::query_as::<_, (String, String)>(
        "SELECT r.scanner, r.trigger FROM scan_runs r
         JOIN jobs j ON j.id = r.job_id
         WHERE r.status = 'queued' AND json_extract(j.payload, '$.kind') = 'scan'
           AND json_extract(j.payload, '$.run_id') = r.id
         ORDER BY r.scanner",
    )
    .fetch_all(&env.pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => panic!("scan jobs: {err}"),
    }
}

/// Step 4: a stored pull queues one scan job and one queued run per enabled scanner, and a
/// repeated pull job queues nothing more.
#[tokio::test]
async fn a_stored_pull_queues_one_scan_per_enabled_scanner() {
    let env = env("pull-job-queue").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    assert_eq!(run(&env, &digest).await, JobOutcome::Done);
    let expected = vec![
        ("grype".to_owned(), "first_pull".to_owned()),
        ("trivy".to_owned(), "first_pull".to_owned()),
    ];
    assert_eq!(scan_jobs(&env).await, expected);
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::DoneEmpty(Some("already pulled".to_owned()))
    );
    assert_eq!(scan_jobs(&env).await, expected, "queued once");
}

/// `scanners.enabled` limits the scans queued.
#[tokio::test]
async fn only_the_enabled_scanners_are_queued() {
    let env = env("pull-job-enabled").await;
    set(&env, "scanners.enabled", "trivy").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    assert_eq!(run(&env, &digest).await, JobOutcome::Done);
    assert_eq!(
        scan_jobs(&env).await,
        vec![("trivy".to_owned(), "first_pull".to_owned())]
    );
}

/// A `manual` pull job for `PID` (#335).
fn manual_job(digest: &str) -> ClaimedJob {
    ClaimedJob {
        id: "j-manual".to_owned(),
        source_id: None,
        attempts: 0,
        payload: format!(
            r#"{{"kind":"pull","platform_id":"{PID}","digest":"{digest}","trigger":"manual"}}"#
        ),
    }
}

async fn pulled_at_of(env: &Env) -> Option<i64> {
    match sqlx::query_scalar("SELECT pulled_at FROM image_platforms WHERE id = ?")
        .bind(PID)
        .fetch_one(&env.pool)
        .await
    {
        Ok(value) => value,
        Err(err) => panic!("pulled_at: {err}"),
    }
}

/// Marks `PID` stored at time 5 with a layout holding one marker file, as an earlier pull left it.
async fn store_with_marker(env: &Env) -> std::path::PathBuf {
    exec(
        env,
        "UPDATE image_platforms SET state = 'stored', size_bytes = 7, pulled_at = 5 WHERE id = ?",
        &[PID],
    )
    .await;
    let layout = env.dir.join("images").join(PID);
    if let Err(err) = std::fs::create_dir_all(&layout) {
        panic!("layout: {err}");
    }
    let marker = layout.join("index.json");
    if let Err(err) = std::fs::write(&marker, b"stored-before") {
        panic!("marker: {err}");
    }
    marker
}

fn tmp_entries(env: &Env) -> usize {
    std::fs::read_dir(env.dir.join("images").join(".tmp"))
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// Q-B (#335): a manual pull of a stored image downloads it again into the temporary folder,
/// verifies every digest, discards the copy and updates `pulled_at`. The stored files stay.
#[tokio::test]
async fn pull_of_stored_image_redownloads_and_keeps_stored_files() {
    let env = env("pull-job-manual-stored").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    let marker = store_with_marker(&env).await;
    let store = StoreRoot::at(env.dir.join("images"));
    let outcome = run_pull(&env.pool, &env.discovery, &store, &manual_job(&digest), NOW).await;
    assert_eq!(outcome, JobOutcome::DoneEmpty(None));
    assert_eq!(
        blob_requests(&env),
        2,
        "the config and the layer were downloaded"
    );
    assert_eq!(state_of(&env, PID).await, "stored");
    assert_eq!(pulled_at_of(&env).await, Some(NOW));
    assert_eq!(
        std::fs::read(&marker).ok().as_deref(),
        Some(&b"stored-before"[..])
    );
    assert_eq!(tmp_entries(&env), 0, "the verified copy is discarded");
}

/// A manual re-download that does not verify fails the job and keeps the stored image as it was.
#[tokio::test]
async fn a_manual_redownload_that_does_not_verify_keeps_the_stored_image() {
    let env = env("pull-job-manual-bad").await;
    let digest = publish(&env, b"layer", b"LAYER", 5);
    seed(&env, &digest).await;
    let marker = store_with_marker(&env).await;
    let store = StoreRoot::at(env.dir.join("images"));
    let outcome = run_pull(&env.pool, &env.discovery, &store, &manual_job(&digest), NOW).await;
    assert_eq!(
        outcome,
        JobOutcome::Failed("image content did not match its digest".to_owned())
    );
    assert_eq!(state_of(&env, PID).await, "stored");
    assert_eq!(pulled_at_of(&env).await, Some(5));
    assert!(marker.is_file());
    assert_eq!(tmp_entries(&env), 0);
}

/// A `first_pull` job that finds its image stored still does nothing (unchanged behaviour).
#[tokio::test]
async fn a_discovery_pull_of_a_stored_image_still_downloads_nothing() {
    let env = env("pull-job-auto-stored").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    store_with_marker(&env).await;
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::DoneEmpty(Some("already pulled".to_owned()))
    );
    assert!(env.script.hits().is_empty());
    assert_eq!(pulled_at_of(&env).await, Some(5));
}

/// Runs `pull` jobs through the real worker step, so the stored `jobs` row is written as in
/// production.
struct PullHandler {
    pool: sqlx::SqlitePool,
    discovery: std::sync::Arc<crate::services::discovery::Discovery>,
    store: StoreRoot,
}

impl crate::worker::JobHandler for PullHandler {
    async fn run(&self, job: ClaimedJob) -> JobOutcome {
        run_pull(&self.pool, &self.discovery, &self.store, &job, NOW).await
    }
}

/// Enqueues the pull as job `id`, runs one worker step, and returns the stored `jobs.empty`.
async fn stored_empty_after_step(env: &Env, id: &str, digest: &str) -> i64 {
    let payload = format!(
        r#"{{"kind":"pull","platform_id":"{PID}","digest":"{digest}","trigger":"first_pull"}}"#
    );
    // Earlier pulls queued scan jobs; the step must claim only this one.
    exec(env, "DELETE FROM jobs", &[]).await;
    if let Err(err) = crate::db::jobs::enqueue(&env.pool, id, None, &payload, NOW).await {
        panic!("enqueue: {err:?}");
    }
    let handler = std::sync::Arc::new(PullHandler {
        pool: env.pool.clone(),
        discovery: env.discovery.clone(),
        store: StoreRoot::at(env.dir.join("images")),
    });
    if let Err(err) = crate::worker::step(&env.pool, &handler, NOW).await {
        panic!("step: {err:?}");
    }
    let status: String = match sqlx::query_scalar("SELECT status FROM jobs WHERE id = ?")
        .bind(id)
        .fetch_one(&env.pool)
        .await
    {
        Ok(value) => value,
        Err(err) => panic!("jobs.status: {err}"),
    };
    assert_eq!(status, "done", "the step ran this job");
    match sqlx::query_scalar("SELECT empty FROM jobs WHERE id = ?")
        .bind(id)
        .fetch_one(&env.pool)
        .await
    {
        Ok(value) => value,
        Err(err) => panic!("jobs.empty: {err}"),
    }
}

/// An unchanged pull (a stored digest, skipped or verified) is recorded as empty (#360).
#[tokio::test]
async fn an_unchanged_pull_is_recorded_as_empty() {
    let env = env("pull-job-empty").await;
    let digest = publish(&env, b"layer", b"layer", 5);
    seed(&env, &digest).await;
    // The first pull stores the image: it has output.
    assert_eq!(run(&env, &digest).await, JobOutcome::Done);
    // A repeated pull is skipped: empty, with its note kept.
    assert_eq!(
        run(&env, &digest).await,
        JobOutcome::DoneEmpty(Some("already pulled".to_owned()))
    );
    // The worker stores the flag: the same unchanged pull, run as a job, sets `jobs.empty`.
    assert_eq!(
        stored_empty_after_step(&env, "j-unchanged", &digest).await,
        1
    );
    // A manual pull of the stored image only verifies it: empty.
    let store = StoreRoot::at(env.dir.join("images"));
    assert_eq!(
        run_pull(&env.pool, &env.discovery, &store, &manual_job(&digest), NOW).await,
        JobOutcome::DoneEmpty(None)
    );
}
