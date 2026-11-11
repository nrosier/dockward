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
        JobOutcome::DoneWithNote("already pulled".to_owned())
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
        JobOutcome::DoneWithNote("already pulled".to_owned())
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
