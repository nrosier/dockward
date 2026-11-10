//! Storage tests against a temporary SQLite database and a loopback fake registry. Nothing here
//! contacts a real registry, and no test uses a real credential.
//!
//! The database is created inside each test from the spinoff's section 9 column definitions,
//! because the clean migration has not landed (Step 1). Each test gets its own directory.

use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::db::storage::testing;
use crate::error::AppError;
use crate::services::registry::manifest::OCI_MANIFEST;
use crate::services::registry::policy::{AddressPolicy, HostLookup, LookupFuture, NamedHub};
use crate::services::registry::transport::{RegistryClient, sha256_digest_text};
use crate::services::storage::StoreRoot;
use crate::services::storage::eviction;
use crate::services::storage::limits::StoreLimits;
use crate::services::storage::pull::{PullPlan, pull_platform};
use crate::services::storage::repository::{SqlStoreRepository, StoreRepository};
use crate::services::storage::startup;

/// A temporary data directory and database for one test. Dropped with the test.
struct Fixture {
    dir: PathBuf,
    pool: SqlitePool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "harborgate-storage-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

async fn fixture(tag: &str) -> Fixture {
    let dir = unique_dir(tag);
    let _ = std::fs::create_dir_all(&dir);
    let db_path = dir.join("test.db");
    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = match SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
    {
        Ok(pool) => pool,
        Err(err) => panic!("test database: {err}"),
    };
    if let Err(err) = sqlx::raw_sql(testing::SCHEMA).execute(&pool).await {
        panic!("test schema: {err}");
    }
    Fixture { dir, pool }
}

async fn seed_hub(pool: &SqlitePool) -> Result<(), AppError> {
    testing::insert_hub(pool, "hub1", "ghcr.io").await
}

/// The insert error text, for a failing fixture. Driver text is kept in test output only.
async fn seed_hub_checked(pool: &SqlitePool) {
    if let Err(err) =
        sqlx::query("INSERT INTO hubs (id, host, kind) VALUES ('hub1', 'ghcr.io', 'default')")
            .execute(pool)
            .await
    {
        panic!("hub insert: {err}");
    }
}

/// Inserts one image and one platform row in `state`, optionally stored at `pulled_at`.
async fn seed_platform(
    pool: &SqlitePool,
    platform_id: &str,
    state: &str,
    pulled_at: Option<i64>,
) -> Result<(), AppError> {
    let image_id = format!("img-{platform_id}");
    let digest = format!("sha256:{platform_id:0>64}");
    testing::insert_image(pool, &image_id, "hub1", "team/app", &digest).await?;
    testing::insert_platform(
        pool,
        platform_id,
        &image_id,
        &format!("sha256:{platform_id:0>64}"),
        state,
        pulled_at,
    )
    .await
}

/// Writes a fake layout directory for `platform_id` under the store, so eviction has something
/// to delete.
fn make_layout(store: &StoreRoot, platform_id: &str) -> Result<PathBuf, AppError> {
    let dir = store.layout_dir(platform_id)?;
    std::fs::create_dir_all(dir.join("blobs/sha256")).map_err(|_| AppError::InternalError)?;
    std::fs::write(dir.join("oci-layout"), b"{}").map_err(|_| AppError::InternalError)?;
    Ok(dir)
}

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{:032x}", i + 1)).collect()
}

/// Unwraps a fixture or assertion result. A failure panics with its error, so a broken setup
/// fails the test instead of looking like a wrong result.
fn must<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// The state of one platform, read through the repository. `None` when the row is missing.
async fn state_of<R: StoreRepository>(repo: &R, platform_id: &str) -> Option<String> {
    must(repo.platform_state(platform_id).await, "read state")
}

/// Generated-style platform ids (32 lowercase hex) for the pull tests.
const P1: &str = "00000000000000000000000000000001";
const P2: &str = "00000000000000000000000000000002";
const P3: &str = "00000000000000000000000000000003";
const P4: &str = "00000000000000000000000000000004";

// ---------- Fake registry -------------------------------------------------------------------

/// A scripted DNS answer for hub hostnames. The loopback fake resolves to 127.0.0.1.
struct LoopbackLookup;

impl HostLookup for LoopbackLookup {
    fn lookup(&self, _host: String) -> LookupFuture {
        Box::pin(async { Ok(vec![std::net::IpAddr::from([127, 0, 0, 1])]) })
    }
}

/// One scripted response.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// Serves scripted replies keyed by path. The last reply for a path repeats.
#[derive(Default)]
struct Script {
    routes: std::sync::Mutex<std::collections::HashMap<String, Reply>>,
}

impl Script {
    fn route(&self, path: &str, reply: Reply) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert(path.to_owned(), reply);
        }
    }

    fn reply_for(&self, path: &str) -> Option<Reply> {
        self.routes.lock().ok()?.get(path).cloned()
    }
}

/// Starts the fake registry on loopback. Returns its authority.
async fn serve(script: Arc<Script>) -> String {
    let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(listener) => listener,
        Err(err) => panic!("loopback bind: {err}"),
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => panic!("loopback addr: {err}"),
    };
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut filled = 0;
                loop {
                    let Ok(n) = socket.read(&mut buf[filled..]).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    filled += n;
                    if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") || filled == buf.len() {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..filled]).to_string();
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                let path = target.split('?').next().unwrap_or("").to_owned();
                let reply = script
                    .reply_for(&path)
                    .unwrap_or_else(|| Reply::new(404, b"{}"));
                let mut out = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    out.push_str(&format!("{name}: {value}\r\n"));
                }
                out.push_str("\r\n");
                let _ = socket.write_all(out.as_bytes()).await;
                let _ = socket.write_all(&reply.body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("127.0.0.1:{port}")
}

fn client() -> Result<RegistryClient, AppError> {
    let named = vec![NamedHub {
        host: "127.0.0.1".to_owned(),
        plain_http: true,
    }];
    RegistryClient::new(AddressPolicy::new(named, Arc::new(LoopbackLookup)))
}

/// A single-platform image on the fake registry: its manifest bytes, its digest and its blobs.
struct FakeImage {
    manifest: Vec<u8>,
    manifest_digest: String,
    blobs: Vec<(String, Vec<u8>)>,
}

fn fake_image(config: &[u8], layer: &[u8]) -> FakeImage {
    let config_digest = sha256_digest_text(&Sha256::digest(config));
    let layer_digest = sha256_digest_text(&Sha256::digest(layer));
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}",
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
        config.len(),
        layer.len()
    )
    .into_bytes();
    let manifest_digest = sha256_digest_text(&Sha256::digest(&manifest));
    FakeImage {
        manifest,
        manifest_digest,
        blobs: vec![
            (config_digest, config.to_vec()),
            (layer_digest, layer.to_vec()),
        ],
    }
}

/// Routes the manifest (by digest and by tag) and the blobs of `image` on the fake registry.
fn publish(script: &Script, image: &FakeImage) {
    script.route(
        &format!("/v2/team/app/manifests/{}", image.manifest_digest),
        Reply::new(200, &image.manifest).header("Content-Type", OCI_MANIFEST),
    );
    for (digest, body) in &image.blobs {
        script.route(
            &format!("/v2/team/app/blobs/{digest}"),
            Reply::new(200, body),
        );
    }
}

fn limits(max_stored: i64, pull_cap: u64) -> StoreLimits {
    StoreLimits {
        max_stored,
        pull_cap_bytes: pull_cap,
        min_free_bytes: 0,
    }
}

// ---------- Pull and layout ------------------------------------------------------------------

/// A client for one fake hub, and the session the pull uses. The fake serves the image at
/// `team/app`.
fn session_for<'a>(
    client: &'a RegistryClient,
    loopback: &str,
) -> crate::services::registry::transport::PullSession<'a> {
    must(client.session(loopback, "team/app", None), "session")
}

#[tokio::test]
async fn a_verified_pull_writes_a_layout_and_renames_it_into_place() {
    let fx = fixture("pull-ok").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let image = fake_image(b"{\"config\":true}", b"layer-bytes");
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    publish(&script, &image);
    must(seed_platform(&fx.pool, P1, "queued", None).await, "seed");
    let repo = SqlStoreRepository::new(fx.pool.clone());
    let client = must(client(), "client");
    let mut session = session_for(&client, &loopback);
    let plan = PullPlan {
        platform_id: P1,
        platform_digest: &image.manifest_digest,
    };
    let outcome = must(
        pull_platform(
            &repo,
            &store,
            &mut session,
            &plan,
            limits(20, u64::MAX),
            u64::MAX,
            100,
        )
        .await,
        "pull",
    );
    assert_eq!(outcome.evicted, 0);
    assert_eq!(outcome.pending_evictions, 0);

    // The final directory holds the layout, and the temporary directory is gone.
    let final_dir = must(store.layout_dir(P1), "path");
    assert!(final_dir.join("oci-layout").is_file());
    assert!(final_dir.join("index.json").is_file());
    assert!(final_dir.join("blobs/sha256").is_dir());
    assert!(!must(store.tmp_dir(P1), "path").exists());
    assert_eq!(state_of(&repo, P1).await.as_deref(), Some("stored"));
}

#[tokio::test]
async fn a_digest_mismatch_leaves_no_final_directory() {
    let fx = fixture("pull-bad").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let image = fake_image(b"{\"config\":true}", b"layer-bytes");
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    publish(&script, &image);
    // The layer bytes served differ from the digest the manifest names.
    let layer_digest = image.blobs[1].0.clone();
    script.route(
        &format!("/v2/team/app/blobs/{layer_digest}"),
        Reply::new(200, b"tampered-bytes"),
    );
    must(seed_platform(&fx.pool, P2, "queued", None).await, "seed");
    let repo = SqlStoreRepository::new(fx.pool.clone());
    let client = must(client(), "client");
    let mut session = session_for(&client, &loopback);
    let plan = PullPlan {
        platform_id: P2,
        platform_digest: &image.manifest_digest,
    };
    let outcome = pull_platform(
        &repo,
        &store,
        &mut session,
        &plan,
        limits(20, u64::MAX),
        u64::MAX,
        100,
    )
    .await;
    assert!(outcome.is_err(), "a digest mismatch must fail the pull");
    assert!(
        !must(store.layout_dir(P2), "path").exists(),
        "no final directory"
    );
    assert!(
        !must(store.tmp_dir(P2), "path").exists(),
        "no temporary directory"
    );
    assert_eq!(state_of(&repo, P2).await.as_deref(), Some("failed"));
}

#[tokio::test]
async fn the_free_disk_refusal_uses_the_fixed_text_and_leaves_the_row_queued() {
    let fx = fixture("disk").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    must(seed_platform(&fx.pool, P3, "queued", None).await, "seed");
    let repo = SqlStoreRepository::new(fx.pool.clone());
    // No request is made: the guard refuses before the registry is contacted.
    let client = must(client(), "client");
    let mut session = session_for(&client, "127.0.0.1:1");
    let plan = PullPlan {
        platform_id: P3,
        platform_digest: &format!("sha256:{:0>64}", "3"),
    };
    let min_free = StoreLimits {
        min_free_bytes: 10,
        ..limits(20, u64::MAX)
    };
    let err = pull_platform(&repo, &store, &mut session, &plan, min_free, 9, 100).await;
    assert_eq!(err, Err(AppError::InsufficientDisk));
    // The job maps the refusal to the fixed last_error text.
    assert_eq!(
        crate::services::storage::messages::NOT_ENOUGH_DISK,
        "not enough disk space"
    );
    assert_eq!(state_of(&repo, P3).await.as_deref(), Some("queued"));
}

#[tokio::test]
async fn the_pull_cap_refusal_uses_the_fixed_text() {
    let fx = fixture("cap").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let image = fake_image(b"{\"config\":true}", b"layer-bytes");
    let script = Arc::new(Script::default());
    let loopback = serve(Arc::clone(&script)).await;
    publish(&script, &image);
    must(seed_platform(&fx.pool, P4, "queued", None).await, "seed");
    let repo = SqlStoreRepository::new(fx.pool.clone());
    let client = must(client(), "client");
    let mut session = session_for(&client, &loopback);
    let plan = PullPlan {
        platform_id: P4,
        platform_digest: &image.manifest_digest,
    };
    // A cap of 8 bytes is below the declared size, so the pull is refused before any blob.
    let err = pull_platform(
        &repo,
        &store,
        &mut session,
        &plan,
        limits(20, 8),
        u64::MAX,
        100,
    )
    .await;
    assert_eq!(err, Err(AppError::ImageTooLarge));
    assert_eq!(
        crate::services::storage::messages::IMAGE_TOO_LARGE,
        "image is larger than the allowed size"
    );
    assert!(
        !must(store.layout_dir(P4), "path").exists(),
        "no final directory"
    );
}

// ---------- Eviction --------------------------------------------------------------------------

/// Seeds a stored platform with its layout directory and one done run with a finding, so the
/// test can check that eviction keeps the findings and history.
async fn seed_stored_with_history(
    fx: &Fixture,
    store: &StoreRoot,
    id: &str,
    pulled_at: i64,
    run: &str,
) {
    must(
        seed_platform(&fx.pool, id, "stored", Some(pulled_at)).await,
        "seed stored",
    );
    must(make_layout(store, id), "layout");
    must(
        testing::insert_scan_run(&fx.pool, run, id, "done").await,
        "seed run",
    );
    must(
        testing::insert_finding(&fx.pool, run, "CVE-2026-0001").await,
        "seed finding",
    );
}

#[tokio::test]
async fn eviction_with_the_maximum_at_n_removes_the_oldest_and_keeps_findings_and_history() {
    let fx = fixture("evict").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let all = ids(4);
    // pulled_at 10, 30, 20, 40: the oldest by pulled_at is all[0] (10), then all[2] (20). The
    // insertion order is not the eviction order, so this checks the sort by pulled_at.
    let pulled = [10_i64, 30, 20, 40];
    for (i, id) in all.iter().enumerate() {
        seed_stored_with_history(&fx, &store, id, pulled[i], &format!("run-{i}")).await;
    }
    let repo = SqlStoreRepository::new(fx.pool.clone());

    let evicted = must(
        eviction::enforce(&repo, &store, 2, None, 500).await,
        "enforce",
    );
    assert_eq!(evicted, 2);

    assert_eq!(state_of(&repo, &all[0]).await.as_deref(), Some("evicted"));
    assert_eq!(state_of(&repo, &all[2]).await.as_deref(), Some("evicted"));
    assert_eq!(state_of(&repo, &all[1]).await.as_deref(), Some("stored"));
    assert_eq!(state_of(&repo, &all[3]).await.as_deref(), Some("stored"));

    // Only the layouts of the evicted images are deleted.
    assert!(!must(store.layout_dir(&all[0]), "path").exists());
    assert!(!must(store.layout_dir(&all[2]), "path").exists());
    assert!(must(store.layout_dir(&all[1]), "path").is_dir());
    assert!(must(store.layout_dir(&all[3]), "path").is_dir());

    // Findings, scan history and the platform rows are kept for every image.
    let findings = must(
        testing::count_rows(&fx.pool, "SELECT COUNT(*) FROM scanner_findings").await,
        "count findings",
    );
    assert_eq!(findings, 4);
    let runs = must(
        testing::count_rows(&fx.pool, "SELECT COUNT(*) FROM scan_runs").await,
        "count runs",
    );
    assert_eq!(runs, 4);
    let rows = must(
        testing::count_rows(&fx.pool, "SELECT COUNT(*) FROM image_platforms").await,
        "count rows",
    );
    assert_eq!(rows, 4, "image_platforms rows stay after eviction");

    // Each eviction is audited once, with no path in the details.
    let (audit_rows, distinct) = must(testing::eviction_audit_counts(&fx.pool).await, "audit");
    assert_eq!((audit_rows, distinct), (2, 2));
    for details in must(testing::eviction_audit_details(&fx.pool).await, "details") {
        // The details carry the hub, the repository and the digest, and no store path.
        assert!(
            !details.contains("images"),
            "audit details name no path: {details}"
        );
        assert!(
            !details.contains("/data"),
            "audit details name no path: {details}"
        );
    }
}

#[tokio::test]
async fn an_image_with_a_running_or_queued_scan_is_never_evicted() {
    let fx = fixture("protect").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let all = ids(3);
    let pulled = [10_i64, 20, 30];
    for (i, id) in all.iter().enumerate() {
        must(
            seed_platform(&fx.pool, id, "stored", Some(pulled[i])).await,
            "seed",
        );
        must(make_layout(&store, id), "layout");
    }
    // The oldest has a running scan; the second has a queued scan. Only the newest is eligible.
    must(
        testing::insert_scan_run(&fx.pool, "r-run", &all[0], "running").await,
        "run",
    );
    must(
        testing::insert_scan_run(&fx.pool, "r-queued", &all[1], "queued").await,
        "run",
    );
    let repo = SqlStoreRepository::new(fx.pool.clone());

    // Maximum 1 with three stored: two are over the limit, but only all[2] is eligible.
    let evicted = must(
        eviction::enforce(&repo, &store, 1, None, 500).await,
        "enforce",
    );
    assert_eq!(evicted, 1);
    assert_eq!(state_of(&repo, &all[0]).await.as_deref(), Some("stored"));
    assert_eq!(state_of(&repo, &all[1]).await.as_deref(), Some("stored"));
    assert_eq!(state_of(&repo, &all[2]).await.as_deref(), Some("evicted"));
    assert!(must(store.layout_dir(&all[0]), "path").is_dir());
}

#[tokio::test]
async fn the_just_pulled_image_is_not_claimed_by_its_own_pull() {
    let fx = fixture("protect-new").await;
    seed_hub_checked(&fx.pool).await;
    let all = ids(2);
    must(
        seed_platform(&fx.pool, &all[0], "stored", Some(5)).await,
        "seed",
    );
    must(
        seed_platform(&fx.pool, &all[1], "pulling", None).await,
        "seed",
    );
    let repo = SqlStoreRepository::new(fx.pool.clone());
    // Store the second and claim over a maximum of 1. The older one is claimed; the new one is
    // stored and must not be.
    let claims = must(
        repo.store_and_claim(&all[1], 1, 9, 1).await,
        "store_and_claim",
    );
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0].platform_id, all[0],
        "the older image is claimed, not the new one"
    );
    assert_eq!(state_of(&repo, &all[1]).await.as_deref(), Some("stored"));
}

#[tokio::test]
async fn two_concurrent_eviction_runs_do_not_evict_the_same_image_twice() {
    let fx = fixture("race").await;
    let store = Arc::new(StoreRoot::at(fx.dir.join("images")));
    seed_hub_checked(&fx.pool).await;
    let all = ids(3);
    let pulled = [1_i64, 2, 3];
    for (i, id) in all.iter().enumerate() {
        must(
            seed_platform(&fx.pool, id, "stored", Some(pulled[i])).await,
            "seed",
        );
        must(make_layout(&store, id), "layout");
    }
    let repo = Arc::new(SqlStoreRepository::new(fx.pool.clone()));
    let mut runs = Vec::new();
    for _ in 0..2 {
        let repo = Arc::clone(&repo);
        let store = Arc::clone(&store);
        runs.push(tokio::spawn(async move {
            eviction::enforce(repo.as_ref(), store.as_ref(), 1, None, 9).await
        }));
    }
    let mut total = 0usize;
    for run in runs {
        let outcome = must(run.await, "join");
        total += must(outcome, "enforce");
    }
    // Three stored, maximum 1: exactly two must go, and across both runs each only once.
    assert_eq!(total, 2);
    let (rows, distinct) = must(testing::eviction_audit_counts(&fx.pool).await, "audit");
    assert_eq!((rows, distinct), (2, 2), "each image is audited once");
    let evicted = must(
        testing::count_rows(
            &fx.pool,
            "SELECT COUNT(*) FROM image_platforms WHERE state = 'evicted'",
        )
        .await,
        "count",
    );
    assert_eq!(evicted, 2);
}

// ---------- Startup repair --------------------------------------------------------------------

#[tokio::test]
async fn startup_completes_an_evicting_row_whose_directory_is_gone() {
    let fx = fixture("repair-gone").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let id = ids(1).remove(0);
    must(
        seed_platform(&fx.pool, &id, "evicting", Some(1)).await,
        "seed",
    );
    // No directory: the crash came after the directory was removed.
    let repo = SqlStoreRepository::new(fx.pool.clone());
    let report = must(startup::repair(&repo, &store, 700).await, "repair");
    assert_eq!(report.evictions_completed, 1);
    assert_eq!(state_of(&repo, &id).await.as_deref(), Some("evicted"));
    let (rows, _) = must(testing::eviction_audit_counts(&fx.pool).await, "audit");
    assert_eq!(rows, 1, "the eviction is audited on repair");
}

#[tokio::test]
async fn startup_reattempts_an_evicting_row_whose_directory_still_exists() {
    let fx = fixture("repair-left").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let id = ids(1).remove(0);
    must(
        seed_platform(&fx.pool, &id, "evicting", Some(1)).await,
        "seed",
    );
    must(make_layout(&store, &id), "layout");
    let repo = SqlStoreRepository::new(fx.pool.clone());
    let report = must(startup::repair(&repo, &store, 700).await, "repair");
    assert_eq!(report.evictions_completed, 1);
    assert!(
        !must(store.layout_dir(&id), "path").exists(),
        "directory removed"
    );
    assert_eq!(state_of(&repo, &id).await.as_deref(), Some("evicted"));
}

#[tokio::test]
async fn startup_clears_tmp_and_orphan_directories_and_fails_a_cut_off_pull() {
    let fx = fixture("repair-orphan").await;
    let store = StoreRoot::at(fx.dir.join("images"));
    seed_hub_checked(&fx.pool).await;
    let ids = ids(2);
    must(
        seed_platform(&fx.pool, &ids[0], "pulling", None).await,
        "seed",
    );
    // An orphan directory with no row, and a leftover in .tmp.
    must(make_layout(&store, &ids[1]), "layout");
    must(
        std::fs::create_dir_all(must(store.tmp_dir(&ids[0]), "path")),
        "tmp",
    );
    let repo = SqlStoreRepository::new(fx.pool.clone());
    let report = must(startup::repair(&repo, &store, 700).await, "repair");
    assert_eq!(report.pulls_failed, 1);
    assert_eq!(state_of(&repo, &ids[0]).await.as_deref(), Some("failed"));
    assert!(
        !must(store.layout_dir(&ids[1]), "path").exists(),
        "orphan removed"
    );
    assert!(
        !must(store.tmp_dir(&ids[0]), "path").exists(),
        "tmp removed"
    );
}

// ---------- Scan start guard -----------------------------------------------------------------

#[tokio::test]
async fn a_scan_moves_to_running_only_while_its_image_is_stored() {
    let fx = fixture("scan-guard").await;
    seed_hub_checked(&fx.pool).await;
    let id = ids(1).remove(0);
    must(
        seed_platform(&fx.pool, &id, "evicting", Some(1)).await,
        "seed",
    );
    must(
        testing::insert_scan_run(&fx.pool, "scan-1", &id, "queued").await,
        "run",
    );
    let repo = SqlStoreRepository::new(fx.pool.clone());
    assert!(!must(repo.start_scan("scan-1", &id, 50).await, "start"));
    // Once the image is stored again, the same guard lets the run start.
    must(
        sqlx::query("UPDATE image_platforms SET state = 'stored' WHERE id = ?")
            .bind(&id)
            .execute(&fx.pool)
            .await,
        "restore",
    );
    assert!(must(repo.start_scan("scan-1", &id, 60).await, "start"));
}

// ---------- Limits and paths ------------------------------------------------------------------

#[test]
fn a_store_path_is_built_only_from_a_generated_id() {
    let store = StoreRoot::at(PathBuf::from("/data/images"));
    assert!(store.layout_dir("../etc").is_err());
    assert!(store.tmp_dir("ABCDEF").is_err());
    assert!(store.layout_dir(&ids(1)[0]).is_ok());
}

#[test]
fn the_default_limits_are_read_when_unset() {
    let defaults = StoreLimits::default();
    assert_eq!(defaults.max_stored, 20);
    assert_eq!(defaults.pull_cap_bytes, 10 * 1024 * 1024 * 1024);
    assert_eq!(defaults.min_free_bytes, 10 * 1024 * 1024 * 1024);
}
