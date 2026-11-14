//! Discovery tests against the real migrated schema and a loopback fake registry. No test
//! contacts a real registry, and no test uses a real credential.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::db;
use crate::services::discovery::handler::SpinoffJobs;
use crate::services::registry::manifest::{OCI_INDEX, OCI_MANIFEST};
use crate::worker::{JobHandler, JobOutcome};

const NOW: i64 = 1_800_000_000;
const REPO: &str = "team/app";

// ---------- Fake registry -------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    pub(crate) fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// Scripted replies keyed by `path?query` or by `path`. The full key wins.
#[derive(Default)]
pub(crate) struct Script {
    routes: Mutex<HashMap<String, Reply>>,
    hits: Mutex<Vec<String>>,
}

impl Script {
    pub(crate) fn route(&self, key: &str, reply: Reply) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert(key.to_owned(), reply);
        }
    }

    fn reply_for(&self, target: &str) -> Option<Reply> {
        let routes = self.routes.lock().ok()?;
        let path = target.split('?').next().unwrap_or("");
        routes.get(target).or_else(|| routes.get(path)).cloned()
    }

    pub(crate) fn hits(&self) -> Vec<String> {
        self.hits
            .lock()
            .map(|hits| hits.clone())
            .unwrap_or_default()
    }
}

/// Starts the fake registry on loopback. Returns its `127.0.0.1:port` authority.
pub(crate) async fn serve(script: Arc<Script>) -> String {
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
                if let Ok(mut hits) = script.hits.lock() {
                    hits.push(target.clone());
                }
                let reply = script
                    .reply_for(&target)
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

fn digest_of(bytes: &[u8]) -> String {
    sha256_digest_text(&Sha256::digest(bytes))
}

/// Publishes the tag list of `repo`.
pub(crate) fn set_tags(script: &Script, repo: &str, tags: &[&str]) {
    let body = serde_json::json!({ "name": repo, "tags": tags }).to_string();
    script.route(
        &format!("/v2/{repo}/tags/list?n=100"),
        Reply::new(200, body.as_bytes()),
    );
}

/// Publishes a single-platform image under `tag`. Returns its manifest digest.
pub(crate) fn put_single(
    script: &Script,
    repo: &str,
    tag: &str,
    arch: &str,
    build: &str,
) -> String {
    let config = serde_json::json!({ "os": "linux", "architecture": arch, "build": build })
        .to_string()
        .into_bytes();
    let config_digest = digest_of(&config);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}",
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},
            "layers":[]}}"#,
        config.len()
    )
    .into_bytes();
    let digest = digest_of(&manifest);
    script.route(
        &format!("/v2/{repo}/manifests/{tag}"),
        Reply::new(200, &manifest).header("Content-Type", OCI_MANIFEST),
    );
    script.route(
        &format!("/v2/{repo}/blobs/{config_digest}"),
        Reply::new(200, &config),
    );
    digest
}

/// Publishes an index under `tag` with the given platforms and, optionally, a BuildKit
/// attestation entry for each. Returns the index digest.
pub(crate) fn put_index(
    script: &Script,
    repo: &str,
    tag: &str,
    platforms: &[(&str, &str, Option<&str>)],
    attestations: bool,
) -> String {
    let mut entries = Vec::new();
    for (os, arch, variant) in platforms {
        let digest = digest_of(format!("{tag}-{os}-{arch}-{variant:?}").as_bytes());
        let mut platform = serde_json::json!({ "os": os, "architecture": arch });
        if let Some(variant) = variant {
            platform["variant"] = serde_json::json!(variant);
        }
        entries.push(serde_json::json!({
            "mediaType": OCI_MANIFEST, "digest": digest, "size": 100, "platform": platform
        }));
        if attestations {
            let att = digest_of(format!("att-{tag}-{os}-{arch}").as_bytes());
            entries.push(serde_json::json!({
                "mediaType": OCI_MANIFEST, "digest": att, "size": 50,
                "platform": { "os": "unknown", "architecture": "unknown" },
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": digest
                }
            }));
        }
    }
    let body = serde_json::json!({
        "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries
    })
    .to_string()
    .into_bytes();
    let digest = digest_of(&body);
    script.route(
        &format!("/v2/{repo}/manifests/{tag}"),
        Reply::new(200, &body).header("Content-Type", OCI_INDEX),
    );
    digest
}

// ---------- Fixture -------------------------------------------------------------------------

pub(crate) struct Env {
    pub(crate) pool: SqlitePool,
    pub(crate) dir: PathBuf,
    pub(crate) script: Arc<Script>,
    pub(crate) discovery: Arc<Discovery>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A migrated database, a fake registry, a custom hub `hub-fake` that points at it, one user
/// `u1` with a GitHub credential `c1`.
pub(crate) async fn env(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!(
        "dockward-discovery-{name}-{}-{}",
        std::process::id(),
        crate::worker::now_secs()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = db::open(&dir).await.unwrap();
    let script = Arc::new(Script::default());
    let authority = serve(script.clone()).await;
    for sql in [
        "INSERT INTO users (id, username, password_hash, role, token_version)
         VALUES ('u1', 'u1', NULL, 'user', 0)",
        "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
         VALUES ('c1', 'u1', 'g', 'v1:fake')",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO hubs (id, host, kind) VALUES ('hub-fake', ?, 'custom')")
        .bind(&authority)
        .execute(&pool)
        .await
        .unwrap();
    let discovery = Discovery::for_test_with_pool(pool.clone());
    Env {
        pool,
        dir,
        script,
        discovery,
    }
}

impl Env {
    pub(crate) async fn add_source(&self, id: &str, repo: &str, tag_value: &str) {
        sqlx::query(
            "INSERT INTO image_sources
                (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES (?, 'u1', 'hub-fake', ?, ?, 'c1', 'o', 'g')",
        )
        .bind(id)
        .bind(repo)
        .bind(tag_value)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    fn payload(&self, repo: &str) -> DiscoverPayload {
        DiscoverPayload::new("hub-fake", repo, None)
    }

    async fn count(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn pulls(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM jobs WHERE json_extract(payload, '$.kind') = 'pull'")
            .await
    }

    async fn run(&self, repo: &str, now: i64) -> DiscoverReport {
        self.discovery
            .discover_now(&self.payload(repo), now)
            .await
            .unwrap()
    }
}

// ---------- Tests ---------------------------------------------------------------------------

#[tokio::test]
async fn a_new_tag_queues_one_pull_and_a_second_run_queues_none() {
    let env = env("new-tag").await;
    env.add_source("s1", REPO, "1.*").await;
    set_tags(&env.script, REPO, &["1.0", "1.1", "2.0", "latest"]);
    put_single(&env.script, REPO, "1.0", "amd64", "a");
    put_single(&env.script, REPO, "1.1", "amd64", "b");
    put_single(&env.script, REPO, "2.0", "amd64", "c");

    let first = env.run(REPO, NOW).await;
    assert_eq!(
        first,
        DiscoverReport {
            queued: 2,
            complete: true
        }
    );
    assert_eq!(env.pulls().await, 2);
    assert_eq!(env.count("SELECT COUNT(*) FROM images").await, 2);
    assert_eq!(env.count("SELECT COUNT(*) FROM tag_observations").await, 2);
    assert_eq!(env.count("SELECT COUNT(*) FROM image_platforms").await, 2);
    // A non-matching tag is never fetched.
    assert!(
        !env.script
            .hits()
            .iter()
            .any(|hit| hit.contains("/manifests/2.0"))
    );

    let second = env.run(REPO, NOW + 3600).await;
    assert_eq!(second.queued, 0);
    assert_eq!(env.pulls().await, 2);
    let last_seen: i64 =
        sqlx::query_scalar("SELECT MIN(last_seen_at) FROM tag_observations WHERE source_id = 's1'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(last_seen, NOW + 3600);
    let discovered: i64 =
        sqlx::query_scalar("SELECT last_discovery_at FROM image_sources WHERE id = 's1'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(discovered, NOW + 3600);
}

#[tokio::test]
async fn a_moved_tag_queues_one_pull_and_keeps_the_old_digest() {
    let env = env("moved").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    let old = put_single(&env.script, REPO, "latest", "amd64", "old");
    assert_eq!(env.run(REPO, NOW).await.queued, 1);

    let new = put_single(&env.script, REPO, "latest", "amd64", "new");
    assert_ne!(old, new);
    assert_eq!(env.run(REPO, NOW + 3600).await.queued, 1);
    assert_eq!(env.pulls().await, 2);
    assert_eq!(env.count("SELECT COUNT(*) FROM tag_observations").await, 2);
    let triggers: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.trigger') FROM jobs ORDER BY created_at, rowid",
    )
    .fetch_all(&env.pool)
    .await
    .unwrap();
    assert_eq!(triggers, vec!["first_pull", "tag_moved"]);

    // The old digest comes back (a rollback): it is known, so nothing is pulled.
    put_single(&env.script, REPO, "latest", "amd64", "old");
    assert_eq!(env.run(REPO, NOW + 7200).await.queued, 0);
    assert_eq!(env.pulls().await, 2);
}

#[tokio::test]
async fn an_unchanged_tag_queues_no_pull_and_downloads_no_blob() {
    let env = env("unchanged").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_single(&env.script, REPO, "latest", "amd64", "same");
    assert_eq!(env.run(REPO, NOW).await.queued, 1);
    let blobs_after_first = env
        .script
        .hits()
        .iter()
        .filter(|hit| hit.contains("/blobs/"))
        .count();
    assert_eq!(blobs_after_first, 1);

    // The next hourly pass sees the same digest: the tag is recorded, nothing is pulled and no
    // blob is downloaded.
    assert_eq!(env.run(REPO, NOW + 3600).await.queued, 0);
    assert_eq!(env.pulls().await, 1);
    let blobs_after_second = env
        .script
        .hits()
        .iter()
        .filter(|hit| hit.contains("/blobs/"))
        .count();
    assert_eq!(blobs_after_second, blobs_after_first);
    assert_eq!(env.count("SELECT COUNT(*) FROM tag_observations").await, 1);
    let last_seen: i64 =
        sqlx::query_scalar("SELECT last_seen_at FROM tag_observations WHERE source_id = 's1'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(last_seen, NOW + 3600);
}

#[tokio::test]
async fn a_moved_tag_pulls_the_new_digest() {
    let env = env("moved-digest").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_single(&env.script, REPO, "latest", "amd64", "old");
    assert_eq!(env.run(REPO, NOW).await.queued, 1);

    let new = put_single(&env.script, REPO, "latest", "amd64", "new");
    assert_eq!(env.run(REPO, NOW + 3600).await.queued, 1);
    let pulled: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.digest') FROM jobs
         WHERE json_extract(payload, '$.kind') = 'pull'
         ORDER BY created_at, rowid",
    )
    .fetch_all(&env.pool)
    .await
    .unwrap();
    assert_eq!(pulled.len(), 2);
    assert_eq!(pulled[1], new);
    let trigger: String = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.trigger') FROM jobs
         WHERE json_extract(payload, '$.kind') = 'pull'
         ORDER BY created_at DESC, rowid DESC LIMIT 1",
    )
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(trigger, "tag_moved");
}

#[tokio::test]
async fn a_stored_or_evicted_digest_is_never_pulled_again() {
    let env = env("known").await;
    env.add_source("s1", REPO, "stable").await;
    set_tags(&env.script, REPO, &["stable", "also-stable"]);
    put_single(&env.script, REPO, "stable", "amd64", "x");
    assert_eq!(env.run(REPO, NOW).await.queued, 1);

    for state in ["stored", "evicted", "failed"] {
        sqlx::query("UPDATE image_platforms SET state = ?")
            .bind(state)
            .execute(&env.pool)
            .await
            .unwrap();
        assert_eq!(env.run(REPO, NOW + 10).await.queued, 0, "{state}");
    }
    // A second source and a second tag that reach the same digest share the image (decision 8).
    env.add_source("s2", REPO, "also-stable").await;
    put_single(&env.script, REPO, "also-stable", "amd64", "x");
    assert_eq!(env.run(REPO, NOW + 20).await.queued, 0);
    assert_eq!(env.pulls().await, 1);
    assert_eq!(env.count("SELECT COUNT(*) FROM images").await, 1);
    assert_eq!(env.count("SELECT COUNT(*) FROM tag_observations").await, 2);
}

#[tokio::test]
async fn two_concurrent_runs_queue_one_pull() {
    let env = env("concurrent").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_single(&env.script, REPO, "latest", "amd64", "race");

    let payload = env.payload(REPO);
    let (a, b) = tokio::join!(
        env.discovery.discover_now(&payload, NOW),
        env.discovery.discover_now(&payload, NOW)
    );
    let queued = a.unwrap().queued + b.unwrap().queued;
    assert_eq!(queued, 1);
    assert_eq!(env.pulls().await, 1);
    assert_eq!(env.count("SELECT COUNT(*) FROM images").await, 1);
    assert_eq!(env.count("SELECT COUNT(*) FROM tag_observations").await, 1);
}

#[tokio::test]
async fn a_multi_arch_index_yields_one_platform_row_each_and_skips_attestations() {
    let env = env("index").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_index(
        &env.script,
        REPO,
        "latest",
        &[
            ("linux", "amd64", None),
            ("linux", "arm64", None),
            ("linux", "arm", Some("v7")),
        ],
        true,
    );

    assert_eq!(env.run(REPO, NOW).await.queued, 3);
    let platforms: Vec<String> =
        sqlx::query_scalar("SELECT platform FROM image_platforms ORDER BY platform")
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(
        platforms,
        vec!["linux/amd64", "linux/arm/v7", "linux/arm64"]
    );
    assert_eq!(
        env.count("SELECT COUNT(*) FROM images WHERE is_index = 1")
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT COUNT(*) FROM image_platforms WHERE state = 'queued'")
            .await,
        3
    );
    assert_eq!(env.pulls().await, 3);
    // Each pull job names a platform row and its digest, and no secret.
    let payloads: Vec<String> = sqlx::query_scalar("SELECT payload FROM jobs")
        .fetch_all(&env.pool)
        .await
        .unwrap();
    for text in payloads {
        let job: PullPayload = serde_json::from_str(&text).unwrap();
        assert_eq!(job.kind, "pull");
        assert!(crate::services::registry::grammar::is_sha256_digest(
            &job.digest
        ));
    }
}

#[tokio::test]
async fn a_single_manifest_yields_one_platform_from_its_config() {
    let env = env("single").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    let digest = put_single(&env.script, REPO, "latest", "arm64", "one");

    assert_eq!(env.run(REPO, NOW).await.queued, 1);
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT p.platform, p.platform_digest, i.is_index
         FROM image_platforms p JOIN images i ON i.id = p.image_id",
    )
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(row, ("linux/arm64".to_owned(), digest, false));
}

#[tokio::test]
async fn a_listing_error_records_nothing() {
    let env = env("list-error").await;
    env.add_source("s1", REPO, "*").await;
    put_single(&env.script, REPO, "a", "amd64", "a");
    put_single(&env.script, REPO, "b", "amd64", "b");
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(200, br#"{"tags":["a"]}"#).header(
            "Link",
            &format!("</v2/{REPO}/tags/list?last=a&n=100>; rel=\"next\""),
        ),
    );
    env.script.route(
        &format!("/v2/{REPO}/tags/list?last=a&n=100"),
        Reply::new(500, b"{}"),
    );

    let result = env.discovery.discover_now(&env.payload(REPO), NOW).await;
    assert_eq!(result, Err(AppError::UpstreamStatus(500)));
    assert_eq!(env.count("SELECT COUNT(*) FROM images").await, 0);
    assert_eq!(env.count("SELECT COUNT(*) FROM tag_observations").await, 0);
    assert_eq!(env.pulls().await, 0);
    // The run is recorded as failed with the fixed text only.
    let (status, summary): (String, Option<String>) =
        sqlx::query_as("SELECT status, error_summary FROM job_runs WHERE job_kind = 'discover'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(summary.as_deref(), Some("registry returned status 500"));
}

#[tokio::test]
async fn a_listing_that_hits_the_page_cap_records_only_the_head() {
    let env = env("page-cap").await;
    env.add_source("s1", REPO, "*").await;
    put_single(&env.script, REPO, "a", "amd64", "a");
    put_single(&env.script, REPO, "b", "amd64", "b");
    put_single(&env.script, REPO, "c", "amd64", "c");
    // Page 1 lists `a`, then every later page lists `b` and links to itself, so the listing
    // never ends. `c` is in the unreachable tail.
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(200, br#"{"tags":["a"]}"#).header(
            "Link",
            &format!("</v2/{REPO}/tags/list?last=a&n=100>; rel=\"next\""),
        ),
    );
    env.script.route(
        &format!("/v2/{REPO}/tags/list?last=a&n=100"),
        Reply::new(200, br#"{"tags":["b"]}"#).header(
            "Link",
            &format!("</v2/{REPO}/tags/list?last=a&n=100>; rel=\"next\""),
        ),
    );

    let report = env.run(REPO, NOW).await;
    assert!(!report.complete);
    assert_eq!(report.queued, 2);
    let tags: Vec<String> = sqlx::query_scalar("SELECT tag FROM tag_observations ORDER BY tag")
        .fetch_all(&env.pool)
        .await
        .unwrap();
    assert_eq!(tags, vec!["a", "b"], "nothing is recorded for the tail");

    // The next run, with the listing healed, finds the tail.
    set_tags(&env.script, REPO, &["a", "b", "c"]);
    let healed = env.run(REPO, NOW + 3600).await;
    assert_eq!((healed.queued, healed.complete), (1, true));
}

#[tokio::test]
async fn a_next_link_to_another_place_ends_the_listing_as_incomplete() {
    let env = env("bad-link").await;
    env.add_source("s1", REPO, "*").await;
    put_single(&env.script, REPO, "a", "amd64", "a");
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(200, br#"{"tags":["a"]}"#).header(
            "Link",
            "<https://elsewhere.example/v2/x/tags/list>; rel=\"next\"",
        ),
    );
    let report = env.run(REPO, NOW).await;
    assert_eq!((report.queued, report.complete), (1, false));
}

#[tokio::test]
async fn one_job_covers_every_source_on_the_repository() {
    let env = env("two-sources").await;
    env.add_source("s1", REPO, "1.*").await;
    env.add_source("s2", REPO, "latest").await;
    env.add_source("s3", "team/other", "*").await;
    set_tags(&env.script, REPO, &["1.0", "latest"]);
    put_single(&env.script, REPO, "1.0", "amd64", "a");
    put_single(&env.script, REPO, "latest", "amd64", "b");

    assert_eq!(env.run(REPO, NOW).await.queued, 2);
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT source_id, tag FROM tag_observations ORDER BY source_id, tag")
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![("s1".into(), "1.0".into()), ("s2".into(), "latest".into())]
    );
    // The other repository's source is untouched.
    let other: Option<i64> =
        sqlx::query_scalar("SELECT last_discovery_at FROM image_sources WHERE id = 's3'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(other, None);
}

#[tokio::test]
async fn the_schedule_queues_one_job_per_repository_each_hour() {
    let env = env("schedule").await;
    env.add_source("s1", REPO, "1.*").await;
    env.add_source("s2", REPO, "latest").await;
    env.add_source("s3", "team/other", "*").await;

    assert_eq!(schedule::schedule_once(&env.pool, NOW).await.unwrap(), 2);
    // While those jobs are queued, the next pass adds none.
    assert_eq!(
        schedule::schedule_once(&env.pool, NOW + 3600)
            .await
            .unwrap(),
        0
    );

    // A finished job lets the next hour queue again.
    sqlx::query("UPDATE jobs SET status = 'done'")
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        schedule::schedule_once(&env.pool, NOW + 7200)
            .await
            .unwrap(),
        2
    );

    // A failed latest job is retried by the next hourly pass, once per repository.
    sqlx::query("UPDATE jobs SET status = 'failed' WHERE created_at = ?")
        .bind(NOW + 7200)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        schedule::schedule_once(&env.pool, NOW + 10_800)
            .await
            .unwrap(),
        2
    );
    // A queued or running latest job still blocks the repository.
    sqlx::query("UPDATE jobs SET status = 'running' WHERE created_at = ?")
        .bind(NOW + 10_800)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        schedule::schedule_once(&env.pool, NOW + 14_400)
            .await
            .unwrap(),
        0
    );

    let payloads: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM jobs WHERE created_at = ? ORDER BY payload")
            .bind(NOW)
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(payloads.len(), 2);
    for text in payloads {
        let job: DiscoverPayload = serde_json::from_str(&text).unwrap();
        assert_eq!((job.kind.as_str(), job.source_id), ("discover", None));
    }
}

#[tokio::test]
async fn the_discover_handler_records_a_job_run_and_maps_failures_to_fixed_text() {
    let env = env("handler").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_single(&env.script, REPO, "latest", "amd64", "h");
    let text = env.payload(REPO).to_text().unwrap();

    assert_eq!(
        env.discovery.run_discover(&text, NOW).await,
        JobOutcome::Done
    );
    let (kind, status, processed): (String, String, i64) =
        sqlx::query_as("SELECT job_kind, status, processed_count FROM job_runs")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(
        (kind.as_str(), status.as_str(), processed),
        ("discover", "done", 1)
    );

    // A registry that answers 401 with no challenge is a credentials failure.
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(401, b"{}"),
    );
    assert_eq!(
        env.discovery.run_discover(&text, NOW + 1).await,
        JobOutcome::Failed("registry rejected the credentials".to_owned())
    );
    // A 404 is not found, and a 500 carries only its status number.
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(404, b"secret body"),
    );
    assert_eq!(
        env.discovery.run_discover(&text, NOW + 2).await,
        JobOutcome::Failed("image not found in registry".to_owned())
    );
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(503, b"secret body"),
    );
    assert_eq!(
        env.discovery.run_discover(&text, NOW + 3).await,
        JobOutcome::Failed("registry returned status 503".to_owned())
    );
    // A 429 defers, except an anonymous Docker Hub pull (decision 40).
    env.script.route(
        &format!("/v2/{REPO}/tags/list?n=100"),
        Reply::new(429, b"{}").header("Retry-After", "600"),
    );
    assert!(matches!(
        env.discovery.run_discover(&text, NOW + 4).await,
        JobOutcome::Deferred { .. }
    ));
    assert_eq!(
        failure(&AppError::RateLimited, true, NOW),
        JobOutcome::Failed(MSG_DOCKER_HUB_RATE_LIMIT.to_owned())
    );
    assert_eq!(
        env.discovery.run_discover("not json", NOW).await,
        JobOutcome::Permanent("job payload is not valid".to_owned())
    );
}

#[tokio::test]
async fn the_job_handler_maps_pull_errors_to_fixed_text_and_other_kinds_permanently() {
    let env = env("dispatch").await;
    let key = Arc::new(
        crate::auth::crypto::credentials_key(
            &crate::config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap(),
        )
        .unwrap(),
    );
    let notifier = crate::services::alerts::Notifier::new(env.pool.clone(), key.clone(), false);
    let handler = SpinoffJobs::new(
        env.discovery.clone(),
        notifier,
        env.pool.clone(),
        crate::services::storage::StoreRoot::at(env.dir.join("images")),
        crate::services::scan::ScanEnv::under(&env.dir),
        crate::services::publish::Publisher::new(
            env.pool.clone(),
            key.clone(),
            crate::services::storage::StoreRoot::at(env.dir.join("images")),
            crate::services::github_url::GithubTarget::default(),
        )
        .unwrap(),
    );
    let job = |payload: &str| crate::db::jobs::ClaimedJob {
        id: "j".to_owned(),
        source_id: None,
        attempts: 0,
        payload: payload.to_owned(),
    };
    // A pull for a platform row that does not exist fails with the fixed not-found text.
    assert_eq!(
        handler
            .run(job(
                r#"{"kind":"pull","platform_id":"00000000000000000000000000000009","digest":"d","trigger":"first_pull"}"#
            ))
            .await,
        JobOutcome::Failed("image not found in registry".to_owned())
    );
    assert_eq!(
        handler
            .run(job(
                r#"{"kind":"pull","platform_id":"../x","digest":"d","trigger":"t"}"#
            ))
            .await,
        JobOutcome::Permanent("job payload is not valid".to_owned())
    );
    assert_eq!(
        handler.run(job(r#"{"kind":"scan"}"#)).await,
        JobOutcome::Permanent("job payload is not valid".to_owned())
    );
    assert_eq!(
        handler.run(job(r#"{"kind":"publish"}"#)).await,
        JobOutcome::Permanent("job payload is not valid".to_owned())
    );
    assert_eq!(
        handler.run(job("{}")).await,
        JobOutcome::Permanent(crate::worker::MSG_UNHANDLED.to_owned())
    );
}

#[test]
fn platform_text_refuses_odd_registry_text() {
    assert_eq!(
        platform_text("linux", "arm", Some("v7")).unwrap(),
        "linux/arm/v7"
    );
    assert!(platform_text("linux", "am d64", None).is_err());
    assert!(platform_text("Linux", "amd64", None).is_err());
    assert!(platform_text("linux", "", None).is_err());
    assert!(platform_text("linux", &"a".repeat(80), None).is_err());
}

#[tokio::test]
async fn a_new_pull_job_payload_carries_the_repository_and_tag() {
    let env = env("pull-fields").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_single(&env.script, REPO, "latest", "amd64", "pf");
    assert_eq!(env.run(REPO, NOW).await.queued, 1);
    let text: String = sqlx::query_scalar(
        "SELECT payload FROM jobs WHERE json_extract(payload, '$.kind') = 'pull'",
    )
    .fetch_one(&env.pool)
    .await
    .unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    assert_eq!(value["repo_full_name"], REPO);
    assert_eq!(value["tag"], "latest");
    assert_eq!(value["trigger"], "first_pull");
}

#[tokio::test]
async fn scheduled_discover_job_carries_trigger_scheduled() {
    let env = env("schedule-trigger").await;
    env.add_source("s1", REPO, "latest").await;
    assert_eq!(schedule::schedule_once(&env.pool, NOW).await.unwrap(), 1);
    let text: String = sqlx::query_scalar("SELECT payload FROM jobs")
        .fetch_one(&env.pool)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["trigger"], "scheduled");
}

#[tokio::test]
async fn a_discovery_with_no_new_tags_is_recorded_as_empty() {
    let env = env("discover-empty").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest"]);
    put_single(&env.script, REPO, "latest", "amd64", "same");
    let text = env.payload(REPO).to_text().unwrap();
    // The first run finds a new tag: it has output.
    assert_eq!(
        env.discovery.run_discover(&text, NOW).await,
        JobOutcome::Done
    );
    // The second run records no new tag: it is empty.
    assert_eq!(
        env.discovery.run_discover(&text, NOW + 3600).await,
        JobOutcome::DoneEmpty(None)
    );
}

/// Marks every platform of the image `digest` as stored, as a finished pull does.
async fn store_platforms(env: &Env, digest: &str) {
    sqlx::query(
        "UPDATE image_platforms SET state = 'stored', pulled_at = 1
         WHERE image_id = (SELECT id FROM images WHERE digest = ?)",
    )
    .bind(digest)
    .execute(&env.pool)
    .await
    .unwrap();
}

async fn scan_triggers(env: &Env) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT json_extract(payload, '$.trigger') FROM jobs
         WHERE json_extract(payload, '$.kind') = 'scan' ORDER BY rowid",
    )
    .fetch_all(&env.pool)
    .await
    .unwrap()
}

/// #391: a tag that moves back to a digest already stored queues a scan of it, once.
#[tokio::test]
async fn a_tag_moved_to_a_scanned_digest_queues_one_rescan_per_scanner() {
    let env = env("moved-rescan").await;
    env.add_source("s1", REPO, "latest").await;
    set_tags(&env.script, REPO, &["latest", "other"]);
    // `other` reaches digest A first; `latest` is on B.
    let a = put_single(&env.script, REPO, "other", "amd64", "a");
    put_single(&env.script, REPO, "latest", "amd64", "b");
    env.add_source("s2", REPO, "other").await;
    assert_eq!(env.run(REPO, NOW).await.queued, 2);
    store_platforms(&env, &a).await;
    store_platforms(&env, &digest_of_latest(&env).await).await;
    assert!(scan_triggers(&env).await.is_empty());

    // `latest` moves to A, which is known: no pull, but a scan per enabled scanner.
    env.script.route(
        &format!("/v2/{REPO}/manifests/latest"),
        env.script
            .reply_for(&format!("/v2/{REPO}/manifests/other"))
            .unwrap(),
    );
    let report = env.run(REPO, NOW + 3600).await;
    assert_eq!(report.queued, 0, "no pull job for a known digest");
    assert_eq!(env.pulls().await, 2);
    assert_eq!(scan_triggers(&env).await, vec!["tag_moved"; 2]);
    let source: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT source_id FROM jobs WHERE json_extract(payload, '$.kind') = 'scan'",
    )
    .fetch_all(&env.pool)
    .await
    .unwrap();
    assert!(source.iter().all(|s| s.as_deref() == Some("s1")));

    // A second discovery of the same digest queues nothing more.
    env.run(REPO, NOW + 7200).await;
    assert_eq!(scan_triggers(&env).await.len(), 2);
}

async fn digest_of_latest(env: &Env) -> String {
    sqlx::query_scalar("SELECT i.digest FROM images i JOIN tag_observations o ON o.image_id = i.id WHERE o.tag = 'latest'")
        .fetch_one(&env.pool)
        .await
        .unwrap()
}

/// #391: a tag moved to a digest whose pull has not finished queues no scan: the pull job does.
#[tokio::test]
async fn a_tag_moved_to_an_unstored_digest_queues_no_scan_beside_the_pull() {
    let env = env("moved-unstored").await;
    env.add_source("s1", REPO, "*").await;
    set_tags(&env.script, REPO, &["latest", "other"]);
    let a = put_single(&env.script, REPO, "other", "amd64", "a");
    put_single(&env.script, REPO, "latest", "amd64", "b");
    assert_eq!(env.run(REPO, NOW).await.queued, 2);
    // Digest A is still `queued` (not pulled). `latest` moves to it.
    env.script.route(
        &format!("/v2/{REPO}/manifests/latest"),
        env.script
            .reply_for(&format!("/v2/{REPO}/manifests/other"))
            .unwrap(),
    );
    let _ = a;
    assert_eq!(env.run(REPO, NOW + 3600).await.queued, 0);
    assert_eq!(env.pulls().await, 2, "no duplicate pull job");
    assert!(scan_triggers(&env).await.is_empty());
}
