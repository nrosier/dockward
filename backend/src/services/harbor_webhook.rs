//! Harbor webhook parsing and filtering (`specs/integrations.md`, Harbor webhook).
//!
//! The body is parsed once. A top-level `specversion` marks CloudEvents. Otherwise the
//! default Harbor JSON shape is used. Both produce one [`ScanEvent`]. A job is created
//! only for a vulnerability scan of the mapping's repository.

use std::future::Future;

use serde_json::Value;

use crate::auth::crypto::DerivedKey;
use crate::error::AppError;
use crate::services::credentials::base_for_join;
use crate::services::harbor_client::{artifact_url, parse_artifact_tags};
use crate::services::pickers::valid_digest;
use crate::services::poller::harbor_login;
use crate::services::sync::HarborFetch;

/// The validated event stored in `sync_jobs.payload`. It holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScanEvent {
    /// `<project>/<repository>`, as Harbor reports it.
    pub repo_full_name: String,
    /// The artifact digest, `sha256:<hex>`.
    pub digest: String,
    /// The tag. Always non-empty: an untagged event is queued once per tag that a lookup of
    /// its digest returns (`specs/integrations.md`, Harbor webhook).
    pub tag: String,
}

/// What a valid body means for the mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Store a `sync_jobs` row with this event.
    Queue(ScanEvent),
    /// A vulnerability scan of this repository with a digest but no tag. The caller looks up
    /// the digest's tags in Harbor and queues one job per tag (`specs/integrations.md`). The
    /// digest has passed the `sha256:` check, so it is safe to put in a URL.
    LookupTags {
        repo_full_name: String,
        digest: String,
    },
    /// Valid, but not a vulnerability scan of this repository. Nothing is stored.
    Ignore,
}

/// Parses the body and decides. Returns `400` for a body that is not JSON or matches
/// neither format. `repo_full_name` is the mapping's `<harbor_project>/<harbor_repository>`.
/// The event's `repository.repo_full_name`, read in either payload format, or `None` when the
/// body does not name one. A project webhook uses it to choose the mapping (#132). The body
/// is validated by `classify` after the mapping is chosen.
pub fn event_repository(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?;
    let data = if object.contains_key("specversion") {
        value.get("data").cloned().unwrap_or(Value::Null)
    } else {
        value.get("event_data").cloned().unwrap_or(Value::Null)
    };
    string_at(&data, &["repository", "repo_full_name"])
}

pub fn classify(body: &[u8], repo_full_name: &str) -> Result<Outcome, AppError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| bad_request())?;
    let object = value.as_object().ok_or_else(bad_request)?;
    let (event_type, data) = if object.contains_key("specversion") {
        // CloudEvents: the type and the payload sit under `type` and `data`.
        (
            string_at(&value, &["type"]),
            value.get("data").cloned().unwrap_or(Value::Null),
        )
    } else {
        // Harbor default: the type is top-level and the payload is under `event_data`.
        if !object.contains_key("type") {
            return Err(bad_request());
        }
        (
            string_at(&value, &["type"]),
            value.get("event_data").cloned().unwrap_or(Value::Null),
        )
    };
    let is_scan_completed = matches!(
        event_type.as_deref(),
        Some("SCANNING_COMPLETED") | Some("harbor.scan.completed")
    );
    if !is_scan_completed {
        return Ok(Outcome::Ignore);
    }
    let scan_type = string_at(&data, &["scan", "scan_type"]);
    if scan_type.as_deref() != Some("vulnerability") {
        return Ok(Outcome::Ignore);
    }
    let repo = string_at(&data, &["repository", "repo_full_name"]);
    if repo.as_deref() != Some(repo_full_name) {
        return Ok(Outcome::Ignore);
    }
    let Some(digest) = string_at(&data, &["resources", "0", "digest"]) else {
        return Err(bad_request());
    };
    // An untagged event carries only the digest. CVEs are tracked per tag, so the caller looks
    // the tags up. A digest that is not `sha256:` plus 64 lowercase hex is ignored before any
    // URL is built from it.
    let tag = match string_at(&data, &["resources", "0", "tag"]) {
        Some(tag) if !tag.is_empty() => tag,
        _ if valid_digest(&digest) => {
            return Ok(Outcome::LookupTags {
                repo_full_name: repo_full_name.to_owned(),
                digest,
            });
        }
        _ => return Ok(Outcome::Ignore),
    };
    Ok(Outcome::Queue(ScanEvent {
        repo_full_name: repo_full_name.to_owned(),
        digest,
        tag,
    }))
}

/// Walks a JSON path of object keys or array indexes and returns the string at the end.
fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = match current {
            Value::Object(map) => map.get(*key)?,
            Value::Array(items) => items.get(key.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    current.as_str().map(str::to_owned)
}

fn bad_request() -> AppError {
    AppError::InvalidRequest("The request body is not a Harbor event.".to_owned())
}

/// Compares two equal-length byte strings without an early exit on the first difference.
/// Used for the digests of the webhook auth secret and the mapping token.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

use sqlx::SqlitePool;

use crate::db::mappings as mapping_db;
use crate::db::sync_jobs;
use crate::services::mappings::digest;

/// The result of one webhook request, for the route to turn into a status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A `sync_jobs` row was stored (`202`).
    Queued,
    /// The event is valid but not for this repository or not a vulnerability scan (`202`).
    Ignored,
}

/// Looks up the mapping that owns `token` by its digest. Returns `None` for an unknown
/// token. The token is hashed before lookup. This is the only step that runs before the
/// route's per-token budget is charged.
pub async fn find_mapping(pool: &SqlitePool, token: &str) -> Result<Option<String>, AppError> {
    mapping_db::find_by_token_hash(pool, &digest(token)).await
}

/// Checks an `Authorization` value against a stored secret digest, in constant time. The value
/// must be `Bearer <secret>`; the prefix is stripped before hashing (`specs/integrations.md`).
/// Shared by mapping and project webhooks, so both check the secret the same way.
pub fn secret_matches(stored_digest: &str, authorization: Option<&str>) -> bool {
    let Some(presented) = authorization.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    constant_time_eq(digest(presented).as_bytes(), stored_digest.as_bytes())
}

/// Looks up the tags of one artifact of a mapping's repository, by digest. The production
/// impl is [`HarborTagLookup`]; tests use a fake and never call Harbor.
pub trait TagLookup: Send + Sync {
    /// The artifact's non-empty tag names. Any failure is an error; the caller queues nothing.
    fn tags(
        &self,
        mapping_id: &str,
        digest: &str,
    ) -> impl Future<Output = Result<Vec<String>, AppError>> + Send;
}

/// The production lookup: `GET .../artifacts/{digest}` (Artifact Read) with the mapping's
/// Harbor credential, through the guarded Harbor reader. Errors are the fixed
/// `upstream_unreachable` or `not_found` values; they never hold the URL, the robot secret,
/// or Harbor's body.
pub struct HarborTagLookup<'a, H> {
    pub pool: &'a SqlitePool,
    pub key: &'a DerivedKey,
    pub http: &'a H,
}

impl<H: HarborFetch> TagLookup for HarborTagLookup<'_, H> {
    async fn tags(&self, mapping_id: &str, digest: &str) -> Result<Vec<String>, AppError> {
        if !valid_digest(digest) {
            return Err(AppError::UpstreamUnreachable);
        }
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        let mapping = mapping_db::find_by_id(&mut conn, mapping_id)
            .await?
            .ok_or(AppError::NotFound)?;
        drop(conn);
        let (username, secret) = harbor_login(self.pool, self.key, &mapping).await?;
        let base = base_for_join(&mapping.harbor_base_url)?;
        let url = artifact_url(
            &base,
            &mapping.harbor_project,
            &mapping.harbor_repository,
            digest,
        )?;
        let (status, body) = self.http.fetch(&url, &username, &secret, &[]).await?;
        if status != 200 {
            return Err(AppError::UpstreamUnreachable);
        }
        parse_artifact_tags(&body)
    }
}

/// Handles one webhook body for an already-found mapping (`specs/integrations.md`). A bad
/// `Authorization` value returns `401`, the same as an unknown token. The secret is
/// compared by digest in constant time.
pub async fn receive_for(
    pool: &SqlitePool,
    mapping_id: &str,
    authorization: Option<&str>,
    body: &[u8],
    now: i64,
    lookup: &impl TagLookup,
    new_job_id: impl FnMut() -> Result<String, AppError>,
) -> Result<Received, AppError> {
    let unauthorized = || AppError::InvalidCredentials;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let row = mapping_db::find_by_id(&mut conn, mapping_id)
        .await?
        .ok_or_else(unauthorized)?;
    drop(conn);
    if !secret_matches(&row.webhook_auth_secret_hash, authorization) {
        return Err(unauthorized());
    }
    let repo_full_name = format!("{}/{}", row.harbor_project, row.harbor_repository);
    queue_event(
        pool,
        mapping_id,
        &repo_full_name,
        body,
        now,
        lookup,
        new_job_id,
    )
    .await
}

/// Classifies one event for a mapping's repository and queues it if it is a vulnerability scan.
/// A tagged event queues one job with no Harbor call. An untagged event with a valid digest
/// asks `lookup` for the digest's tags and queues one job per tag; no tags, or a failed lookup,
/// queues nothing and is still acknowledged, so Harbor does not retry (`specs/integrations.md`).
/// The caller has already checked the `Authorization` secret: the mapping's own for a mapping
/// webhook, or the project's for a project webhook (#132). Both routes share this, so the
/// event rules are the same.
pub async fn queue_event(
    pool: &SqlitePool,
    mapping_id: &str,
    repo_full_name: &str,
    body: &[u8],
    now: i64,
    lookup: &impl TagLookup,
    mut new_job_id: impl FnMut() -> Result<String, AppError>,
) -> Result<Received, AppError> {
    let events = match classify(body, repo_full_name)? {
        Outcome::Ignore => return Ok(Received::Ignored),
        Outcome::Queue(event) => vec![event],
        Outcome::LookupTags {
            repo_full_name,
            digest,
        } => {
            let tags = match lookup.tags(mapping_id, &digest).await {
                Ok(tags) => tags,
                Err(_) => {
                    // Fixed text only: no URL, credential, or Harbor answer.
                    tracing::warn!(
                        mapping_id,
                        "the Harbor tag lookup for an untagged scan event failed; nothing was queued"
                    );
                    return Ok(Received::Ignored);
                }
            };
            tags.into_iter()
                .filter(|tag| !tag.is_empty())
                .map(|tag| ScanEvent {
                    repo_full_name: repo_full_name.clone(),
                    digest: digest.clone(),
                    tag,
                })
                .collect()
        }
    };
    if events.is_empty() {
        return Ok(Received::Ignored);
    }
    for event in &events {
        let payload = serde_json::to_string(event).map_err(|_| AppError::InternalError)?;
        sync_jobs::enqueue(pool, &new_job_id()?, mapping_id, &payload, now).await?;
    }
    Ok(Received::Queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "proj/app";

    /// A default-format scan event for a vulnerability scan of `REPO`.
    fn default_vuln() -> &'static str {
        r#"{
          "type": "SCANNING_COMPLETED",
          "occur_at": 1700000000,
          "operator": "admin",
          "event_data": {
            "repository": {"repo_full_name": "proj/app", "name": "app"},
            "resources": [{"digest": "sha256:aaaa", "tag": "1.2.3"}],
            "scan": {"scan_type": "vulnerability"}
          }
        }"#
    }

    /// The same event in the CloudEvents format.
    fn cloudevents_vuln() -> &'static str {
        r#"{
          "specversion": "1.0",
          "type": "harbor.scan.completed",
          "source": "harbor",
          "data": {
            "repository": {"repo_full_name": "proj/app", "name": "app"},
            "resources": [{"digest": "sha256:aaaa", "tag": "1.2.3"}],
            "scan": {"scan_type": "vulnerability"}
          }
        }"#
    }

    #[test]
    fn default_format_queues_a_job() {
        let outcome = classify(default_vuln().as_bytes(), REPO).unwrap();
        assert_eq!(
            outcome,
            Outcome::Queue(ScanEvent {
                repo_full_name: REPO.to_owned(),
                digest: "sha256:aaaa".to_owned(),
                tag: "1.2.3".to_owned(),
            })
        );
    }

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// An untagged default-format event with a well-formed digest.
    fn untagged() -> String {
        default_vuln()
            .replace(r#", "tag": "1.2.3""#, "")
            .replace("sha256:aaaa", DIGEST)
    }

    #[test]
    fn untagged_event_with_a_valid_digest_needs_a_tag_lookup() {
        // A missing tag and an empty tag both mean the image was pushed by digest.
        let expected = Outcome::LookupTags {
            repo_full_name: REPO.to_owned(),
            digest: DIGEST.to_owned(),
        };
        let missing = untagged();
        assert_eq!(missing.matches("\"tag\"").count(), 0, "fixture");
        assert_eq!(classify(missing.as_bytes(), REPO).unwrap(), expected);
        let empty = default_vuln()
            .replace("sha256:aaaa", DIGEST)
            .replace("1.2.3", "");
        assert_eq!(classify(empty.as_bytes(), REPO).unwrap(), expected);
        // The CloudEvents form is the same.
        let cloud = cloudevents_vuln()
            .replace(r#", "tag": "1.2.3""#, "")
            .replace("sha256:aaaa", DIGEST);
        assert_eq!(classify(cloud.as_bytes(), REPO).unwrap(), expected);
        // A tagged event still queues, so the rule is not too broad.
        assert!(matches!(
            classify(default_vuln().as_bytes(), REPO).unwrap(),
            Outcome::Queue(_)
        ));
    }

    #[test]
    fn untagged_event_with_a_bad_digest_is_ignored() {
        for bad in [
            "sha256:aaaa",
            "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha256:../../x",
            "",
        ] {
            let body = default_vuln()
                .replace(r#", "tag": "1.2.3""#, "")
                .replace("sha256:aaaa", bad);
            assert_eq!(
                classify(body.as_bytes(), REPO).unwrap(),
                Outcome::Ignore,
                "{bad}"
            );
        }
    }

    #[test]
    fn cloudevents_format_produces_the_same_event() {
        let default = classify(default_vuln().as_bytes(), REPO).unwrap();
        let cloud = classify(cloudevents_vuln().as_bytes(), REPO).unwrap();
        assert_eq!(default, cloud);
    }

    #[test]
    fn an_sbom_event_is_ignored() {
        let body = default_vuln().replace("vulnerability", "sbom");
        assert_eq!(classify(body.as_bytes(), REPO).unwrap(), Outcome::Ignore);
    }

    #[test]
    fn another_repository_in_the_same_project_is_ignored() {
        let body = default_vuln().replace("proj/app", "proj/other");
        assert_eq!(classify(body.as_bytes(), REPO).unwrap(), Outcome::Ignore);
    }

    #[test]
    fn a_different_event_type_is_ignored() {
        let body = default_vuln().replace("SCANNING_COMPLETED", "PUSH_ARTIFACT");
        assert_eq!(classify(body.as_bytes(), REPO).unwrap(), Outcome::Ignore);
    }

    #[test]
    fn a_body_that_is_not_json_is_a_bad_request() {
        assert!(classify(b"not json", REPO).is_err());
    }

    #[test]
    fn a_json_object_in_neither_format_is_a_bad_request() {
        assert!(classify(br#"{"hello": "world"}"#, REPO).is_err());
    }

    #[test]
    fn constant_time_eq_matches_equal_values_only() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    // ---- queue_event with a fake lookup (no live Harbor) ----

    use std::sync::Mutex;

    use crate::auth::crypto::{self, credentials_key};
    use crate::config;
    use crate::db;
    use crate::services::sync::HarborFetch;

    /// Answers the lookup from a fixed result and counts the calls.
    struct FakeLookup {
        answer: Result<Vec<String>, AppError>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeLookup {
        fn tags(names: &[&str]) -> Self {
            Self {
                answer: Ok(names.iter().map(|n| (*n).to_owned()).collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                answer: Err(AppError::UpstreamUnreachable),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    impl TagLookup for FakeLookup {
        async fn tags(&self, _mapping_id: &str, digest: &str) -> Result<Vec<String>, AppError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(digest.to_owned());
            }
            self.answer.clone()
        }
    }

    struct Db {
        pool: SqlitePool,
        dir: std::path::PathBuf,
    }

    impl Db {
        /// A fresh database with one mapping `m1` on `proj/app`.
        async fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("harborgate-hwebhook-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let pool = db::open(&dir).await.unwrap();
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, token_version)
                 VALUES ('u', 'u', NULL, 'user', 0)",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
                 VALUES ('c1', 'u', 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake'),
                        ('c2', 'u', 'github', 'g', NULL, NULL, 'v1:fake')",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
                 VALUES ('m1', 'u', 'c1', 'c2', 'https://harbor.example.com', 'proj', 'app', 'o', 'g', 't', 's', 0, 'CRITICAL', 'main')",
            )
            .execute(&pool)
            .await
            .unwrap();
            Self { pool, dir }
        }

        async fn payloads(&self) -> Vec<serde_json::Value> {
            let rows: Vec<(String,)> =
                sqlx::query_as("SELECT payload FROM sync_jobs ORDER BY payload")
                    .fetch_all(&self.pool)
                    .await
                    .unwrap();
            rows.into_iter()
                .map(|(p,)| serde_json::from_str(&p).unwrap())
                .collect()
        }

        async fn finish(self) {
            self.pool.close().await;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn counter() -> impl FnMut() -> Result<String, AppError> {
        let mut n = 0;
        move || {
            n += 1;
            Ok(format!("job-{n}"))
        }
    }

    async fn run(db: &Db, body: &str, lookup: &FakeLookup) -> Received {
        queue_event(
            &db.pool,
            "m1",
            REPO,
            body.as_bytes(),
            1000,
            lookup,
            counter(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_tagged_event_queues_as_before_with_no_lookup() {
        let db = Db::new("tagged").await;
        let lookup = FakeLookup::tags(&["unused"]);
        let received = run(&db, default_vuln(), &lookup).await;
        let jobs = db.payloads().await;
        db.finish().await;
        assert_eq!(received, Received::Queued);
        assert!(lookup.calls().is_empty(), "no lookup for a tagged event");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0]["tag"], "1.2.3");
        assert_eq!(jobs[0]["digest"], "sha256:aaaa");
        assert_eq!(jobs[0]["repo_full_name"], REPO);
    }

    #[tokio::test]
    async fn an_untagged_event_with_one_tag_queues_one_sync() {
        let db = Db::new("one-tag").await;
        let lookup = FakeLookup::tags(&["latest"]);
        let received = run(&db, &untagged(), &lookup).await;
        let jobs = db.payloads().await;
        db.finish().await;
        assert_eq!(received, Received::Queued);
        assert_eq!(lookup.calls(), vec![DIGEST.to_owned()]);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0]["tag"], "latest");
        assert_eq!(jobs[0]["digest"], DIGEST);
    }

    #[tokio::test]
    async fn an_untagged_event_with_two_tags_queues_one_sync_per_tag() {
        let db = Db::new("two-tags").await;
        let lookup = FakeLookup::tags(&["v1", "v2"]);
        let received = run(&db, &untagged(), &lookup).await;
        let jobs = db.payloads().await;
        db.finish().await;
        assert_eq!(received, Received::Queued);
        assert_eq!(lookup.calls().len(), 1, "one lookup, not one per tag");
        let tags: Vec<&str> = jobs.iter().filter_map(|j| j["tag"].as_str()).collect();
        assert_eq!(tags, vec!["v1", "v2"]);
    }

    #[tokio::test]
    async fn an_untagged_event_with_no_tags_queues_nothing() {
        let db = Db::new("no-tags").await;
        let lookup = FakeLookup::tags(&[]);
        let received = run(&db, &untagged(), &lookup).await;
        let jobs = db.payloads().await;
        db.finish().await;
        assert_eq!(received, Received::Ignored);
        assert_eq!(lookup.calls().len(), 1);
        assert!(jobs.is_empty());
    }

    #[tokio::test]
    async fn a_failed_lookup_queues_nothing_and_is_acknowledged() {
        let db = Db::new("lookup-fails").await;
        let lookup = FakeLookup::failing();
        let received = run(&db, &untagged(), &lookup).await;
        let jobs = db.payloads().await;
        db.finish().await;
        assert_eq!(received, Received::Ignored, "Ok, so the route answers 202");
        assert_eq!(lookup.calls().len(), 1);
        assert!(jobs.is_empty());
    }

    #[tokio::test]
    async fn a_bad_digest_makes_no_lookup_and_queues_nothing() {
        let db = Db::new("bad-digest").await;
        let lookup = FakeLookup::tags(&["latest"]);
        let body = untagged().replace(DIGEST, "sha256:../../etc");
        let received = run(&db, &body, &lookup).await;
        let jobs = db.payloads().await;
        db.finish().await;
        assert_eq!(received, Received::Ignored);
        assert!(lookup.calls().is_empty(), "no request for a bad digest");
        assert!(jobs.is_empty());
    }

    // ---- HarborTagLookup against a fake Harbor reader ----

    const TOKEN: &str = "test-fake-robot-secret";

    /// Answers every GET with one status and body, and records the URLs asked.
    struct FakeHarbor {
        answer: Result<(u16, String), ()>,
        urls: Mutex<Vec<String>>,
    }

    impl HarborFetch for FakeHarbor {
        async fn fetch(
            &self,
            url: &reqwest::Url,
            _username: &str,
            _secret: &[u8],
            _extra_headers: &[(&str, &str)],
        ) -> Result<(u16, Vec<u8>), AppError> {
            if let Ok(mut urls) = self.urls.lock() {
                urls.push(url.to_string());
            }
            match &self.answer {
                Ok((status, body)) => Ok((*status, body.clone().into_bytes())),
                Err(()) => Err(AppError::UpstreamUnreachable),
            }
        }
    }

    fn harbor(status: u16, body: &str) -> FakeHarbor {
        FakeHarbor {
            answer: Ok((status, body.to_owned())),
            urls: Mutex::new(Vec::new()),
        }
    }

    /// Gives credential `c1` a real ciphertext so the lookup can decrypt it.
    async fn seal_credential(db: &Db) -> crate::auth::crypto::DerivedKey {
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let key = credentials_key(&root).unwrap();
        let aad = crypto::aad("user_credentials", "encrypted_token", "c1");
        let sealed = crypto::encrypt(&key, &aad, TOKEN.as_bytes()).unwrap();
        sqlx::query("UPDATE user_credentials SET encrypted_token = ? WHERE id = 'c1'")
            .bind(sealed)
            .execute(&db.pool)
            .await
            .unwrap();
        key
    }

    #[tokio::test]
    async fn the_lookup_reads_the_artifact_and_returns_its_tags() {
        let db = Db::new("lookup-ok").await;
        let key = seal_credential(&db).await;
        let http = harbor(
            200,
            r#"{"digest":"x","tags":[{"name":"v1"},{"name":""},{"name":"v2"},{"name":"v1"}]}"#,
        );
        let lookup = HarborTagLookup {
            pool: &db.pool,
            key: &key,
            http: &http,
        };
        let tags = lookup.tags("m1", DIGEST).await.unwrap();
        db.finish().await;
        assert_eq!(tags, vec!["v1", "v2"], "empty and repeated names dropped");
        let urls = http.urls.lock().unwrap().clone();
        let encoded = DIGEST.replace(':', "%3A");
        assert_eq!(
            urls,
            vec![format!(
                "https://harbor.example.com/api/v2.0/projects/proj/repositories/app/artifacts/{encoded}"
            )]
        );
    }

    #[tokio::test]
    async fn a_lookup_failure_is_a_fixed_error_with_no_token_or_url() {
        for answer in [
            Err(()),
            Ok((404, "no such artifact".to_owned())),
            Ok((403, "forbidden".to_owned())),
            Ok((200, "not json".to_owned())),
        ] {
            let db = Db::new("lookup-err").await;
            let key = seal_credential(&db).await;
            let http = FakeHarbor {
                answer,
                urls: Mutex::new(Vec::new()),
            };
            let lookup = HarborTagLookup {
                pool: &db.pool,
                key: &key,
                http: &http,
            };
            let error = lookup.tags("m1", DIGEST).await.unwrap_err();
            // The route's end to end behaviour: nothing queued, acknowledged.
            let received = queue_event(
                &db.pool,
                "m1",
                REPO,
                untagged().as_bytes(),
                1000,
                &lookup,
                counter(),
            )
            .await
            .unwrap();
            let jobs = db.payloads().await;
            db.finish().await;
            let text = format!("{error:?}");
            assert!(!text.contains(TOKEN), "{text}");
            assert!(!text.contains("harbor.example.com"), "{text}");
            assert!(!text.contains(DIGEST), "{text}");
            assert_eq!(received, Received::Ignored);
            assert!(jobs.is_empty());
        }
    }

    #[tokio::test]
    async fn the_lookup_makes_no_request_for_a_bad_digest() {
        let db = Db::new("lookup-bad-digest").await;
        let key = seal_credential(&db).await;
        let http = harbor(200, r#"{"tags":[{"name":"v1"}]}"#);
        let lookup = HarborTagLookup {
            pool: &db.pool,
            key: &key,
            http: &http,
        };
        let result = lookup.tags("m1", "sha256:../x").await;
        db.finish().await;
        assert!(result.is_err());
        assert!(http.urls.lock().unwrap().is_empty());
    }
}
