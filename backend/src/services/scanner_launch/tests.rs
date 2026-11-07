//! Scanner launch tests (#224). A fake Harbor answers the scanner calls. No live Harbor and no
//! real token is used.

use std::sync::{Arc, Mutex};

use reqwest::Url;

use super::*;
use crate::auth::crypto::{self, credentials_key, encrypt as seal};
use crate::config;
use crate::db;
use crate::db::mappings as mapping_db;
use crate::services::harbor_client::HarborReply;

const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const BASE: &str = "https://harbor.example.com";

fn key() -> DerivedKey {
    let root = config::parse_encryption_key(ROOT).unwrap();
    credentials_key(&root).unwrap()
}

fn scanner_json(uuid: &str, name: &str, disabled: bool) -> String {
    format!(
        r#"{{"uuid":"{uuid}","name":"{name}","vendor":"v","version":"1","disabled":{disabled},"url":"https://secret.invalid","auth":"SENTINEL-launch"}}"#
    )
}

/// A fake Harbor. `candidates_status` is the answer to the candidates call (call 2); `scanners`
/// is its body.
struct FakeHarbor {
    candidates_status: u16,
    scanners: Vec<(&'static str, &'static str, bool)>,
    calls: Mutex<Vec<String>>,
}

impl FakeHarbor {
    fn new(candidates_status: u16, scanners: Vec<(&'static str, &'static str, bool)>) -> Arc<Self> {
        Arc::new(Self {
            candidates_status,
            scanners,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl HarborFetch for Arc<FakeHarbor> {
    async fn fetch(
        &self,
        url: &Url,
        _username: &str,
        _secret: &[u8],
        _headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        self.calls.lock().unwrap().push(url.path().to_owned());
        if url.path().ends_with("/scanner/candidates") {
            if self.candidates_status != 200 {
                return Ok(HarborReply::new(self.candidates_status, b"{}".to_vec()));
            }
            let body = self
                .scanners
                .iter()
                .map(|(uuid, name, disabled)| scanner_json(uuid, name, *disabled))
                .collect::<Vec<_>>()
                .join(",");
            return Ok(HarborReply::new(200, format!("[{body}]").into_bytes()));
        }
        // Call 1: the current scanner is the first one.
        let (uuid, name, _) = self
            .scanners
            .first()
            .copied()
            .unwrap_or(("u-0", "None", false));
        Ok(HarborReply::new(
            200,
            scanner_json(uuid, name, false).into_bytes(),
        ))
    }
}

async fn fixture(name: &str) -> (SqlitePool, std::path::PathBuf, MappingRow) {
    let dir = std::env::temp_dir().join(format!("harborgate-launch-{name}-{}", std::process::id()));
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
    let mut conn = pool.acquire().await.unwrap();
    let mapping = mapping_db::find_by_id(&mut conn, "m1")
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    (pool, dir, mapping)
}

fn actor() -> Actor {
    Actor {
        user_id: Some("u1".to_owned()),
        username: "u1".to_owned(),
    }
}

async fn start(
    state: &ScannerLaunchState,
    pool: &SqlitePool,
    harbor: &Arc<FakeHarbor>,
    mapping: &MappingRow,
    tag: &str,
    scanner: Option<&str>,
) -> Result<Queued, PickerFail> {
    start_scan(
        state,
        pool,
        &key(),
        harbor,
        &actor(),
        mapping,
        tag,
        scanner,
        1_000,
    )
    .await
}

async fn jobs(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT payload FROM sync_jobs ORDER BY created_at, id")
        .fetch_all(pool)
        .await
        .unwrap()
}

fn status_of(fail: &PickerFail) -> u16 {
    match fail {
        PickerFail::Fixed { status, .. } => status.as_u16(),
        PickerFail::App(error) => error.status().as_u16(),
    }
}

/// A robot without Scanner Create (403 on the candidates call) still scans: `unavailable`, and the
/// job is a plain `scan` of the tag with the current scanner, with no scanner choice needed.
#[tokio::test]
async fn a_scan_without_scanner_create_still_runs() {
    let (pool, dir, mapping) = fixture("no-create").await;
    let harbor = FakeHarbor::new(403, vec![("u-1", "Trivy", false)]);
    let state = ScannerLaunchState::new();

    let list = list(&state, &pool, &key(), &harbor, "u1", &mapping)
        .await
        .unwrap();
    assert_eq!(list.scanner_choice, "unavailable");
    assert!(list.scanners.is_empty());

    let queued = start(&state, &pool, &harbor, &mapping, "v1", None)
        .await
        .unwrap();
    assert!(queued.queued);
    assert_eq!(queued.scanner_uuid, None);
    let payloads = jobs(&pool).await;
    assert_eq!(payloads.len(), 1);
    let payload: serde_json::Value = serde_json::from_str(&payloads[0]).unwrap();
    assert_eq!(payload["kind"], "scan");
    assert_eq!(payload["tag"], "v1");
    assert_eq!(payload["trigger"], "manual");
    assert!(payload.get("scanner_uuid").is_none(), "no switch");
    let audits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'mapping.scan'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audits, 1);
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// With several scanners the list says `available`, in name order, never leaks the URL or auth,
/// and a scan must name one of them.
#[tokio::test]
async fn several_scanners_need_a_choice() {
    let (pool, dir, mapping) = fixture("several").await;
    let harbor = FakeHarbor::new(
        200,
        vec![
            ("u-2", "trivy", false),
            ("u-1", "Grype", false),
            ("u-3", "Off", true),
        ],
    );
    let state = ScannerLaunchState::new();

    let listed = list(&state, &pool, &key(), &harbor, "u1", &mapping)
        .await
        .unwrap();
    assert_eq!(listed.scanner_choice, "available");
    let names: Vec<&str> = listed.scanners.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        ["Grype", "trivy"],
        "disabled left out, case-insensitive order"
    );
    let text = serde_json::to_string(&listed).unwrap();
    assert!(!text.contains("SENTINEL-launch") && !text.contains("secret.invalid"));
    // The list is cached: a second read makes no Harbor call.
    let calls = harbor.calls();
    list(&state, &pool, &key(), &harbor, "u1", &mapping)
        .await
        .unwrap();
    assert_eq!(harbor.calls(), calls);

    let missing = start(&state, &pool, &harbor, &mapping, "v1", None)
        .await
        .unwrap_err();
    assert_eq!(status_of(&missing), 400, "Choose a scanner.");
    let unknown = start(&state, &pool, &harbor, &mapping, "v1", Some("u-9"))
        .await
        .unwrap_err();
    assert_eq!(status_of(&unknown), 422);
    let disabled = start(&state, &pool, &harbor, &mapping, "v1", Some("u-3"))
        .await
        .unwrap_err();
    assert_eq!(status_of(&disabled), 422, "a disabled scanner cannot scan");
    assert!(
        jobs(&pool).await.is_empty(),
        "a refused request queues nothing"
    );

    let queued = start(&state, &pool, &harbor, &mapping, "v1", Some("u-1"))
        .await
        .unwrap();
    assert_eq!(queued.scanner_uuid.as_deref(), Some("u-1"));
    let payload: serde_json::Value = serde_json::from_str(&jobs(&pool).await[0]).unwrap();
    assert_eq!(payload["kind"], "scanner_scan");
    assert_eq!(payload["scanner_uuid"], "u-1");
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// One scanner needs no choice and a given UUID is ignored. A bad tag is `422`. The same scan
/// again is `409` while queued, and over the cooldown `429` with a wait.
#[tokio::test]
async fn single_scanner_tag_rule_conflict_and_cooldown() {
    let (pool, dir, mapping) = fixture("single").await;
    let harbor = FakeHarbor::new(200, vec![("u-1", "Trivy", false)]);
    let state = ScannerLaunchState::new();

    let bad = start(&state, &pool, &harbor, &mapping, ".bad", None)
        .await
        .unwrap_err();
    assert_eq!(status_of(&bad), 422);
    assert_eq!(harbor.calls(), 0, "a bad tag makes no request");

    let listed = list(&state, &pool, &key(), &harbor, "u1", &mapping)
        .await
        .unwrap();
    assert_eq!(listed.scanner_choice, "single");
    let queued = start(&state, &pool, &harbor, &mapping, "v1", Some("ignored"))
        .await
        .unwrap();
    assert_eq!(queued.scanner_uuid, None);

    let again = start(&state, &pool, &harbor, &mapping, "v1", None)
        .await
        .unwrap_err();
    assert_eq!(status_of(&again), 409, "a scan is already queued");
    assert_eq!(jobs(&pool).await.len(), 1);

    // Mark the job done: the conflict is gone, the 5-minute cooldown is not.
    sqlx::query("UPDATE sync_jobs SET status = 'done'")
        .execute(&pool)
        .await
        .unwrap();
    let limited = start(&state, &pool, &harbor, &mapping, "v1", None)
        .await
        .unwrap_err();
    match limited {
        PickerFail::Fixed {
            status,
            retry_after,
            ..
        } => {
            assert_eq!(status.as_u16(), 429);
            assert!(retry_after.is_some_and(|wait| (1..=300).contains(&wait)));
        }
        other => panic!("expected a 429, got {other:?}"),
    }
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A scan with a switch is refused with `409` while the project lock waits for a restore.
#[tokio::test]
async fn a_pending_restore_blocks_a_new_switch() {
    let (pool, dir, mapping) = fixture("restore-pending").await;
    let harbor = FakeHarbor::new(200, vec![("u-1", "Trivy", false), ("u-2", "Grype", false)]);
    let state = ScannerLaunchState::new();
    sqlx::query(
        "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload) VALUES ('j0', 'm1', 'failed', 8, '{}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO project_scanner_locks (harbor_base_url, harbor_project, job_id, mapping_id, chosen_scanner_uuid, previous_scanner_uuid, state, acquired_at)
         VALUES (?, 'proj', 'j0', 'm1', 'u-2', 'u-1', 'restore_pending', 1)",
    )
    .bind(BASE)
    .execute(&pool)
    .await
    .unwrap();

    let refused = start(&state, &pool, &harbor, &mapping, "v1", Some("u-2"))
        .await
        .unwrap_err();
    assert_eq!(status_of(&refused), 409);
    assert!(jobs(&pool).await.len() == 1, "only the seeded job exists");
    let listed = list(&state, &pool, &key(), &harbor, "u1", &mapping)
        .await
        .unwrap();
    assert_eq!(
        listed.switch.map(|s| s.state),
        Some("restore_pending".to_owned())
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_tag_rule_matches_harbor() {
    assert!(valid_tag("v1.2-rc_3"));
    assert!(valid_tag("_x"));
    assert!(!valid_tag(""));
    assert!(!valid_tag(".x"));
    assert!(!valid_tag("-x"));
    assert!(!valid_tag("a/b"));
    assert!(!valid_tag(&"a".repeat(129)));
    assert!(valid_tag(&"a".repeat(128)));
}
