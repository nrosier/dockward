//! Backup polling (`specs/integrations.md`, Polling).
//!
//! Webhooks are the primary trigger. Every 15 minutes this poller lists the artifacts of
//! each mapping's Harbor repository and queues one sync job for every `(digest, tag)` pair
//! that has a tag and no successful or pending sync. Untagged artifacts are skipped. Each
//! run is recorded in `job_runs` with kind `poll`.
//!
//! The poller only reads from Harbor. It queues jobs; the worker does the syncs. Error
//! text kept in `job_runs` names mapping ids only, never a URL, token, or Harbor answer.

use std::time::Duration;

use serde_json::json;
use sqlx::SqlitePool;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::auth::crypto::DerivedKey;
use crate::db::job_runs::{self, JobRun};
use crate::db::mappings::{self as mapping_db, ListFilter, MappingRow};
use crate::db::{credentials as credential_db, sync_jobs, sync_reports};
use crate::error::AppError;
use crate::services::credentials::{base_for_join, decrypt_token};
use crate::services::harbor_client::{HarborGet, artifacts_list_url, parse_artifact_list};
use crate::services::ids;
use crate::services::sync::HarborFetch;
use crate::worker::now_secs;

/// Delay before the first poll after start.
const FIRST_POLL_DELAY: Duration = Duration::from_secs(60);
/// Time between polls.
const POLL_INTERVAL: Duration = Duration::from_secs(900);
/// Artifacts requested per page.
const PAGE_SIZE: u32 = 100;
/// Pages read per mapping in one poll.
const MAX_PAGES: u32 = 10;

/// Runs one poll over every mapping. Returns how many jobs were queued. A Harbor or
/// credential problem on one mapping is counted and does not stop the others. The run is
/// recorded in `job_runs`: `done` when every mapping was read, otherwise `failed` with the
/// ids of the mappings that could not be read.
pub async fn poll_once<H: HarborFetch>(
    pool: &SqlitePool,
    key: &DerivedKey,
    http: &H,
    now: i64,
) -> Result<u64, AppError> {
    let mappings = mapping_db::list_owned(
        pool,
        &ListFilter {
            user_id: None,
            sort: "created_at",
            sort_sign: 1,
            // SQLite treats a negative LIMIT as no limit.
            limit: -1,
            offset: 0,
        },
    )
    .await?;

    let mut queued = 0u64;
    let mut failed_mappings: Vec<String> = Vec::new();
    for mapping in &mappings {
        match poll_mapping(pool, key, http, mapping, now).await {
            Ok(count) => queued += count,
            Err(error) => {
                tracing::warn!(mapping_id = %mapping.id, ?error, "polling a mapping failed");
                failed_mappings.push(mapping.id.clone());
            }
        }
    }

    let (status, error_summary) = if failed_mappings.is_empty() {
        ("done", None)
    } else {
        (
            "failed",
            Some(format!(
                "polling failed for mappings: {}",
                failed_mappings.join(", ")
            )),
        )
    };
    job_runs::insert(
        pool,
        &JobRun {
            id: ids::new_id()?,
            job_kind: "poll".to_owned(),
            started_at: now,
            finished_at: Some(now_secs().max(now)),
            status: status.to_owned(),
            processed_count: i64::try_from(queued).unwrap_or(i64::MAX),
            error_summary,
        },
    )
    .await?;
    Ok(queued)
}

/// Lists one mapping's artifacts and queues the jobs it needs. Returns how many.
async fn poll_mapping<H: HarborFetch>(
    pool: &SqlitePool,
    key: &DerivedKey,
    http: &H,
    mapping: &MappingRow,
    now: i64,
) -> Result<u64, AppError> {
    let (username, secret) = harbor_login(pool, key, mapping).await?;
    let base = base_for_join(&mapping.harbor_base_url)?;
    let mut queued = 0u64;
    for page in 1..=MAX_PAGES {
        let url = artifacts_list_url(
            &base,
            &mapping.harbor_project,
            &mapping.harbor_repository,
            page,
            PAGE_SIZE,
        )?;
        let (status, body) = http.fetch(&url, &username, &secret, &[]).await?;
        if status != 200 {
            return Err(AppError::UpstreamUnreachable);
        }
        let artifacts = parse_artifact_list(&body)?;
        if artifacts.is_empty() {
            break;
        }
        for (digest, tags) in artifacts {
            for tag in tags.iter().filter(|tag| !tag.is_empty()) {
                if sync_reports::has_success(
                    pool,
                    &mapping.id,
                    &mapping.harbor_repository,
                    tag,
                    &digest,
                )
                .await?
                {
                    continue;
                }
                let payload = json!({
                    "repo_full_name": format!(
                        "{}/{}",
                        mapping.harbor_project, mapping.harbor_repository
                    ),
                    "digest": digest,
                    "tag": tag,
                    "trigger": "poll",
                })
                .to_string();
                sync_jobs::enqueue(pool, &ids::new_id()?, &mapping.id, &payload, now).await?;
                queued += 1;
            }
        }
    }
    Ok(queued)
}

/// The robot username and the decrypted secret of the mapping's Harbor credential.
async fn harbor_login(
    pool: &SqlitePool,
    key: &DerivedKey,
    mapping: &MappingRow,
) -> Result<(String, Zeroizing<Vec<u8>>), AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let credential =
        credential_db::find_owned(&mut conn, &mapping.user_id, &mapping.harbor_cred_id)
            .await?
            .ok_or(AppError::NotFound)?;
    drop(conn);
    let username = credential.username.clone().ok_or(AppError::NotFound)?;
    Ok((username, decrypt_token(key, &credential)?))
}

/// Polls 60 seconds after start and then every 900 seconds, until `stop` turns true. A
/// poll that is running when the signal arrives finishes first.
pub async fn run(
    pool: SqlitePool,
    key: std::sync::Arc<DerivedKey>,
    allow_private: bool,
    mut stop: watch::Receiver<bool>,
) {
    let http = match HarborGet::new(allow_private) {
        Ok(http) => http,
        Err(_) => {
            tracing::error!("the polling client could not be built; backup polling is off");
            return;
        }
    };
    let mut delay = FIRST_POLL_DELAY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        match poll_once(&pool, &key, &http, now_secs()).await {
            Ok(queued) => tracing::info!(queued, "backup poll finished"),
            Err(error) => tracing::warn!(?error, "backup poll failed"),
        }
        delay = POLL_INTERVAL;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use reqwest::Url;

    use super::*;
    use crate::auth::crypto::{self, credentials_key};
    use crate::config;
    use crate::db;

    // Test values only. The root key and the tokens are obviously fake.
    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn key() -> DerivedKey {
        let root = config::parse_encryption_key(ROOT).unwrap();
        credentials_key(&root).unwrap()
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Answers the artifact list of each repository. Page 1 has the list, later pages are
    /// empty. A repository mapped to a status other than 200 answers that status.
    #[derive(Default)]
    struct FakeHarbor {
        /// repository name (as in the URL path) to (status, page 1 body)
        answers: Mutex<HashMap<String, (u16, String)>>,
        pages: Mutex<Vec<String>>,
    }

    impl FakeHarbor {
        fn with(repository: &str, status: u16, body: &str) -> Arc<Self> {
            let fake = Arc::new(Self::default());
            fake.set(repository, status, body);
            fake
        }

        fn set(&self, repository: &str, status: u16, body: &str) {
            lock(&self.answers).insert(repository.to_owned(), (status, body.to_owned()));
        }
    }

    impl HarborFetch for Arc<FakeHarbor> {
        async fn fetch(
            &self,
            url: &Url,
            _username: &str,
            _secret: &[u8],
            _extra_headers: &[(&str, &str)],
        ) -> Result<(u16, Vec<u8>), AppError> {
            let query = url.query().unwrap_or_default().to_owned();
            lock(&self.pages).push(format!("{} {query}", url.path()));
            let repository = url
                .path()
                .split('/')
                .rev()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let (status, body) = lock(&self.answers)
                .get(&repository)
                .cloned()
                .unwrap_or((404, String::new()));
            if status == 200 && !query.starts_with("page=1&") {
                return Ok((200, b"[]".to_vec()));
            }
            Ok((status, body.into_bytes()))
        }
    }

    struct Fixture {
        pool: SqlitePool,
        dir: std::path::PathBuf,
    }

    impl Fixture {
        /// One user, a Harbor credential, a GitHub credential and the mappings `m1`
        /// (repository `app`) and `m2` (repository `other`).
        async fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("harborgate-poller-{name}-{}", std::process::id()));
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
            for (id, service, base_url, username) in [
                (
                    "c1",
                    "harbor",
                    Some("https://harbor.example.com"),
                    Some("robot$hg"),
                ),
                ("c2", "github", None, None),
            ] {
                let stored = crypto::encrypt(
                    &key,
                    &crypto::aad("user_credentials", "encrypted_token", id),
                    b"fake-token-value",
                )
                .unwrap();
                sqlx::query(
                    "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
                     VALUES (?, 'u1', ?, ?, ?, ?, ?)",
                )
                .bind(id)
                .bind(service)
                .bind(id)
                .bind(base_url)
                .bind(username)
                .bind(stored)
                .execute(&pool)
                .await
                .unwrap();
            }
            for (id, repository, github_repo, hash) in
                [("m1", "app", "app", "h1"), ("m2", "other", "other", "h3")]
            {
                sqlx::query(
                    "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, default_branch)
                     VALUES (?, 'u1', 'c1', 'c2', 'https://harbor.example.com', 'proj', ?, 'octo', ?, ?, ?, 'main')",
                )
                .bind(id)
                .bind(repository)
                .bind(github_repo)
                .bind(hash)
                .bind(format!("{hash}-secret"))
                .execute(&pool)
                .await
                .unwrap();
            }
            Self { pool, dir }
        }

        /// Every queued job: (mapping_id, payload as JSON).
        async fn jobs(&self) -> Vec<(String, serde_json::Value)> {
            let rows: Vec<(String, String)> =
                sqlx::query_as("SELECT mapping_id, payload FROM sync_jobs ORDER BY created_at, id")
                    .fetch_all(&self.pool)
                    .await
                    .unwrap();
            rows.into_iter()
                .map(|(mapping, payload)| (mapping, serde_json::from_str(&payload).unwrap()))
                .collect()
        }

        /// Pretends the worker finished every job with a successful upload.
        async fn finish_all_jobs_successfully(&self) {
            let rows: Vec<(String, String, String)> =
                sqlx::query_as("SELECT id, mapping_id, payload FROM sync_jobs")
                    .fetch_all(&self.pool)
                    .await
                    .unwrap();
            for (job_id, mapping_id, payload) in rows {
                let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
                sync_jobs::mark_done(&self.pool, &job_id, 2_000)
                    .await
                    .unwrap();
                sqlx::query(
                    "INSERT INTO sync_reports (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status)
                     SELECT ?, id, ?, harbor_repository, ?, ?, '{}', 'success' FROM repo_mappings WHERE id = ?",
                )
                .bind(ids::new_id().unwrap_or_default())
                .bind(&job_id)
                .bind(value["tag"].as_str().unwrap())
                .bind(value["digest"].as_str().unwrap())
                .bind(&mapping_id)
                .execute(&self.pool)
                .await
                .unwrap();
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A `job_runs` row: id, kind, start, finish, count, error.
    type RunRow = (String, String, i64, Option<i64>, i64, Option<String>);

    const TWO_ARTIFACTS: &str = r#"[
        {"digest": "sha256:aaaa", "tags": [{"name": "v1"}]},
        {"digest": "sha256:bbbb", "tags": [{"name": "v2"}]}
    ]"#;

    #[tokio::test]
    async fn permanently_failed_digest_is_not_requeued() {
        let fx = Fixture::new("permanent-skip").await;
        let harbor = FakeHarbor::with("app", 200, TWO_ARTIFACTS);
        harbor.set("other", 200, "[]");

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap(),
            2
        );
        // Record each job as a permanent failure: one attempt, status failed, as the worker does.
        for (job_id, _) in fx.jobs().await {
            sync_jobs::record_failure(
                &mut fx.pool.acquire().await.unwrap(),
                &job_id,
                1,
                None,
                "the image has no org.opencontainers.image.revision label.",
                true,
                2_000,
            )
            .await
            .unwrap();
        }

        // The next poll does not queue the permanently failed digests again.
        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 3_000).await.unwrap(),
            0
        );
        assert_eq!(fx.jobs().await.len(), 2);
    }

    #[tokio::test]
    async fn second_poll_queues_nothing_for_synced_digests() {
        let fx = Fixture::new("second").await;
        let harbor = FakeHarbor::with("app", 200, TWO_ARTIFACTS);
        harbor.set("other", 200, "[]");

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap(),
            2
        );
        fx.finish_all_jobs_successfully().await;

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 3_000).await.unwrap(),
            0
        );
        assert_eq!(fx.jobs().await.len(), 2);

        // A digest that was never synced is still queued, so the zero above is the
        // dedupe rule and not a poll that never queues anything.
        harbor.set(
            "app",
            200,
            r#"[
                {"digest": "sha256:aaaa", "tags": [{"name": "v1"}]},
                {"digest": "sha256:bbbb", "tags": [{"name": "v2"}]},
                {"digest": "sha256:cccc", "tags": [{"name": "v3"}]}
            ]"#,
        );
        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 4_000).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn untagged_artifacts_are_skipped() {
        let fx = Fixture::new("untagged").await;
        let harbor = FakeHarbor::with(
            "app",
            200,
            r#"[
                {"digest": "sha256:aaaa", "tags": null},
                {"digest": "sha256:bbbb", "tags": []},
                {"digest": "sha256:cccc"},
                {"digest": "sha256:dddd", "tags": [{"name": "v1"}]}
            ]"#,
        );
        harbor.set("other", 200, "[]");

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap(),
            1
        );
        let jobs = fx.jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].1["digest"], "sha256:dddd");
    }

    #[tokio::test]
    async fn one_job_per_digest_and_tag() {
        let fx = Fixture::new("pairs").await;
        let harbor = FakeHarbor::with(
            "app",
            200,
            r#"[
                {"digest": "sha256:aaaa", "tags": [{"name": "v1"}, {"name": "latest"}]},
                {"digest": "sha256:bbbb", "tags": [{"name": "v2"}]}
            ]"#,
        );
        harbor.set("other", 200, "[]");

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap(),
            3
        );
        let mut pairs: Vec<(String, String)> = fx
            .jobs()
            .await
            .into_iter()
            .map(|(_, payload)| {
                (
                    payload["digest"].as_str().unwrap().to_owned(),
                    payload["tag"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("sha256:aaaa".to_owned(), "latest".to_owned()),
                ("sha256:aaaa".to_owned(), "v1".to_owned()),
                ("sha256:bbbb".to_owned(), "v2".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn queued_job_is_not_duplicated() {
        let fx = Fixture::new("queued").await;
        let harbor = FakeHarbor::with("app", 200, TWO_ARTIFACTS);
        harbor.set("other", 200, "[]");

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap(),
            2
        );
        // Nothing has run, so both jobs are still queued; one is now running.
        sqlx::query("UPDATE sync_jobs SET status = 'running' WHERE payload LIKE '%aaaa%'")
            .execute(&fx.pool)
            .await
            .unwrap();
        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 2_000).await.unwrap(),
            0
        );
        assert_eq!(fx.jobs().await.len(), 2);
    }

    #[tokio::test]
    async fn harbor_error_on_one_mapping_does_not_stop_others() {
        let fx = Fixture::new("error").await;
        let harbor = FakeHarbor::with("app", 500, "boom");
        harbor.set(
            "other",
            200,
            r#"[{"digest": "sha256:aaaa", "tags": [{"name": "v1"}]}]"#,
        );

        assert_eq!(
            poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap(),
            1
        );
        let jobs = fx.jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, "m2");

        let run: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status, processed_count, error_summary FROM job_runs WHERE job_kind = 'poll'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(run.0, "failed");
        assert_eq!(run.1, 1);
        let summary = run.2.unwrap();
        assert!(summary.contains("m1"));
        assert!(!summary.contains("m2"));
        assert!(!summary.contains("boom"));
    }

    #[tokio::test]
    async fn run_is_recorded_in_job_runs() {
        let fx = Fixture::new("runs").await;
        let harbor = FakeHarbor::with("app", 200, TWO_ARTIFACTS);
        harbor.set("other", 200, "[]");

        poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap();

        let rows: Vec<RunRow> = sqlx::query_as(
            "SELECT id, job_kind, started_at, finished_at, processed_count, error_summary
             FROM job_runs",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        let (id, kind, started, finished, processed, error) = rows[0].clone();
        assert_eq!(id.len(), 32);
        assert_eq!(kind, "poll");
        assert_eq!(started, 1_000);
        assert!(finished.unwrap() >= started);
        assert_eq!(processed, 2);
        assert_eq!(error, None);
        let status: String = sqlx::query_scalar("SELECT status FROM job_runs")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(status, "done");
    }

    #[tokio::test]
    async fn polled_payload_has_trigger_poll() {
        let fx = Fixture::new("payload").await;
        let harbor = FakeHarbor::with(
            "app",
            200,
            r#"[{"digest": "sha256:aaaa", "tags": [{"name": "v1"}]}]"#,
        );
        harbor.set("other", 200, "[]");

        poll_once(&fx.pool, &key(), &harbor, 1_000).await.unwrap();

        let jobs = fx.jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(
            jobs[0].1,
            serde_json::json!({
                "repo_full_name": "proj/app",
                "digest": "sha256:aaaa",
                "tag": "v1",
                "trigger": "poll",
            })
        );
    }
}
