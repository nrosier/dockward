//! Dashboard summary (`specs/api.md`, Dashboard; `specs/cve-lifecycle.md`, Dashboard counts).
//! The counts are a current snapshot, distinct CVEs per mapping, summed over mappings. The
//! SQL is in `db::dashboard`; this module sums the rows and builds the response.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::dashboard as db;
use crate::error::AppError;
use crate::services::sync_jobs::{self, SyncJob};

/// Failed syncs are counted over this many seconds, measured back from `now`
/// (`specs/cve-lifecycle.md`, Dashboard counts: last 90 days).
pub const FAILED_SYNC_WINDOW_SECS: i64 = 90 * 24 * 60 * 60;

/// Open CVEs by severity, summed over mappings. `CRITICAL` and `HIGH` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OpenCves {
    pub critical: i64,
    pub high: i64,
}

/// The `open_cves` of one mapping, as `GET /mappings` items carry it.
pub type MappingOpenCves = OpenCves;

/// The `GET /dashboard/summary` response (`specs/api.md`, Dashboard).
#[derive(Debug, Serialize)]
pub struct Summary {
    pub open_cves: OpenCves,
    pub fixed_cves: i64,
    pub open_issues: i64,
    pub failed_syncs: i64,
    pub recent_syncs: Vec<SyncJob>,
}

/// Sums per-mapping open counts. A CVE in two mappings is counted in each, as the spec
/// requires (`specs/cve-lifecycle.md`, Decided 2026-11-03).
fn sum_open(rows: &[db::OpenCount]) -> OpenCves {
    rows.iter().fold(
        OpenCves {
            critical: 0,
            high: 0,
        },
        |acc, row| OpenCves {
            critical: acc.critical + row.critical,
            high: acc.high + row.high,
        },
    )
}

/// The open CVEs of one mapping, for the mapping list. `None` when the mapping has none.
pub async fn open_cves_for_mapping(
    pool: &SqlitePool,
    mapping_id: &str,
    now: i64,
) -> Result<MappingOpenCves, AppError> {
    let rows = db::open_by_mapping(pool, None, Some(mapping_id), now).await?;
    Ok(sum_open(&rows))
}

/// The dashboard summary for one scope. `user_id` `None` is every mapping (admin
/// `scope=all`). `now` is Unix seconds.
pub async fn summary(
    pool: &SqlitePool,
    user_id: Option<&str>,
    now: i64,
) -> Result<Summary, AppError> {
    let open_rows = db::open_by_mapping(pool, user_id, None, now).await?;
    Ok(Summary {
        open_cves: sum_open(&open_rows),
        fixed_cves: db::fixed_cves(pool, user_id).await?,
        open_issues: db::open_issues(pool, user_id).await?,
        failed_syncs: db::failed_syncs_since(pool, user_id, now - FAILED_SYNC_WINDOW_SECS).await?,
        recent_syncs: sync_jobs::recent(pool, user_id).await?,
    })
}

#[cfg(test)]
mod tests {
    //! Each test builds its own database and seeds the rows it needs, so every count is
    //! checked against a known answer.

    use super::*;

    const NOW: i64 = 1_700_000_000;

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "harborgate-dashboard-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// One user with a Harbor and a GitHub credential, and the given mappings. Each
    /// mapping is `(id, github_repo)`, with a distinct GitHub target.
    async fn seed(pool: &SqlitePool, user: &str, mappings: &[(&str, &str)]) {
        sqlx::query(
            "INSERT INTO users (id, username, role, token_version) VALUES (?, ?, 'user', 0)",
        )
        .bind(user)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        let (harbor, github) = (format!("{user}-h"), format!("{user}-g"));
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
             VALUES (?, ?, 'harbor', 'h', 'https://harbor.example.com', 'robot$hg', 'v1:fake')",
        )
        .bind(&harbor)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, service_type, label, encrypted_token)
             VALUES (?, ?, 'github', 'g', 'v1:fake')",
        )
        .bind(&github)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        for (id, repo) in mappings {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url,
                    harbor_project, harbor_repository, github_owner, github_repo,
                    webhook_token_hash, webhook_auth_secret_hash)
                 VALUES (?, ?, ?, ?, 'https://harbor.example.com', 'proj', ?, 'octo', ?, ?, ?)",
            )
            .bind(id)
            .bind(user)
            .bind(&harbor)
            .bind(&github)
            .bind(id)
            .bind(repo)
            .bind(format!("hash-token-{id}"))
            .bind(format!("hash-secret-{id}"))
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// One tag's finding for a CVE in a mapping.
    async fn finding(
        pool: &SqlitePool,
        mapping: &str,
        tag: &str,
        cve: &str,
        severity: &str,
        status: &str,
    ) {
        sqlx::query(
            "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, severity, status)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(format!("{mapping}-{tag}-{cve}"))
        .bind(mapping)
        .bind(mapping)
        .bind(tag)
        .bind(cve)
        .bind(severity)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn accept(pool: &SqlitePool, mapping: &str, cve: &str, expires_at: Option<i64>) {
        sqlx::query(
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by_username, expires_at)
             VALUES (?, ?, ?, 'accepted for the test', 'u', ?)",
        )
        .bind(format!("acc-{mapping}-{cve}"))
        .bind(mapping)
        .bind(cve)
        .bind(expires_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn open_totals(pool: &SqlitePool, user: Option<&str>) -> OpenCves {
        sum_open(&db::open_by_mapping(pool, user, None, NOW).await.unwrap())
    }

    #[tokio::test]
    async fn one_cve_on_three_tags_counts_once() {
        let (pool, dir) = fresh_pool("three-tags").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        for tag in ["v1", "v2", "v3"] {
            finding(&pool, "m1", tag, "CVE-2026-0001", "CRITICAL", "open").await;
        }
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves {
                critical: 1,
                high: 0
            }
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn same_cve_in_two_mappings_counts_twice() {
        let (pool, dir) = fresh_pool("two-mappings").await;
        seed(&pool, "u1", &[("m1", "app"), ("m2", "other")]).await;
        finding(&pool, "m1", "v1", "CVE-2026-0001", "HIGH", "open").await;
        finding(&pool, "m2", "v1", "CVE-2026-0001", "HIGH", "open").await;
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves {
                critical: 0,
                high: 2
            }
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mixed_severity_counts_at_highest() {
        let (pool, dir) = fresh_pool("mixed").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        finding(&pool, "m1", "v1", "CVE-2026-0001", "HIGH", "open").await;
        finding(&pool, "m1", "v2", "CVE-2026-0001", "CRITICAL", "open").await;
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves {
                critical: 1,
                high: 0
            }
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn accepted_cve_is_not_open() {
        let (pool, dir) = fresh_pool("accepted").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        finding(&pool, "m1", "v1", "CVE-2026-0001", "CRITICAL", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0002", "CRITICAL", "open").await;
        // CVE-0001 is accepted with no expiry, so it is not open. CVE-0002 is open.
        accept(&pool, "m1", "CVE-2026-0001", None).await;
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves {
                critical: 1,
                high: 0
            }
        );
        // An acceptance whose expiry has passed no longer applies: CVE-0001 is open again.
        sqlx::query("UPDATE cve_acceptances SET expires_at = ? WHERE cve_id = 'CVE-2026-0001'")
            .bind(NOW - 1)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves {
                critical: 2,
                high: 0
            }
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fixed_requires_every_tag_fixed() {
        let (pool, dir) = fresh_pool("fixed").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        // CVE-1 is fixed on both tags. CVE-2 is still open on one tag.
        finding(&pool, "m1", "v1", "CVE-2026-0001", "HIGH", "fixed").await;
        finding(&pool, "m1", "v2", "CVE-2026-0001", "HIGH", "fixed").await;
        finding(&pool, "m1", "v1", "CVE-2026-0002", "HIGH", "fixed").await;
        finding(&pool, "m1", "v2", "CVE-2026-0002", "HIGH", "open").await;
        assert_eq!(db::fixed_cves(&pool, Some("u1")).await.unwrap(), 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failed_syncs_only_last_90_days() {
        let (pool, dir) = fresh_pool("failed").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        let since = NOW - FAILED_SYNC_WINDOW_SECS;
        for (id, updated_at) in [
            ("recent", NOW - 10),
            ("edge", since),
            ("old", since - 1),
            ("older", NOW - 365 * 24 * 60 * 60),
        ] {
            sqlx::query(
                "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
                 VALUES (?, 'm1', 'failed', 8, '{}', ?, ?)",
            )
            .bind(id)
            .bind(updated_at)
            .bind(updated_at)
            .execute(&pool)
            .await
            .unwrap();
        }
        // A done job is never a failed sync, however recent.
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload, created_at, updated_at)
             VALUES ('done', 'm1', 'done', 1, '{}', ?, ?)",
        )
        .bind(NOW)
        .bind(NOW)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            db::failed_syncs_since(&pool, Some("u1"), since)
                .await
                .unwrap(),
            2
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
