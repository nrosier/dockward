//! Dashboard summary (`specs/api.md`, Dashboard; `specs/cve-lifecycle.md`, Dashboard counts).
//! The counts are a current snapshot, distinct CVEs per source, summed over sources. The
//! SQL is in `db::dashboard`; this module sums the rows and builds the response.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::dashboard as db;
use crate::error::AppError;
use crate::services::jobs::{self, Job};

/// Failed syncs are counted over this many seconds, measured back from `now`
/// (`specs/cve-lifecycle.md`, Dashboard counts: last 90 days).
pub const FAILED_SYNC_WINDOW_SECS: i64 = 90 * 24 * 60 * 60;

/// Open CVEs by severity, summed over sources: every severity and their `total`
/// (`specs/api.md`, Dashboard; changed on #129).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct OpenCves {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub unknown: i64,
    /// The sum of the five severities.
    pub total: i64,
}

impl OpenCves {
    /// Counts with `total` set to their sum.
    fn of(critical: i64, high: i64, medium: i64, low: i64, unknown: i64) -> Self {
        Self {
            critical,
            high,
            medium,
            low,
            unknown,
            total: critical + high + medium + low + unknown,
        }
    }
}

/// The `GET /dashboard/summary` response (`specs/api.md`, Dashboard).
#[derive(Debug, Serialize)]
pub struct Summary {
    pub open_cves: OpenCves,
    pub fixed_cves: i64,
    pub accepted_cves: i64,
    pub open_issues: i64,
    pub failed_syncs: i64,
    pub recent_syncs: Vec<Job>,
}

/// Sums per-source open counts. A CVE in two sources is counted in each, as the spec
/// requires (`specs/cve-lifecycle.md`, Decided 2026-11-03).
fn sum_open(rows: &[db::OpenCount]) -> OpenCves {
    rows.iter().fold(OpenCves::default(), |acc, row| {
        OpenCves::of(
            acc.critical + row.critical,
            acc.high + row.high,
            acc.medium + row.medium,
            acc.low + row.low,
            acc.unknown + row.unknown,
        )
    })
}

/// The dashboard summary for one scope. `user_id` `None` is every source (admin
/// `scope=all`). `now` is Unix seconds.
pub async fn summary(
    pool: &SqlitePool,
    user_id: Option<&str>,
    now: i64,
) -> Result<Summary, AppError> {
    let open_rows = db::open_by_source(pool, user_id, None, now).await?;
    Ok(Summary {
        open_cves: sum_open(&open_rows),
        fixed_cves: db::fixed_cves(pool, user_id).await?,
        accepted_cves: db::accepted_cves(pool, user_id, now).await?,
        open_issues: db::open_issues(pool, user_id).await?,
        failed_syncs: db::failed_syncs_since(pool, user_id, now - FAILED_SYNC_WINDOW_SECS).await?,
        recent_syncs: jobs::recent(pool, user_id).await?,
    })
}

#[cfg(test)]
mod tests {
    //! Each test builds its own database and seeds the rows it needs, so every count is
    //! checked against a known answer.

    use super::*;

    const NOW: i64 = 1_700_000_000;

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("dockward-dashboard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        (pool, dir)
    }

    /// One user with a GitHub credential, and the given sources. Each source is
    /// `(id, github_repo)`, with a distinct GitHub target.
    async fn seed(pool: &SqlitePool, user: &str, sources: &[(&str, &str)]) {
        sqlx::query(
            "INSERT INTO users (id, username, role, token_version) VALUES (?, ?, 'user', 0)",
        )
        .bind(user)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        let github = format!("{user}-g");
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES (?, ?, 'g', 'v1:fake')",
        )
        .bind(&github)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        for (id, repo) in sources {
            sqlx::query(
                "INSERT INTO image_sources
                    (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
                 VALUES (?, ?, 'hub-default-ghcr', ?, '*', ?, 'octo', ?)",
            )
            .bind(id)
            .bind(user)
            .bind(id)
            .bind(&github)
            .bind(repo)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// One tag's finding for a CVE in a source.
    async fn finding(
        pool: &SqlitePool,
        source: &str,
        tag: &str,
        cve: &str,
        severity: &str,
        status: &str,
    ) {
        sqlx::query(
            "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, status)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(format!("{source}-{tag}-{cve}"))
        .bind(source)
        .bind(tag)
        .bind(cve)
        .bind(severity)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
        // The tag points at the newest scanned image unless a test observed it already.
        report(pool, source, tag, "sha256:new", 2000).await;
    }

    /// Observes a tag on a scanned image, once per (source, tag). The newest image of a source
    /// is the one whose observation has the latest `first_seen_at` (decision 49).
    async fn report(pool: &SqlitePool, source: &str, tag: &str, digest: &str, seen: i64) {
        let image = format!("img-{source}-{digest}");
        sqlx::query(
            "INSERT OR IGNORE INTO images (id, hub_id, repository, digest, is_index)
             VALUES (?, 'hub-default-ghcr', ?, ?, 0)",
        )
        .bind(&image)
        .bind(source)
        .bind(digest)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO image_platforms (id, image_id, platform, platform_digest, state)
             VALUES (?, ?, 'linux/amd64', ?, 'stored')",
        )
        .bind(format!("plat-{image}"))
        .bind(&image)
        .bind(digest)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO scan_runs (id, image_platform_id, scanner, trigger, status)
             VALUES (?, ?, 'grype', 'first_pull', 'done')",
        )
        .bind(format!("run-{image}"))
        .bind(format!("plat-{image}"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
             SELECT ?1, ?2, ?3, ?4, ?4
             WHERE NOT EXISTS (SELECT 1 FROM tag_observations WHERE source_id = ?1 AND tag = ?2)",
        )
        .bind(source)
        .bind(tag)
        .bind(&image)
        .bind(seen)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn accept(pool: &SqlitePool, source: &str, cve: &str, expires_at: Option<i64>) {
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username, expires_at)
             VALUES (?, ?, ?, 'accepted for the test', 'u', ?)",
        )
        .bind(format!("acc-{source}-{cve}"))
        .bind(source)
        .bind(cve)
        .bind(expires_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn open_totals(pool: &SqlitePool, user: Option<&str>) -> OpenCves {
        sum_open(&db::open_by_source(pool, user, None, NOW).await.unwrap())
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
            OpenCves::of(1, 0, 0, 0, 0)
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The walley case (#196): `latest` is the newest digest and is clean, `0.4` is an older
    /// digest that still reports CVEs. The source has zero open CVEs. A CVE that only the
    /// older digest had as `fixed` adds nothing to the fixed count (decision 23).
    #[tokio::test]
    async fn walley_latest_clean_and_old_tag_open_counts_zero() {
        let (pool, dir) = fresh_pool("walley").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        report(&pool, "m1", "0.4", "sha256:old", 1000).await;
        report(&pool, "m1", "latest", "sha256:new", 2000).await;
        finding(&pool, "m1", "0.4", "CVE-2026-0001", "CRITICAL", "open").await;
        finding(&pool, "m1", "0.4", "CVE-2026-0002", "HIGH", "fixed").await;

        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(0, 0, 0, 0, 0)
        );
        assert!(
            db::open_by_source(&pool, None, Some("m1"), NOW)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(db::fixed_cves(&pool, Some("u1")).await.unwrap(), 0);

        // A newer digest that reports the CVE brings it back.
        report(&pool, "m1", "0.5", "sha256:newer", 3000).await;
        finding(&pool, "m1", "0.5", "CVE-2026-0001", "CRITICAL", "open").await;
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(1, 0, 0, 0, 0)
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn same_cve_in_two_sources_counts_twice() {
        let (pool, dir) = fresh_pool("two-sources").await;
        seed(&pool, "u1", &[("m1", "app"), ("m2", "other")]).await;
        finding(&pool, "m1", "v1", "CVE-2026-0001", "HIGH", "open").await;
        finding(&pool, "m2", "v1", "CVE-2026-0001", "HIGH", "open").await;
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(0, 2, 0, 0, 0)
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
            OpenCves::of(1, 0, 0, 0, 0)
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
            OpenCves::of(1, 0, 0, 0, 0)
        );
        // An acceptance whose expiry has passed no longer applies: CVE-0001 is open again.
        sqlx::query("UPDATE cve_acceptances SET expires_at = ? WHERE cve_id = 'CVE-2026-0001'")
            .bind(NOW - 1)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(2, 0, 0, 0, 0)
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #129: every severity is counted, each CVE once at its highest open severity, and
    /// `total` is the sum.
    #[tokio::test]
    async fn every_severity_is_counted_with_a_total() {
        let (pool, dir) = fresh_pool("every-severity").await;
        seed(&pool, "u1", &[("m1", "app"), ("m2", "other")]).await;
        finding(&pool, "m1", "v1", "CVE-2026-0001", "CRITICAL", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0002", "HIGH", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0003", "MEDIUM", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0004", "LOW", "open").await;
        finding(&pool, "m1", "v2", "CVE-2026-0004", "LOW", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0005", "UNKNOWN", "open").await;
        // LOW on one tag and MEDIUM on another counts once, as MEDIUM.
        finding(&pool, "m2", "v1", "CVE-2026-0006", "LOW", "open").await;
        finding(&pool, "m2", "v2", "CVE-2026-0006", "MEDIUM", "open").await;
        // A fixed LOW and an accepted UNKNOWN are not open.
        finding(&pool, "m2", "v1", "CVE-2026-0007", "LOW", "fixed").await;
        finding(&pool, "m2", "v1", "CVE-2026-0008", "UNKNOWN", "open").await;
        accept(&pool, "m2", "CVE-2026-0008", None).await;

        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(1, 1, 2, 1, 1)
        );
        assert_eq!(open_totals(&pool, Some("u1")).await.total, 6);
        assert_eq!(
            sum_open(
                &db::open_by_source(&pool, None, Some("m2"), NOW)
                    .await
                    .unwrap()
            ),
            OpenCves::of(0, 0, 1, 0, 0)
        );
        let summary = summary(&pool, Some("u1"), NOW).await.unwrap();
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(
            json["open_cves"],
            serde_json::json!({
                "critical": 1, "high": 1, "medium": 2, "low": 1, "unknown": 1, "total": 6
            })
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
                "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
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
            "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
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

    /// #247: the accepted count equals the active acceptances on CVEs open in scope. Expired
    /// and revoked acceptances, fixed CVEs and other users' sources add nothing, and the
    /// open count is unchanged by the accepted ones.
    #[tokio::test]
    async fn accepted_count_matches_active_acceptances_in_scope() {
        let (pool, dir) = fresh_pool("accepted-count").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        seed(&pool, "u2", &[("m2", "other")]).await;
        for (cve, sev) in [
            ("CVE-2026-0001", "MEDIUM"),
            ("CVE-2026-0002", "MEDIUM"),
            ("CVE-2026-0003", "HIGH"),
            ("CVE-2026-0004", "HIGH"),
            ("CVE-2026-0005", "LOW"),
        ] {
            finding(&pool, "m1", "v1", cve, sev, "open").await;
        }
        finding(&pool, "m1", "v1", "CVE-2026-0006", "HIGH", "fixed").await;
        finding(&pool, "m2", "v1", "CVE-2026-0001", "HIGH", "open").await;
        accept(&pool, "m1", "CVE-2026-0001", None).await;
        accept(&pool, "m1", "CVE-2026-0002", Some(NOW + 100)).await;
        accept(&pool, "m1", "CVE-2026-0003", Some(NOW - 1)).await;
        accept(&pool, "m1", "CVE-2026-0004", None).await;
        sqlx::query("UPDATE cve_acceptances SET revoked_at = ?, revoked_by = 'u1' WHERE cve_id = 'CVE-2026-0004'")
            .bind(NOW - 5)
            .execute(&pool)
            .await
            .unwrap();
        accept(&pool, "m1", "CVE-2026-0006", None).await;
        accept(&pool, "m2", "CVE-2026-0001", None).await;

        assert_eq!(db::accepted_cves(&pool, Some("u1"), NOW).await.unwrap(), 2);
        assert_eq!(db::accepted_cves(&pool, Some("u2"), NOW).await.unwrap(), 1);
        assert_eq!(db::accepted_cves(&pool, None, NOW).await.unwrap(), 3);
        // Open on m1: 0003 (expired acceptance), 0004 (revoked), 0005. None on m2.
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(0, 2, 0, 1, 0)
        );
        assert_eq!(
            open_totals(&pool, Some("u2")).await,
            OpenCves::of(0, 0, 0, 0, 0)
        );
        let s = summary(&pool, Some("u1"), NOW).await.unwrap();
        assert_eq!(s.accepted_cves, 2);
        assert_eq!(s.open_cves.total, 3);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Decision 3: an open CVE's severity comes from its open rows only. CVE-A is CRITICAL on
    /// v1 but fixed there and HIGH on v2 (open). Its CRITICAL row is fixed, so it counts as
    /// HIGH. A CVE fixed on every tag does not appear in the open counts at all.
    #[tokio::test]
    async fn severity_is_taken_from_open_rows_only() {
        let (pool, dir) = fresh_pool("open-rows").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        finding(&pool, "m1", "v1", "CVE-2026-0001", "CRITICAL", "fixed").await;
        finding(&pool, "m1", "v2", "CVE-2026-0001", "HIGH", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0002", "CRITICAL", "fixed").await;
        finding(&pool, "m1", "v2", "CVE-2026-0002", "CRITICAL", "fixed").await;
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(0, 1, 0, 0, 0),
            "open_cves must use the open rows only and skip fully fixed CVEs"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Decision 2: an acceptance hides an open CVE only while it is active. An accepted, fully
    /// fixed CVE still counts in `fixed_cves`, because the acceptance rule covers open CVEs only.
    /// When an acceptance expires, the open CVE is counted again.
    #[tokio::test]
    async fn accepted_exclusion_applies_only_while_open() {
        let (pool, dir) = fresh_pool("accepted-open-fixed").await;
        seed(&pool, "u1", &[("m1", "app")]).await;
        // CVE-A is open and accepted. CVE-B is fixed on every tag and accepted.
        finding(&pool, "m1", "v1", "CVE-2026-0001", "CRITICAL", "open").await;
        finding(&pool, "m1", "v1", "CVE-2026-0002", "CRITICAL", "fixed").await;
        accept(&pool, "m1", "CVE-2026-0001", None).await;
        accept(&pool, "m1", "CVE-2026-0002", None).await;

        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(0, 0, 0, 0, 0),
            "an active acceptance must hide an open CVE"
        );
        assert_eq!(
            db::fixed_cves(&pool, Some("u1")).await.unwrap(),
            1,
            "an accepted fixed CVE must still count as fixed"
        );

        // The acceptance of CVE-A expires. It is open again and counted.
        sqlx::query("UPDATE cve_acceptances SET expires_at = ? WHERE cve_id = 'CVE-2026-0001'")
            .bind(NOW - 1)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            open_totals(&pool, Some("u1")).await,
            OpenCves::of(1, 0, 0, 0, 0),
            "an expired acceptance must not hide an open CVE"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
