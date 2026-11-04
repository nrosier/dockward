//! CVE findings per tag and the 10-tag limit (`specs/cve-lifecycle.md`, "Tracking per
//! tag" and "Retention").
//!
//! After a successful sync, [`apply_scan`] makes `cve_findings` match the latest scan of
//! that tag: every reported CVE is stored `open`, the tag's other rows become `fixed`, and
//! only the newest 10 tags of the mapping are kept. Pruning never changes `github_issues`.

use std::collections::HashSet;

use serde_json::Value;
use sqlx::SqlitePool;

use crate::db::findings::{self, Finding};
use crate::db::job_runs::{self, JobRun};
use crate::error::AppError;
use crate::services::{ids, sarif};

/// Tracked tags per mapping.
pub const MAX_TAGS: usize = 10;
/// Longest stored description, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 4_000;

/// What one scan changed, for the callers that act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    /// CVE ids at `CRITICAL` that had no row for this mapping before this scan, on any
    /// tag. The new-CRITICAL alert (#33) uses them.
    pub new_critical: Vec<String>,
    /// Tags whose findings and reports were deleted by the 10-tag limit.
    pub pruned_tags: Vec<String>,
}

/// The description cut to [`MAX_DESCRIPTION_CHARS`] on a `char` boundary. `None` when the
/// text is absent or empty.
fn cap_description(text: Option<&str>) -> Option<String> {
    let text = text.filter(|text| !text.is_empty())?;
    Some(text.chars().take(MAX_DESCRIPTION_CHARS).collect())
}

/// Applies the Trivy report of the latest successful scan of `tag`. The sync report for
/// this scan must already be `success`, because the tracked tag set comes from
/// `sync_reports`. Everything is stored in one transaction. When the limit deleted tags,
/// one `cleanup` row is added to `job_runs` afterwards.
pub async fn apply_scan(
    pool: &SqlitePool,
    mapping_id: &str,
    repo: &str,
    tag: &str,
    report: &Value,
    now: i64,
) -> Result<ApplyResult, AppError> {
    let items = report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;

    // First pass, before any write: which CRITICAL ids are new to the mapping.
    let mut new_critical: Vec<String> = Vec::new();
    for item in items {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() || new_critical.iter().any(|seen| seen == id) {
            continue;
        }
        let severity = sarif::normalize_severity(
            item.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Unknown"),
        );
        if severity == "CRITICAL" && !findings::exists_for_mapping(&mut tx, mapping_id, id).await? {
            new_critical.push(id.to_owned());
        }
    }

    let mut seen_ids: Vec<String> = Vec::new();
    let mut stored: HashSet<&str> = HashSet::new();
    for item in items {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let severity = sarif::normalize_severity(
            item.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Unknown"),
        );
        let package = item.get("package").and_then(Value::as_str);
        let fixed_in = item
            .get("fix_version")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty());
        let description = cap_description(item.get("description").and_then(Value::as_str));
        let row_id = ids::new_id()?;
        findings::upsert(
            &mut tx,
            &Finding {
                id: &row_id,
                mapping_id,
                harbor_repository: repo,
                image_tag: tag,
                cve_id: id,
                package,
                severity,
                fixed_in_version: fixed_in,
                description: description.as_deref(),
                now,
            },
        )
        .await?;
        if stored.insert(id) {
            seen_ids.push(id.to_owned());
        }
    }

    findings::mark_missing_fixed(&mut tx, mapping_id, repo, tag, &seen_ids).await?;

    let mut pruned_tags: Vec<String> = Vec::new();
    let mut deleted: u64 = 0;
    let tags = findings::tags_by_recency(&mut tx, mapping_id).await?;
    for old in tags.into_iter().skip(MAX_TAGS) {
        deleted += findings::delete_tag(&mut tx, mapping_id, repo, &old).await?;
        pruned_tags.push(old);
    }

    tx.commit().await.map_err(|_| AppError::InternalError)?;

    if !pruned_tags.is_empty() {
        job_runs::insert(
            pool,
            &JobRun {
                id: ids::new_id()?,
                job_kind: "cleanup".to_owned(),
                started_at: now,
                finished_at: Some(now),
                status: "done".to_owned(),
                processed_count: i64::try_from(deleted).unwrap_or(i64::MAX),
                error_summary: None,
            },
        )
        .await?;
    }

    Ok(ApplyResult {
        new_critical,
        pruned_tags,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::db;

    struct Fixture {
        pool: SqlitePool,
        dir: std::path::PathBuf,
    }

    impl Fixture {
        async fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("harborgate-findings-{name}-{}", std::process::id()));
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
            for (id, service, base_url) in [
                ("c1", "harbor", Some("https://harbor.example.com")),
                ("c2", "github", None),
            ] {
                sqlx::query(
                    "INSERT INTO user_credentials (id, user_id, service_type, label, base_url, username, encrypted_token)
                     VALUES (?, 'u1', ?, ?, ?, NULL, 'v1:test')",
                )
                .bind(id)
                .bind(service)
                .bind(id)
                .bind(base_url)
                .execute(&pool)
                .await
                .unwrap();
            }
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
                 VALUES ('m1', 'u1', 'c1', 'c2', 'https://harbor.example.com', 'proj', 'app', 'octo', 'app', 'h1', 'h2')",
            )
            .execute(&pool)
            .await
            .unwrap();
            Self { pool, dir }
        }

        /// A successful sync report for `tag` at time `at`, as the sync handler leaves
        /// it before it calls `apply_scan`.
        async fn report(&self, tag: &str, at: i64) {
            sqlx::query(
                "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status, synced_at)
                 VALUES (?, 'm1', 'app', ?, 'sha256:aaaa', '{}', 'success', ?)",
            )
            .bind(ids::new_id().unwrap_or_default())
            .bind(tag)
            .bind(at)
            .execute(&self.pool)
            .await
            .unwrap();
        }

        /// Records a successful sync of `tag` at `at` and applies its report.
        async fn scan(&self, tag: &str, at: i64, report: &Value) -> ApplyResult {
            self.report(tag, at).await;
            apply_scan(&self.pool, "m1", "app", tag, report, at)
                .await
                .unwrap()
        }

        /// `(cve_id, status)` of a tag's rows, ordered by CVE id.
        async fn rows(&self, tag: &str) -> Vec<(String, String)> {
            sqlx::query_as(
                "SELECT cve_id, status FROM cve_findings
                 WHERE mapping_id = 'm1' AND image_tag = ? ORDER BY cve_id",
            )
            .bind(tag)
            .fetch_all(&self.pool)
            .await
            .unwrap()
        }

        async fn count(&self, sql: &'static str) -> i64 {
            sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn vuln(id: &str, severity: &str) -> Value {
        json!({"id": id, "package": "openssl", "version": "1", "severity": severity})
    }

    fn report(items: Vec<Value>) -> Value {
        json!({ "vulnerabilities": items })
    }

    fn row(id: &str, status: &str) -> (String, String) {
        (id.to_owned(), status.to_owned())
    }

    #[tokio::test]
    async fn first_scan_opens_all_findings() {
        let fx = Fixture::new("first").await;
        let scan = report(vec![
            json!({"id": "CVE-2026-0001", "package": "openssl", "version": "1",
                   "severity": "Critical", "fix_version": "2"}),
            vuln("CVE-2026-0002", "High"),
            vuln("CVE-2026-0003", "Weird"),
        ]);
        let result = fx.scan("v1", 100, &scan).await;
        assert_eq!(
            fx.rows("v1").await,
            vec![
                row("CVE-2026-0001", "open"),
                row("CVE-2026-0002", "open"),
                row("CVE-2026-0003", "open")
            ]
        );
        assert!(result.pruned_tags.is_empty());
        let detail: (String, String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT severity, package, fixed_in_version, description FROM cve_findings
             WHERE cve_id = 'CVE-2026-0001'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(
            detail,
            (
                "CRITICAL".to_owned(),
                "openssl".to_owned(),
                Some("2".to_owned()),
                None
            )
        );
        let unknown: String =
            sqlx::query_scalar("SELECT severity FROM cve_findings WHERE cve_id = 'CVE-2026-0003'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(unknown, "UNKNOWN");
    }

    #[tokio::test]
    async fn cve_gone_from_a_newer_scan_of_the_same_tag_is_fixed() {
        let fx = Fixture::new("fixed").await;
        fx.scan(
            "v1",
            100,
            &report(vec![
                vuln("CVE-2026-0001", "High"),
                vuln("CVE-2026-0002", "High"),
            ]),
        )
        .await;
        // Another tag that reports CVE-2026-0002 is not touched by a scan of v1.
        fx.scan("v2", 150, &report(vec![vuln("CVE-2026-0002", "High")]))
            .await;
        fx.scan("v1", 200, &report(vec![vuln("CVE-2026-0002", "High")]))
            .await;
        assert_eq!(
            fx.rows("v1").await,
            vec![row("CVE-2026-0001", "fixed"), row("CVE-2026-0002", "open")]
        );
        assert_eq!(fx.rows("v2").await, vec![row("CVE-2026-0002", "open")]);
    }

    #[tokio::test]
    async fn cve_back_on_a_tag_reopens_the_row() {
        let fx = Fixture::new("reopen").await;
        fx.scan("v1", 100, &report(vec![vuln("CVE-2026-0001", "High")]))
            .await;
        fx.scan("v1", 200, &report(vec![])).await;
        assert_eq!(fx.rows("v1").await, vec![row("CVE-2026-0001", "fixed")]);
        fx.scan("v1", 300, &report(vec![vuln("CVE-2026-0001", "Critical")]))
            .await;
        assert_eq!(fx.rows("v1").await, vec![row("CVE-2026-0001", "open")]);
        // One row, first seen at the first scan, last seen at the latest.
        let times: (i64, i64, String) = sqlx::query_as(
            "SELECT first_seen_at, last_seen_at, severity FROM cve_findings
             WHERE cve_id = 'CVE-2026-0001'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(times, (100, 300, "CRITICAL".to_owned()));
    }

    #[tokio::test]
    async fn eleventh_tag_prunes_the_oldest() {
        let fx = Fixture::new("eleventh").await;
        for n in 1..=10 {
            let result = fx
                .scan(
                    &format!("t{n}"),
                    n * 100,
                    &report(vec![vuln(&format!("CVE-2026-{n:04}"), "High")]),
                )
                .await;
            assert!(result.pruned_tags.is_empty());
        }
        assert_eq!(fx.count("SELECT COUNT(*) FROM job_runs").await, 0);

        let result = fx
            .scan("t11", 1_100, &report(vec![vuln("CVE-2026-0011", "High")]))
            .await;
        assert_eq!(result.pruned_tags, vec!["t1".to_owned()]);
        assert!(fx.rows("t1").await.is_empty());
        assert_eq!(fx.rows("t11").await.len(), 1);
        assert_eq!(
            fx.count("SELECT COUNT(DISTINCT image_tag) FROM cve_findings")
                .await,
            10
        );
        assert_eq!(
            fx.count("SELECT COUNT(*) FROM sync_reports WHERE image_tag = 't1'")
                .await,
            0
        );
        // One cleanup run: one finding row and one report row were deleted.
        let run: (String, String, i64) =
            sqlx::query_as("SELECT job_kind, status, processed_count FROM job_runs")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(run, ("cleanup".to_owned(), "done".to_owned(), 2));
    }

    #[tokio::test]
    async fn zero_cve_tags_count_toward_the_limit() {
        let fx = Fixture::new("zero").await;
        // The oldest tag has a finding; the ten newer tags have none.
        fx.scan("old", 100, &report(vec![vuln("CVE-2026-0001", "High")]))
            .await;
        for n in 1..=9 {
            let result = fx
                .scan(&format!("clean{n}"), 100 + n, &report(vec![]))
                .await;
            assert!(result.pruned_tags.is_empty());
        }
        // Ten tags are tracked now. An eleventh clean tag pushes `old` out.
        let result = fx.scan("clean10", 200, &report(vec![])).await;
        assert_eq!(result.pruned_tags, vec!["old".to_owned()]);
        assert!(fx.rows("old").await.is_empty());
        assert_eq!(
            fx.count("SELECT COUNT(DISTINCT image_tag) FROM sync_reports")
                .await,
            10
        );
    }

    #[tokio::test]
    async fn pruning_keeps_github_issue_rows() {
        let fx = Fixture::new("issues").await;
        fx.scan("t1", 100, &report(vec![vuln("CVE-2026-0001", "Critical")]))
            .await;
        let report_id: String =
            sqlx::query_scalar("SELECT id FROM sync_reports WHERE image_tag = 't1'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO github_issues (id, sync_report_id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url)
             VALUES ('gi1', ?, 'octo', 'app', 'CVE-2026-0001', 7, 'https://github.com/octo/app/issues/7')",
        )
        .bind(&report_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE cve_findings SET github_issue_id = 'gi1'")
            .execute(&fx.pool)
            .await
            .unwrap();

        for n in 2..=11 {
            fx.scan(&format!("t{n}"), n * 100, &report(vec![])).await;
        }
        assert!(fx.rows("t1").await.is_empty());
        let issue: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status, github_issue_number, sync_report_id FROM github_issues WHERE id = 'gi1'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(issue, ("open".to_owned(), 7, None));
    }

    #[tokio::test]
    async fn new_critical_lists_only_first_seen_criticals() {
        let fx = Fixture::new("critical").await;
        let first = fx
            .scan(
                "v1",
                100,
                &report(vec![
                    vuln("CVE-2026-0001", "Critical"),
                    vuln("CVE-2026-0001", "Critical"),
                    vuln("CVE-2026-0002", "High"),
                ]),
            )
            .await;
        assert_eq!(first.new_critical, vec!["CVE-2026-0001".to_owned()]);

        // CVE-2026-0001 is known from tag v1, so it is not new on v2. CVE-2026-0002 was
        // seen before at HIGH and is not new either. CVE-2026-0003 is new.
        let second = fx
            .scan(
                "v2",
                200,
                &report(vec![
                    vuln("CVE-2026-0001", "Critical"),
                    vuln("CVE-2026-0002", "Critical"),
                    vuln("CVE-2026-0003", "Critical"),
                    vuln("CVE-2026-0004", "High"),
                ]),
            )
            .await;
        assert_eq!(second.new_critical, vec!["CVE-2026-0003".to_owned()]);
    }

    #[tokio::test]
    async fn description_is_stored_and_capped_at_4000_chars() {
        let fx = Fixture::new("description").await;
        // Multi-byte characters make a byte cut land inside a character.
        let long: String = "é".repeat(4_500);
        fx.scan(
            "v1",
            100,
            &report(vec![
                json!({"id": "CVE-2026-0001", "severity": "High", "description": "A flaw."}),
                json!({"id": "CVE-2026-0002", "severity": "High", "description": long}),
                json!({"id": "CVE-2026-0003", "severity": "High", "description": ""}),
                json!({"id": "CVE-2026-0004", "severity": "High"}),
            ]),
        )
        .await;
        let stored: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT cve_id, description FROM cve_findings ORDER BY cve_id")
                .fetch_all(&fx.pool)
                .await
                .unwrap();
        assert_eq!(stored[0].1.as_deref(), Some("A flaw."));
        assert_eq!(stored[1].1, Some("é".repeat(4_000)));
        assert_eq!(stored[2].1, None);
        assert_eq!(stored[3].1, None);
    }
}
