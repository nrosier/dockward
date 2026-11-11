//! The one-time re-key of a repository's old HarborGate issues (#311, `specs/cve-lifecycle.md`).
//!
//! Issues created before the rename carry the `harborgate` label and the `<!-- harborgate:<CVE> -->`
//! marker. The first run for a repository renames the label to `dockward` once, rewrites the first
//! line of each old open issue to the new marker, and adds the label where it is missing. Only a
//! clean pass stores the `issue_rekeys` row and writes the audit row. Any other outcome leaves no
//! row, so the next publish runs the pass again. Closed issues and issues without a marker are not
//! touched.
//!
//! Every write is a GitHub call through [`IssueApi`]. Each write waits one second after the write
//! before it. The token is only passed on to the client, and nothing here logs.

use std::time::Duration;

use serde_json::json;
use sqlx::SqlitePool;

use crate::db::github_rekeys;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::github_issues::{self, LABEL, LEGACY_LABEL, LabelRename};
use crate::services::github_scanning::ScanError;
use crate::services::issue_lifecycle::IssueApi;
use crate::services::publish::Clock;

/// The audit action of a completed re-key (`services/audit.rs`, `ACTIONS`).
pub const AUDIT_ACTION: &str = "github.rekey_issues";

/// The pause before each write except the first, so the re-key stays under GitHub's secondary
/// rate limits.
const PAUSE: Duration = Duration::from_secs(1);

/// What the label rename did, as stored in `issue_rekeys.label_result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelResult {
    /// The legacy label was renamed to `dockward`.
    Renamed,
    /// The legacy label did not exist.
    Absent,
    /// `dockward` already existed, so the legacy label was kept and issues were labelled instead.
    Kept,
}

impl LabelResult {
    /// The text stored in `issue_rekeys.label_result` and the audit details.
    pub fn as_str(self) -> &'static str {
        match self {
            LabelResult::Renamed => "renamed",
            LabelResult::Absent => "absent",
            LabelResult::Kept => "kept",
        }
    }
}

/// How one [`run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyOutcome {
    /// A row already exists for the repository, so nothing was called.
    AlreadyDone,
    /// Every step succeeded. `issues` is the number of issue bodies rewritten.
    Completed { label: LabelResult, issues: u32 },
    /// Some calls failed. No row was written, so the next run tries again.
    Incomplete { failed: u32 },
    /// GitHub is rate limiting. The pass stopped and no row was written.
    RateLimited { until: i64 },
    /// GitHub refused the token. The pass stopped and no row was written.
    Refused,
}

/// Spaces the writes: one pause before each write except the first.
struct Pacer<'a, C> {
    clock: &'a C,
    wrote: bool,
}

impl<C: Clock> Pacer<'_, C> {
    async fn before_write(&mut self) {
        if self.wrote {
            self.clock.sleep(PAUSE).await;
        }
        self.wrote = true;
    }
}

/// The outcome a failed call ends the pass with, if it ends the pass. Other failures count as
/// one failed issue.
fn halt(error: &ScanError) -> Option<RekeyOutcome> {
    match error {
        ScanError::RateLimited { until } => Some(RekeyOutcome::RateLimited { until: *until }),
        ScanError::Unauthorized | ScanError::Forbidden(_) => Some(RekeyOutcome::Refused),
        _ => None,
    }
}

/// Runs the re-key of `owner/repo` once. See the module docs for the steps. `Ok` carries the
/// outcome; `Err` is a database failure.
pub async fn run<G: IssueApi, C: Clock>(
    pool: &SqlitePool,
    gh: &G,
    clock: &C,
    token: &[u8],
    owner: &str,
    repo: &str,
) -> Result<RekeyOutcome, AppError> {
    if github_rekeys::issues_done(pool, owner, repo)
        .await?
        .is_some()
    {
        return Ok(RekeyOutcome::AlreadyDone);
    }
    let now = clock.now();
    let mut pacer = Pacer {
        clock,
        wrote: false,
    };
    let mut failed = 0u32;

    pacer.before_write().await;
    let label = match gh
        .rename_label(token, owner, repo, LEGACY_LABEL, LABEL, now)
        .await
    {
        Ok(LabelRename::Renamed) => LabelResult::Renamed,
        Ok(LabelRename::Absent) => LabelResult::Absent,
        Ok(LabelRename::TargetExists) => LabelResult::Kept,
        Err(error) => return Ok(halt(&error).unwrap_or(RekeyOutcome::Incomplete { failed: 1 })),
    };

    // Listed after the rename, so the labels on each issue are the ones GitHub now shows.
    let current = match gh
        .list_open_with_label(token, owner, repo, LABEL, now)
        .await
    {
        Ok(issues) => issues,
        Err(error) => return Ok(halt(&error).unwrap_or(RekeyOutcome::Incomplete { failed: 1 })),
    };
    let legacy = match gh
        .list_open_with_label(token, owner, repo, LEGACY_LABEL, now)
        .await
    {
        Ok(issues) => issues,
        Err(error) => return Ok(halt(&error).unwrap_or(RekeyOutcome::Incomplete { failed: 1 })),
    };
    let issues = github_issues::merge_by_number(current, legacy);

    let mut rekeyed = 0u32;
    for issue in &issues {
        // Only an old open issue with a legacy first line is rewritten or labelled.
        if github_issues::rekeyed_body(&issue.body).is_none() {
            continue;
        }
        // Read the body again: it may have changed since the list.
        let fresh = match gh.body(token, owner, repo, issue.number, now).await {
            Ok(body) => body,
            Err(error) => match halt(&error) {
                Some(outcome) => return Ok(outcome),
                None => {
                    failed += 1;
                    continue;
                }
            },
        };
        if let Some(new_body) = github_issues::rekeyed_body(&fresh) {
            pacer.before_write().await;
            match gh
                .set_body(token, owner, repo, issue.number, &new_body, now)
                .await
            {
                Ok(()) => rekeyed += 1,
                Err(error) => match halt(&error) {
                    Some(outcome) => return Ok(outcome),
                    None => {
                        failed += 1;
                        continue;
                    }
                },
            }
        }
        if !issue.labels.iter().any(|have| have == LABEL) {
            pacer.before_write().await;
            match gh
                .add_labels(token, owner, repo, issue.number, &[LABEL], now)
                .await
            {
                Ok(()) => {}
                Err(error) => match halt(&error) {
                    Some(outcome) => return Ok(outcome),
                    None => failed += 1,
                },
            }
        }
    }

    if failed > 0 {
        return Ok(RekeyOutcome::Incomplete { failed });
    }
    let label_text = label.as_str();
    github_rekeys::insert_issues_done(pool, owner, repo, label_text, rekeyed, now).await?;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    audit::record(
        &mut conn,
        &Actor::system(),
        AUDIT_ACTION,
        &format!("{owner}/{repo}"),
        Some(&json!({"issues": rekeyed, "label": label_text})),
    )
    .await?;
    Ok(RekeyOutcome::Completed {
        label,
        issues: rekeyed,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::db;
    use crate::db::github_rekeys;
    use crate::db::sources::{self as source_db, SourceRow};
    use crate::services::issue_lifecycle::test_support::{FakeGithub, FakeIssues, Issue};
    use crate::services::issue_lifecycle::{self};
    use serde_json::Value;

    const TOKEN: &[u8] = b"canary-token-7f3a9c";

    /// A clock whose sleeps are recorded and return at once.
    struct Recording {
        sleeps: Mutex<Vec<Duration>>,
    }

    impl Clock for Recording {
        fn now(&self) -> i64 {
            1_000
        }

        async fn sleep(&self, duration: Duration) {
            self.sleeps
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(duration);
        }
    }

    fn clock() -> Recording {
        Recording {
            sleeps: Mutex::new(Vec::new()),
        }
    }

    struct Fx {
        pool: SqlitePool,
        dir: std::path::PathBuf,
        github: Arc<FakeGithub>,
        gh: FakeIssues,
    }

    impl Fx {
        async fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("dockward-rekey-{name}-{}", std::process::id()));
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
            sqlx::query(
                "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
                 VALUES ('c2', 'u1', 'c2', 'v1:test')",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo, auto_create_issues, min_issue_severity)
                 VALUES ('m1', 'u1', 'hub-default-ghcr', 'o/app', '*', 'c2', 'octo', 'app', 1, 'HIGH')",
            )
            .execute(&pool)
            .await
            .unwrap();
            let github = Arc::new(FakeGithub::default());
            let gh = FakeIssues(github.clone());
            Self {
                pool,
                dir,
                github,
                gh,
            }
        }

        async fn source(&self) -> SourceRow {
            let mut conn = self.pool.acquire().await.unwrap();
            source_db::find_by_id(&mut conn, "m1")
                .await
                .unwrap()
                .unwrap()
        }

        fn issue(&self, number: u64, body: &str, open: bool, labels: &[&str]) {
            self.github.with(|state| {
                state.issues.push(Issue {
                    number,
                    body: body.to_owned(),
                    open,
                    title: format!("CVE {number}"),
                    labels: labels.iter().map(|l| (*l).to_owned()).collect(),
                });
            });
        }

        fn legacy_label(&self) {
            self.github.with(|state| {
                state.repo_labels = vec!["harborgate".to_owned()];
            });
        }

        async fn run(&self, clock: &Recording) -> Result<RekeyOutcome, AppError> {
            run(&self.pool, &self.gh, clock, TOKEN, "octo", "app").await
        }

        async fn done_row(&self) -> Option<github_rekeys::IssuesDone> {
            github_rekeys::issues_done(&self.pool, "octo", "app")
                .await
                .unwrap()
        }

        /// `(action, target, details)` of every re-key audit row.
        async fn audit_rows(&self) -> Vec<(String, String, Option<String>)> {
            sqlx::query_as(
                "SELECT action, target, details FROM audit_log WHERE action = 'github.rekey_issues'",
            )
            .fetch_all(&self.pool)
            .await
            .unwrap()
        }

        async fn all_audit_text(&self) -> String {
            let rows: Vec<(String, String, Option<String>, String)> =
                sqlx::query_as("SELECT action, target, details, actor_username FROM audit_log")
                    .fetch_all(&self.pool)
                    .await
                    .unwrap();
            format!("{rows:?}")
        }

        fn writes(&self) -> Vec<(&'static str, String, Value)> {
            self.github.writes()
        }

        fn body_of(&self, number: u64) -> String {
            self.github.with(|state| {
                state
                    .issues
                    .iter()
                    .find(|i| i.number == number)
                    .map(|i| i.body.clone())
                    .unwrap_or_default()
            })
        }

        fn labels_of(&self, number: u64) -> Vec<String> {
            self.github.with(|state| {
                state
                    .issues
                    .iter()
                    .find(|i| i.number == number)
                    .map(|i| i.labels.clone())
                    .unwrap_or_default()
            })
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Two open old issues, one closed old issue and one unmarked labelled issue.
    fn seed_mixed(fx: &Fx) {
        fx.legacy_label();
        fx.issue(
            1,
            "<!-- harborgate:CVE-2026-1 -->\n\nfirst",
            true,
            &["harborgate"],
        );
        fx.issue(
            2,
            "<!-- harborgate:CVE-2026-2 -->\r\nsecond",
            true,
            &["harborgate"],
        );
        fx.issue(
            3,
            "<!-- harborgate:CVE-2026-3 -->\n\nclosed",
            false,
            &["harborgate"],
        );
        fx.issue(4, "no marker here", true, &["harborgate"]);
    }

    fn sleep_count(clock: &Recording) -> usize {
        clock.sleeps.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    #[tokio::test]
    async fn rekey_renames_the_label_once_and_rewrites_only_open_old_issues() {
        let fx = Fx::new("mixed").await;
        seed_mixed(&fx);
        let clk = clock();

        let outcome = fx.run(&clk).await.unwrap();
        assert_eq!(
            outcome,
            RekeyOutcome::Completed {
                label: LabelResult::Renamed,
                issues: 2
            }
        );

        let writes = fx.writes();
        let renames = writes
            .iter()
            .filter(|(m, p, _)| *m == "PATCH" && p == "repos/octo/app/labels/harborgate")
            .count();
        assert_eq!(renames, 1);
        let body_patches: Vec<&(&'static str, String, Value)> = writes
            .iter()
            .filter(|(m, p, b)| {
                *m == "PATCH" && p.starts_with("repos/octo/app/issues/") && b.get("body").is_some()
            })
            .collect();
        assert_eq!(body_patches.len(), 2);

        assert_eq!(fx.body_of(1), "<!-- dockward:CVE-2026-1 -->\n\nfirst");
        assert_eq!(fx.body_of(2), "<!-- dockward:CVE-2026-2 -->\r\nsecond");
        assert_eq!(
            fx.body_of(3),
            "<!-- harborgate:CVE-2026-3 -->\n\nclosed",
            "closed is not rewritten"
        );
        assert_eq!(fx.body_of(4), "no marker here", "unmarked is not rewritten");

        let row = fx.done_row().await.unwrap();
        assert_eq!(row.label_result, "renamed");
        assert_eq!(row.issues_rekeyed, 2);
        let audit = fx.audit_rows().await;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].1, "octo/app");
        assert_eq!(
            audit[0].2.as_deref(),
            Some(r#"{"issues":2,"label":"renamed"}"#)
        );

        // A following reconcile adopts the re-keyed issue and sends no POST.
        let source = fx.source().await;
        issue_lifecycle::reconcile(&fx.pool, &fx.gh, TOKEN, &source, "ghcr.io/o/app:v1", 1_000)
            .await
            .unwrap();
        assert!(fx.github.creates().is_empty(), "adoption must not create");
    }

    #[tokio::test]
    async fn a_second_run_is_already_done_with_no_requests() {
        let fx = Fx::new("second").await;
        seed_mixed(&fx);
        let clk = clock();
        fx.run(&clk).await.unwrap();
        let before = fx.github.requests();

        assert_eq!(fx.run(&clk).await.unwrap(), RekeyOutcome::AlreadyDone);
        assert_eq!(
            fx.github.requests(),
            before,
            "no GitHub call on a done repo"
        );
        assert_eq!(fx.audit_rows().await.len(), 1);
    }

    #[tokio::test]
    async fn a_deleted_row_reruns_with_no_body_patch_and_no_duplicates() {
        let fx = Fx::new("deleted-row").await;
        seed_mixed(&fx);
        let clk = clock();
        fx.run(&clk).await.unwrap();
        sqlx::query("DELETE FROM issue_rekeys")
            .execute(&fx.pool)
            .await
            .unwrap();
        let writes_before = fx.writes().len();

        let outcome = fx.run(&clk).await.unwrap();
        assert_eq!(
            outcome,
            RekeyOutcome::Completed {
                label: LabelResult::Absent,
                issues: 0
            }
        );
        let new_writes: Vec<_> = fx.writes().into_iter().skip(writes_before).collect();
        assert!(
            new_writes
                .iter()
                .all(|(m, p, _)| !(*m == "PATCH" && p.starts_with("repos/octo/app/issues/"))),
            "no body PATCH on the rerun: {new_writes:?}"
        );
        assert!(fx.github.creates().is_empty(), "no duplicate issue");
        assert_eq!(fx.done_row().await.unwrap().label_result, "absent");
    }

    #[tokio::test]
    async fn a_422_label_conflict_adds_the_label_and_keeps_the_legacy_one() {
        let fx = Fx::new("kept").await;
        fx.github.with(|state| {
            state.repo_labels = vec!["harborgate".to_owned(), "dockward".to_owned()];
        });
        fx.issue(
            1,
            "<!-- harborgate:CVE-2026-1 -->\n\nfirst",
            true,
            &["harborgate"],
        );
        let clk = clock();

        let outcome = fx.run(&clk).await.unwrap();
        assert_eq!(
            outcome,
            RekeyOutcome::Completed {
                label: LabelResult::Kept,
                issues: 1
            }
        );
        assert!(
            fx.labels_of(1).contains(&"dockward".to_owned()),
            "dockward is added"
        );
        assert_eq!(fx.done_row().await.unwrap().label_result, "kept");

        // Later adoption lists both labels, so the issue is found and nothing is created.
        let source = fx.source().await;
        issue_lifecycle::reconcile(&fx.pool, &fx.gh, TOKEN, &source, "ghcr.io/o/app:v1", 1_000)
            .await
            .unwrap();
        assert!(fx.github.creates().is_empty());
        let legacy_listed = fx.github.with(|state| {
            state
                .log
                .iter()
                .any(|(m, p, _)| *m == "GET" && p.contains("labels=harborgate"))
        });
        assert!(legacy_listed, "the legacy label is still listed after kept");
    }

    #[tokio::test]
    async fn a_rate_limit_leaves_no_row_and_a_rerun_finishes() {
        let fx = Fx::new("ratelimit").await;
        seed_mixed(&fx);
        fx.github.with(|state| state.rate_limited = true);
        let clk = clock();

        assert!(matches!(
            fx.run(&clk).await.unwrap(),
            RekeyOutcome::RateLimited { .. }
        ));
        assert!(fx.done_row().await.is_none(), "no row on a rate limit");

        fx.github.with(|state| state.rate_limited = false);
        assert!(matches!(
            fx.run(&clk).await.unwrap(),
            RekeyOutcome::Completed { .. }
        ));
        assert!(fx.done_row().await.is_some());
    }

    #[tokio::test]
    async fn a_refused_token_writes_nothing_and_leaves_no_row() {
        let fx = Fx::new("refused").await;
        seed_mixed(&fx);
        fx.github.with(|state| state.unauthorized = true);
        let clk = clock();
        let before = fx.github.requests();

        assert_eq!(fx.run(&clk).await.unwrap(), RekeyOutcome::Refused);
        // The only request is the label rename, which is refused. No body or label write follows.
        let writes: Vec<_> = fx.writes();
        assert_eq!(writes.len(), 1, "only the refused rename: {writes:?}");
        assert_eq!(fx.github.requests(), before + 1, "stops at the first call");
        assert!(fx.done_row().await.is_none());
    }

    #[tokio::test]
    async fn a_failed_body_patch_is_incomplete_and_leaves_no_row() {
        let fx = Fx::new("partial").await;
        seed_mixed(&fx);
        fx.github.with(|state| {
            state
                .fail_once
                .push(("PATCH", "repos/octo/app/issues/1".to_owned(), 500));
        });
        let clk = clock();

        assert_eq!(
            fx.run(&clk).await.unwrap(),
            RekeyOutcome::Incomplete { failed: 1 }
        );
        assert_eq!(
            fx.body_of(2),
            "<!-- dockward:CVE-2026-2 -->\r\nsecond",
            "others rewritten"
        );
        assert!(fx.done_row().await.is_none(), "no row after a partial pass");
        assert!(fx.audit_rows().await.is_empty());

        // A rerun finishes the failed one.
        assert!(matches!(
            fx.run(&clk).await.unwrap(),
            RekeyOutcome::Completed { .. }
        ));
        assert_eq!(fx.body_of(1), "<!-- dockward:CVE-2026-1 -->\n\nfirst");
    }

    #[tokio::test]
    async fn a_body_edited_between_list_and_reread_is_not_patched() {
        let fx = Fx::new("edited").await;
        seed_mixed(&fx);
        // Issue 1 is listed with the legacy first line, but its body changes before the re-read.
        fx.github.with(|state| {
            state.edit_before_read =
                Some((1, "<!-- dockward:CVE-2026-1 -->\n\nalready".to_owned()));
        });
        let clk = clock();

        fx.run(&clk).await.unwrap();
        let patched_one = fx
            .writes()
            .into_iter()
            .any(|(m, p, _)| m == "PATCH" && p == "repos/octo/app/issues/1");
        assert!(
            !patched_one,
            "a re-read that no longer matches sends no PATCH"
        );
        assert_eq!(fx.body_of(1), "<!-- dockward:CVE-2026-1 -->\n\nalready");
    }

    #[tokio::test]
    async fn a_manual_create_with_only_the_legacy_label_is_adopted_not_duplicated() {
        let fx = Fx::new("manual").await;
        fx.legacy_label();
        fx.issue(
            1,
            "<!-- harborgate:CVE-2026-1 -->\n\nold",
            true,
            &["harborgate"],
        );
        fx.finding("CVE-2026-1").await;
        let source = fx.source().await;

        // The re-key has not run. The manual route's create-or-adopt finds the legacy issue.
        let made =
            issue_lifecycle::create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-1", 1_000)
                .await
                .unwrap();
        assert_eq!(made.number, 1, "the legacy issue is adopted");
        assert!(fx.github.creates().is_empty(), "no duplicate is created");
    }

    /// One open finding of `CVE-2026-1` on the source's tracked tag.
    impl Fx {
        async fn finding(&self, cve: &str) {
            sqlx::query(
                "INSERT INTO cve_findings
                    (id, source_id, image_tag, cve_id, package, severity, first_seen_at, last_seen_at, status)
                 VALUES ('f1', 'm1', 'v1', ?, 'openssl', 'CRITICAL', 10, 10, 'open')",
            )
            .bind(cve)
            .execute(&self.pool)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn sleeps_are_one_second_between_each_mutative_call() {
        let fx = Fx::new("sleeps").await;
        seed_mixed(&fx);
        let clk = clock();
        fx.run(&clk).await.unwrap();

        let mutative = fx
            .writes()
            .into_iter()
            .filter(|(m, _, _)| matches!(*m, "PATCH" | "POST" | "DELETE" | "PUT"))
            .count();
        assert_eq!(
            sleep_count(&clk),
            mutative - 1,
            "one pause between each pair"
        );
        let sleeps = clk.sleeps.lock().unwrap_or_else(|p| p.into_inner()).clone();
        assert!(sleeps.iter().all(|d| *d >= Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn the_canary_token_is_absent_from_logs_audit_rows_and_errors() {
        use std::io::Write;

        let logs: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        #[derive(Clone)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Sink(logs.clone()))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let fx = Fx::new("canary").await;
        seed_mixed(&fx);
        // The canary is a fake token value; it is passed as the bearer and must never leak.
        let clk = clock();
        fx.github.with(|state| state.rate_limited = true);
        let limited = fx.run(&clk).await.unwrap();
        fx.github.with(|state| state.rate_limited = false);
        fx.run(&clk).await.unwrap();

        let text =
            String::from_utf8_lossy(&logs.lock().unwrap_or_else(|p| p.into_inner())).into_owned();
        let audit = fx.all_audit_text().await;
        let errors = format!("{limited:?}");
        let canary = String::from_utf8_lossy(TOKEN).into_owned();
        assert!(!text.contains(&canary), "token in logs");
        assert!(!audit.contains(&canary), "token in audit rows");
        assert!(!errors.contains(&canary), "token in errors");
    }
}
