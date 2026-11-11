//! Tests of the legacy analysis retirement (`services/legacy_analyses.rs`). GitHub is a fake that
//! models analyses, alerts and confirm-delete chains, and records every call in order. No request
//! leaves the process. The database is the real migrated schema.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::db;
use crate::db::sources::{self as source_db, SourceRow};
use crate::services::github_scanning::{
    Alert, AlertQuery, Analysis, Dismissal, Processing, ScanError, ScanHttp, ScanResponse, Upload,
    confirm_answer_for, confirm_path_for, delete_analysis_with, dismiss_alert_with,
    follow_confirm_with, list_alerts_with, list_analyses_with,
};
use crate::services::github_url::GithubUrls;
use crate::services::publish::Clock;

/// A token no log, audit row or error may hold.
const CANARY_TOKEN: &str = "ghp_CANARY_LEGACY_TOKEN_5b1e";
/// A marker in a response body; no log may hold it.
const CANARY_BODY: &str = "CANARY_LEGACY_BODY_9d2f";

const LEGACY: &str = "harborgate/ghcr.io/octo/app/v1";
const NEW: &str = "dockward/ghcr.io/octo/app/v1";
const REF_MAIN: &str = "refs/heads/main";
const REF_DEV: &str = "refs/heads/dev";
const NOW: i64 = 1_800_000_000;

/// A clock whose `now` moves by `step` seconds on every read, and whose sleeps are recorded.
struct Clock2 {
    step: i64,
    reads: Mutex<i64>,
    sleeps: Mutex<Vec<Duration>>,
}

impl Clock2 {
    fn new(step: i64) -> Self {
        Self {
            step,
            reads: Mutex::new(0),
            sleeps: Mutex::new(Vec::new()),
        }
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.sleeps
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl Clock for Clock2 {
    fn now(&self) -> i64 {
        let mut reads = self.reads.lock().unwrap_or_else(|p| p.into_inner());
        *reads += 1;
        NOW + *reads * self.step
    }

    async fn sleep(&self, duration: Duration) {
        self.sleeps
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(duration);
    }
}

/// One analysis of the fake repository.
#[derive(Clone)]
struct Fake {
    id: u64,
    git_ref: &'static str,
    category: &'static str,
    tool: &'static str,
    deletable: bool,
    created_at: &'static str,
    /// The full `confirm_delete_url` GitHub gives when the delete is not yet complete, as GitHub
    /// documents it: `https://api.github.com/repos/{o}/{r}/code-scanning/analyses/{id}?confirm_delete`.
    confirm_next: Option<String>,
}

/// One alert of the fake repository.
#[derive(Clone)]
struct FakeAlert {
    number: u64,
    rule: &'static str,
    tool: &'static str,
    state: &'static str,
    reason: Option<&'static str>,
    comment: Option<&'static str>,
    category: &'static str,
    git_ref: &'static str,
}

/// Every call the step makes, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    ListAnalyses,
    Delete(u64),
    Confirm(String),
    ListAlerts(String),
    Dismiss {
        number: u64,
        reason: String,
        comment: Option<String>,
    },
}

#[derive(Default)]
struct State {
    analyses: Vec<Fake>,
    alerts: Vec<FakeAlert>,
    calls: Vec<Call>,
    /// Answer every delete with this error.
    delete_error: Option<ScanError>,
    /// Answer a delete of these analysis ids with `NotFound`, and keep them.
    fail_delete_ids: Vec<u64>,
    /// List every analysis whatever `tool_name` asks for, as a list that ignores the filter would.
    ignore_tool_filter: bool,
    /// Answer a dismissal of this alert number with this error, and keep the alert as it was.
    dismiss_error: Option<(u64, ScanError)>,
    /// Answer the analysis list with `DeadlineExceeded` from this list call (1-based) on, as a
    /// paged list does once its deadline has passed between pages.
    fail_list_from: Option<usize>,
}

/// Removes one analysis, as GitHub does, and returns its confirm link. When no analysis of its ref
/// is left, the legacy alerts of that ref go too.
fn remove_analysis(state: &mut State, id: u64) -> Result<Option<String>, ScanError> {
    let Some(position) = state.analyses.iter().position(|analysis| analysis.id == id) else {
        return Err(ScanError::NotFound);
    };
    let removed = state.analyses.remove(position);
    let ref_left = state
        .analyses
        .iter()
        .any(|analysis| analysis.git_ref == removed.git_ref);
    if !ref_left {
        state
            .alerts
            .retain(|alert| !(alert.tool == LEGACY_TOOL_NAME && alert.git_ref == removed.git_ref));
    }
    Ok(removed.confirm_next)
}

/// The answer GitHub gives to a delete: the full confirm URL, passed through the same production
/// parsing a live answer goes through.
fn delete_answer(link: Option<String>) -> Result<Option<String>, ScanError> {
    let body = serde_json::json!({ "confirm_delete_url": link });
    confirm_answer_for(&GithubUrls::default(), "octo", "app", &body)
}

/// The fake GitHub for `octo/app`.
#[derive(Default)]
struct FakeCode {
    state: Mutex<State>,
}

impl FakeCode {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn calls(&self) -> Vec<Call> {
        self.with(|state| state.calls.clone())
    }

    fn deleted(&self) -> Vec<u64> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Delete(id) => Some(id),
                _ => None,
            })
            .collect()
    }

    /// Every DELETE request: the first delete of each chain and each confirm-delete follow.
    fn removals(&self) -> usize {
        self.calls()
            .iter()
            .filter(|call| matches!(call, Call::Delete(_) | Call::Confirm(_)))
            .count()
    }

    fn dismissed(&self) -> Vec<(u64, String, Option<String>)> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Dismiss {
                    number,
                    reason,
                    comment,
                } => Some((number, reason, comment)),
                _ => None,
            })
            .collect()
    }
}

/// The alert query text, for matching the fake list.
fn alert_matches(alert: &FakeAlert, tool: &str, state: &str, git_ref: &str) -> bool {
    alert.tool == tool && alert.state == state && alert.git_ref == git_ref
}

impl CodeScanning for FakeCode {
    /// The retirement never uploads or reads an upload.
    async fn upload(
        &self,
        _token: &[u8],
        _fields: &Upload<'_>,
        _now: i64,
    ) -> Result<String, ScanError> {
        Err(ScanError::Upstream("unused by the retirement".to_owned()))
    }

    async fn status(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        _sarif_id: &str,
        _now: i64,
    ) -> Result<Processing, ScanError> {
        Err(ScanError::Upstream("unused by the retirement".to_owned()))
    }

    async fn list_analyses<C: Clock>(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        tool_name: &str,
        _clock: &C,
        _deadline: i64,
    ) -> Result<Vec<Analysis>, ScanError> {
        self.with(|state| {
            state.calls.push(Call::ListAnalyses);
            let list_number = state
                .calls
                .iter()
                .filter(|call| matches!(call, Call::ListAnalyses))
                .count();
            if state.fail_list_from.is_some_and(|from| list_number >= from) {
                return Err(ScanError::DeadlineExceeded);
            }
            Ok(state
                .analyses
                .iter()
                .filter(|analysis| state.ignore_tool_filter || analysis.tool == tool_name)
                .map(|analysis| Analysis {
                    id: analysis.id,
                    git_ref: Some(analysis.git_ref.to_owned()),
                    category: Some(analysis.category.to_owned()),
                    tool_name: Some(analysis.tool.to_owned()),
                    deletable: analysis.deletable,
                    created_at: Some(analysis.created_at.to_owned()),
                    confirm_path: None,
                })
                .collect())
        })
    }

    async fn delete_analysis(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        id: u64,
        _now: i64,
    ) -> Result<Option<String>, ScanError> {
        self.with(|state| {
            state.calls.push(Call::Delete(id));
            if let Some(error) = state.delete_error.clone() {
                return Err(error);
            }
            if state.fail_delete_ids.contains(&id) {
                return Err(ScanError::NotFound);
            }
            delete_answer(remove_analysis(state, id)?)
        })
    }

    async fn follow_confirm(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        link: &str,
        _now: i64,
    ) -> Result<Option<String>, ScanError> {
        self.with(|state| {
            state.calls.push(Call::Confirm(link.to_owned()));
            let id = link
                .split('?')
                .next()
                .and_then(|route| route.rsplit('/').next())
                .and_then(|segment| segment.parse::<u64>().ok());
            match id {
                Some(id) => delete_answer(remove_analysis(state, id)?),
                None => Err(ScanError::NotFound),
            }
        })
    }

    async fn list_alerts<C: Clock>(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        query: AlertQuery<'_>,
        _clock: &C,
        _deadline: i64,
    ) -> Result<Vec<Alert>, ScanError> {
        self.with(|state| {
            state
                .calls
                .push(Call::ListAlerts(query.tool_name.to_owned()));
            Ok(state
                .alerts
                .iter()
                .filter(|alert| alert_matches(alert, query.tool_name, query.state, query.git_ref))
                .map(|alert| Alert {
                    number: alert.number,
                    rule_id: alert.rule.to_owned(),
                    state: alert.state.to_owned(),
                    dismissed_reason: alert.reason.map(str::to_owned),
                    dismissed_comment: alert.comment.map(str::to_owned),
                    category: Some(alert.category.to_owned()),
                })
                .collect())
        })
    }

    async fn dismiss_alert(
        &self,
        _token: &[u8],
        _owner: &str,
        _repo: &str,
        number: u64,
        dismissal: Dismissal<'_>,
        _now: i64,
    ) -> Result<(), ScanError> {
        self.with(|state| {
            state.calls.push(Call::Dismiss {
                number,
                reason: dismissal.reason.to_owned(),
                comment: dismissal.comment.map(str::to_owned),
            });
            if let Some((_, error)) = state
                .dismiss_error
                .as_ref()
                .filter(|(failing, _)| *failing == number)
            {
                return Err(error.clone());
            }
            if let Some(alert) = state.alerts.iter_mut().find(|alert| alert.number == number) {
                alert.state = "dismissed";
            }
            Ok(())
        })
    }
}

/// The publish-side fixture: a migrated database, one user, one credential and one source
/// `octo/app` for `ghcr.io/octo/app` with tag `v1`.
struct Fx {
    pool: SqlitePool,
    dir: std::path::PathBuf,
    gh: FakeCode,
    source: SourceRow,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fx {
    async fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("dockward-retire-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("dir: {err}"));
        let pool = db::open(&dir)
            .await
            .unwrap_or_else(|err| panic!("open: {err:?}"));
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('u1', 'u1', NULL, 'user', 0)",
        )
        .execute(&pool)
        .await
        .unwrap_or_else(|err| panic!("user: {err}"));
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('c2', 'u1', 'c2', 'v1:test')",
        )
        .execute(&pool)
        .await
        .unwrap_or_else(|err| panic!("cred: {err}"));
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo, auto_create_issues, min_issue_severity)
             VALUES ('m1', 'u1', 'hub-default-ghcr', 'octo/app', 'v1', 'c2', 'octo', 'app', 1, 'HIGH')",
        )
        .execute(&pool)
        .await
        .unwrap_or_else(|err| panic!("source: {err}"));
        let source = {
            let mut conn = pool
                .acquire()
                .await
                .unwrap_or_else(|err| panic!("conn: {err}"));
            source_db::find_by_id(&mut conn, "m1")
                .await
                .unwrap_or_else(|err| panic!("find: {err:?}"))
                .unwrap_or_else(|| panic!("source missing"))
        };
        Self {
            pool,
            dir,
            gh: FakeCode::default(),
            source,
        }
    }

    fn analysis(
        &self,
        id: u64,
        git_ref: &'static str,
        category: &'static str,
        tool: &'static str,
        deletable: bool,
        created_at: &'static str,
    ) {
        self.gh.with(|state| {
            state.analyses.push(Fake {
                id,
                git_ref,
                category,
                tool,
                deletable,
                created_at,
                confirm_next: None,
            });
        });
    }

    fn alert(&self, alert: FakeAlert) {
        self.gh.with(|state| state.alerts.push(alert));
    }

    async fn retire(
        &self,
        clock: &Clock2,
        git_ref: &str,
        started: i64,
    ) -> Result<RetireOutcome, AppError> {
        retire(
            &self.pool,
            &self.gh,
            clock,
            CANARY_TOKEN.as_bytes(),
            &self.source,
            git_ref,
            started,
        )
        .await
    }

    async fn row_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM analysis_retirements")
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|err| panic!("rows: {err}"))
    }

    async fn audit_rows(&self) -> Vec<(String, String, Option<String>)> {
        sqlx::query_as(
            "SELECT action, target, details FROM audit_log WHERE action = 'github.retire_analyses'",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|err| panic!("audit: {err}"))
    }

    async fn all_audit_text(&self) -> String {
        let rows: Vec<(String, String, Option<String>, String)> =
            sqlx::query_as("SELECT action, target, details, actor_username FROM audit_log")
                .fetch_all(&self.pool)
                .await
                .unwrap_or_else(|err| panic!("audit all: {err}"));
        format!("{rows:?}")
    }
}

/// A HarborGate alert on the legacy category.
fn old(
    number: u64,
    rule: &'static str,
    reason: Option<&'static str>,
    comment: Option<&'static str>,
    git_ref: &'static str,
) -> FakeAlert {
    FakeAlert {
        number,
        rule,
        tool: LEGACY_TOOL_NAME,
        state: if reason.is_some() {
            "dismissed"
        } else {
            "open"
        },
        reason,
        comment,
        category: LEGACY,
        git_ref,
    }
}

/// A Dockward alert on the new category.
fn new_alert(
    number: u64,
    rule: &'static str,
    state: &'static str,
    reason: Option<&'static str>,
    git_ref: &'static str,
) -> FakeAlert {
    FakeAlert {
        number,
        rule,
        tool: TOOL_NAME,
        state,
        reason,
        comment: None,
        category: NEW,
        git_ref,
    }
}

/// The log text of every line a test emitted, captured through a `tracing` subscriber.
#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl LogSink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }
}

impl std::io::Write for LogSink {
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

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// ---- Deletion ----

#[tokio::test]
async fn only_the_legacy_category_is_deleted_on_every_ref() {
    let fx = Fx::new("scope").await;
    // Legacy analyses on two refs, and the Harbor-era and dockward analyses that stay.
    fx.analysis(
        1,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        2,
        REF_DEV,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-02T00:00:00Z",
    );
    fx.analysis(
        3,
        REF_MAIN,
        "harborgate/ghcr.io/octo/app/v2",
        LEGACY_TOOL_NAME,
        true,
        "2026-01-03T00:00:00Z",
    );
    fx.analysis(
        4,
        REF_MAIN,
        "harborgate/ghcr.io/octo/app",
        LEGACY_TOOL_NAME,
        true,
        "2026-01-04T00:00:00Z",
    );
    fx.analysis(5, REF_MAIN, NEW, TOOL_NAME, true, "2026-01-05T00:00:00Z");

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 2,
            carried: 0
        })
    );
    let mut deleted = fx.gh.deleted();
    deleted.sort_unstable();
    assert_eq!(
        deleted,
        vec![1, 2],
        "only the two legacy analyses are deleted"
    );
    let remaining: Vec<u64> = fx
        .gh
        .with(|state| state.analyses.iter().map(|a| a.id).collect());
    assert_eq!(
        remaining,
        vec![3, 4, 5],
        "Harbor-era and dockward analyses are untouched"
    );
}

#[tokio::test]
async fn newest_legacy_analysis_is_deleted_first() {
    let fx = Fx::new("order").await;
    fx.analysis(
        10,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        11,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-03-01T00:00:00Z",
    );
    fx.analysis(
        12,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-02-01T00:00:00Z",
    );

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert_eq!(fx.gh.deleted(), vec![11, 12, 10], "newest first");
}

#[tokio::test]
async fn non_deletable_analyses_are_never_attempted() {
    let fx = Fx::new("nodelete").await;
    fx.analysis(
        20,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        false,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        21,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-02T00:00:00Z",
    );

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 1,
            carried: 0
        })
    );
    assert_eq!(
        fx.gh.deleted(),
        vec![21],
        "the non-deletable one is never attempted"
    );
}

#[tokio::test]
async fn a_confirm_delete_url_is_followed_until_null() {
    let fx = Fx::new("confirm").await;
    fx.analysis(
        30,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    // The delete of 30 answers the full confirm URL on the API host, which is then followed.
    fx.gh.with(|state| {
        state.analyses[0].confirm_next = Some(
            "https://api.github.com/repos/octo/app/code-scanning/analyses/30?confirm_delete"
                .to_owned(),
        );
    });

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    let confirms: Vec<String> = fx
        .gh
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Confirm(path) => Some(path),
            _ => None,
        })
        .collect();
    assert_eq!(confirms.len(), 1, "the confirm link is followed once");
    assert!(confirms[0].starts_with("repos/octo/app/code-scanning/analyses/30"));
}

#[tokio::test]
async fn a_failed_delete_is_not_counted_as_retired() {
    // A delete that GitHub refuses keeps the analysis, so the pass repeats and the step gives up.
    let fx = Fx::new("stuck").await;
    fx.analysis(
        40,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh.with(|state| {
        state.analyses[0].confirm_next = None;
        state.delete_error = Some(ScanError::NotFound);
    });
    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(outcome.map_err(|_| "error"), Ok(RetireOutcome::Incomplete));
    assert_eq!(fx.row_count().await, 0);
}

// ---- Carry-over ----

#[tokio::test]
async fn a_clear_group_is_carried_with_the_same_reason_and_comment() {
    let fx = Fx::new("carry").await;
    fx.alert(old(
        1,
        "rule-a",
        Some("false positive"),
        Some("checked by hand"),
        REF_MAIN,
    ));
    fx.alert(old(
        2,
        "rule-a",
        Some("false positive"),
        Some("checked by hand"),
        REF_MAIN,
    ));
    fx.alert(new_alert(100, "rule-a", "open", None, REF_MAIN));

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 0,
            carried: 1
        })
    );
    assert_eq!(
        fx.gh.dismissed(),
        vec![(
            100,
            "false positive".to_owned(),
            Some("checked by hand".to_owned())
        )]
    );
}

#[tokio::test]
async fn a_mixed_group_is_not_carried() {
    let fx = Fx::new("mixed").await;
    // One old alert is open, one dismissed: the group is mixed, so nothing is carried.
    fx.alert(old(1, "rule-m", Some("won't fix"), Some("note"), REF_MAIN));
    fx.alert(FakeAlert {
        state: "open",
        reason: None,
        comment: None,
        ..old(2, "rule-m", None, None, REF_MAIN)
    });
    fx.alert(new_alert(200, "rule-m", "open", None, REF_MAIN));

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert!(
        fx.gh.dismissed().is_empty(),
        "a mixed group is left for the user"
    );
}

#[tokio::test]
async fn a_group_with_two_reasons_is_not_carried() {
    let fx = Fx::new("reasons").await;
    fx.alert(old(1, "rule-r", Some("won't fix"), None, REF_MAIN));
    fx.alert(old(2, "rule-r", Some("mitigated"), None, REF_MAIN));
    fx.alert(new_alert(300, "rule-r", "open", None, REF_MAIN));

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert!(fx.gh.dismissed().is_empty());
}

#[tokio::test]
async fn an_already_dismissed_new_alert_is_skipped() {
    let fx = Fx::new("skip").await;
    fx.alert(old(1, "rule-s", Some("mitigated"), None, REF_MAIN));
    fx.alert(new_alert(
        400,
        "rule-s",
        "dismissed",
        Some("won't fix"),
        REF_MAIN,
    ));

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert!(
        fx.gh.dismissed().is_empty(),
        "an already-dismissed new alert is not touched"
    );
}

#[tokio::test]
async fn every_carry_over_patch_comes_before_the_first_delete() {
    let fx = Fx::new("order2").await;
    fx.alert(old(1, "rule-o", Some("used in tests"), None, REF_MAIN));
    fx.alert(new_alert(500, "rule-o", "open", None, REF_MAIN));
    fx.analysis(
        50,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    let calls = fx.gh.calls();
    let first_delete = calls
        .iter()
        .position(|call| matches!(call, Call::Delete(_)))
        .unwrap_or_else(|| panic!("no delete happened"));
    let last_dismiss = calls
        .iter()
        .rposition(|call| matches!(call, Call::Dismiss { .. }))
        .unwrap_or_else(|| panic!("no dismissal happened"));
    assert!(
        last_dismiss < first_delete,
        "all dismissals precede the first delete: {calls:?}"
    );
}

// ---- Failures, rows and the second run ----

#[tokio::test]
async fn a_403_on_delete_stops_with_no_row() {
    let fx = Fx::new("refused").await;
    fx.analysis(
        60,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh
        .with(|state| state.delete_error = Some(ScanError::Forbidden(CANARY_BODY.to_owned())));

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(outcome.map_err(|_| "error"), Ok(RetireOutcome::Refused));
    assert_eq!(fx.row_count().await, 0, "no row on a refused delete");
    assert!(
        fx.audit_rows().await.is_empty(),
        "no audit row on a refused delete"
    );
}

#[tokio::test]
async fn rate_limited_stops_with_no_row() {
    let fx = Fx::new("limited").await;
    fx.analysis(
        70,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh
        .with(|state| state.delete_error = Some(ScanError::RateLimited { until: 5_000 }));

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::RateLimited { until: 5_000 })
    );
    assert_eq!(fx.row_count().await, 0);
}

#[tokio::test]
async fn a_second_run_is_a_no_op() {
    let fx = Fx::new("twice").await;
    fx.analysis(
        80,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );

    let clock = Clock2::new(0);
    let first = fx.retire(&clock, REF_MAIN, NOW).await;
    assert!(matches!(first, Ok(RetireOutcome::Completed { .. })));
    let calls_before = fx.gh.calls().len();

    let second = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(second.map_err(|_| "error"), Ok(RetireOutcome::AlreadyDone));
    assert_eq!(
        fx.gh.calls().len(),
        calls_before,
        "AlreadyDone makes no call"
    );
    assert_eq!(fx.row_count().await, 1);
}

#[tokio::test]
async fn a_clean_pass_writes_one_row_and_one_audit_row() {
    let fx = Fx::new("audit").await;
    fx.alert(old(1, "rule-a", Some("mitigated"), None, REF_MAIN));
    fx.alert(new_alert(900, "rule-a", "open", None, REF_MAIN));
    fx.analysis(
        90,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert_eq!(fx.row_count().await, 1);
    let audit = fx.audit_rows().await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0, "github.retire_analyses");
    assert_eq!(audit[0].1, "octo/app");
    let details: Value = serde_json::from_str(audit[0].2.as_deref().unwrap_or("null"))
        .unwrap_or_else(|err| panic!("details: {err}"));
    assert_eq!(details, serde_json::json!({"analyses": 1, "dismissals": 1}));
}

#[tokio::test]
async fn the_300_second_budget_stops_the_loop() {
    let fx = Fx::new("budget").await;
    // Many legacy analyses, and a clock that moves 200 s on every read: the budget ends the run.
    for id in 100..110 {
        fx.analysis(
            id,
            REF_MAIN,
            LEGACY,
            LEGACY_TOOL_NAME,
            true,
            "2026-01-01T00:00:00Z",
        );
    }
    let clock = Clock2::new(200);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(outcome.map_err(|_| "error"), Ok(RetireOutcome::Incomplete));
    assert_eq!(fx.row_count().await, 0, "a budget stop writes no row");
    assert!(
        fx.gh.deleted().len() < 10,
        "the loop stopped before every analysis"
    );
}

#[tokio::test]
async fn the_step_paces_mutative_calls_one_second_apart() {
    let fx = Fx::new("pace").await;
    fx.analysis(
        110,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        111,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-02T00:00:00Z",
    );

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    let sleeps = clock.sleeps();
    assert!(!sleeps.is_empty());
    assert!(
        sleeps.iter().all(|d| *d == Duration::from_secs(1)),
        "every pause is 1 s"
    );
}

// ---- Canary ----

#[tokio::test]
async fn the_canary_token_is_absent_from_logs_audit_rows_and_errors() {
    let logs = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fx = Fx::new("canary").await;
    fx.alert(old(
        1,
        "rule-c",
        Some("mitigated"),
        Some(CANARY_BODY),
        REF_MAIN,
    ));
    fx.alert(new_alert(900, "rule-c", "open", None, REF_MAIN));
    fx.analysis(
        120,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh.with(|state| {
        state.delete_error = Some(ScanError::Forbidden(format!(
            "{CANARY_BODY} {CANARY_TOKEN}"
        )))
    });

    let clock = Clock2::new(0);
    let refused = fx.retire(&clock, REF_MAIN, NOW).await;
    let refused_text = format!("{:?}", refused.map_err(|_| "error"));
    let audit = fx.all_audit_text().await;
    let logged = logs.text();

    for canary in [CANARY_TOKEN, CANARY_BODY] {
        assert!(!logged.contains(canary), "{canary} reached the logs");
        assert!(!audit.contains(canary), "{canary} reached an audit row");
        assert!(
            !refused_text.contains(canary),
            "{canary} reached an error string"
        );
    }
    assert!(
        logged.contains(REFUSED_LOG),
        "the fixed refusal text is logged"
    );
}

// ---- Host check ----

#[test]
fn a_confirm_link_on_another_host_is_refused() {
    let urls = GithubUrls::default();
    assert_eq!(
        confirm_path_for(
            &urls,
            "octo",
            "app",
            "https://evil.example/repos/octo/app/code-scanning/analyses/1?confirm_delete"
        ),
        None
    );
    assert_eq!(
        confirm_path_for(
            &urls,
            "octo",
            "app",
            "http://api.github.com/repos/octo/app/code-scanning/analyses/1?confirm_delete"
        ),
        None
    );
    assert_eq!(
        confirm_path_for(
            &urls,
            "octo",
            "app",
            "https://api.github.com@evil.example/repos/octo/app/code-scanning/analyses/1?confirm_delete"
        ),
        None
    );
    assert_eq!(
        confirm_path_for(
            &urls,
            "octo",
            "app",
            "https://api.github.com/repos/octo/app/code-scanning/analyses/1?confirm_delete"
        ),
        Some("repos/octo/app/code-scanning/analyses/1?confirm_delete".to_owned())
    );
}

/// Records every request path and answers each with `null` (a completed delete).
#[derive(Default)]
struct RecordingHttp {
    requests: Mutex<Vec<String>>,
}

impl ScanHttp for RecordingHttp {
    async fn post(
        &self,
        path: &str,
        _token: &[u8],
        _body: &Value,
    ) -> Result<ScanResponse, ScanError> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(path.to_owned());
        Ok(answer())
    }

    async fn patch(
        &self,
        path: &str,
        _token: &[u8],
        _body: &Value,
    ) -> Result<ScanResponse, ScanError> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(path.to_owned());
        Ok(answer())
    }

    async fn get(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(path.to_owned());
        Ok(answer())
    }

    async fn delete(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(path.to_owned());
        Ok(answer())
    }
}

fn answer() -> ScanResponse {
    ScanResponse {
        status: 200,
        retry_after: None,
        ratelimit_remaining: None,
        ratelimit_reset: None,
        link_next: None,
        body: Value::Null,
    }
}

#[tokio::test]
async fn a_confirm_link_on_another_host_is_never_fetched() {
    // The confirm path is checked before the request: a path that does not pass the API URL
    // check is refused and the fake sees no request for it.
    let http = RecordingHttp::default();
    let refused = follow_confirm_with(
        &http,
        CANARY_TOKEN.as_bytes(),
        "octo",
        "app",
        "https://evil.example/repos/octo/app/code-scanning/analyses/1?confirm_delete",
        NOW,
    )
    .await;
    assert!(refused.is_err(), "a foreign confirm link is refused");
    assert!(
        http.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "and never fetched"
    );

    // The relative path of a link on the API host is followed. A full URL is refused: only the
    // path that the delete answer was normalised to is accepted.
    let full_url_refused = follow_confirm_with(
        &http,
        CANARY_TOKEN.as_bytes(),
        "octo",
        "app",
        "https://api.github.com/repos/octo/app/code-scanning/analyses/1?confirm_delete",
        NOW,
    )
    .await;
    assert!(
        full_url_refused.is_err(),
        "a full URL is not a confirm path"
    );
    assert!(
        http.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "and a full URL is not fetched"
    );
    let followed = follow_confirm_with(
        &http,
        CANARY_TOKEN.as_bytes(),
        "octo",
        "app",
        "repos/octo/app/code-scanning/analyses/1?confirm_delete",
        NOW,
    )
    .await;
    assert_eq!(followed, Ok(None));
    assert_eq!(
        http.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1
    );
}

#[tokio::test]
async fn a_delete_answer_with_a_foreign_confirm_link_is_refused() {
    // The `confirm_delete_url` in a delete answer is read by `confirm_answer`; a foreign host
    // ends the chain with an error and nothing further is fetched.
    let http = RecordingHttp::default();
    let body = serde_json::json!({"confirm_delete_url": "https://evil.example/confirm"});
    let urls = GithubUrls::default();
    let found = confirm_answer_for(&urls, "octo", "app", &body);
    assert!(
        found.is_err(),
        "a foreign confirm link in an answer is refused"
    );
    assert!(
        http.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    );
}

// ---- Review fixes (#311 slice 6b): category echo, chains, retry, tool filter ----

/// The legacy category as GitHub may echo it, with the trailing `/` the legacy upload used.
const LEGACY_SLASH: &str = "harborgate/ghcr.io/octo/app/v1/";
/// A child path of the legacy category. It must never match.
const LEGACY_CHILD: &str = "harborgate/ghcr.io/octo/app/v1/other";

#[tokio::test]
async fn a_legacy_category_echoed_with_a_trailing_slash_is_deleted() {
    let fx = Fx::new("echo").await;
    fx.analysis(
        60,
        REF_MAIN,
        LEGACY_SLASH,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 1,
            carried: 0
        })
    );
    assert_eq!(fx.gh.deleted(), vec![60], "the echoed category is deleted");
    assert_eq!(
        fx.row_count().await,
        1,
        "the row is written after the delete"
    );
}

#[tokio::test]
async fn a_child_path_of_the_legacy_category_is_never_deleted() {
    let fx = Fx::new("child").await;
    fx.analysis(
        61,
        REF_MAIN,
        LEGACY_SLASH,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        62,
        REF_MAIN,
        LEGACY_CHILD,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-02T00:00:00Z",
    );
    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert_eq!(fx.gh.deleted(), vec![61], "only the exact category");
    let remaining: Vec<u64> = fx
        .gh
        .with(|state| state.analyses.iter().map(|a| a.id).collect());
    assert_eq!(remaining, vec![62], "the child path is untouched");
}

#[tokio::test]
async fn a_retry_uses_the_stored_carry_over_plan() {
    let fx = Fx::new("retry").await;
    // Rule p is mixed on the first run: open on main, dismissed on dev.
    fx.alert(old(1, "rule-p", None, None, REF_MAIN));
    fx.alert(old(2, "rule-p", Some("won't fix"), None, REF_DEV));
    fx.alert(new_alert(700, "rule-p", "open", None, REF_DEV));
    // Main's analysis is newer, so it is deleted first. Dev's delete fails in the first run.
    fx.analysis(
        70,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-03-01T00:00:00Z",
    );
    fx.analysis(
        71,
        REF_DEV,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh.with(|state| state.fail_delete_ids = vec![71]);

    let clock = Clock2::new(0);
    let first = fx.retire(&clock, REF_DEV, NOW).await;
    assert_eq!(first.map_err(|_| "error"), Ok(RetireOutcome::Incomplete));
    assert!(
        fx.gh.dismissed().is_empty(),
        "the mixed group is not carried"
    );

    fx.gh.with(|state| state.fail_delete_ids.clear());
    let second = fx.retire(&clock, REF_DEV, NOW).await;
    assert!(matches!(second, Ok(RetireOutcome::Completed { .. })));
    assert!(
        fx.gh.dismissed().is_empty(),
        "the second run reads the stored plan, so the mixed group is still not carried"
    );
}

#[tokio::test]
async fn a_carried_rule_is_not_dismissed_again_on_retry() {
    let fx = Fx::new("reopen").await;
    fx.alert(old(1, "rule-q", Some("mitigated"), None, REF_MAIN));
    fx.alert(new_alert(800, "rule-q", "open", None, REF_MAIN));
    fx.analysis(
        90,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh.with(|state| state.fail_delete_ids = vec![90]);

    let clock = Clock2::new(0);
    let first = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(first.map_err(|_| "error"), Ok(RetireOutcome::Incomplete));
    assert_eq!(fx.gh.dismissed().len(), 1, "run 1 carries the clear group");

    // The alert is reopened between the runs. The retry must not dismiss it again.
    fx.gh.with(|state| state.fail_delete_ids.clear());
    let second = fx.retire(&clock, REF_MAIN, NOW).await;
    assert!(matches!(second, Ok(RetireOutcome::Completed { .. })));
    assert_eq!(
        fx.gh.dismissed().len(),
        1,
        "a carried rule is not dismissed again"
    );
}

#[tokio::test]
async fn a_twelve_step_chain_completes_in_one_run() {
    let fx = Fx::new("chain12").await;
    // Analysis 200 links to 201, 201 to 202, and so on up to 211, which is the last one.
    for id in 200..212u64 {
        fx.analysis(
            id,
            REF_MAIN,
            LEGACY,
            LEGACY_TOOL_NAME,
            true,
            "2026-01-01T00:00:00Z",
        );
    }
    // Each analysis but the last links to the next one. The fake removes the analysis a link names.
    fx.gh.with(|state| {
        for index in 0..11usize {
            let next = 201 + index as u64;
            state.analyses[index].confirm_next = Some(format!(
                "https://api.github.com/repos/octo/app/code-scanning/analyses/{next}?confirm_delete"
            ));
        }
    });

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 12,
            carried: 0
        })
    );
    assert_eq!(fx.row_count().await, 1, "the step finished in one run");
    let remaining: Vec<u64> = fx
        .gh
        .with(|state| state.analyses.iter().map(|a| a.id).collect());
    assert!(remaining.is_empty(), "all twelve are deleted");
}

#[tokio::test]
async fn analyses_deleted_counts_every_delete_call() {
    let fx = Fx::new("count").await;
    // Analysis 70 is deleted and its confirm link removes 71: two DELETE calls, one candidate.
    fx.analysis(
        70,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-03-01T00:00:00Z",
    );
    fx.analysis(
        71,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.gh.with(|state| {
        state.analyses[0].confirm_next = Some(
            "https://api.github.com/repos/octo/app/code-scanning/analyses/71?confirm_delete"
                .to_owned(),
        );
    });

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 2,
            carried: 0
        })
    );
    assert_eq!(fx.gh.removals(), 2, "two DELETE calls were made");
    let audit = fx.audit_rows().await;
    let details: Value = serde_json::from_str(audit[0].2.as_deref().unwrap_or("null"))
        .unwrap_or_else(|err| panic!("details: {err}"));
    assert_eq!(details["analyses"], 2);
}

#[tokio::test]
async fn a_list_that_ignores_tool_name_never_deletes_another_tool() {
    let fx = Fx::new("tool").await;
    fx.analysis(
        130,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        131,
        REF_MAIN,
        LEGACY,
        "other-tool",
        true,
        "2026-01-02T00:00:00Z",
    );
    fx.gh.with(|state| state.ignore_tool_filter = true);

    let clock = Clock2::new(0);
    fx.retire(&clock, REF_MAIN, NOW)
        .await
        .unwrap_or_else(|_| panic!("retire"));
    assert_eq!(fx.gh.deleted(), vec![130], "only the HarborGate analysis");
    let remaining: Vec<u64> = fx
        .gh
        .with(|state| state.analyses.iter().map(|a| a.id).collect());
    assert_eq!(remaining, vec![131]);
}

// ---- Confirm-link shape (#311 slice 6b, F2) ----

/// The confirm links that name the retired repository and an analysis of its family pass. Every
/// other shape is refused. The shape is the one GitHub documents: `repos/{owner}/{repo}/
/// code-scanning/analyses/{id}?confirm_delete`.
#[test]
fn a_confirm_link_must_name_the_retired_analysis_exactly() {
    let urls = GithubUrls::default();
    let ok = |route: &str| {
        let link = format!("https://api.github.com/{route}");
        confirm_path_for(&urls, "octo", "app", &link).is_some()
    };
    // Accepted: the documented shape, with owner and repo compared case-insensitively.
    assert!(ok(
        "repos/octo/app/code-scanning/analyses/41?confirm_delete"
    ));
    assert!(ok(
        "repos/Octo/App/code-scanning/analyses/41?confirm_delete"
    ));
    // Refused: another repository.
    assert!(!ok(
        "repos/other/app/code-scanning/analyses/41?confirm_delete"
    ));
    assert!(!ok(
        "repos/octo/other/code-scanning/analyses/41?confirm_delete"
    ));
    // Refused: another analysis family, or a sub-path.
    assert!(!ok("repos/octo/app/code-scanning/alerts/41?confirm_delete"));
    assert!(!ok(
        "repos/octo/app/code-scanning/analyses/41/extra?confirm_delete"
    ));
    assert!(!ok(
        "repos/octo/app/code-scanning/analyses/abc?confirm_delete"
    ));
    // Refused: an extra query parameter, or none where the confirm flag is required.
    assert!(!ok(
        "repos/octo/app/code-scanning/analyses/41?confirm_delete&token=x"
    ));
    assert!(!ok(
        "repos/octo/app/code-scanning/analyses/41?confirm_delete=true&x=1"
    ));
    assert!(!ok("repos/octo/app/code-scanning/analyses/41?next=1"));
    assert!(!ok("repos/octo/app/code-scanning/analyses/41"));
}

#[tokio::test]
async fn a_confirm_link_for_another_repo_or_family_sends_no_request() {
    let urls = GithubUrls::default();
    for link in [
        "repos/other/app/code-scanning/analyses/41?confirm_delete",
        "repos/octo/app/code-scanning/alerts/41?confirm_delete",
        "repos/octo/app/code-scanning/analyses/41?confirm_delete&token=x",
    ] {
        let http = RecordingHttp::default();
        let body = serde_json::json!({ "confirm_delete_url": link });
        let answer = confirm_answer_for(&urls, "octo", "app", &body);
        assert!(answer.is_err(), "{link} is refused");
        let refused =
            follow_confirm_with(&http, CANARY_TOKEN.as_bytes(), "octo", "app", link, NOW).await;
        assert!(refused.is_err(), "{link} is refused by follow");
        assert!(
            http.requests
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "{link} sends no request"
        );
    }
}

/// The analysis list runs past its deadline on its third call, as a paged list does when the
/// clock passes the deadline between pages. The two deletes of the first pass happen before it.
/// The run stops with `Incomplete`, writes no row, and makes no DELETE after the list stop.
#[tokio::test]
async fn a_list_past_the_deadline_stops_the_step_with_no_row_and_no_later_delete() {
    let fx = Fx::new("deadline").await;
    fx.analysis(
        1,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    fx.analysis(
        2,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-02T00:00:00Z",
    );
    fx.gh.with(|state| state.fail_list_from = Some(3));

    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(outcome.map_err(|_| "error"), Ok(RetireOutcome::Incomplete));
    assert_eq!(fx.row_count().await, 0, "a deadline stop writes no row");
    assert_eq!(fx.gh.deleted(), vec![2, 1], "the first pass deletes both");
    let calls = fx.gh.calls();
    let stop = calls
        .iter()
        .rposition(|call| matches!(call, Call::ListAnalyses))
        .unwrap_or_else(|| panic!("the list was called"));
    assert!(
        calls[stop + 1..]
            .iter()
            .all(|call| !matches!(call, Call::Delete(_) | Call::Confirm(_))),
        "no DELETE follows the list stop: {calls:?}"
    );
}

/// The converse: a list that finishes inside its deadline completes and writes the row.
#[tokio::test]
async fn a_list_inside_its_deadline_completes_and_writes_the_row() {
    let fx = Fx::new("inside").await;
    fx.analysis(
        1,
        REF_MAIN,
        LEGACY,
        LEGACY_TOOL_NAME,
        true,
        "2026-01-01T00:00:00Z",
    );
    let clock = Clock2::new(0);
    let outcome = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 1,
            carried: 0
        })
    );
    assert_eq!(fx.row_count().await, 1, "a clean pass writes the row");
}

// ---- Confirm chain through the production HTTP path ----

/// A scripted GitHub at the HTTP layer, for `octo/app`. Analysis 41 is deleted first; its DELETE
/// answers the full confirm URL that GitHub documents for 42, and the follow of that URL deletes
/// 42 and answers `null`. Listing returns what is left. Every DELETE path is recorded in order.
struct ChainHttp {
    analyses: Mutex<Vec<(u64, &'static str)>>,
    deletes: Mutex<Vec<String>>,
}

impl ChainHttp {
    fn new() -> Self {
        Self {
            analyses: Mutex::new(vec![
                (41, "2026-02-01T00:00:00Z"),
                (42, "2026-01-01T00:00:00Z"),
            ]),
            deletes: Mutex::new(Vec::new()),
        }
    }

    fn remove(&self, id: u64) -> bool {
        let mut analyses = self.analyses.lock().unwrap_or_else(|p| p.into_inner());
        let before = analyses.len();
        analyses.retain(|(kept, _)| *kept != id);
        before != analyses.len()
    }

    fn answer(body: Value) -> ScanResponse {
        ScanResponse {
            status: 200,
            retry_after: None,
            ratelimit_remaining: None,
            ratelimit_reset: None,
            link_next: None,
            body,
        }
    }
}

impl ScanHttp for ChainHttp {
    async fn post(&self, _: &str, _: &[u8], _: &Value) -> Result<ScanResponse, ScanError> {
        Err(ScanError::Upstream("unused by the chain".to_owned()))
    }

    async fn patch(&self, path: &str, _: &[u8], _: &Value) -> Result<ScanResponse, ScanError> {
        // A dismissal: GitHub answers with the alert; the chain has no alerts to dismiss.
        Err(ScanError::Upstream(format!("unexpected PATCH {path}")))
    }

    async fn get(&self, path: &str, _: &[u8]) -> Result<ScanResponse, ScanError> {
        if path.starts_with("repos/octo/app/code-scanning/alerts") {
            return Ok(Self::answer(Value::Array(Vec::new())));
        }
        let analyses = self.analyses.lock().unwrap_or_else(|p| p.into_inner());
        let items: Vec<Value> = analyses
            .iter()
            .map(|(id, created)| {
                serde_json::json!({
                    "id": id,
                    "ref": REF_MAIN,
                    "category": LEGACY,
                    "tool": {"name": LEGACY_TOOL_NAME},
                    "deletable": true,
                    "created_at": created,
                    "confirm_delete_url": null,
                })
            })
            .collect();
        Ok(Self::answer(Value::Array(items)))
    }

    async fn delete(&self, path: &str, _: &[u8]) -> Result<ScanResponse, ScanError> {
        self.deletes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(path.to_owned());
        match path {
            "repos/octo/app/code-scanning/analyses/41?confirm_delete=true" => {
                self.remove(41);
                Ok(Self::answer(serde_json::json!({
                    "confirm_delete_url":
                        "https://api.github.com/repos/octo/app/code-scanning/analyses/42?confirm_delete"
                })))
            }
            "repos/octo/app/code-scanning/analyses/42?confirm_delete" => {
                self.remove(42);
                Ok(Self::answer(Value::Null))
            }
            _ => Err(ScanError::NotFound),
        }
    }
}

/// The production client for the retirement, over a [`ScanHttp`]: each call goes through the same
/// `_with` functions that `GithubScanning` uses. Only the methods the retirement calls are wired.
struct HttpCode(Arc<ChainHttp>);

impl CodeScanning for HttpCode {
    async fn upload(&self, _: &[u8], _: &Upload<'_>, _: i64) -> Result<String, ScanError> {
        Err(ScanError::Upstream("unused by the retirement".to_owned()))
    }

    async fn status(
        &self,
        _: &[u8],
        _: &str,
        _: &str,
        _: &str,
        _: i64,
    ) -> Result<Processing, ScanError> {
        Err(ScanError::Upstream("unused by the retirement".to_owned()))
    }

    async fn list_analyses<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        tool_name: &str,
        clock: &C,
        deadline: i64,
    ) -> Result<Vec<Analysis>, ScanError> {
        list_analyses_with(&*self.0, token, owner, repo, tool_name, clock, deadline).await
    }

    async fn delete_analysis(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        id: u64,
        now: i64,
    ) -> Result<Option<String>, ScanError> {
        delete_analysis_with(&*self.0, token, owner, repo, id, now).await
    }

    async fn follow_confirm(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        link: &str,
        now: i64,
    ) -> Result<Option<String>, ScanError> {
        follow_confirm_with(&*self.0, token, owner, repo, link, now).await
    }

    async fn list_alerts<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        query: AlertQuery<'_>,
        clock: &C,
        deadline: i64,
    ) -> Result<Vec<Alert>, ScanError> {
        list_alerts_with(&*self.0, token, owner, repo, query, clock, deadline).await
    }

    async fn dismiss_alert(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        dismissal: Dismissal<'_>,
        now: i64,
    ) -> Result<(), ScanError> {
        dismiss_alert_with(&*self.0, token, owner, repo, number, dismissal, now).await
    }
}

#[tokio::test]
async fn a_confirm_chain_deletes_the_linked_analysis_and_writes_the_row() {
    // The whole retirement, with the production delete and follow functions under it. The answer
    // to the DELETE of 41 carries the full confirm URL; the follow sends the path it names, and
    // that answer is null. The run completes with both analyses removed and the row written.
    let http = Arc::new(ChainHttp::new());
    let fx = Fx::new("chain").await;
    let clock = Clock2::new(0);
    let outcome = retire(
        &fx.pool,
        &HttpCode(Arc::clone(&http)),
        &clock,
        CANARY_TOKEN.as_bytes(),
        &fx.source,
        REF_MAIN,
        NOW,
    )
    .await;
    assert_eq!(
        outcome.map_err(|_| "error"),
        Ok(RetireOutcome::Completed {
            deleted: 2,
            carried: 0
        }),
        "both analyses are deleted"
    );
    assert_eq!(fx.row_count().await, 1, "the done row is written");
    assert_eq!(
        http.deletes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone(),
        vec![
            "repos/octo/app/code-scanning/analyses/41?confirm_delete=true".to_owned(),
            "repos/octo/app/code-scanning/analyses/42?confirm_delete".to_owned(),
        ],
        "exactly the first delete and the one confirm follow, in order"
    );
}

// ---- Carry-over marking per rule ----

#[tokio::test]
async fn a_rule_applied_before_a_rate_limit_is_not_dismissed_again() {
    // Run 1 dismisses rule-q's alert 800, then is rate limited on rule-r's alert 802. Run 2 must
    // not dismiss 800 again: rule-q was recorded as applied when its dismissal finished.
    let fx = Fx::new("per-rule").await;
    fx.alert(old(1, "rule-q", Some("false positive"), None, REF_MAIN));
    fx.alert(old(2, "rule-r", Some("false positive"), None, REF_MAIN));
    fx.alert(new_alert(800, "rule-q", "open", None, REF_MAIN));
    fx.alert(new_alert(802, "rule-r", "open", None, REF_MAIN));
    fx.gh.with(|state| {
        state.dismiss_error = Some((802, ScanError::RateLimited { until: 5_000 }));
    });

    let clock = Clock2::new(0);
    let first = fx.retire(&clock, REF_MAIN, NOW).await;
    assert_eq!(
        first.map_err(|_| "error"),
        Ok(RetireOutcome::RateLimited { until: 5_000 })
    );
    assert_eq!(fx.row_count().await, 0, "the first run writes no row");

    // GitHub reopens 800, and the rate limit is gone.
    fx.gh.with(|state| {
        state.dismiss_error = None;
        for alert in state.alerts.iter_mut().filter(|alert| alert.number == 800) {
            alert.state = "open";
        }
    });

    let second = fx.retire(&clock, REF_MAIN, NOW).await;
    assert!(
        matches!(second, Ok(RetireOutcome::Completed { .. })),
        "the second run completes"
    );
    let dismissed_800 = fx
        .gh
        .dismissed()
        .iter()
        .filter(|(number, _, _)| *number == 800)
        .count();
    assert_eq!(
        dismissed_800, 1,
        "alert 800 is dismissed once, in run 1 only"
    );
    assert_eq!(
        fx.gh
            .dismissed()
            .iter()
            .filter(|(number, _, _)| *number == 802)
            .count(),
        2,
        "802 was attempted in run 1 and dismissed in run 2"
    );
}
