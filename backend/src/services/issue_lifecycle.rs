//! The GitHub issue lifecycle (`specs/cve-lifecycle.md`, "GitHub issue rules"; defaults in
//! `specs/integrations.md`, "GitHub issues").
//!
//! After each applied scan, [`reconcile`] makes the GitHub issues of one source follow its
//! `cve_findings`: create or adopt an issue for an eligible CVE, reuse it while it is open,
//! close it with a comment when the newest scanned digest no longer reports the CVE
//! (#196), and reopen it when a later scan of the newest digest reports the CVE again. Each
//! scan reads the GitHub state of the tracked issues, and an issue closed by hand is honoured. [`create_manual`] is the same create-or-adopt step for the manual route.
//!
//! The token is only passed on to the GitHub client. Nothing here logs it, an error value,
//! or a response body: every log line and error message is fixed text.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;

use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::credentials as credential_db;
use crate::db::github_issues::{self as issue_db, FindingRow, IssueRow, NewIssue};
use crate::db::github_rekeys;
use crate::db::scan_runs as runs_db;
use crate::db::sources::{self as source_db, SourceRow};
use crate::error::AppError;
use crate::services::credentials::decrypt_token;
use crate::services::github_issues::{
    self, GithubIssues, IssueRef, LABEL, LEGACY_LABEL, LabelRename, MAX_ID_BYTES, valid_cve_id,
};
use crate::services::github_scanning::ScanError;
use crate::services::ids;
use crate::services::merged_view::{self, ScannerRef};

/// The longest issue title GitHub takes, in characters. GitHub's own validation answer is
/// `title is too long (maximum is 256 characters)`; the REST page for creating an issue
/// (https://docs.github.com/rest/issues/issues#create-an-issue) does not state the limit.
const MAX_TITLE_CHARS: usize = 256;

/// The scanner keys of `scan_runs.scanner`.
const ALL_SCANNERS: [&str; 2] = ["grype", "trivy"];

/// The package text when a row has none, in the title and in the table.
const UNKNOWN_PACKAGE: &str = "unknown package";

/// The comment when the manual route reopens a closed issue.
const MANUAL_REOPEN_COMMENT: &str = "CVE reopened manually from Dockward.";

/// Serialises "look for a row, look for a marked issue, create an issue, store the row".
/// Dockward runs as one instance (`specs/architecture.md`), so one process-wide lock is
/// enough to stop a sync and a manual click from both creating the issue for one CVE.
static CREATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The GitHub Issues calls the lifecycle needs. The production impl is [`GithubIssues`];
/// tests answer from a model of GitHub.
pub trait IssueApi: Send + Sync + 'static {
    /// Lists the open issues that carry `label` (`LABEL` or `LEGACY_LABEL`).
    fn list_open_with_label(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        label: &str,
        now: i64,
    ) -> impl Future<Output = Result<Vec<IssueRef>, ScanError>> + Send;

    /// Lists the open issues that carry the current label (`LABEL`).
    fn list_open_labelled(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        now: i64,
    ) -> impl Future<Output = Result<Vec<IssueRef>, ScanError>> + Send {
        self.list_open_with_label(token, owner, repo, LABEL, now)
    }

    /// Renames a label in the repository.
    fn rename_label(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        from: &str,
        to: &str,
        now: i64,
    ) -> impl Future<Output = Result<LabelRename, ScanError>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        labels: &[&str],
        now: i64,
    ) -> impl Future<Output = Result<IssueRef, ScanError>> + Send;

    /// Creates the labels that are missing in the repository.
    fn ensure_labels(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        labels: &[&str],
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;

    /// Adds labels to an issue.
    fn add_labels(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        labels: &[&str],
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;

    /// Changes the title of an issue.
    fn retitle(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        title: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;

    fn comment(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;

    fn set_state(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        open: bool,
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;

    /// True when the issue is open on GitHub.
    fn is_open(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> impl Future<Output = Result<bool, ScanError>> + Send;

    /// The body of an issue.
    fn body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> impl Future<Output = Result<String, ScanError>> + Send;

    /// Replaces the body of an issue.
    fn set_body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;
}

impl IssueApi for GithubIssues {
    async fn list_open_with_label(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        label: &str,
        now: i64,
    ) -> Result<Vec<IssueRef>, ScanError> {
        GithubIssues::list_open_labelled(self, token, owner, repo, label, now).await
    }

    async fn rename_label(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        from: &str,
        to: &str,
        now: i64,
    ) -> Result<LabelRename, ScanError> {
        GithubIssues::rename_label(self, token, owner, repo, from, to, now).await
    }

    async fn create(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        labels: &[&str],
        now: i64,
    ) -> Result<IssueRef, ScanError> {
        GithubIssues::create(self, token, owner, repo, title, body, labels, now).await
    }

    async fn ensure_labels(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        labels: &[&str],
        now: i64,
    ) -> Result<(), ScanError> {
        GithubIssues::ensure_labels(self, token, owner, repo, labels, now).await
    }

    async fn add_labels(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        labels: &[&str],
        now: i64,
    ) -> Result<(), ScanError> {
        GithubIssues::add_labels(self, token, owner, repo, number, labels, now).await
    }

    async fn retitle(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        title: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        GithubIssues::retitle(self, token, owner, repo, number, title, now).await
    }

    async fn comment(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        GithubIssues::comment(self, token, owner, repo, number, body, now).await
    }

    async fn set_state(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        open: bool,
        now: i64,
    ) -> Result<(), ScanError> {
        GithubIssues::set_state(self, token, owner, repo, number, open, now).await
    }

    async fn is_open(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> Result<bool, ScanError> {
        GithubIssues::is_open(self, token, owner, repo, number, now).await
    }

    async fn body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> Result<String, ScanError> {
        GithubIssues::body(self, token, owner, repo, number, now).await
    }

    async fn set_body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        GithubIssues::set_body(self, token, owner, repo, number, body, now).await
    }
}

/// How a [`reconcile`] run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every CVE was looked at. Some GitHub calls may have failed and were skipped.
    Complete,
    /// GitHub rate limited a call. The run stopped; the next scan reconciles again.
    RateLimited {
        /// Unix seconds when GitHub allows calls again.
        until: i64,
    },
    /// GitHub refused the token (`401` or `403`). The run stopped at the first refusal,
    /// because every later call would fail the same way.
    Refused,
}

/// The issue created or reopened by the manual route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualIssue {
    pub url: String,
    pub number: i64,
}

/// Why one CVE step stopped.
enum Failure {
    Scan(ScanError),
    Db(AppError),
}

impl From<ScanError> for Failure {
    fn from(error: ScanError) -> Self {
        Failure::Scan(error)
    }
}

impl From<AppError> for Failure {
    fn from(error: AppError) -> Self {
        Failure::Db(error)
    }
}

/// Severity order for the automatic issue rule. Only `CRITICAL` (2) and `HIGH` (1) can
/// create issues automatically; every other severity is 0 and never reaches a minimum
/// (`specs/integrations.md`, "GitHub issues"; unchanged by #129).
fn rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 2,
        "HIGH" => 1,
        _ => 0,
    }
}

/// True when `severity` reaches the source's `min_issue_severity`. Used by the automatic
/// path only; MEDIUM, LOW and UNKNOWN never pass.
fn meets_minimum(severity: &str, min_issue_severity: Option<&str>) -> bool {
    let needed = if min_issue_severity == Some("HIGH") {
        1
    } else {
        2
    };
    rank(severity) >= needed
}

/// Every severity, highest first, for picking the highest of a CVE's rows. A value outside
/// the five (the CHECK constraint makes it impossible) sorts as `UNKNOWN`.
const SEVERITY_ORDER: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/// The position of `severity` in [`SEVERITY_ORDER`] as a rank: CRITICAL 4 down to UNKNOWN 0.
fn full_rank(severity: &str) -> usize {
    SEVERITY_ORDER
        .iter()
        .position(|known| *known == severity)
        .map_or(0, |index| SEVERITY_ORDER.len() - 1 - index)
}

/// What the open rows of one CVE say, for the issue text and the rules.
struct CveView {
    cve_id: String,
    /// The highest severity among the open rows, over all five severities.
    severity: &'static str,
    /// Package of the most recently scanned open row.
    package: Option<String>,
    /// Fixed-in version of the most recently scanned open row.
    fixed_in: Option<String>,
    /// Every tracked tag where the CVE is open, on the newest digest or not (#196, decision 25).
    tags: Vec<String>,
    /// Description of the most recently scanned open row.
    description: Option<String>,
    /// The scanners that report the CVE on the newest digest, in the merged-view order. Empty when
    /// the digest has no stored scanner report (#224).
    scanners: Vec<ScannerRef>,
}

/// The view of a CVE from its rows, or `None` when no tracked tag reports it (no `open` row).
fn summarize(cve_id: &str, rows: &[FindingRow]) -> Option<CveView> {
    let open: Vec<&FindingRow> = rows.iter().filter(|row| row.status == "open").collect();
    let latest = open
        .iter()
        .max_by(|a, b| {
            a.last_seen_at
                .cmp(&b.last_seen_at)
                .then_with(|| b.image_tag.cmp(&a.image_tag))
        })
        .copied()?;
    let highest = open
        .iter()
        .map(|row| full_rank(&row.severity))
        .max()
        .unwrap_or(0);
    let severity = SEVERITY_ORDER[SEVERITY_ORDER.len() - 1 - highest];
    let mut tags: Vec<String> = open.iter().map(|row| row.image_tag.clone()).collect();
    tags.sort();
    tags.dedup();
    Some(CveView {
        cve_id: cve_id.to_owned(),
        severity,
        package: latest.package.clone(),
        fixed_in: latest.fixed_in_version.clone(),
        tags,
        description: latest.description.clone(),
        scanners: Vec::new(),
    })
}

/// The view of a CVE as the newest scanned digest reports it: only the rows of `newest_tags`
/// count, or every row when the source has no successful report (`None`).
fn reported_in(
    cve_id: &str,
    rows: &[FindingRow],
    newest_tags: Option<&[String]>,
) -> Option<CveView> {
    match newest_tags {
        Some(tags) => {
            let scoped: Vec<FindingRow> = rows
                .iter()
                .filter(|row| tags.contains(&row.image_tag))
                .cloned()
                .collect();
            summarize(cve_id, &scoped)
        }
        None => summarize(cve_id, rows),
    }
}

/// Text kept on one line: no line break, no backtick.
fn plain(text: &str) -> String {
    text.replace(['\r', '\n', '`'], " ").trim().to_owned()
}

/// `<CVE id> <package>` and nothing else.
fn issue_title(view: &CveView) -> String {
    let package = view
        .package
        .as_deref()
        .map(plain)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| UNKNOWN_PACKAGE.to_owned());
    let title = format!("{} {}", plain(&view.cve_id), package);
    title.chars().take(MAX_TITLE_CHARS).collect()
}

/// The marker line, the table from [`github_issues::issue_body`], and the affected tags.
fn issue_text(view: &CveView, source: &SourceRow) -> String {
    let image = format!("{}/{}", source.hub_host, source.repository);
    let mut body = github_issues::issue_body(
        &view.cve_id,
        view.severity,
        &code_span(view.package.as_deref().unwrap_or(UNKNOWN_PACKAGE)),
        view.fixed_in.as_deref(),
        &image,
        view.description.as_deref(),
    );
    let tags: Vec<String> = view
        .tags
        .iter()
        .map(|tag| format!("`{}`", plain(tag)))
        .collect();
    body.push_str(&format!("\nAffected tags: {}\n", tags.join(", ")));
    // The `Found by` line goes right after the table (#224 d2).
    match merged_view::found_by_line(&view.scanners) {
        Some(line) => github_issues::with_found_by(&body, &line).unwrap_or(body),
        None => body,
    }
}

fn valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A package name as one inline code span, so `@scope/pkg` cannot @-mention a GitHub user or
/// organisation. Backticks and line breaks in the name are replaced first.
fn code_span(text: &str) -> String {
    format!("`{}`", plain(text))
}

fn to_number(number: i64) -> Result<u64, AppError> {
    u64::try_from(number).map_err(|_| AppError::InternalError)
}

/// What [`Ctx::create_or_adopt`] did.
enum Made {
    /// A new row was stored, for a new or an adopted issue.
    Created(IssueRow),
    /// The CVE already had a row, so nothing was created.
    Existing(IssueRow),
}

/// What every GitHub step needs: the database, the client, the token, the source and the
/// time. The token is only passed on to the client.
struct Ctx<'a, G> {
    pool: &'a SqlitePool,
    gh: &'a G,
    token: &'a [u8],
    source: &'a SourceRow,
    now: i64,
}

impl<G: IssueApi> Ctx<'_, G> {
    fn owner(&self) -> &str {
        &self.source.github_owner
    }

    fn repo(&self) -> &str {
        &self.source.github_repo
    }

    /// Finds or makes the issue for a CVE and stores the row. Under [`CREATE_LOCK`] it first
    /// looks for the row again, so a concurrent caller that finished first wins and this one
    /// gets [`Made::Existing`]. Otherwise an open labelled issue with the marker is adopted,
    /// or a new issue is created, and the CVE's findings are linked to the row. `listed`
    /// keeps the open issues after the first lookup, so one run lists them once.
    async fn create_or_adopt(
        &self,
        view: &CveView,
        listed: &mut Option<Vec<IssueRef>>,
    ) -> Result<Made, Failure> {
        let _guard = CREATE_LOCK.lock().await;
        if let Some(row) = self.find_row(&view.cve_id).await? {
            return Ok(Made::Existing(row));
        }
        if listed.is_none() {
            *listed = Some(self.list_open().await?);
        }
        let adopted = listed
            .as_deref()
            .and_then(|issues| github_issues::find_marked(issues, &view.cve_id))
            .cloned();
        let labels = github_issues::issue_labels(view.severity);
        let issue = match adopted {
            Some(issue) => {
                self.fix_adopted(&issue, view, &labels).await?;
                issue
            }
            None => {
                self.gh
                    .ensure_labels(self.token, self.owner(), self.repo(), &labels, self.now)
                    .await?;
                self.gh
                    .create(
                        self.token,
                        self.owner(),
                        self.repo(),
                        &issue_title(view),
                        &issue_text(view, self.source),
                        &labels,
                        self.now,
                    )
                    .await?
            }
        };
        let number = i64::try_from(issue.number).map_err(|_| AppError::InternalError)?;
        let id = ids::new_id()?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        let stored = issue_db::insert(
            &mut conn,
            &NewIssue {
                id: &id,
                github_owner: self.owner(),
                github_repo: self.repo(),
                cve_id: &view.cve_id,
                github_issue_number: number,
                github_issue_url: &issue.html_url,
            },
        )
        .await?;
        if !stored {
            // Another writer stored a row after the check above (a second process, for
            // example). Its row wins; this one is not an error.
            let row = issue_db::find(&mut conn, self.owner(), self.repo(), &view.cve_id)
                .await?
                .ok_or(AppError::InternalError)?;
            return Ok(Made::Existing(row));
        }
        issue_db::link_findings(&mut conn, &self.source.id, &view.cve_id, &id).await?;
        Ok(Made::Created(IssueRow {
            id,
            github_owner: self.owner().to_owned(),
            github_repo: self.repo().to_owned(),
            cve_id: view.cve_id.clone(),
            github_issue_number: number,
            github_issue_url: issue.html_url,
            status: "open".to_owned(),
            closed_manually: false,
        }))
    }

    /// The open issues an adoption lookup covers. The current label is always read. Until the
    /// re-key has completed, or when it kept the old label, the legacy label is read too and the
    /// two lists are merged by issue number, so an old issue is adopted and no duplicate is made
    /// (#311).
    async fn list_open(&self) -> Result<Vec<IssueRef>, Failure> {
        let current = self
            .gh
            .list_open_labelled(self.token, self.owner(), self.repo(), self.now)
            .await?;
        let read_legacy =
            match github_rekeys::issues_done(self.pool, self.owner(), self.repo()).await? {
                Some(done) => done.label_result == "kept",
                None => true,
            };
        if !read_legacy {
            return Ok(current);
        }
        let legacy = self
            .gh
            .list_open_with_label(
                self.token,
                self.owner(),
                self.repo(),
                LEGACY_LABEL,
                self.now,
            )
            .await?;
        Ok(github_issues::merge_by_number(current, legacy))
    }

    /// An adopted issue gets the new title when its own differs, and the labels it lacks.
    /// The marker and the body are not touched.
    async fn fix_adopted(
        &self,
        issue: &IssueRef,
        view: &CveView,
        labels: &[&str],
    ) -> Result<(), Failure> {
        let title = issue_title(view);
        if issue.title != title {
            self.gh
                .retitle(
                    self.token,
                    self.owner(),
                    self.repo(),
                    issue.number,
                    &title,
                    self.now,
                )
                .await?;
        }
        let missing: Vec<&str> = labels
            .iter()
            .copied()
            .filter(|wanted| !issue.labels.iter().any(|have| have == wanted))
            .collect();
        if !missing.is_empty() {
            self.gh
                .ensure_labels(self.token, self.owner(), self.repo(), &missing, self.now)
                .await?;
            self.gh
                .add_labels(
                    self.token,
                    self.owner(),
                    self.repo(),
                    issue.number,
                    &missing,
                    self.now,
                )
                .await?;
        }
        Ok(())
    }

    /// Sets the `Found by` line of an open issue to the scanners that report the CVE now, with a
    /// PATCH on the body, only when the line differs (`specs/integrations.md`, "GitHub issues").
    /// Nothing is read or sent when no scanner is known, so a source that has no stored scanner
    /// report makes the same GitHub calls as before.
    async fn refresh_found_by(
        &self,
        row: &IssueRow,
        scanners: &[ScannerRef],
    ) -> Result<(), Failure> {
        let Some(line) = merged_view::found_by_line(scanners) else {
            return Ok(());
        };
        let number = to_number(row.github_issue_number)?;
        let body = self
            .gh
            .body(self.token, self.owner(), self.repo(), number, self.now)
            .await?;
        if let Some(next) = github_issues::with_found_by(&body, &line) {
            self.gh
                .set_body(
                    self.token,
                    self.owner(),
                    self.repo(),
                    number,
                    &next,
                    self.now,
                )
                .await?;
        }
        Ok(())
    }

    async fn find_row(&self, cve_id: &str) -> Result<Option<IssueRow>, AppError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        issue_db::find(&mut conn, self.owner(), self.repo(), cve_id).await
    }

    /// True when another source that targets the same GitHub repository reports `cve_id`:
    /// a tag of its newest scanned digest has the CVE `open` (every tracked tag when it has
    /// no successful report). The issue is shared (#185), so it closes only when no source
    /// of the repository reports the CVE (`specs/cve-lifecycle.md`).
    async fn reported_elsewhere(&self, cve_id: &str) -> Result<bool, AppError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        let siblings =
            issue_db::sibling_sources(&mut conn, &self.source.id, self.owner(), self.repo())
                .await?;
        for sibling in siblings {
            let rows = issue_db::findings_for_cve(&mut conn, &sibling.id, cve_id).await?;
            if rows.is_empty() {
                continue;
            }
            let newest = issue_db::newest_image_tags(&mut conn, &sibling.id).await?;
            if reported_in(cve_id, &rows, newest.as_deref()).is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reopens the issue of a closed row, marks the row `open`, then comments.
    async fn reopen(&self, row: &IssueRow, comment: &str) -> Result<(), Failure> {
        let number = to_number(row.github_issue_number)?;
        self.gh
            .set_state(
                self.token,
                self.owner(),
                self.repo(),
                number,
                true,
                self.now,
            )
            .await?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        issue_db::set_status(&mut conn, &row.id, "open").await?;
        drop(conn);
        self.gh
            .comment(
                self.token,
                self.owner(),
                self.repo(),
                number,
                comment,
                self.now,
            )
            .await?;
        Ok(())
    }

    /// Comments on the issue of an open row, closes it, and marks the row `closed`.
    async fn close(&self, row: &IssueRow, comment: &str) -> Result<(), Failure> {
        let number = to_number(row.github_issue_number)?;
        self.gh
            .comment(
                self.token,
                self.owner(),
                self.repo(),
                number,
                comment,
                self.now,
            )
            .await?;
        self.gh
            .set_state(
                self.token,
                self.owner(),
                self.repo(),
                number,
                false,
                self.now,
            )
            .await?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        issue_db::set_status(&mut conn, &row.id, "closed").await?;
        Ok(())
    }

    /// Reads whether the issue of `row` is open on GitHub.
    async fn github_is_open(&self, row: &IssueRow) -> Result<bool, Failure> {
        let number = to_number(row.github_issue_number)?;
        Ok(self
            .gh
            .is_open(self.token, self.owner(), self.repo(), number, self.now)
            .await?)
    }

    /// Stores a status without any GitHub call (the issue already has that state there).
    async fn store_status(&self, row: &IssueRow, status: &str) -> Result<(), Failure> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        issue_db::set_status(&mut conn, &row.id, status).await?;
        Ok(())
    }

    /// Applies the issue rules to one CVE of the source, given its rows. The CVE counts as
    /// reported only when a tag of the newest scanned digest has it `open`
    /// (`rules.newest_tags`); older tags never keep an issue open.
    async fn step(
        &self,
        cve_id: &str,
        rows: &[FindingRow],
        rules: &Rules<'_>,
        listed: &mut Option<Vec<IssueRef>>,
    ) -> Result<(), Failure> {
        let view = reported_in(cve_id, rows, rules.newest_tags.as_deref());
        let existing = {
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(|_| AppError::InternalError)?;
            let row = issue_db::find(&mut conn, self.owner(), self.repo(), cve_id).await?;
            if let Some(row) = &row {
                issue_db::link_findings(&mut conn, &self.source.id, cve_id, &row.id).await?;
            }
            row
        };
        let reported = view.is_some();
        // `Affected tags:` lists every tracked tag that still reports the CVE, older ones too
        // (#196, decision 25); the close rule above reads the newest digest only.
        let all_tags = summarize(cve_id, rows)
            .map(|all| all.tags)
            .unwrap_or_default();
        let view = view.map(|mut view| {
            view.scanners = rules.scanners.get(cve_id).cloned().unwrap_or_default();
            view.tags = all_tags;
            view
        });
        let view_scanners: Vec<ScannerRef> = view
            .as_ref()
            .map(|view| view.scanners.clone())
            .unwrap_or_default();
        match (existing, view) {
            // (a) Reported, eligible, and no issue yet: adopt or create. Skipped when
            // `auto_create_issues` is off.
            (None, Some(view)) => {
                let accepted = rules.accepted.iter().any(|id| id == cve_id);
                if rules.auto_create
                    && !accepted
                    && meets_minimum(view.severity, rules.min_issue_severity)
                {
                    self.create_or_adopt(&view, listed).await?;
                }
            }
            (None, None) => {}
            // (b) A row Dockward closed, and the newest digest reports the CVE again: reopen
            // the same issue. A row closed by hand is only reopened if someone reopened the
            // issue on GitHub (then only the row is updated).
            (Some(row), Some(_)) if row.status == "closed" => {
                if row.closed_manually {
                    if self.github_is_open(&row).await? {
                        self.store_status(&row, "open").await?;
                    }
                } else {
                    let comment = match merged_view::names_text(&view_scanners) {
                        Some(names) => {
                            format!(
                                "CVE is back in scan {}, found by {names}.",
                                rules.scan_label
                            )
                        }
                        None => format!("CVE is back in scan {}", rules.scan_label),
                    };
                    self.reopen(&row, &comment).await?;
                    self.refresh_found_by(&row, &view_scanners).await?;
                }
            }
            // (c) The row is open: read the GitHub state first. The row is shared by every
            // source of the GitHub repository (#185), so the CVE counts as reported when
            // another of them reports it.
            (Some(row), _) if row.status == "open" => {
                let reported = reported || self.reported_elsewhere(cve_id).await?;
                if self.github_is_open(&row).await? {
                    // Open on both sides. When the newest digest no longer reports the CVE:
                    // comment, then close. An enabled scanner with no report for the newest
                    // digest holds the issue open (#224 d14).
                    if !reported {
                        if !rules.close_blocked {
                            let comment = format!(
                                "No scanner reports this CVE since scan {}.",
                                rules.scan_label
                            );
                            self.close(&row, &comment).await?;
                        }
                    } else {
                        self.refresh_found_by(&row, &view_scanners).await?;
                    }
                } else if reported {
                    // Closed by hand while the CVE is still reported: honour it.
                    let mut conn = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| AppError::InternalError)?;
                    issue_db::mark_closed_manually(&mut conn, &row.id).await?;
                } else {
                    // Closed on GitHub and the CVE is gone: no comment, only the row.
                    self.store_status(&row, "closed").await?;
                }
            }
            // (d) Nothing to do.
            _ => {}
        }
        Ok(())
    }
}

/// The source's rule inputs for one reconcile run.
struct Rules<'a> {
    auto_create: bool,
    min_issue_severity: Option<&'a str>,
    scan_label: &'a str,
    /// CVE ids with an active acceptance.
    accepted: Vec<String>,
    /// Image tags of the newest scanned digest, or `None` when the source has no successful
    /// report (then every tracked tag counts).
    newest_tags: Option<Vec<String>>,
    /// The scanners that report each CVE on the newest digest (#224).
    scanners: HashMap<String, Vec<ScannerRef>>,
    /// True while an enabled scanner has no report for the newest digest of this source or of a
    /// source that shares the GitHub repository. No issue closes then (#224 d14).
    close_blocked: bool,
}

/// What the stored scanner reports say for one source (#224): the scanners per CVE on the newest
/// digest, and whether a close must wait. A digest with no stored scanner report (one that was
/// synced the old way) has no scanners, so nothing changes for it.
async fn scanner_state(
    pool: &SqlitePool,
    source: &SourceRow,
) -> Result<(HashMap<String, Vec<ScannerRef>>, bool), AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let enabled = enabled_scanner_keys(&mut conn).await?;
    let newest = issue_db::newest_image(&mut conn, &source.id).await?;
    let mut blocked = false;
    if let Some(image_id) = &newest {
        blocked = image_awaits_scanner(&mut conn, image_id, &enabled).await?;
    }
    let siblings = issue_db::sibling_sources(
        &mut conn,
        &source.id,
        &source.github_owner,
        &source.github_repo,
    )
    .await?;
    for sibling in siblings {
        if blocked {
            break;
        }
        if let Some(image_id) = issue_db::newest_image(&mut conn, &sibling.id).await? {
            blocked = image_awaits_scanner(&mut conn, &image_id, &enabled).await?;
        }
    }
    drop(conn);
    let mut by_cve = HashMap::new();
    if let Some(image_id) = newest {
        let merged = merged_view::load(pool, &image_id).await?;
        by_cve = merged_view::scanners_by_cve(&merged);
    }
    Ok((by_cve, blocked))
}

/// The scanner keys the operator enabled: `scanners.enabled` of `system_config`, a comma
/// separated list of `grype` and `trivy`. An unset or unusable value enables both. Unknown
/// words are ignored.
pub(crate) async fn enabled_scanner_keys(
    conn: &mut sqlx::SqliteConnection,
) -> Result<Vec<String>, AppError> {
    let value = runs_db::enabled_scanners_setting_in(conn).await?;
    let listed: Vec<String> = value
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(|word| word.trim().to_ascii_lowercase())
        .filter(|word| ALL_SCANNERS.contains(&word.as_str()))
        .collect();
    if listed.is_empty() {
        return Ok(ALL_SCANNERS.iter().map(|key| (*key).to_owned()).collect());
    }
    Ok(listed)
}

/// True while an enabled scanner has no `done` run for some platform of the image. An evicted
/// platform counts through its last `done` run. A queued, running or failed run is not a result,
/// so it holds issue closing open (#224 d14; `specs/spinoff-local-scan.md`, section 9).
async fn image_awaits_scanner(
    conn: &mut sqlx::SqliteConnection,
    image_id: &str,
    enabled: &[String],
) -> Result<bool, AppError> {
    let platforms = runs_db::platform_ids_in(conn, image_id).await?;
    let done = runs_db::done_pairs_in(conn, image_id).await?;
    Ok(platforms.iter().any(|platform| {
        enabled
            .iter()
            .any(|scanner| !done.iter().any(|(p, s)| p == platform && s == scanner))
    }))
}

/// Makes the GitHub issues of `source` follow its findings. `scan_label` names the scan in
/// the comments. A rate limit stops the run and is returned in [`Outcome`]. Any other GitHub
/// error is logged as fixed text and the next CVE continues. A database error is returned.
pub async fn reconcile<G: IssueApi>(
    pool: &SqlitePool,
    gh: &G,
    token: &[u8],
    source: &SourceRow,
    scan_label: &str,
    now: i64,
) -> Result<Outcome, AppError> {
    let (rows, accepted, newest_tags) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        (
            issue_db::findings_for_source(&mut conn, &source.id).await?,
            issue_db::accepted_cves(&mut conn, &source.id, now).await?,
            issue_db::newest_image_tags(&mut conn, &source.id).await?,
        )
    };
    let (scanners, close_blocked) = scanner_state(pool, source).await?;
    let mut by_cve: BTreeMap<String, Vec<FindingRow>> = BTreeMap::new();
    for row in rows {
        by_cve.entry(row.cve_id.clone()).or_default().push(row);
    }
    let rules = Rules {
        auto_create: source.auto_create_issues,
        min_issue_severity: Some(source.min_issue_severity.as_str()),
        scan_label,
        accepted,
        newest_tags,
        scanners,
        close_blocked,
    };
    let ctx = Ctx {
        pool,
        gh,
        token,
        source,
        now,
    };
    let mut listed: Option<Vec<IssueRef>> = None;
    for (cve_id, rows) in &by_cve {
        if !valid_cve_id(cve_id) {
            continue;
        }
        match ctx.step(cve_id, rows, &rules, &mut listed).await {
            Ok(()) => {}
            Err(Failure::Scan(ScanError::RateLimited { until })) => {
                return Ok(Outcome::RateLimited { until });
            }
            Err(Failure::Scan(ScanError::Unauthorized)) => {
                tracing::warn!(
                    reason = "Unauthorized",
                    "GitHub refused the issue updates; stopping"
                );
                return Ok(Outcome::Refused);
            }
            Err(Failure::Scan(ScanError::Forbidden(_))) => {
                tracing::warn!(
                    reason = "Forbidden",
                    "GitHub refused the issue updates; stopping"
                );
                return Ok(Outcome::Refused);
            }
            Err(Failure::Scan(_)) => {
                tracing::warn!("a GitHub issue update failed; continuing with the next CVE");
            }
            Err(Failure::Db(error)) => return Err(error),
        }
    }
    Ok(Outcome::Complete)
}

/// A GitHub failure in the manual route is `502`; a database error stays as it is.
fn manual_error(failure: Failure) -> AppError {
    match failure {
        Failure::Db(error) => error,
        Failure::Scan(_) => AppError::UpstreamUnreachable,
    }
}

/// The manual issue route's work (`specs/api.md`, `POST /api/v1/cves/:id/issue`) for a
/// source the caller owns.
///
/// - `404` when the source has no finding for the CVE.
/// - `409` (with the URL) when its issue is open, and `409` while an active acceptance exists.
/// - `422` when no tracked tag reports the CVE as open. Any open severity is allowed, LOW
///   and UNKNOWN included (#129); the confirmation for those is a frontend step. The
///   source's `min_issue_severity` and `auto_create_issues` do not apply: the manual action
///   overrides them.
/// - A closed issue is reopened, never duplicated. Otherwise an open labelled issue with the
///   marker is adopted, or a new one is created.
/// - A GitHub failure is `502`.
pub async fn create_manual<G: IssueApi>(
    pool: &SqlitePool,
    gh: &G,
    token: &[u8],
    source: &SourceRow,
    cve_id: &str,
    now: i64,
) -> Result<ManualIssue, AppError> {
    let (rows, existing, accepted) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        (
            issue_db::findings_for_cve(&mut conn, &source.id, cve_id).await?,
            issue_db::find(&mut conn, &source.github_owner, &source.github_repo, cve_id).await?,
            issue_db::accepted_cves(&mut conn, &source.id, now).await?,
        )
    };
    if rows.is_empty() {
        return Err(AppError::NotFound);
    }
    if let Some(row) = &existing
        && row.status == "open"
    {
        return Err(AppError::Conflict(format!(
            "An open GitHub issue already exists: {}",
            row.github_issue_url
        )));
    }
    if accepted.iter().any(|id| id == cve_id) {
        return Err(AppError::Conflict(
            "This CVE has an active risk acceptance.".to_owned(),
        ));
    }
    let view = summarize(cve_id, &rows).ok_or_else(|| {
        AppError::ValidationFailed(
            "Only a CVE that is open on a tracked tag can get an issue.".to_owned(),
        )
    })?;
    let ctx = Ctx {
        pool,
        gh,
        token,
        source,
        now,
    };
    let row = match existing {
        Some(row) => {
            ctx.reopen(&row, MANUAL_REOPEN_COMMENT)
                .await
                .map_err(manual_error)?;
            row
        }
        None => {
            let mut listed = None;
            match ctx
                .create_or_adopt(&view, &mut listed)
                .await
                .map_err(manual_error)?
            {
                Made::Created(row) => row,
                // A concurrent caller stored the row first and it is still open.
                Made::Existing(row) if row.status == "open" => {
                    return Err(AppError::Conflict(format!(
                        "An open GitHub issue already exists: {}",
                        row.github_issue_url
                    )));
                }
                Made::Existing(row) => {
                    ctx.reopen(&row, MANUAL_REOPEN_COMMENT)
                        .await
                        .map_err(manual_error)?;
                    row
                }
            }
        }
    };
    Ok(ManualIssue {
        url: row.github_issue_url,
        number: row.github_issue_number,
    })
}

/// Splits the route id `<source_id>:<cve_id>`. An id in any other shape, an empty part, a
/// part over 128 bytes, or a character outside the allowed set is `404`, before any database
/// call.
fn split_id(id: &str) -> Result<(&str, &str), AppError> {
    match id.split_once(':') {
        Some((source_id, cve_id)) if valid_source_id(source_id) && valid_cve_id(cve_id) => {
            Ok((source_id, cve_id))
        }
        _ => Err(AppError::NotFound),
    }
}

/// `POST /api/v1/cves/:id/issue` for `user_id`: finds the source the caller owns (another
/// tenant's source is `404`), decrypts the GitHub token of its credential, and calls
/// [`create_manual`].
pub async fn create_manual_for_user<G: IssueApi>(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    gh: &G,
    user_id: &str,
    id: &str,
    now: i64,
) -> Result<ManualIssue, AppError> {
    let (source_id, cve_id) = split_id(id)?;
    let (source, credential) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        let source = source_db::find_owned(&mut conn, user_id, source_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let credential = credential_db::find_owned(&mut conn, user_id, &source.github_cred_id)
            .await?
            .ok_or(AppError::NotFound)?;
        (source, credential)
    };
    let token = decrypt_token(credentials_key, &credential)?;
    create_manual(pool, gh, &token, &source, cve_id, now).await
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A model of GitHub for the tests: it answers the `ScanHttp` calls of the issues client
    //! from an in-memory list of issues and records every request.

    use std::sync::Mutex;

    use serde_json::{Value, json};

    use super::*;
    use crate::services::github_scanning::{ScanHttp, ScanResponse};

    pub struct Issue {
        pub number: u64,
        pub body: String,
        pub open: bool,
        pub title: String,
        pub labels: Vec<String>,
    }

    #[derive(Default)]
    pub struct State {
        pub issues: Vec<Issue>,
        /// Labels that exist in the repository.
        pub repo_labels: Vec<String>,
        /// `(method, path, body)` of every request, in order.
        pub log: Vec<(&'static str, String, Value)>,
        pub rate_limited: bool,
        /// Answer every call as a refused token (`401`).
        pub unauthorized: bool,
        /// Make a list call wait (at most 100 ms) until a second caller also lists, so two
        /// concurrent callers really overlap. A lock that serialises them makes the first
        /// caller time out and go on alone.
        pub rendezvous: bool,
        pub listing: usize,
        /// Answer `(method, path-prefix)` with the given status and no change, once per entry.
        pub fail_once: Vec<(&'static str, String, u16)>,
        /// Replace the body of this issue number before the next body read.
        pub edit_before_read: Option<(u64, String)>,
    }

    /// The fake GitHub for `octo/app`.
    #[derive(Default)]
    pub struct FakeGithub {
        pub state: Mutex<State>,
    }

    impl FakeGithub {
        pub fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            f(&mut guard)
        }

        /// Bodies of the requests that created issues.
        pub fn creates(&self) -> Vec<Value> {
            self.with(|state| {
                state
                    .log
                    .iter()
                    .filter(|(method, path, _)| {
                        *method == "POST" && path == "repos/octo/app/issues"
                    })
                    .map(|(_, _, body)| body.clone())
                    .collect()
            })
        }

        /// `(method, path, body)` of every request that is not a list or a label creation.
        pub fn writes(&self) -> Vec<(&'static str, String, Value)> {
            self.with(|state| {
                state
                    .log
                    .iter()
                    .filter(|(method, path, _)| *method != "GET" && path != "repos/octo/app/labels")
                    .cloned()
                    .collect()
            })
        }

        pub fn requests(&self) -> usize {
            self.with(|state| state.log.len())
        }

        fn respond(
            &self,
            method: &'static str,
            path: &str,
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.with(|state| {
                state.log.push((method, path.to_owned(), body.clone()));
                if state.rate_limited {
                    return Err(ScanError::RateLimited { until: 5_000 });
                }
                if state.unauthorized {
                    return Err(ScanError::Unauthorized);
                }
                if let Some(index) = state
                    .fail_once
                    .iter()
                    .position(|(m, p, _)| *m == method && path == p)
                {
                    let (_, _, status) = state.fail_once.remove(index);
                    return Ok(ScanResponse {
                        status,
                        retry_after: None,
                        ratelimit_remaining: None,
                        ratelimit_reset: None,
                        link_next: None,
                        body: json!({"message": "refused"}),
                    });
                }
                if let Some((number, text)) = state.edit_before_read.clone()
                    && method == "GET"
                    && path == format!("repos/octo/app/issues/{number}")
                {
                    state.edit_before_read = None;
                    if let Some(issue) = state.issues.iter_mut().find(|i| i.number == number) {
                        issue.body = text;
                    }
                }
                let reply = |status: u16, body: Value| ScanResponse {
                    status,
                    retry_after: None,
                    ratelimit_remaining: None,
                    ratelimit_reset: None,
                    link_next: None,
                    body,
                };
                let issue_json = |issue: &Issue| {
                    json!({
                        "number": issue.number,
                        "html_url": format!("https://github.com/octo/app/issues/{}", issue.number),
                        "body": issue.body,
                        "title": issue.title,
                        "labels": issue.labels.iter().map(|l| json!({"name": l})).collect::<Vec<_>>(),
                        "state": if issue.open { "open" } else { "closed" },
                    })
                };
                match (method, path) {
                    ("GET", single) if single.starts_with("repos/octo/app/issues/") => {
                        let number: Option<u64> =
                            single.rsplit('/').next().and_then(|last| last.parse().ok());
                        match state.issues.iter().find(|i| Some(i.number) == number) {
                            Some(issue) => Ok(reply(200, issue_json(issue))),
                            None => Ok(reply(404, json!({}))),
                        }
                    }
                    ("GET", list) => {
                        // The label filter is the `labels=` query of the list path.
                        let wanted = list
                            .split_once("labels=")
                            .map(|(_, rest)| rest.split('&').next().unwrap_or_default());
                        let items: Vec<Value> = state
                            .issues
                            .iter()
                            .filter(|issue| issue.open)
                            .filter(|issue| {
                                wanted.is_none_or(|label| issue.labels.iter().any(|l| l == label))
                            })
                            .map(issue_json)
                            .collect();
                        Ok(reply(200, Value::Array(items)))
                    }
                    ("PATCH", label_path) if label_path.starts_with("repos/octo/app/labels/") => {
                        let from = label_path.trim_start_matches("repos/octo/app/labels/");
                        let to = body
                            .get("new_name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        if !state.repo_labels.iter().any(|l| l == from) {
                            return Ok(reply(404, json!({"message": "Not Found"})));
                        }
                        if state.repo_labels.contains(&to) {
                            return Ok(reply(
                                422,
                                json!({"errors": [{"resource": "Label", "code": "already_exists", "field": "new_name"}]}),
                            ));
                        }
                        for label in state.repo_labels.iter_mut().filter(|l| **l == from) {
                            label.clone_from(&to);
                        }
                        for issue in &mut state.issues {
                            for label in issue.labels.iter_mut().filter(|l| **l == from) {
                                label.clone_from(&to);
                            }
                        }
                        Ok(reply(200, json!({})))
                    }
                    ("POST", "repos/octo/app/issues") => {
                        let number = state.issues.len() as u64 + 1;
                        let text = body
                            .get("body")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let title = body
                            .get("title")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let labels = body
                            .get("labels")
                            .and_then(Value::as_array)
                            .map(|l| l.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                            .unwrap_or_default();
                        state.issues.push(Issue {
                            number,
                            body: text,
                            open: true,
                            title,
                            labels,
                        });
                        let created = state.issues.last().map(issue_json).unwrap_or(Value::Null);
                        Ok(reply(201, created))
                    }
                    ("POST", "repos/octo/app/labels") => {
                        let name = body
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        if state.repo_labels.contains(&name) {
                            return Ok(reply(
                                422,
                                json!({"errors": [{"resource": "Label", "code": "already_exists", "field": "name"}]}),
                            ));
                        }
                        state.repo_labels.push(name);
                        Ok(reply(201, json!({})))
                    }
                    ("POST", labels) if labels.ends_with("/labels") => {
                        let number: Option<u64> = labels
                            .trim_end_matches("/labels")
                            .rsplit('/')
                            .next()
                            .and_then(|n| n.parse().ok());
                        let added: Vec<String> = body
                            .get("labels")
                            .and_then(Value::as_array)
                            .map(|l| l.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                            .unwrap_or_default();
                        if let Some(issue) = state.issues.iter_mut().find(|i| Some(i.number) == number) {
                            for label in added {
                                if !issue.labels.contains(&label) {
                                    issue.labels.push(label);
                                }
                            }
                        }
                        Ok(reply(200, json!([])))
                    }
                    ("POST", _) => Ok(reply(201, json!({}))),
                    (_, _) => {
                        let number: Option<u64> =
                            path.rsplit('/').next().and_then(|last| last.parse().ok());
                        if let Some(issue) = state
                            .issues
                            .iter_mut()
                            .find(|issue| Some(issue.number) == number)
                        {
                            if let Some(state_text) = body.get("state").and_then(Value::as_str) {
                                issue.open = state_text == "open";
                            }
                            if let Some(title) = body.get("title").and_then(Value::as_str) {
                                issue.title = title.to_owned();
                            }
                            if let Some(text) = body.get("body").and_then(Value::as_str) {
                                issue.body = text.to_owned();
                            }
                        }
                        Ok(reply(200, json!({})))
                    }
                }
            })
        }
    }

    impl ScanHttp for FakeGithub {
        async fn post(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            // Let a concurrent caller run, so a missing lock shows up as a second create.
            tokio::task::yield_now().await;
            self.respond("POST", path, body)
        }

        async fn patch(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.respond("PATCH", path, body)
        }

        async fn delete(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            self.respond("DELETE", path, &Value::Null)
        }

        async fn get(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            // The answer is read now and delivered later, like a slow network: a caller
            // that lists while another is creating gets a list without the new issue.
            let answer = self.respond("GET", path, &Value::Null);
            if self.with(|state| {
                state.listing += 1;
                state.rendezvous
            }) {
                for _ in 0..50 {
                    if self.with(|state| state.listing >= 2) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            }
            tokio::task::yield_now().await;
            answer
        }
    }

    /// The lifecycle's `IssueApi` over the fake GitHub, through the real issues client
    /// functions, so the label, the marker and the paths are the production ones.
    pub struct FakeIssues(pub std::sync::Arc<FakeGithub>);

    impl IssueApi for FakeIssues {
        async fn list_open_with_label(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            label: &str,
            now: i64,
        ) -> Result<Vec<IssueRef>, ScanError> {
            github_issues::list_open_labelled_with(&*self.0, token, owner, repo, label, now).await
        }

        async fn rename_label(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            from: &str,
            to: &str,
            now: i64,
        ) -> Result<LabelRename, ScanError> {
            github_issues::rename_label_with(&*self.0, token, owner, repo, from, to, now).await
        }

        async fn create(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            title: &str,
            body: &str,
            labels: &[&str],
            now: i64,
        ) -> Result<IssueRef, ScanError> {
            github_issues::create_with(&*self.0, token, owner, repo, title, body, labels, now).await
        }

        async fn ensure_labels(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            labels: &[&str],
            now: i64,
        ) -> Result<(), ScanError> {
            github_issues::ensure_labels_with(&*self.0, token, owner, repo, labels, now).await
        }

        async fn add_labels(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            labels: &[&str],
            now: i64,
        ) -> Result<(), ScanError> {
            github_issues::add_labels_with(&*self.0, token, owner, repo, number, labels, now).await
        }

        async fn retitle(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            title: &str,
            now: i64,
        ) -> Result<(), ScanError> {
            github_issues::retitle_with(&*self.0, token, owner, repo, number, title, now).await
        }

        async fn comment(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            body: &str,
            now: i64,
        ) -> Result<(), ScanError> {
            github_issues::comment_with(&*self.0, token, owner, repo, number, body, now).await
        }

        async fn set_state(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            open: bool,
            now: i64,
        ) -> Result<(), ScanError> {
            github_issues::set_state_with(&*self.0, token, owner, repo, number, open, now).await
        }

        async fn is_open(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            now: i64,
        ) -> Result<bool, ScanError> {
            github_issues::is_open_with(&*self.0, token, owner, repo, number, now).await
        }

        async fn body(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            now: i64,
        ) -> Result<String, ScanError> {
            github_issues::body_with(&*self.0, token, owner, repo, number, now).await
        }

        async fn set_body(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            body: &str,
            now: i64,
        ) -> Result<(), ScanError> {
            github_issues::set_body_with(&*self.0, token, owner, repo, number, body, now).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::test_support::{FakeGithub, FakeIssues};
    use super::*;
    use crate::db;

    const TOKEN: &[u8] = b"fake-token-value";

    struct Fixture {
        pool: SqlitePool,
        dir: std::path::PathBuf,
        github: Arc<FakeGithub>,
        gh: FakeIssues,
        /// The `finished_at` of the next scan run; each run is later than the one before.
        clock: AtomicI64,
    }

    impl Fixture {
        async fn new(name: &str, min: &str, auto: bool) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("dockward-lifecycle-{name}-{}", std::process::id()));
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
            let github = Arc::new(FakeGithub::default());
            let fixture = Self {
                pool,
                dir,
                github: github.clone(),
                gh: FakeIssues(github),
                clock: AtomicI64::new(1_000),
            };
            fixture.source_row("m1", min, auto).await;
            fixture
        }

        /// A source on `ghcr.io`. `m1` is `o/app`; any other id is `o/web`. Both target the
        /// GitHub repository `octo/app`.
        async fn source_row(&self, id: &str, min: &str, auto: bool) {
            let repository = if id == "m1" { "o/app" } else { "o/web" };
            sqlx::query(
                "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo, auto_create_issues, min_issue_severity)
                 VALUES (?, 'u1', 'hub-default-ghcr', ?, '*', 'c2', 'octo', 'app', ?, ?)",
            )
            .bind(id)
            .bind(repository)
            .bind(auto)
            .bind(min)
            .execute(&self.pool)
            .await
            .unwrap();
        }

        async fn source(&self, id: &str) -> SourceRow {
            let mut conn = self.pool.acquire().await.unwrap();
            source_db::find_by_id(&mut conn, id).await.unwrap().unwrap()
        }

        /// Stores a finding for `tag` as an `open` row seen at `at`.
        async fn finding(&self, source_id: &str, tag: &str, cve: &str, severity: &str, at: i64) {
            self.finding_pkg(source_id, tag, cve, severity, "openssl", at)
                .await;
        }

        async fn finding_pkg(
            &self,
            source_id: &str,
            tag: &str,
            cve: &str,
            severity: &str,
            package: &str,
            at: i64,
        ) {
            self.finding_full(source_id, tag, cve, severity, package, None, at)
                .await;
        }

        #[allow(clippy::too_many_arguments)]
        async fn finding_full(
            &self,
            source_id: &str,
            tag: &str,
            cve: &str,
            severity: &str,
            package: &str,
            description: Option<&str>,
            at: i64,
        ) {
            sqlx::query(
                "INSERT INTO cve_findings
                    (id, source_id, image_tag, cve_id, package, severity, description,
                     first_seen_at, last_seen_at, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                 ON CONFLICT (source_id, image_tag, cve_id) DO UPDATE SET
                    severity = excluded.severity, package = excluded.package,
                    description = excluded.description, last_seen_at = excluded.last_seen_at,
                    status = 'open'",
            )
            .bind(ids::new_id().unwrap_or_default())
            .bind(source_id)
            .bind(tag)
            .bind(cve)
            .bind(package)
            .bind(severity)
            .bind(description)
            .bind(at)
            .bind(at)
            .execute(&self.pool)
            .await
            .unwrap();
        }

        async fn fix(&self, tag: &str, cve: &str) {
            sqlx::query(
                "UPDATE cve_findings SET status = 'fixed' WHERE image_tag = ? AND cve_id = ?",
            )
            .bind(tag)
            .bind(cve)
            .execute(&self.pool)
            .await
            .unwrap();
        }

        /// Source `m1` observes `tag` on `digest` from `first_seen` on (decision 49). The image
        /// has one platform. No scan run is stored.
        async fn observe(&self, tag: &str, digest: &str, first_seen: i64) {
            let image = format!("img-{digest}");
            sqlx::query(
                "INSERT OR IGNORE INTO images (id, hub_id, repository, digest, is_index)
                 VALUES (?, 'hub-default-ghcr', 'o/app', ?, 0)",
            )
            .bind(&image)
            .bind(digest)
            .execute(&self.pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT OR IGNORE INTO image_platforms (id, image_id, platform, platform_digest, state)
                 VALUES (?, ?, 'linux/amd64', ?, 'stored')",
            )
            .bind(format!("plat-{digest}"))
            .bind(&image)
            .bind(digest)
            .execute(&self.pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
                 VALUES ('m1', ?, ?, ?, ?)",
            )
            .bind(tag)
            .bind(&image)
            .bind(first_seen)
            .bind(first_seen)
            .execute(&self.pool)
            .await
            .unwrap();
        }

        /// A finished scan of `digest` by `scanner` (`grype` or `trivy`) that found `cves`
        /// (CVE id, package). It is later than every run stored before it.
        async fn scan_run(&self, digest: &str, scanner: &str, cves: &[(&str, &str)]) {
            let run_id = ids::new_id().unwrap();
            let finished = self.clock.fetch_add(1, Ordering::SeqCst);
            sqlx::query(
                "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
                 VALUES (?, ?, ?, 'first_pull', 'done', ?)",
            )
            .bind(&run_id)
            .bind(format!("plat-{digest}"))
            .bind(scanner)
            .bind(finished)
            .execute(&self.pool)
            .await
            .unwrap();
            for (cve, package) in cves {
                sqlx::query(
                    "INSERT INTO scanner_findings (run_id, cve_id, package, version, severity)
                     VALUES (?, ?, ?, '1.0', 'CRITICAL')",
                )
                .bind(&run_id)
                .bind(cve)
                .bind(package)
                .execute(&self.pool)
                .await
                .unwrap();
            }
        }

        /// Source `m1` observes `tag` on `digest` from `first_seen` on, and both scanners have a
        /// finished, clean scan of it.
        async fn report(&self, tag: &str, digest: &str, first_seen: i64) {
            self.observe(tag, digest, first_seen).await;
            self.scan_run(digest, "grype", &[]).await;
            self.scan_run(digest, "trivy", &[]).await;
        }

        async fn reconcile(&self, label: &str) -> Outcome {
            let source = self.source("m1").await;
            reconcile(&self.pool, &self.gh, TOKEN, &source, label, 1_000)
                .await
                .unwrap()
        }

        /// `(cve_id, issue number, status)` of every tracked issue.
        async fn issues(&self) -> Vec<(String, i64, String)> {
            sqlx::query_as(
                "SELECT cve_id, github_issue_number, status FROM github_issues ORDER BY cve_id",
            )
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

    #[tokio::test]
    async fn critical_creates_one_issue_with_label_and_marker() {
        let fx = Fixture::new("critical", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.finding("m1", "v1", "CVE-2026-0002", "MEDIUM", 10).await;

        assert_eq!(fx.reconcile("ghcr.io/o/app:v1").await, Outcome::Complete);

        let creates = fx.github.creates();
        assert_eq!(creates.len(), 1);
        assert_eq!(
            creates[0]["labels"],
            serde_json::json!(["dockward", "areai:security", "critical"])
        );
        let body = creates[0]["body"].as_str().unwrap();
        assert_eq!(body.lines().next(), Some("<!-- dockward:CVE-2026-0001 -->"));
        assert_eq!(creates[0]["title"], "CVE-2026-0001 openssl");
        assert!(body.contains("`v1`"));
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 1, "open".to_owned())]
        );
        assert_eq!(
            fx.count("SELECT COUNT(*) FROM cve_findings WHERE github_issue_id IS NOT NULL")
                .await,
            1
        );
    }

    #[tokio::test]
    async fn high_creates_only_when_min_severity_is_high() {
        let fx = Fixture::new("high", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0003", "HIGH", 10).await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert!(fx.github.creates().is_empty());

        sqlx::query("UPDATE image_sources SET min_issue_severity = 'HIGH' WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.github.creates().len(), 1);
    }

    #[tokio::test]
    async fn open_issue_is_reused_on_next_scan() {
        let fx = Fixture::new("reuse", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        let listed_after_first = fx.github.requests();

        // A later scan of another tag reports the same CVE.
        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 20)
            .await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        assert_eq!(fx.github.creates().len(), 1);
        assert_eq!(fx.issues().await.len(), 1);
        // The second run only reads the issue's state (one GET): nothing is created or changed.
        assert_eq!(fx.github.requests(), listed_after_first + 1);
        assert_eq!(fx.github.writes().len(), 1);
        assert_eq!(
            fx.count("SELECT COUNT(*) FROM cve_findings WHERE github_issue_id IS NOT NULL")
                .await,
            2
        );
    }

    /// #185: one issue is shared by two sources on the same GitHub repository. It stays
    /// open while either reports the CVE, survives the delete of one source, and closes only
    /// when no remaining source reports it.
    #[tokio::test]
    async fn shared_issue_stays_open_while_another_source_reports_the_cve() {
        let fx = Fixture::new("shared", "CRITICAL", true).await;
        // A second source, another repository, the same GitHub repository octo/app.
        fx.source_row("m2", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.finding("m2", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        let m2 = fx.source("m2").await;
        reconcile(&fx.pool, &fx.gh, TOKEN, &m2, "ghcr.io/o/web:v1", 1_000)
            .await
            .unwrap();
        assert_eq!(fx.github.creates().len(), 1, "one shared issue");
        let number = fx.issues().await[0].1;

        // m1 no longer reports the CVE; m2 still does, so the shared issue stays open.
        fx.fix("v1", "CVE-2026-0001").await;
        sqlx::query("UPDATE cve_findings SET status = 'open' WHERE source_id = 'm2'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), number, "open".to_owned())]
        );

        // m1 is deleted through the source delete rule: the shared row survives, still open.
        let mut conn = fx.pool.acquire().await.unwrap();
        issue_db::delete_unreported_elsewhere(&mut conn, "m1", "octo", "app")
            .await
            .unwrap();
        drop(conn);
        sqlx::query("DELETE FROM image_sources WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), number, "open".to_owned())]
        );
        reconcile(&fx.pool, &fx.gh, TOKEN, &m2, "ghcr.io/o/web:v2", 1_000)
            .await
            .unwrap();
        assert_eq!(fx.issues().await[0].2, "open");

        // The last source stops reporting it: now the issue closes.
        sqlx::query("UPDATE cve_findings SET status = 'fixed' WHERE source_id = 'm2'")
            .execute(&fx.pool)
            .await
            .unwrap();
        reconcile(&fx.pool, &fx.gh, TOKEN, &m2, "ghcr.io/o/web:v3", 1_000)
            .await
            .unwrap();
        assert_eq!(fx.issues().await[0].2, "closed");
    }

    #[tokio::test]
    async fn readopts_after_source_delete_and_recreate() {
        let fx = Fixture::new("readopt", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.github.creates().len(), 1);

        // The source is deleted: its issue rows go with it, and GitHub is not changed.
        let mut conn = fx.pool.acquire().await.unwrap();
        issue_db::delete_unreported_elsewhere(&mut conn, "m1", "octo", "app")
            .await
            .unwrap();
        drop(conn);
        sqlx::query("DELETE FROM image_sources WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        assert!(fx.issues().await.is_empty());

        // A new source for the same repository, and the CVE is reported again.
        fx.source_row("m2", "CRITICAL", true).await;
        fx.finding("m2", "v1", "CVE-2026-0001", "CRITICAL", 30)
            .await;
        let source = fx.source("m2").await;
        reconcile(&fx.pool, &fx.gh, TOKEN, &source, "ghcr.io/o/app:v1", 2_000)
            .await
            .unwrap();

        assert_eq!(fx.github.creates().len(), 1, "no second issue is created");
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 1, "open".to_owned())]
        );
    }

    #[tokio::test]
    async fn created_issue_has_labels_and_the_cve_title() {
        let fx = Fixture::new("labels-high", "HIGH", true).await;
        fx.finding_pkg("m1", "v1", "CVE-2024-1", "HIGH", "openssl", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        let creates = fx.github.creates();
        assert_eq!(creates.len(), 1);
        assert_eq!(
            creates[0]["labels"],
            serde_json::json!(["dockward", "areai:security", "high"])
        );
        assert_eq!(creates[0]["title"], "CVE-2024-1 openssl");
    }

    #[tokio::test]
    async fn unknown_cve_gets_no_severity_label() {
        let fx = Fixture::new("labels-unknown", "HIGH", true).await;
        fx.finding("m1", "v1", "CVE-2024-2", "UNKNOWN", 10).await;
        let source = fx.source("m1").await;
        create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2024-2", 1_000)
            .await
            .unwrap();

        assert_eq!(
            fx.github.creates()[0]["labels"],
            serde_json::json!(["dockward", "areai:security"])
        );
    }

    #[tokio::test]
    async fn a_missing_label_is_created_and_an_existing_one_is_not_again() {
        let fx = Fixture::new("labels-ensure", "HIGH", true).await;
        fx.github.with(|state| {
            state.repo_labels = vec!["dockward".to_owned(), "high".to_owned()];
        });
        fx.finding("m1", "v1", "CVE-2024-3", "HIGH", 10).await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        let writes = fx.github.with(|state| state.log.clone());
        let label_posts: Vec<&str> = writes
            .iter()
            .filter(|(_, path, _)| path == "repos/octo/app/labels")
            .filter_map(|(_, _, body)| body["name"].as_str())
            .collect();
        // Every label is asked for once; the repository ends with each exactly once.
        assert_eq!(label_posts, vec!["dockward", "areai:security", "high"]);
        let repo_labels = fx.github.with(|state| state.repo_labels.clone());
        assert_eq!(repo_labels, vec!["dockward", "high", "areai:security"]);
        // The create comes after the labels exist.
        let create_at = writes
            .iter()
            .position(|(_, path, _)| path == "repos/octo/app/issues")
            .unwrap();
        let last_label_at = writes
            .iter()
            .rposition(|(_, path, _)| path == "repos/octo/app/labels")
            .unwrap();
        assert!(last_label_at < create_at);
    }

    #[tokio::test]
    async fn an_adopted_issue_with_the_old_title_is_renamed_and_keeps_its_marker() {
        let fx = Fixture::new("adopt-rename", "CRITICAL", true).await;
        let marker = "<!-- harborgate:CVE-2024-4 -->\n\nold body";
        fx.github.with(|state| {
            state.issues.push(test_support::Issue {
                number: 1,
                body: marker.to_owned(),
                open: true,
                title: "CVE-2024-4: openssl (CRITICAL) in ghcr.io/o/app".to_owned(),
                labels: vec!["harborgate".to_owned()],
            });
        });
        fx.finding("m1", "v1", "CVE-2024-4", "CRITICAL", 10).await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        assert!(fx.github.creates().is_empty());
        let writes = fx.github.writes();
        let rename = writes
            .iter()
            .find(|(method, path, _)| *method == "PATCH" && path == "repos/octo/app/issues/1")
            .unwrap();
        assert_eq!(rename.2, serde_json::json!({"title": "CVE-2024-4 openssl"}));
        fx.github.with(|state| {
            assert_eq!(state.issues[0].title, "CVE-2024-4 openssl");
            assert_eq!(state.issues[0].body, marker);
            assert!(
                state.issues[0]
                    .labels
                    .contains(&"areai:security".to_owned())
            );
            assert!(state.issues[0].labels.contains(&"critical".to_owned()));
        });

        // A second adoption with the right title sends no rename.
        let fx2 = Fixture::new("adopt-same", "CRITICAL", true).await;
        fx2.github.with(|state| {
            state.issues.push(test_support::Issue {
                number: 1,
                body: "<!-- dockward:CVE-2024-5 -->".to_owned(),
                open: true,
                title: "CVE-2024-5 openssl".to_owned(),
                labels: vec![
                    "dockward".to_owned(),
                    "areai:security".to_owned(),
                    "critical".to_owned(),
                ],
            });
        });
        fx2.finding("m1", "v1", "CVE-2024-5", "CRITICAL", 10).await;
        fx2.reconcile("ghcr.io/o/app:v1").await;
        assert!(fx2.github.writes().is_empty());
    }

    #[tokio::test]
    async fn the_body_contains_the_cve_description() {
        let fx = Fixture::new("body-description", "HIGH", true).await;
        fx.finding_full(
            "m1",
            "v1",
            "CVE-2024-6",
            "HIGH",
            "openssl",
            Some("Buffer overflow in the parser."),
            10,
        )
        .await;
        fx.finding_full("m1", "v1", "CVE-2024-7", "HIGH", "zlib", None, 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        let creates = fx.github.creates();
        assert_eq!(creates.len(), 2);
        let with = creates[0]["body"].as_str().unwrap();
        assert!(with.contains("Buffer overflow in the parser."));
        let without = creates[1]["body"].as_str().unwrap();
        assert!(without.contains("| Package | `zlib` |"));
        assert!(!without.contains("Description"));
    }

    /// Newest digest clean, an older tag still reports the CVE: the issue closes (#196).
    #[tokio::test]
    async fn closes_when_newest_digest_is_clean_though_an_older_tag_reports() {
        let fx = Fixture::new("newest-clean", "CRITICAL", true).await;
        fx.report("v1", "sha256:old", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.issues().await[0].2, "open");

        // A newer digest is scanned and has no row for the CVE. v1 still reports it.
        fx.report("v2", "sha256:new", 200).await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        assert_eq!(fx.issues().await[0].2, "closed");
        let writes = fx.github.writes();
        // create, comment, close.
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[2].2["state"], "closed");
        assert_eq!(
            fx.count("SELECT COUNT(*) FROM cve_findings WHERE status = 'open'")
                .await,
            1,
            "the older tag keeps its own open finding"
        );
    }

    /// The issue body lists every tracked tag that still reports the CVE, an older tag too
    /// (#196, decision 25), while the issue is created because the newest digest reports it.
    #[tokio::test]
    async fn affected_tags_lists_older_tags_that_still_report() {
        let fx = Fixture::new("affected-older", "CRITICAL", true).await;
        fx.report("v1", "sha256:old", 100).await;
        fx.report("v2", "sha256:new", 200).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 20)
            .await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        let creates = fx.github.creates();
        assert_eq!(creates.len(), 1);
        let body = creates[0]["body"].as_str().unwrap();
        assert!(body.contains("Affected tags: `v1`, `v2`"), "{body}");
    }

    /// Newest digest still reports the CVE: the issue stays open.
    #[tokio::test]
    async fn stays_open_while_the_newest_digest_reports() {
        let fx = Fixture::new("newest-reports", "CRITICAL", true).await;
        fx.report("v1", "sha256:old", 100).await;
        fx.report("v2", "sha256:new", 200).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 20)
            .await;
        fx.reconcile("ghcr.io/o/app:v2").await;
        // The older tag is scanned clean; the newest digest still reports the CVE.
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        assert_eq!(fx.issues().await[0].2, "open");
        assert_eq!(fx.github.writes().len(), 1, "only the create");
    }

    /// Newest digest clean, then it reports the CVE again: the same issue reopens.
    #[tokio::test]
    async fn reopens_the_same_issue_when_the_newest_digest_reports_again() {
        let fx = Fixture::new("newest-back", "CRITICAL", true).await;
        fx.report("v1", "sha256:old", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        fx.report("v2", "sha256:new", 200).await;
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "closed");

        // A later scan of the newest digest reports the CVE again.
        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 40)
            .await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        assert_eq!(fx.github.creates().len(), 1, "no new issue");
        let writes = fx.github.writes();
        // create, comment, close, reopen, comment.
        assert_eq!(writes.len(), 5);
        assert_eq!(writes[3].2["state"], "open");
        assert_eq!(writes[4].2["body"], "CVE is back in scan ghcr.io/o/app:v2");
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 1, "open".to_owned())]
        );
    }

    /// An issue closed by hand on GitHub while the CVE is still reported stays closed, and
    /// Dockward posts nothing.
    #[tokio::test]
    async fn a_manual_close_is_honoured_without_reopen_or_comment() {
        let fx = Fixture::new("manual-close", "CRITICAL", true).await;
        fx.report("v1", "sha256:aaa", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.github.writes().len(), 1);

        // Someone closes the issue on GitHub.
        fx.github.with(|state| state.issues[0].open = false);
        fx.reconcile("ghcr.io/o/app:v1").await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        assert_eq!(fx.issues().await[0].2, "closed");
        assert_eq!(
            fx.github.writes().len(),
            1,
            "no reopen, no comment, no close"
        );
        assert!(
            !fx.github.with(|state| state.issues[0].open),
            "the issue is still closed on GitHub"
        );

        // The CVE then leaves the newest digest: still no close comment on a closed issue.
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.github.writes().len(), 1);
    }

    /// The spec has no acceptance exception for reopening: accepting stops new issues and
    /// does not close one, but a closed issue whose CVE returns is reopened.
    #[tokio::test]
    async fn accepted_cve_with_a_closed_issue_follows_the_reopen_rule() {
        let fx = Fixture::new("accepted-closed", "CRITICAL", true).await;
        fx.report("v1", "sha256:old", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        fx.report("v2", "sha256:new", 200).await;
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "closed");
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username, expires_at)
             VALUES ('a1', 'm1', 'CVE-2026-0001', 'accepted for the test', 'u1', 'u1', NULL)",
        )
        .execute(&fx.pool)
        .await
        .unwrap();

        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 40)
            .await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        assert_eq!(fx.github.creates().len(), 1, "accepting never creates one");
        assert_eq!(fx.issues().await[0].2, "open");
    }

    /// The merged CVE found by two scanners gets one issue whose body says so, and the line is
    /// refreshed (one PATCH of the body) when the scanner set changes.
    #[tokio::test]
    async fn the_issue_body_names_the_scanner_count_and_names() {
        let fx = Fixture::new("found-by", "CRITICAL", true).await;
        fx.observe("v1", "sha256:new", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.scan_run("sha256:new", "grype", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.scan_run("sha256:new", "trivy", &[("CVE-2026-0001", "openssl")])
            .await;

        fx.reconcile("ghcr.io/o/app:v1").await;

        let created = fx.github.creates();
        assert_eq!(created.len(), 1);
        let body = created[0]["body"].as_str().unwrap();
        assert!(
            body.contains("\nFound by 2 scanners: `Grype`, `Trivy`\n"),
            "{body}"
        );
        assert!(body.starts_with("<!-- dockward:CVE-2026-0001 -->"));
        assert!(body.contains("| Image | ghcr.io/o/app |"), "{body}");

        // One scanner stops reporting: its newer run is clean, and the line is refreshed on the
        // next scan.
        fx.scan_run("sha256:new", "grype", &[]).await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        let patched = fx.github.with(|state| state.issues[0].body.clone());
        assert!(patched.contains("Found by 1 scanner: `Trivy`"), "{patched}");
        assert_eq!(patched.matches("Found by ").count(), 1);
    }

    /// d14: the issue stays open while an enabled scanner has no finished run for the newest
    /// image, and closes only when every enabled scanner has finished and none reports the CVE.
    #[tokio::test]
    async fn closes_only_when_every_enabled_scanner_runs_clean() {
        let fx = Fixture::new("d14", "CRITICAL", true).await;
        fx.observe("v1", "sha256:old", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.scan_run("sha256:old", "grype", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.scan_run("sha256:old", "trivy", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.issues().await[0].2, "open");

        // A newer image. The CVE is gone from the findings, but only Trivy has finished on it.
        fx.observe("v2", "sha256:new", 200).await;
        fx.fix("v1", "CVE-2026-0001").await;
        fx.scan_run("sha256:new", "trivy", &[]).await;
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(
            fx.issues().await[0].2,
            "open",
            "Grype has not finished on the newest image: a partial result never closes"
        );

        // Grype is clean too: the issue closes.
        fx.scan_run("sha256:new", "grype", &[]).await;
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "closed");
        let writes = fx.github.writes();
        let comment = writes
            .iter()
            .find(|(_, path, _)| path.ends_with("/comments"))
            .unwrap();
        assert_eq!(
            comment.2["body"],
            "No scanner reports this CVE since scan ghcr.io/o/app:v2."
        );
    }

    /// A scanner that is not enabled is not waited for (`scanners.enabled` of `system_config`).
    #[tokio::test]
    async fn a_disabled_scanner_is_not_waited_for() {
        let fx = Fixture::new("disabled", "CRITICAL", true).await;
        sqlx::query("INSERT INTO system_config (key, value) VALUES ('scanners.enabled', 'trivy')")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.observe("v1", "sha256:old", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.scan_run("sha256:old", "trivy", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        fx.observe("v2", "sha256:new", 200).await;
        fx.fix("v1", "CVE-2026-0001").await;
        fx.scan_run("sha256:new", "trivy", &[]).await;

        fx.reconcile("ghcr.io/o/app:v2").await;

        assert_eq!(fx.issues().await[0].2, "closed", "Grype is not enabled");
    }

    /// A platform with no finished run holds a close, and an evicted platform counts through its
    /// last `done` run (section 9).
    #[tokio::test]
    async fn every_platform_must_have_finished_before_a_close() {
        let fx = Fixture::new("platforms", "CRITICAL", true).await;
        fx.observe("v1", "sha256:old", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.scan_run("sha256:old", "grype", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.scan_run("sha256:old", "trivy", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        fx.observe("v2", "sha256:new", 200).await;
        fx.fix("v1", "CVE-2026-0001").await;
        fx.scan_run("sha256:new", "grype", &[]).await;
        fx.scan_run("sha256:new", "trivy", &[]).await;
        // A second platform of the newest image that no scanner has finished.
        sqlx::query(
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
             VALUES ('plat-arm', 'img-sha256:new', 'linux/arm64', 'sha256:arm', 'queued')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "open");

        // The platform is stored and both scanners finish on it, then it is evicted: it still
        // counts through its last done run.
        for scanner in ["grype", "trivy"] {
            let run_id = ids::new_id().unwrap();
            sqlx::query(
                "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
                 VALUES (?, 'plat-arm', ?, 'first_pull', 'done', 5000)",
            )
            .bind(run_id)
            .bind(scanner)
            .execute(&fx.pool)
            .await
            .unwrap();
        }
        sqlx::query("UPDATE image_platforms SET state = 'evicted' WHERE id = 'plat-arm'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "closed");
    }

    /// A scanner that still reports the CVE keeps the issue open even though another is clean.
    #[tokio::test]
    async fn stays_open_while_one_scanner_still_reports() {
        let fx = Fixture::new("d3", "CRITICAL", true).await;
        fx.observe("v1", "sha256:new", 100).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.scan_run("sha256:new", "grype", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.scan_run("sha256:new", "trivy", &[("CVE-2026-0001", "openssl")])
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        fx.scan_run("sha256:new", "trivy", &[]).await;
        // Findings still list the CVE because Grype reports it.
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.issues().await[0].2, "open");
        assert!(
            !fx.github
                .writes()
                .iter()
                .any(|(_, p, _)| p.ends_with("/comments")),
            "no close comment"
        );
    }

    /// Decision 49: the newest image is the observation with the latest `first_seen_at` for the
    /// tag, not the highest digest or the latest insert. A tag that moves back to an older
    /// digest makes that digest newest again.
    #[tokio::test]
    async fn the_newest_image_is_the_latest_first_seen_observation() {
        let fx = Fixture::new("newest", "CRITICAL", true).await;
        fx.report("latest", "sha256:zzz", 100).await;
        fx.report("latest", "sha256:aaa", 200).await;
        let mut conn = fx.pool.acquire().await.unwrap();
        let newest = issue_db::newest_image(&mut conn, "m1").await.unwrap();
        assert_eq!(newest.as_deref(), Some("img-sha256:aaa"));
        // The tag points back at the first digest, seen again later.
        sqlx::query(
            "UPDATE tag_observations SET first_seen_at = 300 WHERE image_id = 'img-sha256:zzz'",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        let newest = issue_db::newest_image(&mut conn, "m1").await.unwrap();
        assert_eq!(newest.as_deref(), Some("img-sha256:zzz"));
        let tags = issue_db::newest_image_tags(&mut conn, "m1").await.unwrap();
        assert_eq!(tags, Some(vec!["latest".to_owned()]));
        // The old digest no longer owns the tag.
        let old = issue_db::current_tags_of_image(&mut conn, "m1", "img-sha256:aaa")
            .await
            .unwrap();
        assert!(old.is_empty());
    }

    #[tokio::test]
    async fn closes_when_no_tag_reports() {
        let fx = Fixture::new("closes", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;

        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("ghcr.io/o/app:v2").await;

        let writes = fx.github.writes();
        // create, comment, close.
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[1].0, "POST");
        assert_eq!(writes[1].1, "repos/octo/app/issues/1/comments");
        assert_eq!(
            writes[1].2["body"],
            "No scanner reports this CVE since scan ghcr.io/o/app:v2."
        );
        assert_eq!(writes[2].0, "PATCH");
        assert_eq!(writes[2].2["state"], "closed");
        assert_eq!(fx.issues().await[0].2, "closed");
        // Running again does nothing more.
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.github.writes().len(), 3);
    }

    #[tokio::test]
    async fn reopens_when_cve_returns() {
        let fx = Fixture::new("reopens", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("ghcr.io/o/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "closed");

        // The CVE returns on a later scan of v3.
        fx.finding("m1", "v3", "CVE-2026-0001", "CRITICAL", 40)
            .await;
        fx.reconcile("ghcr.io/o/app:v3").await;

        assert_eq!(fx.github.creates().len(), 1, "the same issue is reused");
        let writes = fx.github.writes();
        // create, comment, close, reopen, comment.
        assert_eq!(writes.len(), 5);
        assert_eq!(writes[3].0, "PATCH");
        assert_eq!(writes[3].2["state"], "open");
        assert_eq!(writes[4].2["body"], "CVE is back in scan ghcr.io/o/app:v3");
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 1, "open".to_owned())]
        );
    }

    #[tokio::test]
    async fn accepted_cve_creates_no_issue() {
        let fx = Fixture::new("accepted", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username, expires_at)
             VALUES ('a1', 'm1', 'CVE-2026-0001', 'accepted for the test', 'u1', 'u1', NULL)",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert!(fx.github.creates().is_empty());
        assert!(fx.issues().await.is_empty());

        // An acceptance that has expired counts for nothing: the issue is created.
        sqlx::query("UPDATE cve_acceptances SET expires_at = 500 WHERE id = 'a1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.github.creates().len(), 1);
    }

    #[tokio::test]
    async fn auto_create_off_skips_creation_but_still_closes() {
        let fx = Fixture::new("autooff", "CRITICAL", false).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert!(fx.github.creates().is_empty());

        // An issue made by hand exists; it still follows the close rule.
        sqlx::query(
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
             VALUES ('gi1', 'octo', 'app', 'CVE-2026-0001', 7, 'https://github.com/octo/app/issues/7', 'open')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        fx.github.with(|state| {
            state.issues.push(test_support::Issue {
                number: 7,
                body: String::new(),
                open: true,
                title: String::new(),
                labels: Vec::new(),
            })
        });
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("ghcr.io/o/app:v1").await;
        assert_eq!(fx.issues().await[0].2, "closed");
    }

    #[tokio::test]
    async fn rate_limit_stops_the_run_and_is_returned() {
        let fx = Fixture::new("limited", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.finding("m1", "v1", "CVE-2026-0002", "CRITICAL", 10)
            .await;
        fx.github.with(|state| state.rate_limited = true);

        let outcome = fx.reconcile("ghcr.io/o/app:v1").await;

        assert_eq!(outcome, Outcome::RateLimited { until: 5_000 });
        // The run stopped at the first call.
        assert_eq!(fx.github.requests(), 1);
        assert!(fx.issues().await.is_empty());
    }

    #[tokio::test]
    async fn concurrent_reconciles_create_one_issue_and_no_error() {
        let fx = Fixture::new("race-sync", "CRITICAL", true).await;
        fx.github.with(|state| state.rendezvous = true);
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        let source = fx.source("m1").await;

        let (a, b) = tokio::join!(
            reconcile(&fx.pool, &fx.gh, TOKEN, &source, "ghcr.io/o/app:v1", 1_000),
            reconcile(&fx.pool, &fx.gh, TOKEN, &source, "ghcr.io/o/app:v1", 1_000),
        );

        assert_eq!(a.unwrap(), Outcome::Complete);
        assert_eq!(b.unwrap(), Outcome::Complete);
        assert_eq!(fx.github.creates().len(), 1, "exactly one GitHub issue");
        assert_eq!(fx.issues().await.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_manual_creates_make_one_issue_and_never_a_500() {
        let fx = Fixture::new("race-manual", "CRITICAL", true).await;
        fx.github.with(|state| state.rendezvous = true);
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        let source = fx.source("m1").await;

        let (a, b) = tokio::join!(
            create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0001", 1_000),
            create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0001", 1_000),
        );

        // One call creates the issue; the other sees it and gets the `409`.
        let results = [a, b];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let statuses: Vec<_> = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .map(AppError::status)
            .collect();
        assert_eq!(statuses, vec![axum::http::StatusCode::CONFLICT]);
        assert_eq!(fx.github.creates().len(), 1, "exactly one GitHub issue");
    }

    #[tokio::test]
    async fn manual_and_sync_racing_make_one_issue() {
        let fx = Fixture::new("race-mixed", "CRITICAL", true).await;
        fx.github.with(|state| state.rendezvous = true);
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        let source = fx.source("m1").await;

        let (synced, manual) = tokio::join!(
            reconcile(&fx.pool, &fx.gh, TOKEN, &source, "ghcr.io/o/app:v1", 1_000),
            create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0001", 1_000),
        );

        assert_eq!(synced.unwrap(), Outcome::Complete);
        if let Err(error) = manual {
            assert_eq!(error.status(), axum::http::StatusCode::CONFLICT);
        }
        assert_eq!(fx.github.creates().len(), 1, "exactly one GitHub issue");
        assert_eq!(fx.issues().await.len(), 1);
    }

    /// An `IssueApi` that stores a row for the CVE just before it creates the issue, as a
    /// second process would. The insert after the create then hits the UNIQUE constraint.
    struct Racing {
        inner: FakeIssues,
        pool: SqlitePool,
    }

    impl IssueApi for Racing {
        async fn list_open_with_label(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            label: &str,
            now: i64,
        ) -> Result<Vec<IssueRef>, ScanError> {
            self.inner
                .list_open_with_label(token, owner, repo, label, now)
                .await
        }

        async fn rename_label(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            from: &str,
            to: &str,
            now: i64,
        ) -> Result<LabelRename, ScanError> {
            self.inner
                .rename_label(token, owner, repo, from, to, now)
                .await
        }

        async fn create(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            title: &str,
            body: &str,
            labels: &[&str],
            now: i64,
        ) -> Result<IssueRef, ScanError> {
            sqlx::query(
                "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
                 VALUES ('other', 'octo', 'app', 'CVE-2026-0001', 99, 'https://github.com/octo/app/issues/99', 'open')",
            )
            .execute(&self.pool)
            .await
            .map_err(|_| ScanError::Upstream("test setup failed".to_owned()))?;
            self.inner
                .create(token, owner, repo, title, body, labels, now)
                .await
        }

        async fn ensure_labels(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            labels: &[&str],
            now: i64,
        ) -> Result<(), ScanError> {
            self.inner
                .ensure_labels(token, owner, repo, labels, now)
                .await
        }

        async fn add_labels(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            labels: &[&str],
            now: i64,
        ) -> Result<(), ScanError> {
            self.inner
                .add_labels(token, owner, repo, number, labels, now)
                .await
        }

        async fn retitle(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            title: &str,
            now: i64,
        ) -> Result<(), ScanError> {
            self.inner
                .retitle(token, owner, repo, number, title, now)
                .await
        }

        async fn comment(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            body: &str,
            now: i64,
        ) -> Result<(), ScanError> {
            self.inner
                .comment(token, owner, repo, number, body, now)
                .await
        }

        async fn set_state(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            open: bool,
            now: i64,
        ) -> Result<(), ScanError> {
            self.inner
                .set_state(token, owner, repo, number, open, now)
                .await
        }

        async fn is_open(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            now: i64,
        ) -> Result<bool, ScanError> {
            self.inner.is_open(token, owner, repo, number, now).await
        }

        async fn body(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            now: i64,
        ) -> Result<String, ScanError> {
            self.inner.body(token, owner, repo, number, now).await
        }

        async fn set_body(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            number: u64,
            body: &str,
            now: i64,
        ) -> Result<(), ScanError> {
            self.inner
                .set_body(token, owner, repo, number, body, now)
                .await
        }
    }

    #[tokio::test]
    async fn a_unique_conflict_on_insert_keeps_the_winner_and_is_not_an_error() {
        let fx = Fixture::new("unique", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        let source = fx.source("m1").await;
        let gh = Racing {
            inner: FakeIssues(fx.github.clone()),
            pool: fx.pool.clone(),
        };

        let outcome = reconcile(&fx.pool, &gh, TOKEN, &source, "ghcr.io/o/app:v1", 1_000).await;

        assert_eq!(outcome.unwrap(), Outcome::Complete);
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 99, "open".to_owned())]
        );
        let manual = create_manual(&fx.pool, &gh, TOKEN, &source, "CVE-2026-0001", 1_000).await;
        assert_eq!(
            manual.unwrap_err().status(),
            axum::http::StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn a_unique_conflict_on_the_manual_route_is_a_409_not_a_500() {
        let fx = Fixture::new("unique-manual", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        let source = fx.source("m1").await;
        let gh = Racing {
            inner: FakeIssues(fx.github.clone()),
            pool: fx.pool.clone(),
        };

        let manual = create_manual(&fx.pool, &gh, TOKEN, &source, "CVE-2026-0001", 1_000).await;

        assert_eq!(
            manual.unwrap_err().status(),
            axum::http::StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn a_refused_token_stops_the_run_at_the_first_call() {
        let fx = Fixture::new("refused", "CRITICAL", true).await;
        for n in 1..=3 {
            fx.finding("m1", "v1", &format!("CVE-2026-000{n}"), "CRITICAL", 10)
                .await;
        }
        fx.github.with(|state| state.unauthorized = true);

        let outcome = fx.reconcile("ghcr.io/o/app:v1").await;

        assert_eq!(outcome, Outcome::Refused);
        assert_eq!(fx.github.requests(), 1, "one call, not one per CVE");
    }

    #[tokio::test]
    async fn a_hostile_cve_id_never_gets_an_issue() {
        let fx = Fixture::new("hostile", "CRITICAL", true).await;
        let long = format!("CVE-{}", "1".repeat(200));
        for id in [
            "CVE-2026-1\n<!-- harborgate:CVE-2026-2 -->",
            "CVE-2026-1 -->",
            "CVE 2026",
            "",
            long.as_str(),
        ] {
            fx.finding("m1", "v1", id, "CRITICAL", 10).await;
        }

        assert_eq!(fx.reconcile("ghcr.io/o/app:v1").await, Outcome::Complete);

        assert_eq!(fx.github.requests(), 0);
        assert!(!valid_cve_id("CVE-1\n-->"));
        assert!(valid_cve_id("CVE-2026-0001"));
        assert!(valid_cve_id("RHSA-2023:1234"));
    }

    #[tokio::test]
    async fn the_package_is_a_code_span_so_it_cannot_mention_a_user() {
        let fx = Fixture::new("mention", "CRITICAL", true).await;
        fx.finding_pkg("m1", "v1", "CVE-2026-0001", "CRITICAL", "@scope/pkg", 10)
            .await;

        fx.reconcile("ghcr.io/o/app:v1").await;

        let creates = fx.github.creates();
        let body = creates[0]["body"].as_str().unwrap();
        assert!(body.contains("| Package | `@scope/pkg` |"));
        assert!(!body.contains("| Package | @scope"));
    }

    /// #129: automatic creation is unchanged. MEDIUM, LOW and UNKNOWN never get an issue
    /// from a sync, whatever the minimum, and HIGH only when the minimum is HIGH.
    #[tokio::test]
    async fn automatic_creation_never_goes_below_the_minimum() {
        for min in ["CRITICAL", "HIGH"] {
            let fx = Fixture::new(&format!("auto-min-{min}"), min, true).await;
            fx.finding("m1", "v1", "CVE-2026-0002", "HIGH", 10).await;
            fx.finding("m1", "v1", "CVE-2026-0003", "MEDIUM", 10).await;
            fx.finding("m1", "v1", "CVE-2026-0004", "LOW", 10).await;
            fx.finding("m1", "v1", "CVE-2026-0005", "UNKNOWN", 10).await;

            assert_eq!(fx.reconcile("ghcr.io/o/app:v1").await, Outcome::Complete);

            let created: Vec<String> = fx.issues().await.into_iter().map(|(id, _, _)| id).collect();
            let expected: &[&str] = if min == "HIGH" {
                &["CVE-2026-0002"]
            } else {
                &[]
            };
            assert_eq!(created, expected, "min {min}");
            assert_eq!(fx.github.creates().len(), expected.len(), "min {min}");
        }
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "BOGUS"] {
            assert_eq!(
                meets_minimum(severity, Some("HIGH")),
                matches!(severity, "CRITICAL" | "HIGH"),
                "{severity}"
            );
            assert_eq!(
                meets_minimum(severity, Some("CRITICAL")),
                severity == "CRITICAL",
                "{severity}"
            );
            assert_eq!(meets_minimum(severity, None), severity == "CRITICAL");
        }
    }

    /// A manual LOW issue does not make the next sync create issues for other LOW CVEs, and
    /// the sync keeps the manual issue open while the CVE is reported.
    #[tokio::test]
    async fn manual_low_issue_is_kept_by_sync_and_others_stay_without() {
        let fx = Fixture::new("manual-low-sync", "HIGH", true).await;
        fx.finding("m1", "v1", "CVE-2026-0004", "LOW", 10).await;
        fx.finding("m1", "v1", "CVE-2026-0005", "LOW", 10).await;
        let source = fx.source("m1").await;

        let made = create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0004", 1_000)
            .await
            .unwrap();
        assert_eq!(made.number, 1);
        assert_eq!(fx.github.creates()[0]["title"], "CVE-2026-0004 openssl");
        fx.reconcile("ghcr.io/o/app:v1").await;

        assert_eq!(
            fx.github.creates().len(),
            1,
            "the other LOW CVE gets no issue"
        );
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0004".to_owned(), 1, "open".to_owned())]
        );
    }

    /// The manual route at UNKNOWN severity: an active acceptance is 409, a closed issue is
    /// reopened (never a second one), and an open issue is 409 with its URL.
    #[tokio::test]
    async fn manual_unknown_follows_the_acceptance_reopen_and_open_rules() {
        let fx = Fixture::new("manual-unknown", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0005", "UNKNOWN", 10).await;
        let source = fx.source("m1").await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username)
             VALUES ('a1', 'm1', 'CVE-2026-0005', 'accepted for the test', 'u1', 'u1')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();

        let refused = create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0005", 1_000)
            .await
            .unwrap_err();
        assert_eq!(refused.status(), axum::http::StatusCode::CONFLICT);
        assert_eq!(fx.github.requests(), 0);

        sqlx::query("UPDATE cve_acceptances SET revoked_at = 5, revoked_by = 'u1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        let first = create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0005", 1_000)
            .await
            .unwrap();

        // The issue is closed on GitHub and in the row; the manual route reopens it.
        sqlx::query("UPDATE github_issues SET status = 'closed'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.github.with(|state| state.issues[0].open = false);
        let reopened = create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0005", 1_000)
            .await
            .unwrap();
        assert_eq!(reopened, first);
        assert_eq!(fx.github.creates().len(), 1, "no second issue");
        let writes = fx.github.writes();
        assert_eq!(writes.last().unwrap().2["body"], MANUAL_REOPEN_COMMENT);

        let open = create_manual(&fx.pool, &fx.gh, TOKEN, &source, "CVE-2026-0005", 1_000)
            .await
            .unwrap_err();
        assert_eq!(open.status(), axum::http::StatusCode::CONFLICT);
        assert!(open.message().contains(&first.url));
    }

    /// The issue text uses the highest open severity over all five values.
    #[test]
    fn summarize_takes_the_highest_of_all_five_severities() {
        let row = |tag: &str, severity: &str, status: &str, at: i64| FindingRow {
            cve_id: "CVE-1".to_owned(),
            image_tag: tag.to_owned(),
            package: None,
            severity: severity.to_owned(),
            fixed_in_version: None,
            status: status.to_owned(),
            last_seen_at: Some(at),
            description: None,
        };
        for (rows, expected) in [
            (
                vec![row("a", "UNKNOWN", "open", 9), row("b", "LOW", "open", 1)],
                "LOW",
            ),
            (
                vec![row("a", "LOW", "open", 9), row("b", "MEDIUM", "open", 1)],
                "MEDIUM",
            ),
            (
                vec![row("a", "MEDIUM", "open", 9), row("b", "HIGH", "open", 1)],
                "HIGH",
            ),
            (
                vec![row("a", "HIGH", "open", 1), row("b", "CRITICAL", "open", 9)],
                "CRITICAL",
            ),
            (vec![row("a", "UNKNOWN", "open", 1)], "UNKNOWN"),
            // A fixed CRITICAL row does not count.
            (
                vec![row("a", "CRITICAL", "fixed", 9), row("b", "LOW", "open", 1)],
                "LOW",
            ),
        ] {
            assert_eq!(summarize("CVE-1", &rows).unwrap().severity, expected);
        }
        assert!(summarize("CVE-1", &[row("a", "HIGH", "fixed", 1)]).is_none());
    }

    #[test]
    fn route_ids_with_empty_parts_or_odd_characters_are_not_found() {
        let long = "a".repeat(129);
        let long_source = format!("{long}:CVE-2026-0001");
        let long_cve = format!("m1:{long}");
        for id in [
            "",
            ":",
            "m1:",
            ":CVE-2026-0001",
            "no-colon",
            "m1:CVE 2026",
            "m 1:CVE-2026-0001",
            "m1:CVE-1\n-->",
            long_source.as_str(),
            long_cve.as_str(),
        ] {
            assert_eq!(split_id(id).unwrap_err(), AppError::NotFound, "id {id:?}");
        }
        assert_eq!(
            split_id("m1:CVE-2026-0001").unwrap(),
            ("m1", "CVE-2026-0001")
        );
        assert_eq!(
            split_id("m1:RHSA-2023:1234").unwrap(),
            ("m1", "RHSA-2023:1234")
        );
    }
}
