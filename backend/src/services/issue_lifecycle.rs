//! The GitHub issue lifecycle (`specs/cve-lifecycle.md`, "GitHub issue rules"; defaults in
//! `specs/integrations.md`, "GitHub issues").
//!
//! After each applied scan, [`reconcile`] makes the GitHub issues of one mapping follow its
//! `cve_findings`: create or adopt an issue for an eligible CVE, reuse it while it is open,
//! close it with a comment when no tracked tag reports the CVE, and reopen it when the CVE
//! returns. [`create_manual`] is the same create-or-adopt step for the manual route.
//!
//! The token is only passed on to the GitHub client. Nothing here logs it, an error value,
//! or a response body: every log line and error message is fixed text.

use std::collections::BTreeMap;
use std::future::Future;

use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::credentials as credential_db;
use crate::db::github_issues::{self as issue_db, FindingRow, IssueRow, NewIssue};
use crate::db::mappings::{self as mapping_db, MappingRow};
use crate::error::AppError;
use crate::services::credentials::decrypt_token;
use crate::services::github_issues::{self, GithubIssues, IssueRef};
use crate::services::github_scanning::ScanError;
use crate::services::ids;

/// The longest issue title GitHub takes, in characters. GitHub's own validation answer is
/// `title is too long (maximum is 256 characters)`; the REST page for creating an issue
/// (https://docs.github.com/rest/issues/issues#create-an-issue) does not state the limit.
const MAX_TITLE_CHARS: usize = 256;

/// The package text when a row has none, in the title and in the table.
const UNKNOWN_PACKAGE: &str = "unknown package";

/// The comment when the manual route reopens a closed issue.
const MANUAL_REOPEN_COMMENT: &str = "CVE reopened manually from HarborGate.";

/// The longest CVE id or mapping id the manual route and the lifecycle accept, in bytes.
const MAX_ID_BYTES: usize = 128;

/// Serialises "look for a row, look for a marked issue, create an issue, store the row".
/// HarborGate runs as one instance (`specs/architecture.md`), so one process-wide lock is
/// enough to stop a sync and a manual click from both creating the issue for one CVE.
static CREATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The GitHub Issues calls the lifecycle needs. The production impl is [`GithubIssues`];
/// tests answer from a model of GitHub.
pub trait IssueApi: Send + Sync + 'static {
    fn list_open_labelled(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        now: i64,
    ) -> impl Future<Output = Result<Vec<IssueRef>, ScanError>> + Send;

    fn create(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        now: i64,
    ) -> impl Future<Output = Result<IssueRef, ScanError>> + Send;

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
}

impl IssueApi for GithubIssues {
    async fn list_open_labelled(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        now: i64,
    ) -> Result<Vec<IssueRef>, ScanError> {
        GithubIssues::list_open_labelled(self, token, owner, repo, now).await
    }

    async fn create(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        now: i64,
    ) -> Result<IssueRef, ScanError> {
        GithubIssues::create(self, token, owner, repo, title, body, now).await
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

/// True when `severity` reaches the mapping's `min_issue_severity`. Used by the automatic
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
    /// Every tag where the CVE is open.
    tags: Vec<String>,
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
    })
}

/// Text kept on one line: no line break, no backtick.
fn plain(text: &str) -> String {
    text.replace(['\r', '\n', '`'], " ").trim().to_owned()
}

/// `<CVE-ID>: <package> (<SEVERITY>) in <harbor_project>/<harbor_repository>`.
fn issue_title(view: &CveView, mapping: &MappingRow) -> String {
    let package = view
        .package
        .as_deref()
        .map(plain)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| UNKNOWN_PACKAGE.to_owned());
    let title = format!(
        "{}: {} ({}) in {}/{}",
        plain(&view.cve_id),
        package,
        view.severity,
        mapping.harbor_project,
        mapping.harbor_repository
    );
    title.chars().take(MAX_TITLE_CHARS).collect()
}

/// The marker line, the table from [`github_issues::issue_body`], and the affected tags.
fn issue_text(view: &CveView, mapping: &MappingRow) -> String {
    let harbor = format!("{}/{}", mapping.harbor_project, mapping.harbor_repository);
    let mut body = github_issues::issue_body(
        &view.cve_id,
        view.severity,
        &code_span(view.package.as_deref().unwrap_or(UNKNOWN_PACKAGE)),
        view.fixed_in.as_deref(),
        &harbor,
    );
    let tags: Vec<String> = view
        .tags
        .iter()
        .map(|tag| format!("`{}`", plain(tag)))
        .collect();
    body.push_str(&format!("\nAffected tags: {}\n", tags.join(", ")));
    body
}

/// True for an id that is safe in the marker line and the route: 1 to 128 bytes of ASCII
/// letters, digits, `.`, `_`, `-` and `:` (a CVE id may be `RHSA-2023:1234`). A Harbor-supplied
/// id with a line break or `-->` fails, so it cannot break the first-line marker. Findings
/// with such an id never get an issue.
fn valid_cve_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn valid_mapping_id(id: &str) -> bool {
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

/// What every GitHub step needs: the database, the client, the token, the mapping and the
/// time. The token is only passed on to the client.
struct Ctx<'a, G> {
    pool: &'a SqlitePool,
    gh: &'a G,
    token: &'a [u8],
    mapping: &'a MappingRow,
    now: i64,
}

impl<G: IssueApi> Ctx<'_, G> {
    fn owner(&self) -> &str {
        &self.mapping.github_owner
    }

    fn repo(&self) -> &str {
        &self.mapping.github_repo
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
            *listed = Some(
                self.gh
                    .list_open_labelled(self.token, self.owner(), self.repo(), self.now)
                    .await?,
            );
        }
        let adopted = listed
            .as_deref()
            .and_then(|issues| github_issues::find_marked(issues, &view.cve_id))
            .cloned();
        let issue = match adopted {
            Some(issue) => issue,
            None => {
                self.gh
                    .create(
                        self.token,
                        self.owner(),
                        self.repo(),
                        &issue_title(view, self.mapping),
                        &issue_text(view, self.mapping),
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
        issue_db::link_findings(&mut conn, &self.mapping.id, &view.cve_id, &id).await?;
        Ok(Made::Created(IssueRow {
            id,
            github_owner: self.owner().to_owned(),
            github_repo: self.repo().to_owned(),
            cve_id: view.cve_id.clone(),
            github_issue_number: number,
            github_issue_url: issue.html_url,
            status: "open".to_owned(),
        }))
    }

    async fn find_row(&self, cve_id: &str) -> Result<Option<IssueRow>, AppError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        issue_db::find(&mut conn, self.owner(), self.repo(), cve_id).await
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

    /// Applies the issue rules to one CVE of the mapping, given its rows.
    async fn step(
        &self,
        cve_id: &str,
        rows: &[FindingRow],
        rules: &Rules<'_>,
        listed: &mut Option<Vec<IssueRef>>,
    ) -> Result<(), Failure> {
        let view = summarize(cve_id, rows);
        let existing = {
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(|_| AppError::InternalError)?;
            let row = issue_db::find(&mut conn, self.owner(), self.repo(), cve_id).await?;
            if let Some(row) = &row {
                issue_db::link_findings(&mut conn, &self.mapping.id, cve_id, &row.id).await?;
            }
            row
        };
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
            // (b) The CVE is back: reopen the same issue.
            (Some(row), Some(_)) if row.status == "closed" => {
                let comment = format!("CVE is back in scan {}", rules.scan_label);
                self.reopen(&row, &comment).await?;
            }
            // (c) No tracked tag reports it any more: comment, then close.
            (Some(row), None) if row.status == "open" => {
                let comment = format!(
                    "No tracked tag reports this CVE since scan {}.",
                    rules.scan_label
                );
                self.close(&row, &comment).await?;
            }
            // (d) Nothing to do.
            _ => {}
        }
        Ok(())
    }
}

/// The mapping's rule inputs for one reconcile run.
struct Rules<'a> {
    auto_create: bool,
    min_issue_severity: Option<&'a str>,
    scan_label: &'a str,
    /// CVE ids with an active acceptance.
    accepted: Vec<String>,
}

/// Makes the GitHub issues of `mapping` follow its findings. `scan_label` names the scan in
/// the comments. A rate limit stops the run and is returned in [`Outcome`]. Any other GitHub
/// error is logged as fixed text and the next CVE continues. A database error is returned.
pub async fn reconcile<G: IssueApi>(
    pool: &SqlitePool,
    gh: &G,
    token: &[u8],
    mapping: &MappingRow,
    scan_label: &str,
    now: i64,
) -> Result<Outcome, AppError> {
    let (rows, accepted) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        (
            issue_db::findings_for_mapping(&mut conn, &mapping.id).await?,
            issue_db::accepted_cves(&mut conn, &mapping.id, now).await?,
        )
    };
    let mut by_cve: BTreeMap<String, Vec<FindingRow>> = BTreeMap::new();
    for row in rows {
        by_cve.entry(row.cve_id.clone()).or_default().push(row);
    }
    let rules = Rules {
        auto_create: mapping.auto_create_issues.unwrap_or(false),
        min_issue_severity: mapping.min_issue_severity.as_deref(),
        scan_label,
        accepted,
    };
    let ctx = Ctx {
        pool,
        gh,
        token,
        mapping,
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
/// mapping the caller owns.
///
/// - `404` when the mapping has no finding for the CVE.
/// - `409` (with the URL) when its issue is open, and `409` while an active acceptance exists.
/// - `422` when no tracked tag reports the CVE as open. Any open severity is allowed, LOW
///   and UNKNOWN included (#129); the confirmation for those is a frontend step. The
///   mapping's `min_issue_severity` and `auto_create_issues` do not apply: the manual action
///   overrides them.
/// - A closed issue is reopened, never duplicated. Otherwise an open labelled issue with the
///   marker is adopted, or a new one is created.
/// - A GitHub failure is `502`.
pub async fn create_manual<G: IssueApi>(
    pool: &SqlitePool,
    gh: &G,
    token: &[u8],
    mapping: &MappingRow,
    cve_id: &str,
    now: i64,
) -> Result<ManualIssue, AppError> {
    let (rows, existing, accepted) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        (
            issue_db::findings_for_cve(&mut conn, &mapping.id, cve_id).await?,
            issue_db::find(
                &mut conn,
                &mapping.github_owner,
                &mapping.github_repo,
                cve_id,
            )
            .await?,
            issue_db::accepted_cves(&mut conn, &mapping.id, now).await?,
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
        mapping,
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

/// Splits the route id `<mapping_id>:<cve_id>`. An id in any other shape, an empty part, a
/// part over 128 bytes, or a character outside the allowed set is `404`, before any database
/// call.
fn split_id(id: &str) -> Result<(&str, &str), AppError> {
    match id.split_once(':') {
        Some((mapping_id, cve_id)) if valid_mapping_id(mapping_id) && valid_cve_id(cve_id) => {
            Ok((mapping_id, cve_id))
        }
        _ => Err(AppError::NotFound),
    }
}

/// `POST /api/v1/cves/:id/issue` for `user_id`: finds the mapping the caller owns (another
/// tenant's mapping is `404`), decrypts the GitHub token of its credential, and calls
/// [`create_manual`].
pub async fn create_manual_for_user<G: IssueApi>(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    gh: &G,
    user_id: &str,
    id: &str,
    now: i64,
) -> Result<ManualIssue, AppError> {
    let (mapping_id, cve_id) = split_id(id)?;
    let (mapping, credential) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        let mapping = mapping_db::find_owned(&mut conn, user_id, mapping_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let credential = credential_db::find_owned(&mut conn, user_id, &mapping.github_cred_id)
            .await?
            .ok_or(AppError::NotFound)?;
        (mapping, credential)
    };
    let token = decrypt_token(credentials_key, &credential)?;
    create_manual(pool, gh, &token, &mapping, cve_id, now).await
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
    }

    #[derive(Default)]
    pub struct State {
        pub issues: Vec<Issue>,
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

        /// `(method, path, body)` of every request that is not a list.
        pub fn writes(&self) -> Vec<(&'static str, String, Value)> {
            self.with(|state| {
                state
                    .log
                    .iter()
                    .filter(|(method, _, _)| *method != "GET")
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
                    })
                };
                match (method, path) {
                    ("GET", _) => {
                        let items: Vec<Value> = state
                            .issues
                            .iter()
                            .filter(|issue| issue.open)
                            .map(issue_json)
                            .collect();
                        Ok(reply(200, Value::Array(items)))
                    }
                    ("POST", "repos/octo/app/issues") => {
                        let number = state.issues.len() as u64 + 1;
                        let text = body
                            .get("body")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        state.issues.push(Issue {
                            number,
                            body: text,
                            open: true,
                        });
                        let created = state.issues.last().map(issue_json).unwrap_or(Value::Null);
                        Ok(reply(201, created))
                    }
                    ("POST", _) => Ok(reply(201, json!({}))),
                    (_, _) => {
                        let number: Option<u64> =
                            path.rsplit('/').next().and_then(|last| last.parse().ok());
                        let open = body.get("state").and_then(Value::as_str) == Some("open");
                        if let Some(issue) = state
                            .issues
                            .iter_mut()
                            .find(|issue| Some(issue.number) == number)
                        {
                            issue.open = open;
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
        async fn list_open_labelled(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            now: i64,
        ) -> Result<Vec<IssueRef>, ScanError> {
            github_issues::list_open_labelled_with(&*self.0, token, owner, repo, now).await
        }

        async fn create(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            title: &str,
            body: &str,
            now: i64,
        ) -> Result<IssueRef, ScanError> {
            github_issues::create_with(&*self.0, token, owner, repo, title, body, now).await
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
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::test_support::{FakeGithub, FakeIssues};
    use super::*;
    use crate::db;
    use crate::db::mappings as mapping_db;

    const TOKEN: &[u8] = b"fake-token-value";

    struct Fixture {
        pool: SqlitePool,
        dir: std::path::PathBuf,
        github: Arc<FakeGithub>,
        gh: FakeIssues,
    }

    impl Fixture {
        async fn new(name: &str, min: &str, auto: bool) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "harborgate-lifecycle-{name}-{}",
                std::process::id()
            ));
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
            let github = Arc::new(FakeGithub::default());
            let fixture = Self {
                pool,
                dir,
                github: github.clone(),
                gh: FakeIssues(github),
            };
            fixture.mapping_row("m1", min, auto).await;
            fixture
        }

        async fn mapping_row(&self, id: &str, min: &str, auto: bool) {
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity)
                 VALUES (?, 'u1', 'c1', 'c2', 'https://harbor.example.com', 'proj', 'app', 'octo', 'app', ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(format!("hash-token-{id}"))
            .bind(format!("hash-secret-{id}"))
            .bind(auto)
            .bind(min)
            .execute(&self.pool)
            .await
            .unwrap();
        }

        async fn mapping(&self, id: &str) -> MappingRow {
            let mut conn = self.pool.acquire().await.unwrap();
            mapping_db::find_by_id(&mut conn, id)
                .await
                .unwrap()
                .unwrap()
        }

        /// Stores a finding for `tag` as an `open` row seen at `at`.
        async fn finding(&self, mapping_id: &str, tag: &str, cve: &str, severity: &str, at: i64) {
            self.finding_pkg(mapping_id, tag, cve, severity, "openssl", at)
                .await;
        }

        async fn finding_pkg(
            &self,
            mapping_id: &str,
            tag: &str,
            cve: &str,
            severity: &str,
            package: &str,
            at: i64,
        ) {
            let mut conn = self.pool.acquire().await.unwrap();
            db::findings::upsert(
                &mut conn,
                &db::findings::Finding {
                    id: &ids::new_id().unwrap_or_default(),
                    mapping_id,
                    harbor_repository: "app",
                    image_tag: tag,
                    cve_id: cve,
                    package: Some(package),
                    severity,
                    fixed_in_version: None,
                    description: None,
                    now: at,
                },
            )
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

        async fn reconcile(&self, label: &str) -> Outcome {
            let mapping = self.mapping("m1").await;
            reconcile(&self.pool, &self.gh, TOKEN, &mapping, label, 1_000)
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

        assert_eq!(fx.reconcile("proj/app:v1").await, Outcome::Complete);

        let creates = fx.github.creates();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0]["labels"], serde_json::json!(["harborgate"]));
        let body = creates[0]["body"].as_str().unwrap();
        assert_eq!(
            body.lines().next(),
            Some("<!-- harborgate:CVE-2026-0001 -->")
        );
        assert_eq!(
            creates[0]["title"],
            "CVE-2026-0001: openssl (CRITICAL) in proj/app"
        );
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
        fx.reconcile("proj/app:v1").await;
        assert!(fx.github.creates().is_empty());

        sqlx::query("UPDATE repo_mappings SET min_issue_severity = 'HIGH' WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.reconcile("proj/app:v1").await;
        assert_eq!(fx.github.creates().len(), 1);
    }

    #[tokio::test]
    async fn open_issue_is_reused_on_next_scan() {
        let fx = Fixture::new("reuse", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("proj/app:v1").await;
        let listed_after_first = fx.github.requests();

        // A later scan of another tag reports the same CVE.
        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 20)
            .await;
        fx.reconcile("proj/app:v2").await;

        assert_eq!(fx.github.creates().len(), 1);
        assert_eq!(fx.issues().await.len(), 1);
        // The second run needs no GitHub call at all: the row exists and nothing changed.
        assert_eq!(fx.github.requests(), listed_after_first);
        assert_eq!(
            fx.count("SELECT COUNT(*) FROM cve_findings WHERE github_issue_id IS NOT NULL")
                .await,
            2
        );
    }

    #[tokio::test]
    async fn readopts_after_mapping_delete_and_recreate() {
        let fx = Fixture::new("readopt", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("proj/app:v1").await;
        assert_eq!(fx.github.creates().len(), 1);

        // The mapping is deleted: its issue rows go with it, and GitHub is not changed.
        let mut conn = fx.pool.acquire().await.unwrap();
        mapping_db::delete_github_issues(&mut conn, "octo", "app")
            .await
            .unwrap();
        drop(conn);
        sqlx::query("DELETE FROM repo_mappings WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        assert!(fx.issues().await.is_empty());

        // A new mapping for the same repository, and the CVE is reported again.
        fx.mapping_row("m2", "CRITICAL", true).await;
        fx.finding("m2", "v1", "CVE-2026-0001", "CRITICAL", 30)
            .await;
        let mapping = fx.mapping("m2").await;
        reconcile(&fx.pool, &fx.gh, TOKEN, &mapping, "proj/app:v1", 2_000)
            .await
            .unwrap();

        assert_eq!(fx.github.creates().len(), 1, "no second issue is created");
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 1, "open".to_owned())]
        );
    }

    #[tokio::test]
    async fn stays_open_while_another_tag_reports() {
        let fx = Fixture::new("stays", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.finding("m1", "v2", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("proj/app:v2").await;

        // v1 is scanned clean, v2 still reports the CVE.
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("proj/app:v1").await;

        assert_eq!(fx.issues().await[0].2, "open");
        // The only write is the create: no comment and no close.
        assert_eq!(fx.github.writes().len(), 1);
        assert_eq!(fx.github.creates().len(), 1);
    }

    #[tokio::test]
    async fn closes_when_no_tag_reports() {
        let fx = Fixture::new("closes", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("proj/app:v1").await;

        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("proj/app:v2").await;

        let writes = fx.github.writes();
        // create, comment, close.
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[1].0, "POST");
        assert_eq!(writes[1].1, "repos/octo/app/issues/1/comments");
        assert_eq!(
            writes[1].2["body"],
            "No tracked tag reports this CVE since scan proj/app:v2."
        );
        assert_eq!(writes[2].0, "PATCH");
        assert_eq!(writes[2].2["state"], "closed");
        assert_eq!(fx.issues().await[0].2, "closed");
        // Running again does nothing more.
        fx.reconcile("proj/app:v2").await;
        assert_eq!(fx.github.writes().len(), 3);
    }

    #[tokio::test]
    async fn reopens_when_cve_returns() {
        let fx = Fixture::new("reopens", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("proj/app:v1").await;
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("proj/app:v2").await;
        assert_eq!(fx.issues().await[0].2, "closed");

        // The CVE returns on a later scan of v3.
        fx.finding("m1", "v3", "CVE-2026-0001", "CRITICAL", 40)
            .await;
        fx.reconcile("proj/app:v3").await;

        assert_eq!(fx.github.creates().len(), 1, "the same issue is reused");
        let writes = fx.github.writes();
        // create, comment, close, reopen, comment.
        assert_eq!(writes.len(), 5);
        assert_eq!(writes[3].0, "PATCH");
        assert_eq!(writes[3].2["state"], "open");
        assert_eq!(writes[4].2["body"], "CVE is back in scan proj/app:v3");
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
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by, created_by_username, expires_at)
             VALUES ('a1', 'm1', 'CVE-2026-0001', 'accepted for the test', 'u1', 'u1', NULL)",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        fx.reconcile("proj/app:v1").await;
        assert!(fx.github.creates().is_empty());
        assert!(fx.issues().await.is_empty());

        // An acceptance that has expired counts for nothing: the issue is created.
        sqlx::query("UPDATE cve_acceptances SET expires_at = 500 WHERE id = 'a1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.reconcile("proj/app:v1").await;
        assert_eq!(fx.github.creates().len(), 1);
    }

    #[tokio::test]
    async fn auto_create_off_skips_creation_but_still_closes() {
        let fx = Fixture::new("autooff", "CRITICAL", false).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        fx.reconcile("proj/app:v1").await;
        assert!(fx.github.creates().is_empty());

        // An issue made by hand exists; it still follows the close rule.
        sqlx::query(
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
             VALUES ('gi1', 'octo', 'app', 'CVE-2026-0001', 7, 'https://github.com/octo/app/issues/7', 'open')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        fx.fix("v1", "CVE-2026-0001").await;
        fx.reconcile("proj/app:v1").await;
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

        let outcome = fx.reconcile("proj/app:v1").await;

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
        let mapping = fx.mapping("m1").await;

        let (a, b) = tokio::join!(
            reconcile(&fx.pool, &fx.gh, TOKEN, &mapping, "proj/app:v1", 1_000),
            reconcile(&fx.pool, &fx.gh, TOKEN, &mapping, "proj/app:v1", 1_000),
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
        let mapping = fx.mapping("m1").await;

        let (a, b) = tokio::join!(
            create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0001", 1_000),
            create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0001", 1_000),
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
        let mapping = fx.mapping("m1").await;

        let (synced, manual) = tokio::join!(
            reconcile(&fx.pool, &fx.gh, TOKEN, &mapping, "proj/app:v1", 1_000),
            create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0001", 1_000),
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
        async fn list_open_labelled(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            now: i64,
        ) -> Result<Vec<IssueRef>, ScanError> {
            self.inner.list_open_labelled(token, owner, repo, now).await
        }

        async fn create(
            &self,
            token: &[u8],
            owner: &str,
            repo: &str,
            title: &str,
            body: &str,
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
                .create(token, owner, repo, title, body, now)
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
    }

    #[tokio::test]
    async fn a_unique_conflict_on_insert_keeps_the_winner_and_is_not_an_error() {
        let fx = Fixture::new("unique", "CRITICAL", true).await;
        fx.finding("m1", "v1", "CVE-2026-0001", "CRITICAL", 10)
            .await;
        let mapping = fx.mapping("m1").await;
        let gh = Racing {
            inner: FakeIssues(fx.github.clone()),
            pool: fx.pool.clone(),
        };

        let outcome = reconcile(&fx.pool, &gh, TOKEN, &mapping, "proj/app:v1", 1_000).await;

        assert_eq!(outcome.unwrap(), Outcome::Complete);
        assert_eq!(
            fx.issues().await,
            vec![("CVE-2026-0001".to_owned(), 99, "open".to_owned())]
        );
        let manual = create_manual(&fx.pool, &gh, TOKEN, &mapping, "CVE-2026-0001", 1_000).await;
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
        let mapping = fx.mapping("m1").await;
        let gh = Racing {
            inner: FakeIssues(fx.github.clone()),
            pool: fx.pool.clone(),
        };

        let manual = create_manual(&fx.pool, &gh, TOKEN, &mapping, "CVE-2026-0001", 1_000).await;

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

        let outcome = fx.reconcile("proj/app:v1").await;

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

        assert_eq!(fx.reconcile("proj/app:v1").await, Outcome::Complete);

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

        fx.reconcile("proj/app:v1").await;

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

            assert_eq!(fx.reconcile("proj/app:v1").await, Outcome::Complete);

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
        let mapping = fx.mapping("m1").await;

        let made = create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0004", 1_000)
            .await
            .unwrap();
        assert_eq!(made.number, 1);
        assert_eq!(
            fx.github.creates()[0]["title"],
            "CVE-2026-0004: openssl (LOW) in proj/app"
        );
        fx.reconcile("proj/app:v1").await;

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
        let mapping = fx.mapping("m1").await;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, mapping_id, cve_id, reason, created_by, created_by_username)
             VALUES ('a1', 'm1', 'CVE-2026-0005', 'accepted for the test', 'u1', 'u1')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();

        let refused = create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0005", 1_000)
            .await
            .unwrap_err();
        assert_eq!(refused.status(), axum::http::StatusCode::CONFLICT);
        assert_eq!(fx.github.requests(), 0);

        sqlx::query("UPDATE cve_acceptances SET revoked_at = 5, revoked_by = 'u1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        let first = create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0005", 1_000)
            .await
            .unwrap();

        // The issue is closed on GitHub and in the row; the manual route reopens it.
        sqlx::query("UPDATE github_issues SET status = 'closed'")
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.github.with(|state| state.issues[0].open = false);
        let reopened = create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0005", 1_000)
            .await
            .unwrap();
        assert_eq!(reopened, first);
        assert_eq!(fx.github.creates().len(), 1, "no second issue");
        let writes = fx.github.writes();
        assert_eq!(writes.last().unwrap().2["body"], MANUAL_REOPEN_COMMENT);

        let open = create_manual(&fx.pool, &fx.gh, TOKEN, &mapping, "CVE-2026-0005", 1_000)
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
        let long_mapping = format!("{long}:CVE-2026-0001");
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
            long_mapping.as_str(),
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
