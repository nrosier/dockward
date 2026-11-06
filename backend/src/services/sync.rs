//! The sync job handler: Harbor report to SARIF upload (`specs/integrations.md`, OCI
//! labels, Vulnerability report endpoint, SARIF conversion and upload).
//!
//! One job reads the artifact labels and the Trivy report from Harbor, converts the
//! report to SARIF, uploads it to GitHub code scanning, waits for GitHub to process it,
//! and records the result in `sync_reports`. It ties together the Harbor client, the
//! converter and the GitHub client, and it adds no HTTP of its own.
//!
//! Every message returned in a [`JobOutcome`] is stored or logged, so none of them holds a
//! token, a header, or a decrypted credential.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::auth::crypto::DerivedKey;
use crate::db::credentials::{self as credential_db, CredentialRow};
use crate::db::mappings::{self as mapping_db, MappingRow};
use crate::db::sync_jobs::ClaimedJob;
use crate::db::sync_reports::{self as report_db, NewReport};
use crate::error::AppError;
use crate::services::alerts::Notifier;
use crate::services::credentials::{base_for_join, decrypt_token};
use crate::services::github_issues::GithubIssues;
use crate::services::github_scanning::{
    GithubScanning, Processing, ScanError, Upload, encode_sarif,
};
use crate::services::harbor_client::{
    HarborGet, HarborReply, ReportState, TRIVY_REPORT_MIME, artifact_url, branch_for, check_source,
    index_image_child, parse_labels, parse_report, require_revision, vulnerabilities_url,
};
use crate::services::issue_lifecycle::{self, IssueApi};
use crate::services::resolve::{self, JobKind};
use crate::services::{findings, ids, sarif};
use crate::worker::{JobHandler, JobOutcome, now_secs};

/// Waits between processing polls: 5 s, then 10 s, then every 15 s.
const FIRST_WAIT: Duration = Duration::from_secs(5);
const SECOND_WAIT: Duration = Duration::from_secs(10);
const LATER_WAIT: Duration = Duration::from_secs(15);
/// Total time one attempt waits for GitHub to process an upload.
const MAX_WAIT: Duration = Duration::from_secs(300);

pub(crate) const MSG_GONE: &str = "mapping or credential no longer exists";
pub(crate) const MSG_DATABASE: &str = "the database could not be read or written";
pub(crate) const MSG_INTERNAL: &str = "an internal error stopped this job; it will be retried";
const MSG_DECRYPT: &str = "a stored credential could not be decrypted";
const MSG_NOT_YET: &str = "Harbor report not available yet";
const MSG_TOO_LARGE: &str = "SARIF over 10 MB compressed";
const MSG_PENDING: &str = "GitHub processing still pending";

/// The job payload (`specs/integrations.md`): `{repo_full_name, digest, tag}`. The Harbor
/// project and repository come from the mapping, which the webhook already matched to
/// `repo_full_name`, so that field is not read. It and `trigger` are ignored.
#[derive(Debug, Deserialize)]
struct Payload {
    digest: String,
    tag: String,
}

/// Reads from Harbor. The production impl is [`HarborGet`]; tests use recorded answers.
pub trait HarborFetch: Send + Sync + 'static {
    fn fetch(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> impl Future<Output = Result<HarborReply, AppError>> + Send;
}

impl HarborFetch for HarborGet {
    async fn fetch(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        self.get(url, username, secret, extra_headers).await
    }
}

/// Calls GitHub code scanning. The production impl is [`GithubScanning`].
pub trait CodeScanning: Send + Sync + 'static {
    fn upload(
        &self,
        token: &[u8],
        fields: &Upload<'_>,
        now: i64,
    ) -> impl Future<Output = Result<String, ScanError>> + Send;

    fn status(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        sarif_id: &str,
        now: i64,
    ) -> impl Future<Output = Result<Processing, ScanError>> + Send;
}

impl CodeScanning for GithubScanning {
    async fn upload(
        &self,
        token: &[u8],
        fields: &Upload<'_>,
        now: i64,
    ) -> Result<String, ScanError> {
        GithubScanning::upload(self, token, fields, now).await
    }

    async fn status(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        sarif_id: &str,
        now: i64,
    ) -> Result<Processing, ScanError> {
        GithubScanning::status(self, token, owner, repo, sarif_id, now).await
    }
}

/// The clock and the sleeper, so tests do not wait five minutes.
pub trait Clock: Send + Sync + 'static {
    /// Unix seconds.
    fn now(&self) -> i64;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

/// The real clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        now_secs()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Runs sync jobs. The type parameters default to the production clients.
pub struct SyncHandler<H = HarborGet, G = GithubScanning, C = SystemClock, I = GithubIssues> {
    pool: SqlitePool,
    credentials_key: Arc<DerivedKey>,
    harbor: H,
    github: G,
    clock: C,
    issues: I,
    alerts: Notifier,
}

impl SyncHandler {
    /// Builds the production handler: the guarded Harbor and GitHub clients and the
    /// system clock.
    pub fn new(
        pool: SqlitePool,
        credentials_key: Arc<DerivedKey>,
        allow_private_harbor: bool,
        allow_private_alerts: bool,
    ) -> Result<Self, AppError> {
        let alerts = Notifier::new(pool.clone(), credentials_key.clone(), allow_private_alerts);
        Ok(Self {
            pool,
            credentials_key,
            harbor: HarborGet::new(allow_private_harbor)?,
            github: GithubScanning::new()?,
            clock: SystemClock,
            issues: GithubIssues::new()?,
            alerts,
        })
    }
}

impl<H: HarborFetch, G: CodeScanning, C: Clock, I: IssueApi> SyncHandler<H, G, C, I> {
    #[cfg(test)]
    pub(crate) fn with_parts(
        pool: SqlitePool,
        credentials_key: Arc<DerivedKey>,
        harbor: H,
        github: G,
        clock: C,
        issues: I,
    ) -> Self {
        // No alert channel exists in these tests, so this notifier sends nothing.
        let alerts = Notifier::new(pool.clone(), credentials_key.clone(), false);
        Self {
            pool,
            credentials_key,
            harbor,
            github,
            clock,
            issues,
            alerts,
        }
    }

    /// Replaces the notifier, so a test can record alerts instead of sending them.
    #[cfg(test)]
    pub(crate) fn with_alerts(mut self, alerts: Notifier) -> Self {
        self.alerts = alerts;
        self
    }
}

/// An early exit from a job: the outcome to report.
type Flow<T> = Result<T, JobOutcome>;

fn failed(message: &str) -> JobOutcome {
    JobOutcome::Failed(message.to_owned())
}

fn database(_: AppError) -> JobOutcome {
    failed(MSG_DATABASE)
}

/// A failure that is not a database fault, such as the OS random source. The text is
/// fixed and names no internal detail.
fn internal(_: AppError) -> JobOutcome {
    failed(MSG_INTERNAL)
}

/// Maps a GitHub error to the job outcome. A rate limit defers the job. The other
/// messages are fixed text that names the GitHub permission, never the token.
fn scan_outcome(error: ScanError) -> JobOutcome {
    match error {
        ScanError::RateLimited { until } => JobOutcome::Deferred {
            until,
            reason: "GitHub rate limit reached".to_owned(),
        },
        ScanError::Unauthorized => failed(
            "GitHub rejected the token; check the GitHub credential (Code scanning alerts: read and write)",
        ),
        ScanError::Forbidden(_) => failed(
            "GitHub refused the request; the token needs the Code scanning alerts: read and write permission",
        ),
        ScanError::NotFound => failed(
            "GitHub could not find the repository or the SARIF upload; check the token's access and the Code scanning alerts permission",
        ),
        ScanError::TooLarge => failed(MSG_TOO_LARGE),
        other @ (ScanError::Rejected(_) | ScanError::Upstream(_)) => {
            JobOutcome::Failed(other.to_string())
        }
    }
}

/// The text of a validation failure from the Harbor client, or a fixed text.
fn validation_message(error: AppError, fallback: &str) -> JobOutcome {
    match error {
        AppError::ValidationFailed(message) => JobOutcome::Failed(message),
        _ => failed(fallback),
    }
}

/// Like `validation_message`, but for a failure that retrying cannot fix: a missing revision
/// label or a source mismatch is a property of the image (`specs/integrations.md`).
fn permanent_validation(error: AppError, fallback: &str) -> JobOutcome {
    match error {
        AppError::ValidationFailed(message) => JobOutcome::Permanent(message),
        _ => JobOutcome::Permanent(fallback.to_owned()),
    }
}

/// Counts the report's vulnerabilities by severity.
fn summarize(report: &Value) -> String {
    let mut counts = [0u64; 5];
    let items = report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for item in items {
        let severity = sarif::normalize_severity(
            item.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Unknown"),
        );
        let slot = match severity {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            _ => 4,
        };
        counts[slot] += 1;
    }
    json!({
        "critical": counts[0],
        "high": counts[1],
        "medium": counts[2],
        "low": counts[3],
        "unknown": counts[4],
    })
    .to_string()
}

/// The delay before the poll with this zero-based index.
fn wait_for(index: u32) -> Duration {
    match index {
        0 => FIRST_WAIT,
        1 => SECOND_WAIT,
        _ => LATER_WAIT,
    }
}

/// What one job needs after the database reads and the decryption.
struct Context {
    mapping: MappingRow,
    harbor_username: String,
    harbor_secret: Zeroizing<Vec<u8>>,
    github_token: Zeroizing<Vec<u8>>,
    payload: Payload,
}

impl<H: HarborFetch, G: CodeScanning, C: Clock, I: IssueApi> SyncHandler<H, G, C, I> {
    async fn execute(&self, job: &ClaimedJob) -> Flow<()> {
        let context = self.load(job).await?;

        let existing = report_db::find_pending_for_job(&self.pool, &job.id)
            .await
            .map_err(database)?;
        if let Some(report) = &existing
            && let Some(sarif_id) = &report.github_sarif_id
        {
            // A retry after a pending wait: poll the same upload, never upload twice. The
            // Harbor report is fetched again only if GitHub reports `Complete`.
            return self
                .wait_for_processing(&context, &report.id, sarif_id, None)
                .await;
        }

        let (sarif_b64, summary, revision, branch, vuln_report) =
            self.read_and_convert(&context).await?;

        // A pending report left by an earlier attempt that never uploaded is reused.
        let report_id = match existing {
            Some(report) => report.id,
            None => {
                let id = ids::new_id().map_err(internal)?;
                let repository = context.mapping.harbor_repository.as_str();
                let new = NewReport {
                    id: &id,
                    mapping_id: &job.mapping_id,
                    sync_job_id: &job.id,
                    harbor_repository: repository,
                    image_tag: &context.payload.tag,
                    image_digest: &context.payload.digest,
                    commit_sha: Some(&revision),
                    vulnerability_summary: &summary,
                };
                let mut conn = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| failed(MSG_DATABASE))?;
                report_db::insert_pending(&mut conn, &new)
                    .await
                    .map_err(database)?;
                id
            }
        };

        let Some(sarif_b64) = sarif_b64 else {
            report_db::finish(
                &self.pool,
                &report_id,
                "failed",
                Some(MSG_TOO_LARGE),
                self.clock.now(),
            )
            .await
            .map_err(database)?;
            return Err(failed(MSG_TOO_LARGE));
        };

        let git_ref = format!("refs/heads/{branch}");
        let upload = Upload {
            owner: &context.mapping.github_owner,
            repo: &context.mapping.github_repo,
            commit_sha: &revision,
            git_ref: &git_ref,
            sarif_b64: &sarif_b64,
        };
        let sarif_id = self
            .github
            .upload(&context.github_token, &upload, self.clock.now())
            .await
            .map_err(scan_outcome)?;
        report_db::set_sarif_id(&self.pool, &report_id, &sarif_id)
            .await
            .map_err(database)?;
        self.wait_for_processing(&context, &report_id, &sarif_id, Some(&vuln_report))
            .await
    }

    /// Loads the mapping and both credentials, and decrypts both tokens.
    async fn load(&self, job: &ClaimedJob) -> Flow<Context> {
        let payload: Payload = serde_json::from_str(&job.payload)
            .map_err(|_| failed("the job payload is not valid"))?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| failed(MSG_DATABASE))?;
        let mapping = mapping_db::find_by_id(&mut conn, &job.mapping_id)
            .await
            .map_err(database)?
            .ok_or_else(|| failed(MSG_GONE))?;
        let harbor =
            credential_db::find_owned(&mut conn, &mapping.user_id, &mapping.harbor_cred_id)
                .await
                .map_err(database)?
                .ok_or_else(|| failed(MSG_GONE))?;
        let github =
            credential_db::find_owned(&mut conn, &mapping.user_id, &mapping.github_cred_id)
                .await
                .map_err(database)?
                .ok_or_else(|| failed(MSG_GONE))?;
        drop(conn);
        let harbor_username = harbor
            .username
            .clone()
            .ok_or_else(|| failed("the Harbor credential has no robot username"))?;
        Ok(Context {
            harbor_secret: self.decrypt(&harbor)?,
            github_token: self.decrypt(&github)?,
            harbor_username,
            mapping,
            payload,
        })
    }

    fn decrypt(&self, row: &CredentialRow) -> Flow<Zeroizing<Vec<u8>>> {
        decrypt_token(&self.credentials_key, row).map_err(|_| failed(MSG_DECRYPT))
    }

    /// Reads the labels and the report from Harbor and converts the report. Returns the
    /// encoded SARIF (`None` when it is over 10 MB compressed), the severity summary, the
    /// commit SHA, the branch and the parsed Harbor report.
    async fn read_and_convert(
        &self,
        context: &Context,
    ) -> Flow<(Option<String>, String, String, String, Value)> {
        let mapping = &context.mapping;
        let base = base_for_join(&mapping.harbor_base_url).map_err(database)?;
        let digest = context.payload.digest.as_str();

        let artifact = artifact_url(
            &base,
            &mapping.harbor_project,
            &mapping.harbor_repository,
            digest,
        )
        .map_err(|e| validation_message(e, "the Harbor names are not valid"))?;
        let body = self
            .harbor_body(context, &artifact, &[], "the Harbor artifact")
            .await?;
        let mut labels = parse_labels(&body)
            .map_err(|_| failed("Harbor returned an artifact that could not be read"))?;
        // An image index carries no image config, so its labels are on its image child.
        if labels.revision.is_none()
            && let Some(child) = index_image_child(&body)
        {
            let child_url = artifact_url(
                &base,
                &mapping.harbor_project,
                &mapping.harbor_repository,
                &child,
            )
            .map_err(|e| validation_message(e, "the Harbor names are not valid"))?;
            let child_body = self
                .harbor_body(context, &child_url, &[], "the Harbor image")
                .await?;
            labels = parse_labels(&child_body)
                .map_err(|_| failed("Harbor returned an artifact that could not be read"))?;
        }
        let revision = require_revision(&labels)
            .map_err(|e| permanent_validation(e, "the image has no revision label"))?
            .to_owned();
        check_source(&labels, &mapping.github_owner, &mapping.github_repo)
            .map_err(|e| permanent_validation(e, "the image source label does not match"))?;
        let branch = branch_for(&labels, &mapping.default_branch);

        let report = self.fetch_report(context).await?;

        let document = sarif::convert(&report, &mapping.harbor_project, &mapping.harbor_repository)
            .map_err(|_| failed("the Harbor report could not be converted to SARIF"))?;
        let summary = summarize(&report);
        let encoded = match encode_sarif(&document) {
            Ok(encoded) => Some(encoded),
            Err(ScanError::TooLarge) => None,
            Err(other) => return Err(scan_outcome(other)),
        };
        Ok((encoded, summary, revision, branch, report))
    }

    /// Reads and parses the Trivy report from Harbor. `NotYet` and a `404` fail the job for
    /// backoff.
    async fn fetch_report(&self, context: &Context) -> Flow<Value> {
        let mapping = &context.mapping;
        let base = base_for_join(&mapping.harbor_base_url).map_err(database)?;
        let report_url = vulnerabilities_url(
            &base,
            &mapping.harbor_project,
            &mapping.harbor_repository,
            &context.payload.digest,
        )
        .map_err(|e| validation_message(e, "the Harbor names are not valid"))?;
        let body = self
            .harbor_body(
                context,
                &report_url,
                &[("X-Accept-Vulnerabilities", TRIVY_REPORT_MIME)],
                "the Harbor report",
            )
            .await?;
        match parse_report(&body)
            .map_err(|_| failed("Harbor returned a report that could not be read"))?
        {
            ReportState::Ready(report) => Ok(report),
            ReportState::NotYet => Err(failed(MSG_NOT_YET)),
        }
    }

    /// One Harbor GET. `404` on the report is the backoff case; any other non-200 fails.
    async fn harbor_body(
        &self,
        context: &Context,
        url: &Url,
        headers: &[(&str, &str)],
        what: &str,
    ) -> Flow<Vec<u8>> {
        let HarborReply { status, body, .. } = self
            .harbor
            .fetch(
                url,
                &context.harbor_username,
                &context.harbor_secret,
                headers,
            )
            .await
            .map_err(|_| failed("Harbor could not be reached"))?;
        match status {
            200 => Ok(body),
            404 if !headers.is_empty() => Err(failed(MSG_NOT_YET)),
            401 | 403 => Err(failed("Harbor rejected the robot account credentials")),
            404 => Err(failed(&format!("{what} was not found in Harbor"))),
            other => Err(failed(&format!("Harbor returned status {other}"))),
        }
    }

    /// Makes the GitHub issues follow the findings that were just applied. Nothing here can
    /// fail the job: the report is already `success`, so a retry would upload the SARIF again
    /// and add a second report row. A rate limit, a refused token or a database error is
    /// logged as fixed text, and the next scan reconciles the issues. Another GitHub error is
    /// logged inside the reconcile.
    async fn reconcile_issues(&self, context: &Context) {
        let mapping = &context.mapping;
        let scan_label = format!(
            "{}/{}:{}",
            mapping.harbor_project, mapping.harbor_repository, context.payload.tag
        );
        let result = issue_lifecycle::reconcile(
            &self.pool,
            &self.issues,
            &context.github_token,
            mapping,
            &scan_label,
            self.clock.now(),
        )
        .await;
        match result {
            Ok(issue_lifecycle::Outcome::Complete) => {}
            Ok(issue_lifecycle::Outcome::RateLimited { .. }) => {
                tracing::warn!(
                    "GitHub rate limit reached while updating issues; the next scan retries"
                );
            }
            Ok(issue_lifecycle::Outcome::Refused) => {
                tracing::warn!(
                    "GitHub refused the issue updates; check the token's Issues permission"
                );
            }
            Err(_) => {
                tracing::warn!("the database failed while updating issues; the next scan retries");
            }
        }
    }

    /// Polls GitHub after 5 s, 10 s, then every 15 s, for at most 300 s in total. On
    /// `Complete` the report is marked `success` and the findings of the tag are updated
    /// from `vuln_report`. A retry has no report in hand (`None`), so it is fetched from
    /// Harbor again, before the report is marked `success`.
    async fn wait_for_processing(
        &self,
        context: &Context,
        report_id: &str,
        sarif_id: &str,
        vuln_report: Option<&Value>,
    ) -> Flow<()> {
        let mapping = &context.mapping;
        let mut waited = Duration::ZERO;
        let mut index = 0;
        while waited < MAX_WAIT {
            let delay = wait_for(index);
            self.clock.sleep(delay).await;
            waited += delay;
            index += 1;
            let processing = self
                .github
                .status(
                    &context.github_token,
                    &mapping.github_owner,
                    &mapping.github_repo,
                    sarif_id,
                    self.clock.now(),
                )
                .await
                .map_err(scan_outcome)?;
            match processing {
                Processing::Pending => {}
                Processing::Complete => {
                    let fetched;
                    let vuln_report = match vuln_report {
                        Some(report) => report,
                        None => {
                            fetched = self.fetch_report(context).await?;
                            &fetched
                        }
                    };
                    report_db::finish(&self.pool, report_id, "success", None, self.clock.now())
                        .await
                        .map_err(database)?;
                    let applied = findings::apply_scan(
                        &self.pool,
                        &mapping.id,
                        &mapping.harbor_repository,
                        &context.payload.tag,
                        vuln_report,
                        self.clock.now(),
                    )
                    .await
                    .map_err(database)?;
                    self.alerts.spawn_new_critical(
                        mapping,
                        &context.payload.tag,
                        &applied.new_critical,
                    );
                    self.reconcile_issues(context).await;
                    return Ok(());
                }
                Processing::Failed(errors) => {
                    // A permanent failure recorded on the report. The job is done, so it
                    // is not retried.
                    let message = errors.join("; ");
                    report_db::finish(
                        &self.pool,
                        report_id,
                        "failed",
                        Some(&message),
                        self.clock.now(),
                    )
                    .await
                    .map_err(database)?;
                    return Ok(());
                }
            }
        }
        Err(failed(MSG_PENDING))
    }
}

impl<H: HarborFetch, G: CodeScanning, C: Clock, I: IssueApi> JobHandler
    for SyncHandler<H, G, C, I>
{
    /// Branches on the payload's `kind` before the payload is parsed (#132): a sync job runs the
    /// Harbor-to-GitHub sync, a resolve job expands a digest into sync jobs, and an unknown kind
    /// fails for good.
    async fn run(&self, job: ClaimedJob) -> JobOutcome {
        match resolve::job_kind(&job.payload) {
            JobKind::Sync => match self.execute(&job).await {
                Ok(()) => JobOutcome::Done,
                Err(outcome) => outcome,
            },
            JobKind::Resolve => {
                resolve::run(
                    &self.pool,
                    &self.credentials_key,
                    &self.harbor,
                    &self.clock,
                    &job,
                )
                .await
            }
            JobKind::Unknown => JobOutcome::Permanent(resolve::MSG_UNKNOWN_KIND.to_owned()),
        }
    }

    fn on_give_up(&self, job: &ClaimedJob, now: i64) {
        self.alerts.spawn_sync_failed(&job.id, &job.mapping_id, now);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::auth::crypto::{self, credentials_key};
    use crate::config;
    use crate::db;
    use crate::services::alert_channels;
    use crate::services::alert_send::{Alert, AlertEvent};
    use crate::services::audit::Actor;
    use crate::services::issue_lifecycle::test_support::{FakeGithub, FakeIssues};

    // Test values only. The root key and the tokens are obviously fake.
    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    fn key() -> DerivedKey {
        let root = config::parse_encryption_key(ROOT).unwrap();
        credentials_key(&root).unwrap()
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Answers the artifact URL and the report URL with recorded answers.
    struct FakeHarbor {
        artifact: (u16, Vec<u8>),
        /// Answers for artifact paths ending in a given digest, ahead of `artifact`.
        by_digest: Vec<(String, Vec<u8>)>,
        report: (u16, Vec<u8>),
        urls: Mutex<Vec<String>>,
        report_headers: Mutex<Vec<(String, String)>>,
    }

    impl FakeHarbor {
        fn new(artifact: &str, report: (u16, &str)) -> Self {
            Self {
                artifact: (200, artifact.as_bytes().to_vec()),
                by_digest: Vec::new(),
                report: (report.0, report.1.as_bytes().to_vec()),
                urls: Mutex::new(Vec::new()),
                report_headers: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            lock(&self.urls).len()
        }
    }

    impl HarborFetch for Arc<FakeHarbor> {
        async fn fetch(
            &self,
            url: &Url,
            _username: &str,
            _secret: &[u8],
            extra_headers: &[(&str, &str)],
        ) -> Result<HarborReply, AppError> {
            lock(&self.urls).push(url.path().to_owned());
            if url.path().ends_with("/additions/vulnerabilities") {
                for (name, value) in extra_headers {
                    lock(&self.report_headers).push(((*name).to_owned(), (*value).to_owned()));
                }
                Ok(HarborReply::new(self.report.0, self.report.1.clone()))
            } else if let Some((_, body)) = self
                .by_digest
                .iter()
                .find(|(digest, _)| url.path().ends_with(digest.as_str()))
            {
                Ok(HarborReply::new(200, body.clone()))
            } else {
                Ok(HarborReply::new(self.artifact.0, self.artifact.1.clone()))
            }
        }
    }

    /// Records uploads and answers statuses from a queue; the last status repeats.
    struct FakeScanner {
        upload_result: Result<String, ScanError>,
        statuses: Mutex<VecDeque<Result<Processing, ScanError>>>,
        uploads: AtomicUsize,
        status_calls: AtomicUsize,
        sent: Mutex<Vec<(String, String, String)>>,
    }

    impl FakeScanner {
        fn new(
            upload_result: Result<String, ScanError>,
            statuses: Vec<Result<Processing, ScanError>>,
        ) -> Arc<Self> {
            Arc::new(Self {
                upload_result,
                statuses: Mutex::new(statuses.into()),
                uploads: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
                sent: Mutex::new(Vec::new()),
            })
        }

        fn uploads(&self) -> usize {
            self.uploads.load(Ordering::SeqCst)
        }
    }

    impl CodeScanning for Arc<FakeScanner> {
        async fn upload(
            &self,
            _token: &[u8],
            fields: &Upload<'_>,
            _now: i64,
        ) -> Result<String, ScanError> {
            self.uploads.fetch_add(1, Ordering::SeqCst);
            lock(&self.sent).push((
                fields.git_ref.to_owned(),
                fields.commit_sha.to_owned(),
                format!("{}/{}", fields.owner, fields.repo),
            ));
            self.upload_result.clone()
        }

        async fn status(
            &self,
            _token: &[u8],
            _owner: &str,
            _repo: &str,
            _sarif_id: &str,
            _now: i64,
        ) -> Result<Processing, ScanError> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            let mut queue = lock(&self.statuses);
            if queue.len() > 1 {
                queue.pop_front().unwrap_or(Ok(Processing::Pending))
            } else {
                queue.front().cloned().unwrap_or(Ok(Processing::Pending))
            }
        }
    }

    /// A clock that never waits: it records each sleep.
    struct FakeClock {
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    impl Clock for FakeClock {
        fn now(&self) -> i64 {
            1_000
        }

        async fn sleep(&self, duration: Duration) {
            lock(&self.sleeps).push(duration);
        }
    }

    fn artifact(labels: &str) -> String {
        format!(r#"{{"digest": "sha256:aaaa", "extra_attrs": {{"labels": {labels}}}}}"#)
    }

    fn good_artifact() -> String {
        artifact(&format!(
            r#"{{"org.opencontainers.image.revision": "{REVISION}", "org.opencontainers.image.source": "https://github.com/octo/app"}}"#
        ))
    }

    fn report_body() -> String {
        format!(
            r#"{{"{TRIVY_REPORT_MIME}": {{
                "vulnerabilities": [
                    {{"id": "CVE-2026-0001", "package": "openssl", "version": "1", "severity": "Critical", "fix_version": "2"}},
                    {{"id": "CVE-2026-0002", "package": "zlib", "version": "1", "severity": "High"}},
                    {{"id": "CVE-2026-0003", "package": "zlib", "version": "1", "severity": "High"}},
                    {{"id": "CVE-2026-0004", "package": "curl", "version": "1", "severity": "Weird"}}
                ]
            }}}}"#
        )
    }

    struct Fixture {
        pool: SqlitePool,
        dir: std::path::PathBuf,
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    impl Fixture {
        async fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("harborgate-sync-{name}-{}", std::process::id()));
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
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
                 VALUES ('m1', 'u1', 'c1', 'c2', 'https://harbor.example.com', 'proj', 'app', 'octo', 'app', 'h1', 'h2', 0, 'CRITICAL', 'main')",
            )
            .execute(&pool)
            .await
            .unwrap();
            db::sync_jobs::enqueue(
                &pool,
                "j1",
                "m1",
                r#"{"repo_full_name":"proj/app","digest":"sha256:aaaa","tag":"v1"}"#,
                1_000,
            )
            .await
            .unwrap();
            Self {
                pool,
                dir,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn job(&self) -> ClaimedJob {
            ClaimedJob {
                id: "j1".to_owned(),
                mapping_id: "m1".to_owned(),
                attempts: 0,
                payload: r#"{"repo_full_name":"proj/app","digest":"sha256:aaaa","tag":"v1"}"#
                    .to_owned(),
            }
        }

        fn handler(
            &self,
            harbor: &Arc<FakeHarbor>,
            scanner: &Arc<FakeScanner>,
        ) -> SyncHandler<Arc<FakeHarbor>, Arc<FakeScanner>, FakeClock, FakeIssues> {
            self.handler_with(harbor, scanner, Arc::new(FakeGithub::default()))
        }

        fn handler_with(
            &self,
            harbor: &Arc<FakeHarbor>,
            scanner: &Arc<FakeScanner>,
            github: Arc<FakeGithub>,
        ) -> SyncHandler<Arc<FakeHarbor>, Arc<FakeScanner>, FakeClock, FakeIssues> {
            SyncHandler::with_parts(
                self.pool.clone(),
                Arc::new(key()),
                harbor.clone(),
                scanner.clone(),
                FakeClock {
                    sleeps: self.sleeps.clone(),
                },
                FakeIssues(github),
            )
        }

        /// The one report row: status, sarif id, error, commit, summary.
        async fn report(
            &self,
        ) -> Option<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
        )> {
            sqlx::query_as(
                "SELECT sarif_status, github_sarif_id, error_message, commit_sha, vulnerability_summary
                 FROM sync_reports WHERE sync_job_id = 'j1'",
            )
            .fetch_optional(&self.pool)
            .await
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn ok_harbor() -> Arc<FakeHarbor> {
        Arc::new(FakeHarbor::new(&good_artifact(), (200, &report_body())))
    }

    #[tokio::test]
    async fn happy_path_uploads_and_records_success() {
        let fx = Fixture::new("happy").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1);
        assert_eq!(
            lock(&scanner.sent).clone(),
            vec![(
                "refs/heads/main".to_owned(),
                REVISION.to_owned(),
                "octo/app".to_owned()
            )]
        );
        assert_eq!(
            lock(&harbor.report_headers).clone(),
            vec![(
                "X-Accept-Vulnerabilities".to_owned(),
                TRIVY_REPORT_MIME.to_owned()
            )]
        );
        let (status, sarif_id, error, commit, summary) = fx.report().await.unwrap();
        assert_eq!(status, "success");
        assert_eq!(sarif_id.as_deref(), Some("sarif-1"));
        assert_eq!(error, None);
        assert_eq!(commit.as_deref(), Some(REVISION));
        let summary: Value = serde_json::from_str(&summary).unwrap();
        assert_eq!(
            summary,
            json!({"critical": 1, "high": 2, "medium": 0, "low": 0, "unknown": 1})
        );
        assert_eq!(lock(&fx.sleeps).clone(), vec![FIRST_WAIT]);
        // Complete applies the report to cve_findings.
        let applied: Vec<(String, String)> = sqlx::query_as(
            "SELECT cve_id, severity FROM cve_findings WHERE image_tag = 'v1' ORDER BY cve_id",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(applied.len(), 4);
        assert_eq!(
            applied[0],
            ("CVE-2026-0001".to_owned(), "CRITICAL".to_owned())
        );
    }

    /// A payload with no `kind` (every job stored before #132) still runs the sync.
    #[tokio::test]
    async fn a_legacy_sync_payload_with_no_kind_still_syncs() {
        let fx = Fixture::new("legacy-kind").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let job = fx.job();
        assert!(!job.payload.contains("kind"), "fixture");

        let outcome = fx.handler(&harbor, &scanner).run(job).await;

        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1);
        // `"kind":"sync"` is the same job.
        let mut explicit = fx.job();
        explicit.payload = explicit.payload.replacen('{', r#"{"kind":"sync","#, 1);
        let again = fx.handler(&harbor, &scanner).run(explicit).await;
        assert_eq!(again, JobOutcome::Done);
    }

    #[tokio::test]
    async fn an_unknown_job_kind_is_permanent_with_no_harbor_call() {
        let fx = Fixture::new("unknown-kind").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let mut job = fx.job();
        job.payload = job.payload.replacen('{', r#"{"kind":"refresh","#, 1);

        let outcome = fx.handler(&harbor, &scanner).run(job).await;

        assert_eq!(
            outcome,
            JobOutcome::Permanent(resolve::MSG_UNKNOWN_KIND.to_owned())
        );
        assert_eq!(harbor.calls(), 0);
        assert_eq!(scanner.uploads(), 0);
    }

    /// The sync handler sends a resolve job to the resolve module: the artifact is read once,
    /// sync children are queued, and nothing is uploaded.
    #[tokio::test]
    async fn the_sync_handler_runs_a_resolve_job_as_a_fan_out() {
        let fx = Fixture::new("dispatch-resolve").await;
        let digest = format!("sha256:{}", "b".repeat(64));
        let artifact = format!(
            r#"{{"digest": "{digest}", "tags": [{{"name": "v1", "push_time": "2026-11-05T10:00:00Z"}}, {{"name": "v2", "push_time": "2026-11-05T11:00:00Z"}}]}}"#
        );
        let harbor = Arc::new(FakeHarbor::new(&artifact, (200, "{}")));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let payload =
            format!(r#"{{"kind":"resolve","repo_full_name":"proj/app","digest":"{digest}"}}"#);
        sqlx::query(
            "INSERT INTO sync_jobs (id, mapping_id, status, attempts, payload) VALUES ('r1', 'm1', 'running', 0, ?)",
        )
        .bind(&payload)
        .execute(&fx.pool)
        .await
        .unwrap();
        let job = ClaimedJob {
            id: "r1".to_owned(),
            mapping_id: "m1".to_owned(),
            attempts: 0,
            payload,
        };

        let outcome = fx.handler(&harbor, &scanner).run(job).await;

        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(harbor.calls(), 1);
        assert_eq!(scanner.uploads(), 0);
        let tags: Vec<String> = sqlx::query_scalar(
            "SELECT json_extract(payload, '$.tag') FROM sync_jobs WHERE json_extract(payload, '$.digest') = ? AND id != 'r1' ORDER BY rowid",
        )
        .bind(&digest)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(tags, vec!["v2", "v1"]);
    }

    #[tokio::test]
    async fn missing_revision_fails_without_upload() {
        let fx = Fixture::new("norev").await;
        let harbor = Arc::new(FakeHarbor::new(&artifact("{}"), (200, &report_body())));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert!(matches!(outcome, JobOutcome::Permanent(ref m) if m.contains("revision")));
        assert_eq!(scanner.uploads(), 0);
        assert!(fx.report().await.is_none());
    }

    /// A `docker buildx` push is an image index with no image config; the labels are on its
    /// image child, in `extra_attrs.config.Labels` (the live Harbor shape, 2026-11-06). The
    /// sync reads them there, skips the attestation child, and reads the report on the
    /// event digest.
    #[tokio::test]
    async fn an_image_index_reads_labels_from_its_image_child() {
        let fx = Fixture::new("index").await;
        let image_hex = "a".repeat(64);
        let attestation_hex = "b".repeat(64);
        let index = format!(
            r#"{{"digest": "sha256:aaaa", "labels": null, "tags": [{{"name": "v1"}}],
            "media_type": "application/vnd.oci.image.index.v1+json",
            "references": [
                {{"child_digest": "sha256:{attestation_hex}", "platform": {{"os": "unknown", "architecture": "unknown"}},
                  "annotations": {{"vnd.docker.reference.type": "attestation-manifest"}}}},
                {{"child_digest": "sha256:{image_hex}", "platform": {{"os": "linux", "architecture": "amd64"}}}}
            ]}}"#
        );
        let image = format!(
            r#"{{"digest": "sha256:{image_hex}", "labels": null, "tags": null,
            "extra_attrs": {{"os": "linux", "config": {{"Labels": {{
                "org.opencontainers.image.revision": "{REVISION}",
                "org.opencontainers.image.source": "https://github.com/octo/app"}}}}}}}}"#
        );
        let mut fake = FakeHarbor::new(&index, (200, &report_body()));
        fake.by_digest = vec![
            (image_hex.clone(), image.into_bytes()),
            (attestation_hex.clone(), b"{}".to_vec()),
        ];
        let harbor = Arc::new(fake);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);

        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;

        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1);
        assert_eq!(lock(&scanner.sent)[0].1, REVISION);
        let urls = lock(&harbor.urls).clone();
        assert_eq!(urls.len(), 3, "index, image child, report: {urls:?}");
        assert!(urls[1].ends_with(&image_hex));
        assert!(!urls.iter().any(|u| u.contains(&attestation_hex)));
        // The report is the event digest's, not the child's.
        assert!(urls[2].contains("sha256") && urls[2].ends_with("/additions/vulnerabilities"));
        assert!(!urls[2].contains(&image_hex));
    }

    #[tokio::test]
    async fn source_mismatch_fails_without_upload() {
        let fx = Fixture::new("source").await;
        let labels = format!(
            r#"{{"org.opencontainers.image.revision": "{REVISION}", "org.opencontainers.image.source": "https://github.com/octo/other"}}"#
        );
        let harbor = Arc::new(FakeHarbor::new(&artifact(&labels), (200, &report_body())));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert!(matches!(outcome, JobOutcome::Permanent(ref m) if m.contains("source")));
        assert_eq!(scanner.uploads(), 0);
        assert!(fx.report().await.is_none());
    }

    #[tokio::test]
    async fn report_not_yet_fails_for_backoff() {
        let fx = Fixture::new("notyet").await;
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (200, "{}")));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_NOT_YET.to_owned()));
        assert_eq!(scanner.uploads(), 0);
    }

    #[tokio::test]
    async fn harbor_404_fails_for_backoff() {
        let fx = Fixture::new("h404").await;
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (404, "{}")));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_NOT_YET.to_owned()));
        assert_eq!(scanner.uploads(), 0);
    }

    #[tokio::test]
    async fn too_large_records_failed_report_and_uploads_nothing() {
        // Random base64 characters barely compress, so the SARIF stays over 10 MB gzipped.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let description: String = (0..16_000_000)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                char::from(ALPHABET[((state >> 33) % 64) as usize])
            })
            .collect();
        let report = json!({TRIVY_REPORT_MIME: {"vulnerabilities": [
            {"id": "CVE-2026-0001", "package": "p", "version": "1", "severity": "High",
             "description": description}
        ]}})
        .to_string();
        let fx = Fixture::new("large").await;
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (200, &report)));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_TOO_LARGE.to_owned()));
        assert_eq!(scanner.uploads(), 0);
        let (status, sarif_id, error, _, _) = fx.report().await.unwrap();
        assert_eq!(status, "failed");
        assert_eq!(sarif_id, None);
        assert_eq!(error.as_deref(), Some(MSG_TOO_LARGE));
    }

    #[tokio::test]
    async fn pending_after_five_minutes_keeps_sarif_id_and_fails() {
        let fx = Fixture::new("pending").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Pending)]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_PENDING.to_owned()));
        let sleeps = lock(&fx.sleeps).clone();
        assert_eq!(sleeps[..3], [FIRST_WAIT, SECOND_WAIT, LATER_WAIT]);
        assert_eq!(sleeps.iter().sum::<Duration>(), MAX_WAIT);
        assert!(sleeps[2..].iter().all(|d| *d == LATER_WAIT));
        let (status, sarif_id, _, _, _) = fx.report().await.unwrap();
        assert_eq!(status, "pending");
        assert_eq!(sarif_id.as_deref(), Some("sarif-1"));
        assert_eq!(scanner.uploads(), 1);
    }

    #[tokio::test]
    async fn retry_with_sarif_id_polls_without_reupload() {
        let fx = Fixture::new("retry").await;
        let new = NewReport {
            id: "r1",
            mapping_id: "m1",
            sync_job_id: "j1",
            harbor_repository: "app",
            image_tag: "v1",
            image_digest: "sha256:aaaa",
            commit_sha: Some(REVISION),
            vulnerability_summary: "{}",
        };
        let mut conn = fx.pool.acquire().await.unwrap();
        report_db::insert_pending(&mut conn, &new).await.unwrap();
        drop(conn);
        report_db::set_sarif_id(&fx.pool, "r1", "sarif-9")
            .await
            .unwrap();

        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("unused".to_owned()), vec![Ok(Processing::Complete)]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 0);
        // Only the Harbor report is read again, and only because GitHub said Complete.
        // The artifact labels are not read again.
        assert_eq!(harbor.calls(), 1);
        assert_eq!(scanner.status_calls.load(Ordering::SeqCst), 1);
        let (status, sarif_id, _, _, _) = fx.report().await.unwrap();
        assert_eq!(status, "success");
        assert_eq!(sarif_id.as_deref(), Some("sarif-9"));
        // The findings of the tag are applied on Complete, on the retry path too.
        let applied: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cve_findings WHERE mapping_id = 'm1' AND image_tag = 'v1' AND status = 'open'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(applied, 4);
    }

    #[tokio::test]
    async fn retry_with_sarif_id_that_stays_pending_applies_no_findings() {
        let fx = Fixture::new("retry-pending").await;
        let new = NewReport {
            id: "r1",
            mapping_id: "m1",
            sync_job_id: "j1",
            harbor_repository: "app",
            image_tag: "v1",
            image_digest: "sha256:aaaa",
            commit_sha: Some(REVISION),
            vulnerability_summary: "{}",
        };
        let mut conn = fx.pool.acquire().await.unwrap();
        report_db::insert_pending(&mut conn, &new).await.unwrap();
        drop(conn);
        report_db::set_sarif_id(&fx.pool, "r1", "sarif-9")
            .await
            .unwrap();

        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("unused".to_owned()), vec![Ok(Processing::Pending)]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_PENDING.to_owned()));
        assert_eq!(harbor.calls(), 0);
        let findings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_findings")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(findings, 0);
    }

    #[tokio::test]
    async fn rate_limit_defers() {
        let fx = Fixture::new("rate").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Err(ScanError::RateLimited { until: 5_000 }), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert!(matches!(outcome, JobOutcome::Deferred { until: 5_000, .. }));

        // A rate limit while polling defers too, and the report keeps its SARIF id.
        let fx = Fixture::new("rate-status").await;
        let scanner = FakeScanner::new(
            Ok("sarif-1".to_owned()),
            vec![Err(ScanError::RateLimited { until: 7_000 })],
        );
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert!(matches!(outcome, JobOutcome::Deferred { until: 7_000, .. }));
        let (status, sarif_id, _, _, _) = fx.report().await.unwrap();
        assert_eq!(status, "pending");
        assert_eq!(sarif_id.as_deref(), Some("sarif-1"));
    }

    #[tokio::test]
    async fn github_failed_processing_records_errors() {
        let fx = Fixture::new("ghfail").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(
            Ok("sarif-1".to_owned()),
            vec![Ok(Processing::Failed(vec![
                "rule id is missing".to_owned(),
                "too many results".to_owned(),
            ]))],
        );
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Done);
        let (status, _, error, _, _) = fx.report().await.unwrap();
        assert_eq!(status, "failed");
        assert_eq!(
            error.as_deref(),
            Some("rule id is missing; too many results")
        );
        // A report GitHub refused changes no findings.
        let findings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_findings")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(findings, 0);
    }

    #[tokio::test]
    async fn deleted_mapping_fails_cleanly() {
        let fx = Fixture::new("gone").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let mut job = fx.job();
        job.mapping_id = "no-such-mapping".to_owned();
        let outcome = fx.handler(&harbor, &scanner).run(job).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_GONE.to_owned()));
        assert_eq!(harbor.calls(), 0);
        assert_eq!(scanner.uploads(), 0);
    }

    #[tokio::test]
    async fn complete_scan_creates_the_issue_with_the_scan_label() {
        let fx = Fixture::new("issues").await;
        sqlx::query("UPDATE repo_mappings SET auto_create_issues = 1 WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let github = Arc::new(FakeGithub::default());
        let outcome = fx
            .handler_with(&harbor, &scanner, github.clone())
            .run(fx.job())
            .await;
        assert_eq!(outcome, JobOutcome::Done);
        // CVE-2026-0001 is the only CRITICAL finding in the report.
        let creates = github.creates();
        assert_eq!(creates.len(), 1);
        assert_eq!(
            creates[0]["title"],
            "CVE-2026-0001: openssl (CRITICAL) in proj/app"
        );
    }

    #[tokio::test]
    async fn rate_limit_during_issue_updates_finishes_the_job_done() {
        let fx = Fixture::new("issues-limited").await;
        sqlx::query("UPDATE repo_mappings SET auto_create_issues = 1 WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let github = Arc::new(FakeGithub::default());
        github.with(|state| state.rate_limited = true);

        let outcome = fx
            .handler_with(&harbor, &scanner, github.clone())
            .run(fx.job())
            .await;

        // The job is Done, not Deferred, so it is not run again and the SARIF is not
        // uploaded a second time.
        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1);
        assert_eq!(github.requests(), 1);
        let (status, ..) = fx.report().await.unwrap();
        assert_eq!(status, "success");
        let reports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_reports")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(reports, 1);
        let findings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_findings")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(findings, 4);
    }

    #[tokio::test]
    async fn database_error_during_issue_updates_finishes_the_job_done() {
        let fx = Fixture::new("issues-db-error").await;
        sqlx::query("UPDATE repo_mappings SET auto_create_issues = 1 WHERE id = 'm1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        // Only the issue step reads the acceptances. With the table gone, the findings are
        // applied and the report is `success`, and then the issue step fails on the database.
        sqlx::query("DROP TABLE cve_acceptances")
            .execute(&fx.pool)
            .await
            .unwrap();
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let github = Arc::new(FakeGithub::default());

        let outcome = fx
            .handler_with(&harbor, &scanner, github.clone())
            .run(fx.job())
            .await;

        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1);
        let (status, ..) = fx.report().await.unwrap();
        assert_eq!(status, "success");
        // The findings were applied before the issue step failed.
        let findings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_findings")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(findings, 4);
        assert_eq!(github.requests(), 0);
    }

    /// A notifier whose sender records every alert and makes no network connection.
    fn recording_notifier(pool: &SqlitePool) -> (Notifier, Arc<Mutex<Vec<Alert>>>) {
        let sent: Arc<Mutex<Vec<Alert>>> = Arc::new(Mutex::new(Vec::new()));
        let log = sent.clone();
        let notifier =
            Notifier::with_sender(pool.clone(), Arc::new(key()), move |_config, alert| {
                lock(&log).push(alert);
                Box::pin(async { Ok(()) })
            });
        (notifier, sent)
    }

    /// One enabled webhook channel. Its URL is never contacted: the sender is a recorder.
    async fn seed_channel(pool: &SqlitePool) {
        let actor = Actor {
            user_id: Some("u1".to_owned()),
            username: "u1".to_owned(),
        };
        alert_channels::create(
            pool,
            &key(),
            &actor,
            false,
            "webhook",
            true,
            json!({"url": "https://hooks.example.test/services/FAKE_URL_TOKEN_1"}),
        )
        .await
        .unwrap();
    }

    /// The `alert_deliveries` dedupe keys, sorted.
    async fn delivery_keys(pool: &SqlitePool) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT dedupe_key FROM alert_deliveries ORDER BY dedupe_key",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// Waits until `wanted` is among the delivery keys. The alert tasks run in the
    /// background, so the rows appear shortly after the handler returns.
    async fn wait_for_key(pool: &SqlitePool, wanted: &str) {
        for _ in 0..200 {
            if delivery_keys(pool).await.iter().any(|key| key == wanted) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the expected delivery row did not appear");
    }

    #[tokio::test]
    async fn a_complete_scan_alerts_each_new_critical_cve_once_across_mappings() {
        let fx = Fixture::new("alert-critical").await;
        seed_channel(&fx.pool).await;
        let (notifier, sent) = recording_notifier(&fx.pool);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);

        // Mapping m1 finds CVE-2026-0001 as CRITICAL.
        let harbor = ok_harbor();
        let outcome = fx
            .handler(&harbor, &scanner)
            .with_alerts(notifier.clone())
            .run(fx.job())
            .await;
        assert_eq!(outcome, JobOutcome::Done);
        wait_for_key(&fx.pool, "CVE-2026-0001").await;
        assert_eq!(delivery_keys(&fx.pool).await, vec!["CVE-2026-0001"]);
        {
            let alerts = lock(&sent);
            assert_eq!(alerts.len(), 1);
            assert_eq!(alerts[0].event, AlertEvent::CriticalCve);
            assert_eq!(alerts[0].cve_id.as_deref(), Some("CVE-2026-0001"));
            assert_eq!(alerts[0].image_tag.as_deref(), Some("v1"));
            assert_eq!(alerts[0].mapping_id, "m1");
            assert_eq!(alerts[0].harbor, "proj/app");
            assert_eq!(alerts[0].github, "octo/app");
        }

        // A second mapping finds the same CVE, and one more that is new. The alerts run in
        // order, so once the second key is stored the first one has been decided.
        sqlx::query(
            "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash, auto_create_issues, min_issue_severity, default_branch)
             VALUES ('m2', 'u1', 'c1', 'c2', 'https://harbor.example.com', 'proj', 'other', 'octo', 'other', 'h3', 'h4', 0, 'CRITICAL', 'main')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        let labels = artifact(&format!(
            r#"{{"org.opencontainers.image.revision": "{REVISION}"}}"#
        ));
        let report = format!(
            r#"{{"{TRIVY_REPORT_MIME}": {{"vulnerabilities": [
                {{"id": "CVE-2026-0001", "package": "openssl", "version": "1", "severity": "Critical"}},
                {{"id": "CVE-2026-0099", "package": "curl", "version": "1", "severity": "Critical"}}
            ]}}}}"#
        );
        let harbor_two = Arc::new(FakeHarbor::new(&labels, (200, &report)));
        let scanner_two =
            FakeScanner::new(Ok("sarif-2".to_owned()), vec![Ok(Processing::Complete)]);
        let mut job = fx.job();
        job.id = "j2".to_owned();
        job.mapping_id = "m2".to_owned();
        db::sync_jobs::enqueue(&fx.pool, "j2", "m2", &job.payload, 1_000)
            .await
            .unwrap();
        let outcome = fx
            .handler(&harbor_two, &scanner_two)
            .with_alerts(notifier)
            .run(job)
            .await;
        assert_eq!(outcome, JobOutcome::Done);
        wait_for_key(&fx.pool, "CVE-2026-0099").await;

        // The shared CVE was not sent a second time, and the new one was.
        assert_eq!(
            delivery_keys(&fx.pool).await,
            vec!["CVE-2026-0001", "CVE-2026-0099"]
        );
        let alerts = lock(&sent);
        let ids: Vec<&str> = alerts
            .iter()
            .filter_map(|alert| alert.cve_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["CVE-2026-0001", "CVE-2026-0099"]);
        assert_eq!(alerts[1].mapping_id, "m2");
    }

    #[tokio::test]
    async fn the_sync_handler_alerts_when_the_worker_gives_up_a_job() {
        let fx = Fixture::new("alert-give-up").await;
        seed_channel(&fx.pool).await;
        let (notifier, sent) = recording_notifier(&fx.pool);
        // The report never becomes available, so every attempt fails. This is the last one.
        sqlx::query("UPDATE sync_jobs SET attempts = 7 WHERE id = 'j1'")
            .execute(&fx.pool)
            .await
            .unwrap();
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (200, "{}")));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let handler = Arc::new(fx.handler(&harbor, &scanner).with_alerts(notifier));

        let step = crate::worker::step(&fx.pool, &handler, 1_000)
            .await
            .unwrap();
        assert_eq!(step, crate::worker::Step::GaveUp);
        wait_for_key(&fx.pool, "sync_failed:j1").await;

        assert_eq!(delivery_keys(&fx.pool).await, vec!["sync_failed:j1"]);
        let alerts = lock(&sent);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event, AlertEvent::SyncFailed);
        assert_eq!(alerts[0].mapping_id, "m1");
        assert_eq!(alerts[0].harbor, "proj/app");
        assert_eq!(alerts[0].github, "octo/app");
    }

    #[tokio::test]
    async fn a_failed_attempt_that_will_retry_sends_no_alert() {
        let fx = Fixture::new("alert-retry").await;
        seed_channel(&fx.pool).await;
        let (notifier, sent) = recording_notifier(&fx.pool);
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (200, "{}")));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let handler = Arc::new(fx.handler(&harbor, &scanner).with_alerts(notifier));

        let step = crate::worker::step(&fx.pool, &handler, 1_000)
            .await
            .unwrap();
        assert!(matches!(step, crate::worker::Step::Retry { .. }));
        // Nothing was spawned, so a short wait is enough to see that nothing arrives.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(delivery_keys(&fx.pool).await.is_empty());
        assert!(lock(&sent).is_empty());
    }
}
