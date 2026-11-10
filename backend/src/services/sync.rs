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
use crate::db::scanner_reports as scanner_db;
use crate::db::sync_jobs::ClaimedJob;
use crate::db::sync_reports::{self as report_db, NewReport};
use crate::error::AppError;
use crate::services::alerts::Notifier;
use crate::services::artifact_removal;
use crate::services::credentials::{base_for_join, decrypt_token};
use crate::services::github_issues::GithubIssues;
use crate::services::github_scanning::{
    GithubScanning, Processing, ScanError, Upload, encode_sarif,
};
use crate::services::github_url::GithubTarget;
use crate::services::harbor_client::{
    HarborGet, HarborReply, ReportState, TRIVY_REPORT_MIME, artifact_url, branch_for, check_source,
    index_image_child, parse_artifact_tags, parse_labels, parse_report, require_revision,
    vulnerabilities_url,
};
use crate::services::issue_lifecycle::{self, IssueApi};
use crate::services::resolve::{self, JobKind};
use crate::services::{
    findings, ids, merged_view, sarif, scanner_scan, scanner_store, scheduled_scan,
};
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
/// The note of a webhook job whose scanner matches no registration. Catalog key
/// `sync.note.scannerUnmatched`.
pub const NOTE_SCANNER_UNMATCHED: &str = "scanner not recognised";
const MSG_TOO_LARGE: &str = "SARIF over 10 MB compressed";
const MSG_PENDING: &str = "GitHub processing still pending";

/// The job payload (`specs/integrations.md`): `{repo_full_name, digest, tag}`. The Harbor
/// project and repository come from the mapping, which the webhook already matched to
/// `repo_full_name`, so that field is not read. `trigger` is read only to tell a scheduled
/// scan (#191), whose report records the CVE ids that are new for the digest.
#[derive(Debug, Deserialize)]
struct Payload {
    digest: String,
    tag: String,
    #[serde(default)]
    trigger: Option<String>,
    /// Set by the job a scanner scan queues after it stored a report (#224, step 8). The job then
    /// reads the merged stored reports of the digest, not Harbor's current-scanner report.
    #[serde(default)]
    scanner_uuid: Option<String>,
    /// The scanner name of the webhook event (#224 d10). Absent for a poll job and an event with no
    /// scan overview.
    #[serde(default)]
    scanner_name: Option<String>,
}

/// What [`SyncHandler::read_and_convert`] returns: the encoded SARIF (`None` when over the
/// size limit), the severity summary, the commit SHA, the branch, the parsed Harbor report and
/// the tag's push time in Unix milliseconds.
type Converted = (Option<String>, String, String, String, Value, Option<i64>);

/// Reads from Harbor. The production impl is [`HarborGet`]; tests use recorded answers.
pub trait HarborFetch: Send + Sync + 'static {
    fn fetch(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> impl Future<Output = Result<HarborReply, AppError>> + Send;

    /// Sends one JSON `POST`. The scheduled scan (#191) and the scanner job (#224) use it, to
    /// start a Harbor scan. The default refuses, so a reader that never starts a scan (the poller,
    /// the pull, the read-only test fakes) needs no implementation.
    fn post_json(
        &self,
        _url: &Url,
        _username: &str,
        _secret: &[u8],
        _body: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> impl Future<Output = Result<HarborReply, AppError>> + Send {
        std::future::ready(Err(AppError::InternalError))
    }

    /// Sends one JSON `PUT` with extra headers. Only the scanner job uses it, to set the project
    /// scanner (#224). The default refuses.
    fn put_json(
        &self,
        _url: &Url,
        _username: &str,
        _secret: &[u8],
        _body: &[u8],
        _extra_headers: &[(&str, &str)],
    ) -> impl Future<Output = Result<HarborReply, AppError>> + Send {
        std::future::ready(Err(AppError::InternalError))
    }
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

    async fn post_json(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        HarborGet::post_json(self, url, username, secret, body, extra_headers).await
    }

    async fn put_json(
        &self,
        url: &Url,
        username: &str,
        secret: &[u8],
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HarborReply, AppError> {
        HarborGet::put_json(self, url, username, secret, body, extra_headers).await
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
    /// The configured GitHub URLs. The web URL is the host the source label must name.
    github_target: GithubTarget,
}

impl SyncHandler {
    /// Builds the production handler: the guarded Harbor and GitHub clients and the
    /// system clock.
    pub fn new(
        pool: SqlitePool,
        credentials_key: Arc<DerivedKey>,
        allow_private_harbor: bool,
        allow_private_alerts: bool,
        github_target: GithubTarget,
    ) -> Result<Self, AppError> {
        let alerts = Notifier::new(pool.clone(), credentials_key.clone(), allow_private_alerts);
        Ok(Self {
            pool,
            credentials_key,
            harbor: HarborGet::new(allow_private_harbor)?,
            github: GithubScanning::new(github_target.clone())?,
            clock: SystemClock,
            issues: GithubIssues::new(github_target.clone())?,
            alerts,
            github_target,
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
            github_target: GithubTarget::default(),
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
    job_id: String,
    mapping: MappingRow,
    harbor_username: String,
    harbor_secret: Zeroizing<Vec<u8>>,
    github_token: Zeroizing<Vec<u8>>,
    payload: Payload,
    /// True once this job's report is read from the stored scanner reports (the merged view), not
    /// from Harbor's current-scanner report (#224).
    merged: bool,
}

impl Context {
    fn reads_merged(&self) -> bool {
        self.merged
            || self
                .payload
                .scanner_uuid
                .as_deref()
                .is_some_and(|uuid| !uuid.is_empty())
    }
}

impl<H: HarborFetch, G: CodeScanning, C: Clock, I: IssueApi> SyncHandler<H, G, C, I> {
    async fn execute(&self, job: &ClaimedJob) -> Flow<()> {
        let mut context = self.load(job).await?;

        let existing = report_db::find_pending_for_job(&self.pool, &job.id)
            .await
            .map_err(database)?;
        if let Some(report) = &existing
            && let Some(sarif_id) = &report.github_sarif_id
        {
            // A retry after a pending wait: poll the same upload, never upload twice. The
            // report is read again only if GitHub reports `Complete`. If the first attempt stored
            // the scanner reports, the retry reads them too.
            context.merged = self.has_stored_reports(&context).await?;
            return self
                .wait_for_processing(&context, &report.id, sarif_id, None)
                .await;
        }

        let (sarif_b64, summary, revision, branch, vuln_report, push_time) =
            self.read_and_convert(&context).await?;
        // The report is the merged view of the stored scanner reports from here on.
        context.merged = true;

        // A pending report left by an earlier attempt that never uploaded is reused.
        let report_id = match existing {
            Some(report) => report.id,
            None => {
                let id = ids::new_id().map_err(internal)?;
                // TODO(spinoff part 2): the mapping id stands in for the source id, and the push
                // time (Harbor only) is no longer stored.
                let _ = push_time;
                let new = NewReport {
                    id: &id,
                    source_id: &job.mapping_id,
                    sync_job_id: &job.id,
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
            job_id: job.id.clone(),
            mapping,
            payload,
            merged: false,
        })
    }

    fn decrypt(&self, row: &CredentialRow) -> Flow<Zeroizing<Vec<u8>>> {
        decrypt_token(&self.credentials_key, row).map_err(|_| failed(MSG_DECRYPT))
    }

    /// Reads the labels and the report from Harbor and converts the report. Returns the
    /// encoded SARIF (`None` when it is over 10 MB compressed), the severity summary, the
    /// commit SHA, the branch and the parsed Harbor report.
    async fn read_and_convert(&self, context: &Context) -> Flow<Converted> {
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
        let body = self.harbor_body(context, &artifact, &[]).await?;
        // The tag's push time on this digest, for the newest-digest issue rule (#196). A body
        // that cannot be read as tags, or a tag Harbor gave no time, leaves it `None`.
        let push_time = parse_artifact_tags(&body).ok().and_then(|tags| {
            tags.iter()
                .find(|tag| tag.name == context.payload.tag)
                .and_then(|tag| resolve::push_millis(tag.push_time.as_deref()))
        });
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
            let child_body = self.harbor_body(context, &child_url, &[]).await?;
            labels = parse_labels(&child_body)
                .map_err(|_| failed("Harbor returned an artifact that could not be read"))?;
        }
        let revision = require_revision(&labels)
            .map_err(|e| permanent_validation(e, "the image has no revision label"))?
            .to_owned();
        check_source(
            &labels,
            self.github_target.current().web_url(),
            &mapping.github_owner,
            &mapping.github_repo,
        )
        .map_err(|e| permanent_validation(e, "the image source label does not match"))?;
        let branch = branch_for(&labels, &mapping.default_branch);

        // A job from a webhook, a poll or a resolve fan-out reads Harbor's report for the project's
        // current scanner and stores it under that scanner (#224). A job a scanner scan queued
        // reads the stored reports instead. Either way the report used below is the merged view.
        if !context.reads_merged() {
            self.ingest_current_report(context).await?;
        }
        let report = self.merged_report(context).await?;

        let document = sarif::convert(&report, &mapping.harbor_project, &mapping.harbor_repository)
            .map_err(|_| failed("the Harbor report could not be converted to SARIF"))?;
        let summary = summarize(&report);
        let encoded = match encode_sarif(&document) {
            Ok(encoded) => Some(encoded),
            Err(ScanError::TooLarge) => None,
            Err(other) => return Err(scan_outcome(other)),
        };
        Ok((encoded, summary, revision, branch, report, push_time))
    }

    /// Reads and parses the Trivy report from Harbor. `NotYet` and a `404` fail the job for
    /// backoff.
    async fn fetch_report(&self, context: &Context) -> Flow<Value> {
        if context.reads_merged() {
            return self.merged_report(context).await;
        }
        self.fetch_harbor_report(context).await
    }

    /// Whether the mapping has a stored scanner report for this job's digest.
    async fn has_stored_reports(&self, context: &Context) -> Flow<bool> {
        let reports = scanner_db::reports_for_digest(
            &self.pool,
            &context.mapping.id,
            &context.payload.digest,
        )
        .await
        .map_err(database)?;
        Ok(!reports.is_empty())
    }

    /// Reads Harbor's report for the project's current scanner and stores it under that scanner
    /// (#224 d10, `specs/integrations.md`, "Webhook and poll jobs").
    ///
    /// - Call 1 gives the current scanner. A `403` (no Scanner Read) stores the report under the
    ///   unknown scanner.
    /// - An event that names another scanner stores nothing here: a registered scanner of that name
    ///   gets a fetch-only `scanner_scan` job, and this job ends `done`. A name no registration
    ///   matches (after one refresh of the scanner list) ends `done` with `scanner not recognised`.
    /// - Otherwise the report is stored under the current scanner. The first such store replaces the
    ///   digest's migrated `unknown` report.
    async fn ingest_current_report(&self, context: &Context) -> Flow<()> {
        let mapping = &context.mapping;
        let current = scanner_scan::current_scanner(
            &self.pool,
            &self.harbor,
            &self.clock,
            mapping,
            &context.harbor_username,
            &context.harbor_secret,
        )
        .await?;
        let identity = match current {
            None => scanner_store::Identity::Unknown,
            Some(current) => {
                if let Some(event_name) = context
                    .payload
                    .scanner_name
                    .as_deref()
                    .filter(|name| *name != current.name)
                {
                    return self
                        .delegate_to_event_scanner(context, event_name, &current.uuid)
                        .await;
                }
                scanner_store::Identity::Known {
                    uuid: current.uuid,
                    name: current.name,
                }
            }
        };
        let report = self.fetch_harbor_report(context).await?;
        scanner_store::store_normal(
            &self.pool,
            &mapping.id,
            &context.payload.digest,
            &identity,
            &report,
            self.clock.now(),
        )
        .await
        .map_err(database)
    }

    /// The event came from a scanner other than the project's current one. Always ends the job:
    /// `Err(Done)` after queueing the fetch, or `Err(DoneWithNote)` when no registration matches.
    async fn delegate_to_event_scanner(
        &self,
        context: &Context,
        event_name: &str,
        current_uuid: &str,
    ) -> Flow<()> {
        let mapping = &context.mapping;
        let mut matched = self
            .registered_scanners_named(mapping, event_name, current_uuid)
            .await?;
        if matched.is_empty() {
            // One refresh by call 2, then match again. A refusal leaves the name unmatched.
            scanner_scan::refresh_scanners(
                &self.pool,
                &self.harbor,
                &self.clock,
                mapping,
                &context.harbor_username,
                &context.harbor_secret,
            )
            .await?;
            matched = self
                .registered_scanners_named(mapping, event_name, current_uuid)
                .await?;
        }
        // Names are not known to be unique (UNVERIFIED): two matches are ambiguous, and a report is
        // never fetched under a guessed scanner.
        let [uuid] = matched.as_slice() else {
            return Err(JobOutcome::DoneWithNote(NOTE_SCANNER_UNMATCHED.to_owned()));
        };
        scanner_scan::queue_fetch_only(
            &self.pool,
            mapping,
            &context.payload.tag,
            uuid,
            self.clock.now(),
        )
        .await
        .map_err(database)?;
        Err(JobOutcome::Done)
    }

    /// The UUIDs of the enabled, not removed scanners of this Harbor whose name equals `name`
    /// (case-sensitive), leaving out the project's current scanner.
    async fn registered_scanners_named(
        &self,
        mapping: &MappingRow,
        name: &str,
        current_uuid: &str,
    ) -> Flow<Vec<String>> {
        let rows = scanner_db::list_scanners(&self.pool, &mapping.harbor_base_url)
            .await
            .map_err(database)?;
        Ok(rows
            .into_iter()
            .filter(|row| {
                row.name == name
                    && !row.disabled
                    && row.removed_at.is_none()
                    && row.uuid != current_uuid
            })
            .map(|row| row.uuid)
            .collect())
    }

    /// The Harbor half of [`Self::fetch_report`]: the report of the project's current scanner.
    async fn fetch_harbor_report(&self, context: &Context) -> Flow<Value> {
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
            )
            .await?;
        match parse_report(&body)
            .map_err(|_| failed("Harbor returned a report that could not be read"))?
        {
            ReportState::Ready(report) => Ok(report),
            ReportState::NotYet => Err(failed(MSG_NOT_YET)),
        }
    }

    /// The merged view of the stored scanner reports of the digest, as a report (#224 d2, d6): one
    /// item per (CVE id, package), with the scanners that found it. A digest with no stored report
    /// fails the job for backoff, like a report Harbor does not have yet.
    async fn merged_report(&self, context: &Context) -> Flow<Value> {
        let mapping = &context.mapping;
        let merged = merged_view::load(
            &self.pool,
            &mapping.id,
            &mapping.harbor_base_url,
            &context.payload.digest,
        )
        .await
        .map_err(database)?;
        if merged.scanners.is_empty() {
            return Err(failed(MSG_NOT_YET));
        }
        Ok(merged_view::to_report(&merged.findings))
    }

    /// One Harbor GET. `404` on the report is the backoff case, a `404` on an artifact is final; any other non-200 fails.
    async fn harbor_body(
        &self,
        context: &Context,
        url: &Url,
        headers: &[(&str, &str)],
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
            // The artifact is gone: the image was deleted after the job was queued. Final.
            404 => Err(JobOutcome::DoneWithNote(
                resolve::NOTE_ARTIFACT_GONE.to_owned(),
            )),
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

    /// The CVE ids of this scan as a JSON array and, for a scheduled scan only, the ids not in
    /// the last stored result for the same digest (#191). A report from before migration 0008
    /// has no stored ids, so the open findings of its tag stand in for them.
    async fn cve_result(
        &self,
        context: &Context,
        vuln_report: &Value,
    ) -> Flow<(String, Option<String>)> {
        let ids = scheduled_scan::report_cve_ids(vuln_report);
        let encoded = serde_json::to_string(&ids).map_err(|_| failed(MSG_INTERNAL))?;
        if context.payload.trigger.as_deref() != Some(scheduled_scan::TRIGGER_SCHEDULE) {
            return Ok((encoded, None));
        }
        let mapping = &context.mapping;
        // TODO(spinoff part 2): the mapping id is passed as the source id until the Harbor
        // sync path is ported. The result carries no cve_ids (they are not stored any more).
        let previous = report_db::last_result_for_digest(
            &self.pool,
            &mapping.id,
            &context.payload.digest,
            &context.job_id,
        )
        .await
        .map_err(database)?;
        let previous = match previous {
            None => None,
            Some((_, Some(stored))) => Some(stored),
            Some((tag, None)) => {
                let open = crate::db::findings::open_ids_for_tag(
                    &self.pool,
                    &mapping.id,
                    &mapping.harbor_repository,
                    &tag,
                )
                .await
                .map_err(database)?;
                Some(serde_json::to_string(&open).map_err(|_| failed(MSG_INTERNAL))?)
            }
        };
        let new_ids = scheduled_scan::new_cve_ids(&ids, previous.as_deref());
        let new_encoded = serde_json::to_string(&new_ids).map_err(|_| failed(MSG_INTERNAL))?;
        Ok((encoded, Some(new_encoded)))
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
                    // The last stored result for the digest is read before this scan's
                    // findings replace the tag's rows (#191).
                    // The ids are written while the report is still pending, so a crash between
                    // the two writes leaves a pending report that the retry completes again.
                    let (cve_ids, new_ids) = self.cve_result(context, vuln_report).await?;
                    // TODO(spinoff part 2): publish_reports has no cve_ids columns; the CVE set is
                    // read from cve_findings. The Harbor sync path is ported in part 2.
                    let _ = (cve_ids, new_ids);
                    report_db::finish(&self.pool, report_id, "success", None, self.clock.now())
                        .await
                        .map_err(database)?;
                    // `cve_findings` has one row per CVE id; a merged report has one item per
                    // (CVE id, package), so the first package of each id is kept (#224).
                    let per_cve;
                    let for_findings = if context.reads_merged() {
                        per_cve = merged_view::first_per_cve(vuln_report);
                        &per_cve
                    } else {
                        vuln_report
                    };
                    let applied = findings::apply_scan(
                        &self.pool,
                        &mapping.id,
                        &mapping.harbor_repository,
                        &context.payload.tag,
                        for_findings,
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
            JobKind::Sync => {
                let outcome = match self.execute(&job).await {
                    Ok(()) => JobOutcome::Done,
                    Err(outcome) => outcome,
                };
                artifact_removal::settle_gone(&self.pool, &job, outcome).await
            }
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
            JobKind::Scan => {
                scheduled_scan::run_job(
                    &self.pool,
                    &self.credentials_key,
                    &self.harbor,
                    &self.clock,
                    &job,
                )
                .await
            }
            JobKind::ScannerScan => {
                let outcome = scanner_scan::run_job(
                    &self.pool,
                    &self.credentials_key,
                    &self.harbor,
                    &self.clock,
                    &job,
                )
                .await;
                artifact_removal::settle_gone(&self.pool, &job, outcome).await
            }
            JobKind::ScannerRestore => {
                scanner_scan::run_restore_job(
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
        /// The project's current scanner (uuid, name), answered to call 1. `None` is a `403`.
        current: Mutex<Option<(String, String)>>,
        /// The body of the scanner list, answered to call 2. `None` is a `403`.
        candidates: Mutex<Option<String>>,
        /// How many scanner list reads were made.
        candidate_reads: AtomicUsize,
    }

    impl FakeHarbor {
        /// Gives the robot Scanner Read (the current scanner) and Create (the list).
        fn with_scanners(self, current: (&str, &str), candidates: &str) -> Arc<Self> {
            *lock(&self.current) = Some((current.0.to_owned(), current.1.to_owned()));
            *lock(&self.candidates) = Some(candidates.to_owned());
            Arc::new(self)
        }

        fn new(artifact: &str, report: (u16, &str)) -> Self {
            Self {
                artifact: (200, artifact.as_bytes().to_vec()),
                by_digest: Vec::new(),
                report: (report.0, report.1.as_bytes().to_vec()),
                urls: Mutex::new(Vec::new()),
                report_headers: Mutex::new(Vec::new()),
                current: Mutex::new(None),
                candidates: Mutex::new(None),
                candidate_reads: AtomicUsize::new(0),
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
            // The robot of these tests has no Scanner permissions (`403`), so the report is stored
            // under the unknown scanner. The scanner calls are not counted with the others.
            if url.path().ends_with("/scanner/candidates") {
                self.candidate_reads.fetch_add(1, Ordering::SeqCst);
                return Ok(match lock(&self.candidates).clone() {
                    Some(body) => HarborReply::new(200, body.into_bytes()),
                    None => HarborReply::new(403, Vec::new()),
                });
            }
            if url.path().ends_with("/scanner") {
                return Ok(match lock(&self.current).clone() {
                    Some((uuid, name)) => HarborReply::new(
                        200,
                        format!(r#"{{"uuid":"{uuid}","name":"{name}"}}"#).into_bytes(),
                    ),
                    None => HarborReply::new(403, Vec::new()),
                });
            }
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

    fn scanner_list(entries: &[(&str, &str)]) -> String {
        let items: Vec<Value> = entries
            .iter()
            .map(|(uuid, name)| json!({"uuid": uuid, "name": name, "disabled": false}))
            .collect();
        Value::Array(items).to_string()
    }

    fn event_payload(scanner_name: Option<&str>) -> String {
        let mut payload =
            json!({"repo_full_name": "proj/app", "digest": "sha256:aaaa", "tag": "v1"});
        if let Some(name) = scanner_name {
            payload["scanner_name"] = json!(name);
        }
        payload.to_string()
    }

    async fn stored_scanners(fx: &Fixture) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT scanner_uuid FROM scanner_reports WHERE mapping_id = 'm1' ORDER BY scanner_uuid",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap()
    }

    async fn seed_report(fx: &Fixture, uuid: &str, name: Option<&str>, cve: &str) {
        let id = ids::new_id().unwrap();
        let mut tx = fx.pool.begin().await.unwrap();
        crate::db::scanner_reports::replace_report(
            &mut tx,
            &crate::db::scanner_reports::NewScannerReport {
                id: &id,
                mapping_id: "m1",
                image_digest: "sha256:aaaa",
                scanner_uuid: uuid,
                scanner_name: name,
                scanner_vendor: None,
                scanner_version: None,
                image_push_time: None,
                stored_at: 1,
            },
            &[crate::db::scanner_reports::NewScannerFinding {
                cve_id: cve,
                package: "p",
                version: None,
                fixed_in_version: None,
                severity: "HIGH",
                cvss_v3: None,
                description: None,
            }],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// A webhook from the project's current scanner stores that scanner's report under its UUID.
    #[tokio::test]
    async fn a_webhook_from_the_current_scanner_stores_its_report() {
        let fx = Fixture::new("hook-current").await;
        let list = scanner_list(&[("uuid-a", "Trivy"), ("uuid-b", "Grype")]);
        let harbor = FakeHarbor::new(&good_artifact(), (200, &report_body()))
            .with_scanners(("uuid-a", "Trivy"), &list);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let mut job = fx.job();
        job.payload = event_payload(Some("Trivy"));
        assert_eq!(
            fx.handler(&harbor, &scanner).run(job).await,
            JobOutcome::Done
        );
        assert_eq!(stored_scanners(&fx).await, vec!["uuid-a".to_owned()]);
        assert_eq!(scanner.uploads(), 1);
    }

    /// A webhook from scanner B while A is the project's scanner stores nothing itself: it queues a
    /// fetch-only `scanner_scan` job for B, and A's report is untouched.
    #[tokio::test]
    async fn a_webhook_from_another_scanner_queues_a_fetch_only_job_and_keeps_the_others_report() {
        let fx = Fixture::new("hook-other").await;
        seed_report(&fx, "uuid-a", Some("Trivy"), "CVE-2026-9000").await;
        let list = scanner_list(&[("uuid-a", "Trivy"), ("uuid-b", "Grype")]);
        let harbor = FakeHarbor::new(&good_artifact(), (200, &report_body()))
            .with_scanners(("uuid-a", "Trivy"), &list);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let mut job = fx.job();
        job.payload = event_payload(Some("Grype"));
        assert_eq!(
            fx.handler(&harbor, &scanner).run(job).await,
            JobOutcome::Done
        );

        assert_eq!(
            scanner.uploads(),
            0,
            "nothing is uploaded for another scanner"
        );
        assert_eq!(
            lock(&harbor.report_headers).len(),
            0,
            "no report is read under the wrong scanner"
        );
        assert_eq!(stored_scanners(&fx).await, vec!["uuid-a".to_owned()]);
        let queued: Vec<String> = sqlx::query_scalar(
            "SELECT payload FROM sync_jobs WHERE json_extract(payload, '$.kind') = 'scanner_scan'",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(queued.len(), 1);
        let payload: Value = serde_json::from_str(&queued[0]).unwrap();
        assert_eq!(payload["scanner_uuid"], "uuid-b");
        assert_eq!(payload["fetch_only"], true);
        assert_eq!(payload["trigger"], "webhook");
        assert_eq!(payload["tag"], "v1");
    }

    /// A webhook naming a scanner no registration matches stores nothing, makes one list refresh,
    /// and ends done with the fixed note.
    #[tokio::test]
    async fn a_webhook_from_an_unknown_scanner_is_done_with_a_note() {
        let fx = Fixture::new("hook-unmatched").await;
        let list = scanner_list(&[("uuid-a", "Trivy")]);
        let harbor = FakeHarbor::new(&good_artifact(), (200, &report_body()))
            .with_scanners(("uuid-a", "Trivy"), &list);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let mut job = fx.job();
        job.payload = event_payload(Some("Mystery"));
        let outcome = fx.handler(&harbor, &scanner).run(job).await;
        assert_eq!(
            outcome,
            JobOutcome::DoneWithNote(NOTE_SCANNER_UNMATCHED.to_owned())
        );
        assert!(stored_scanners(&fx).await.is_empty());
        assert_eq!(harbor.candidate_reads.load(Ordering::SeqCst), 1);
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sync_jobs WHERE json_extract(payload, '$.kind') = 'scanner_scan'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(queued, 0);
    }

    /// The first normal sync with a known scanner replaces the migrated `unknown` report of the
    /// digest.
    #[tokio::test]
    async fn the_first_known_scanner_sync_replaces_the_unknown_report() {
        let fx = Fixture::new("replace-unknown").await;
        seed_report(&fx, "unknown", None, "CVE-2026-9000").await;
        let list = scanner_list(&[("uuid-a", "Trivy")]);
        let harbor = FakeHarbor::new(&good_artifact(), (200, &report_body()))
            .with_scanners(("uuid-a", "Trivy"), &list);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        assert_eq!(
            fx.handler(&harbor, &scanner).run(fx.job()).await,
            JobOutcome::Done
        );
        assert_eq!(stored_scanners(&fx).await, vec!["uuid-a".to_owned()]);
    }

    /// Without Scanner Read the report is stored as `unknown`, and it replaces the old unknown one.
    #[tokio::test]
    async fn a_sync_without_scanner_read_keeps_one_unknown_report() {
        let fx = Fixture::new("keep-unknown").await;
        seed_report(&fx, "unknown", None, "CVE-2026-9000").await;
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        assert_eq!(
            fx.handler(&harbor, &scanner).run(fx.job()).await,
            JobOutcome::Done
        );
        assert_eq!(stored_scanners(&fx).await, vec!["unknown".to_owned()]);
        let cves: Vec<String> = sqlx::query_scalar(
            "SELECT sf.cve_id FROM scanner_findings sf JOIN scanner_reports sr ON sr.id = sf.report_id
             WHERE sr.scanner_uuid = 'unknown' ORDER BY sf.cve_id",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert!(cves.contains(&"CVE-2026-0001".to_owned()));
        assert!(!cves.contains(&"CVE-2026-9000".to_owned()), "replaced");
    }

    /// A sync job queued after a scanner report was stored reads the merged stored reports, not
    /// Harbor: the CVE both scanners found is one finding, and the upload happens once (#224).
    #[tokio::test]
    async fn a_scanner_sync_uploads_the_merged_stored_reports() {
        let fx = Fixture::new("merged-sync").await;
        for (uuid, name, cves) in [
            ("u-1", "Grype", vec!["CVE-2026-0001", "CVE-2026-0002"]),
            ("u-2", "Trivy", vec!["CVE-2026-0001"]),
        ] {
            let id = ids::new_id().unwrap();
            let findings: Vec<crate::db::scanner_reports::NewScannerFinding<'_>> = cves
                .iter()
                .map(|cve| crate::db::scanner_reports::NewScannerFinding {
                    cve_id: cve,
                    package: "openssl",
                    version: Some("1"),
                    fixed_in_version: None,
                    severity: "HIGH",
                    cvss_v3: None,
                    description: None,
                })
                .collect();
            let mut tx = fx.pool.begin().await.unwrap();
            crate::db::scanner_reports::replace_report(
                &mut tx,
                &crate::db::scanner_reports::NewScannerReport {
                    id: &id,
                    mapping_id: "m1",
                    image_digest: "sha256:aaaa",
                    scanner_uuid: uuid,
                    scanner_name: Some(name),
                    scanner_vendor: None,
                    scanner_version: None,
                    image_push_time: None,
                    stored_at: 1,
                },
                &findings,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let payload = r#"{"repo_full_name":"proj/app","digest":"sha256:aaaa","tag":"v1","scanner_uuid":"u-2","trigger":"manual"}"#;
        let mut job = fx.job();
        job.payload = payload.to_owned();
        let harbor = ok_harbor();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let outcome = fx.handler(&harbor, &scanner).run(job).await;
        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1);
        assert!(
            lock(&harbor.report_headers).is_empty(),
            "the report came from the stored reports, not from Harbor"
        );
        let applied: Vec<String> = sqlx::query_scalar(
            "SELECT cve_id FROM cve_findings WHERE image_tag = 'v1' ORDER BY cve_id",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(applied, ["CVE-2026-0001", "CVE-2026-0002"]);
    }

    /// A scheduled scan (#191) records only the CVE ids that are not in the last stored result
    /// for the same digest, and the usual sync still runs (upload, findings). Other triggers
    /// store the ids but no new list. A clean scheduled scan reports nothing new.
    #[tokio::test]
    async fn a_scheduled_sync_records_only_the_new_ids_for_the_digest() {
        let fx = Fixture::new("scheduled-new").await;
        // A webhook sync of the same digest on another tag stored the last result: 0001, 0002.
        sqlx::query(
            "INSERT INTO sync_reports (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status, synced_at, cve_ids)
             VALUES ('r0', 'm1', NULL, 'app', 'v0', 'sha256:aaaa', '{}', 'success', 900, '[\"CVE-2026-0001\",\"CVE-2026-0002\"]')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        let payload = r#"{"repo_full_name":"proj/app","digest":"sha256:aaaa","tag":"v1","trigger":"schedule"}"#;
        sqlx::query("UPDATE sync_jobs SET payload = ? WHERE id = 'j1'")
            .bind(payload)
            .execute(&fx.pool)
            .await
            .unwrap();
        let mut job = fx.job();
        job.payload = payload.to_owned();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        let outcome = fx.handler(&ok_harbor(), &scanner).run(job).await;
        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 1, "the existing sync rules apply");
        let (all, new): (String, Option<String>) = sqlx::query_as(
            "SELECT cve_ids, new_cve_ids FROM sync_reports WHERE sync_job_id = 'j1'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(
            all,
            r#"["CVE-2026-0001","CVE-2026-0002","CVE-2026-0003","CVE-2026-0004"]"#
        );
        assert_eq!(new.as_deref(), Some(r#"["CVE-2026-0003","CVE-2026-0004"]"#));

        // A clean scheduled scan of the same digest: nothing new.
        let clean = format!(r#"{{"{TRIVY_REPORT_MIME}": {{"vulnerabilities": []}}}}"#);
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (200, &clean)));
        db::sync_jobs::enqueue(&fx.pool, "j2", "m1", payload, 1_000)
            .await
            .unwrap();
        let job2 = ClaimedJob {
            id: "j2".to_owned(),
            mapping_id: "m1".to_owned(),
            attempts: 0,
            payload: payload.to_owned(),
        };
        let scanner = FakeScanner::new(Ok("sarif-2".to_owned()), vec![Ok(Processing::Complete)]);
        assert_eq!(
            fx.handler(&harbor, &scanner).run(job2).await,
            JobOutcome::Done
        );
        let new: Option<String> =
            sqlx::query_scalar("SELECT new_cve_ids FROM sync_reports WHERE sync_job_id = 'j2'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(new.as_deref(), Some("[]"));
    }

    /// Harbor's own scan-completed webhook for the same scan can finish its sync first. That
    /// report is newer than the scheduled job, so it is not the "last result", and the new ids
    /// are still reported once, against the result from before the scan.
    #[tokio::test]
    async fn a_report_stored_after_the_scan_started_is_not_the_last_result() {
        let fx = Fixture::new("scheduled-race").await;
        for (id, synced_at, ids) in [
            ("r-before", 900, r#"["CVE-2026-0001"]"#),
            (
                "r-after",
                1_500,
                r#"["CVE-2026-0001","CVE-2026-0002","CVE-2026-0003","CVE-2026-0004"]"#,
            ),
        ] {
            sqlx::query(
                "INSERT INTO sync_reports (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status, synced_at, cve_ids)
                 VALUES (?, 'm1', NULL, 'app', 'v1', 'sha256:aaaa', '{}', 'success', ?, ?)",
            )
            .bind(id)
            .bind(synced_at)
            .bind(ids)
            .execute(&fx.pool)
            .await
            .unwrap();
        }
        let payload = r#"{"repo_full_name":"proj/app","digest":"sha256:aaaa","tag":"v1","trigger":"schedule"}"#;
        sqlx::query("UPDATE sync_jobs SET payload = ? WHERE id = 'j1'")
            .bind(payload)
            .execute(&fx.pool)
            .await
            .unwrap();
        let mut job = fx.job();
        job.payload = payload.to_owned();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        assert_eq!(
            fx.handler(&ok_harbor(), &scanner).run(job).await,
            JobOutcome::Done
        );
        let new: Option<String> =
            sqlx::query_scalar("SELECT new_cve_ids FROM sync_reports WHERE sync_job_id = 'j1'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(
            new.as_deref(),
            Some(r#"["CVE-2026-0002","CVE-2026-0003","CVE-2026-0004"]"#)
        );
    }

    /// A report from before migration 0008 has no stored ids; the open findings of its tag
    /// stand in for them.
    #[tokio::test]
    async fn a_legacy_last_result_is_read_from_its_tag_findings() {
        let fx = Fixture::new("scheduled-legacy").await;
        sqlx::query(
            "INSERT INTO sync_reports (id, mapping_id, sync_job_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status, synced_at)
             VALUES ('r-old', 'm1', NULL, 'app', 'old', 'sha256:aaaa', '{}', 'success', 900)",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        for (id, cve, status) in [
            ("f1", "CVE-2026-0001", "open"),
            ("f2", "CVE-2026-0002", "open"),
            ("f3", "CVE-2026-0003", "fixed"),
        ] {
            sqlx::query(
                "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, severity, status)
                 VALUES (?, 'm1', 'app', 'old', ?, 'HIGH', ?)",
            )
            .bind(id)
            .bind(cve)
            .bind(status)
            .execute(&fx.pool)
            .await
            .unwrap();
        }
        let payload = r#"{"repo_full_name":"proj/app","digest":"sha256:aaaa","tag":"v1","trigger":"schedule"}"#;
        sqlx::query("UPDATE sync_jobs SET payload = ? WHERE id = 'j1'")
            .bind(payload)
            .execute(&fx.pool)
            .await
            .unwrap();
        let mut job = fx.job();
        job.payload = payload.to_owned();
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        assert_eq!(
            fx.handler(&ok_harbor(), &scanner).run(job).await,
            JobOutcome::Done
        );
        let new: Option<String> =
            sqlx::query_scalar("SELECT new_cve_ids FROM sync_reports WHERE sync_job_id = 'j1'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(new.as_deref(), Some(r#"["CVE-2026-0003","CVE-2026-0004"]"#));
    }

    #[tokio::test]
    async fn a_webhook_sync_stores_the_ids_and_no_new_list() {
        let fx = Fixture::new("webhook-ids").await;
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![Ok(Processing::Complete)]);
        assert_eq!(
            fx.handler(&ok_harbor(), &scanner).run(fx.job()).await,
            JobOutcome::Done
        );
        let (all, new): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT cve_ids, new_cve_ids FROM sync_reports WHERE sync_job_id = 'j1'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert!(all.is_some());
        assert_eq!(new, None);
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
    async fn report_404_fails_for_backoff() {
        let fx = Fixture::new("h404").await;
        let harbor = Arc::new(FakeHarbor::new(&good_artifact(), (404, "{}")));
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Failed(MSG_NOT_YET.to_owned()));
        assert_eq!(scanner.uploads(), 0);
    }

    #[tokio::test]
    async fn artifact_404_removes_the_tags_data_and_keeps_no_note() {
        let fx = Fixture::new("a404").await;
        // Data of the gone tag `v1` and of another tag `v2`, and a GitHub issue row.
        for (id, tag) in [("r1", "v1"), ("r2", "v2")] {
            sqlx::query(
                "INSERT INTO sync_reports (id, mapping_id, harbor_repository, image_tag, image_digest, vulnerability_summary, sarif_status, synced_at)
                 VALUES (?, 'm1', 'app', ?, ?, '{}', 'success', 10)",
            )
            .bind(id)
            .bind(tag)
            .bind(format!("sha256:{tag}"))
            .execute(&fx.pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO cve_findings (id, mapping_id, harbor_repository, image_tag, cve_id, severity)
                 VALUES (?, 'm1', 'app', ?, 'CVE-1', 'HIGH')",
            )
            .bind(format!("f-{tag}"))
            .bind(tag)
            .execute(&fx.pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url)
             VALUES ('gi', 'octo', 'app', 'CVE-1', 7, 'https://github.com/octo/app/issues/7')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        let mut fake = FakeHarbor::new(&good_artifact(), (200, "{}"));
        fake.artifact = (404, b"{}".to_vec());
        let harbor = Arc::new(fake);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(outcome, JobOutcome::Done);
        assert_eq!(scanner.uploads(), 0);
        let count = |sql: &'static str| {
            let pool = fx.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(sql)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        // The tag's findings, report and the job row are gone; no done note survives anywhere.
        assert_eq!(
            count("SELECT COUNT(*) FROM cve_findings WHERE image_tag = 'v1'").await,
            0
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM sync_reports WHERE image_tag = 'v1'").await,
            0
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM sync_jobs WHERE id = 'j1'").await,
            0
        );
        assert_eq!(
            count(
                "SELECT COUNT(*) FROM sync_jobs WHERE last_error = 'artifact no longer in Harbor'"
            )
            .await,
            0
        );
        // The other tag and the GitHub issue are untouched.
        assert_eq!(
            count("SELECT COUNT(*) FROM cve_findings WHERE image_tag = 'v2'").await,
            1
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM sync_reports WHERE image_tag = 'v2'").await,
            1
        );
        assert_eq!(count("SELECT COUNT(*) FROM github_issues").await, 1);
        assert_eq!(
            count("SELECT COUNT(*) FROM audit_log WHERE action = 'artifact.remove'").await,
            1
        );
    }

    #[tokio::test]
    async fn artifact_500_still_fails_for_retry() {
        let fx = Fixture::new("a500").await;
        let mut fake = FakeHarbor::new(&good_artifact(), (200, "{}"));
        fake.artifact = (500, b"{}".to_vec());
        let harbor = Arc::new(fake);
        let scanner = FakeScanner::new(Ok("sarif-1".to_owned()), vec![]);
        let outcome = fx.handler(&harbor, &scanner).run(fx.job()).await;
        assert_eq!(
            outcome,
            JobOutcome::Failed("Harbor returned status 500".to_owned())
        );
        assert_eq!(scanner.uploads(), 0);
    }

    #[tokio::test]
    async fn too_large_records_failed_report_and_uploads_nothing() {
        // Random base64 characters barely compress, so the SARIF stays over 10 MB gzipped.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        // A stored description is capped at 4,000 characters, so the size comes from many findings.
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from(ALPHABET[((state >> 33) % 64) as usize])
        };
        let items: Vec<serde_json::Value> = (0..4_500)
            .map(|n| {
                let description: String = (0..4_000).map(|_| next()).collect();
                json!({"id": format!("CVE-2026-{n:05}"), "package": "p", "version": "1",
                       "severity": "High", "description": description})
            })
            .collect();
        let report = json!({TRIVY_REPORT_MIME: {"vulnerabilities": items}}).to_string();
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
            source_id: "m1",
            sync_job_id: "j1",
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
            source_id: "m1",
            sync_job_id: "j1",
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
        assert_eq!(creates[0]["title"], "CVE-2026-0001 openssl");
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
