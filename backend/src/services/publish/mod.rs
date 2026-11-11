//! The `publish` job (`specs/spinoff-local-scan.md`, section 6 steps 6 and 7, section 13;
//! decisions 6, 20, 36, 46 and 47).
//!
//! When every enabled scanner's run for every platform of a source's newest image has ended, one
//! `publish` job per source reads the OCI labels from the first scanned platform's stored config
//! ([`labels`]), builds one merged SARIF from the merged findings (one result per (CVE id,
//! package), with the scanner count and names and the platforms as properties), uploads it to
//! Code Scanning under the category `dockward/<hub host>/<repository>/<tag value>`, waits for
//! GitHub to process it, and then runs the issue rules ([`issue_lifecycle::reconcile`]).
//!
//! Older images upload nothing (step 7): the job re-checks that its image is still the source's
//! newest (decision 49) and ends with a note otherwise.
//!
//! Issues are keyed on the GitHub repository and the CVE, with the marker `harborgate:<CVE id>`
//! (decisions 20, 27 and 47). Sources that target one GitHub repository share one issue per CVE,
//! and an issue closes only when no source of that repository reports the CVE. A failed scanner
//! or platform has no `done` run, so the issue rules hold every close open (section 16).
//!
//! Error text. A job's `last_error`, a report's `error_message` and a log line carry only the
//! fixed strings in [`messages`]. No registry body, token, header or GitHub response body is ever
//! copied: GitHub's own `message` and `errors` are dropped on the way in. The GitHub token is held
//! in a zeroizing buffer and only passed to the client.

pub mod labels;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::auth::crypto::DerivedKey;
use crate::db::credentials as credential_db;
use crate::db::jobs::{self, ClaimedJob};
use crate::db::publish as publish_db;
use crate::db::scans as scans_db;
use crate::db::scans::PlatformImage;
use crate::db::sources::{self as source_db, SourceRow};
use crate::db::sync_reports::{self as report_db, NewReport};
use crate::error::AppError;
use crate::services::credentials::decrypt_token;
use crate::services::discovery::{MSG_BAD_PAYLOAD, fixed_text};
use crate::services::github_issues::GithubIssues;
use crate::services::github_scanning::{
    Alert, AlertQuery, Analysis, Dismissal, GithubScanning, Processing, ScanError, Upload,
    encode_sarif,
};
use crate::services::github_url::GithubTarget;
use crate::services::ids;
use crate::services::issue_lifecycle::{self, IssueApi};
use crate::services::issue_rekey;
use crate::services::legacy_analyses;
use crate::services::merged_view::{self, MergedFinding};
use crate::services::sarif;
use crate::services::storage::messages::NO_LONGER_STORED;
use crate::services::storage::{StoreRoot, checked_id};
use crate::worker::{JobOutcome, now_secs};

use labels::LabelFault;

/// The fixed texts of the publish job.
pub mod messages {
    /// The source row, or its GitHub credential, no longer exists for this owner.
    pub const GONE: &str = "source or credential no longer exists";
    /// The stored GitHub credential could not be decrypted.
    pub const DECRYPT: &str = "a stored credential could not be decrypted";
    /// The image config in the stored layout could not be read.
    pub const CONFIG_UNREADABLE: &str = "image config could not be read";
    /// The SARIF is over the 10 MB limit.
    pub const TOO_LARGE: &str = "SARIF over 10 MB compressed";
    /// GitHub still processes the upload after the wait.
    pub const PENDING: &str = "GitHub processing still pending";
    /// GitHub finished processing and reported a failure. Its error list is not copied.
    pub const PROCESSING_FAILED: &str = "GitHub could not process the SARIF";
    /// GitHub refused the token (401).
    pub const UNAUTHORIZED: &str = "GitHub rejected the token; check the GitHub credential (Code scanning alerts: read and write)";
    /// GitHub refused the request (403).
    pub const FORBIDDEN: &str = "GitHub refused the request; the token needs the Code scanning alerts: read and write permission";
    /// GitHub could not find the repository or the upload (404).
    pub const NOT_FOUND: &str = "GitHub could not find the repository or the SARIF upload; check the token's access and the Code scanning alerts permission";
    /// GitHub refused the request as malformed (400). Its message is not copied.
    pub const REJECTED: &str = "GitHub rejected the SARIF upload";
    /// GitHub failed or could not be reached. Its message is not copied.
    pub const UPSTREAM: &str = "GitHub request failed";
    /// The note when the image is no longer the source's newest (step 7).
    pub const NOT_NEWEST: &str = "not the newest image";
    /// The note when a scan of the image is still open. The hook queues a job when they end.
    pub const NOT_READY: &str = "scans not finished";
    /// The note when no scanner has a finished run for the image.
    pub const NO_RESULT: &str = "no completed scan";
    /// The note when the source was deleted before the job ran.
    pub const SOURCE_GONE: &str = "source no longer exists";
}

/// Waits between processing polls: 5 s, then 10 s, then every 15 s.
const FIRST_WAIT: Duration = Duration::from_secs(5);
const SECOND_WAIT: Duration = Duration::from_secs(10);
const LATER_WAIT: Duration = Duration::from_secs(15);
/// Total time one attempt waits for GitHub to process an upload. The legacy analysis retirement
/// (`services/legacy_analyses.rs`) uses the same budget.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(300);

/// The payload of a `publish` job: ids, and the image it is about (repository, digest, the tag
/// the source observed) with the trigger. Never a token or a label. The image fields are
/// `serde(default)` so a job queued before they existed still reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishPayload {
    pub kind: String,
    pub source_id: String,
    pub image_id: String,
    #[serde(default)]
    pub repo_full_name: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub trigger: Option<String>,
}

/// The trigger of a publish job: the scan that ended the image's last open run led to it.
pub const PUBLISH_TRIGGER: &str = "scan";

impl PublishPayload {
    pub fn new(source_id: &str, image_id: &str, image: &PlatformImage) -> Self {
        Self {
            kind: "publish".to_owned(),
            source_id: source_id.to_owned(),
            image_id: image_id.to_owned(),
            repo_full_name: Some(image.repo_full_name.clone()),
            tag: image.tag.clone(),
            digest: Some(image.digest.clone()),
            trigger: Some(PUBLISH_TRIGGER.to_owned()),
        }
    }

    pub fn to_text(&self) -> Result<String, AppError> {
        serde_json::to_string(self).map_err(|_| AppError::InternalError)
    }
}

/// Queues one `publish` job for each source whose newest image is `image_id`, when every scan of
/// the image has ended and no platform is still waiting to be pulled (section 6 step 6). Returns
/// the number of jobs queued. A source with an open publish job for the same image adds nothing.
/// A source for which the image is not the newest is skipped: older images upload nothing
/// (step 7).
pub async fn queue_publish(pool: &SqlitePool, image_id: &str, now: i64) -> Result<usize, AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    if scans_db::image_has_open_runs(&mut tx, image_id).await?
        || publish_db::image_has_pending_pull(&mut tx, image_id).await?
    {
        tx.commit().await.map_err(|_| AppError::InternalError)?;
        return Ok(0);
    }
    let mut queued = 0usize;
    for source_id in publish_db::sources_with_newest_image(&mut tx, image_id).await? {
        if publish_db::open_publish_job_exists(&mut tx, &source_id, image_id).await? {
            continue;
        }
        let Some(image) = scans_db::image_in(&mut tx, image_id, Some(&source_id)).await? else {
            return Err(AppError::InternalError);
        };
        let payload = PublishPayload::new(&source_id, image_id, &image).to_text()?;
        let job_id = ids::new_id()?;
        jobs::enqueue_in(&mut tx, &job_id, Some(&source_id), &payload, now).await?;
        queued += 1;
    }
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(queued)
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

    /// Lists the analyses of one tool, all pages (#311 slice 6b). `deadline` is Unix seconds on
    /// `clock`; the list stops with `DeadlineExceeded` once `clock.now()` reaches it.
    fn list_analyses<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        tool_name: &str,
        clock: &C,
        deadline: i64,
    ) -> impl Future<Output = Result<Vec<Analysis>, ScanError>> + Send;

    /// DELETEs one analysis. Returns the next confirm-delete path, or `None` when done.
    fn delete_analysis(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        id: u64,
        now: i64,
    ) -> impl Future<Output = Result<Option<String>, ScanError>> + Send;

    /// Follows a confirm-delete path of `owner`/`repo`, the relative path a delete returned. Returns
    /// the next path, or `None` when done.
    fn follow_confirm(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        path: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<String>, ScanError>> + Send;

    /// Lists the alerts of one tool, state and ref, all pages. `deadline` is as for
    /// `list_analyses`.
    fn list_alerts<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        query: AlertQuery<'_>,
        clock: &C,
        deadline: i64,
    ) -> impl Future<Output = Result<Vec<Alert>, ScanError>> + Send;

    /// Dismisses one alert.
    fn dismiss_alert(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        dismissal: Dismissal<'_>,
        now: i64,
    ) -> impl Future<Output = Result<(), ScanError>> + Send;
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

    async fn list_analyses<C: Clock>(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        tool_name: &str,
        clock: &C,
        deadline: i64,
    ) -> Result<Vec<Analysis>, ScanError> {
        GithubScanning::list_analyses(self, token, owner, repo, tool_name, clock, deadline).await
    }

    async fn delete_analysis(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        id: u64,
        now: i64,
    ) -> Result<Option<String>, ScanError> {
        GithubScanning::delete_analysis(self, token, owner, repo, id, now).await
    }

    async fn follow_confirm(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        path: &str,
        now: i64,
    ) -> Result<Option<String>, ScanError> {
        GithubScanning::follow_confirm(self, token, owner, repo, path, now).await
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
        GithubScanning::list_alerts(self, token, owner, repo, query, clock, deadline).await
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
        GithubScanning::dismiss_alert(self, token, owner, repo, number, dismissal, now).await
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

/// Runs `publish` jobs. The type parameters default to the production clients.
pub struct Publisher<G = GithubScanning, I = GithubIssues, C = SystemClock> {
    pool: SqlitePool,
    key: Arc<DerivedKey>,
    store: StoreRoot,
    github: G,
    issues: I,
    clock: C,
    target: GithubTarget,
}

impl Publisher {
    /// The production setup: the guarded GitHub clients and the system clock.
    pub fn new(
        pool: SqlitePool,
        key: Arc<DerivedKey>,
        store: StoreRoot,
        target: GithubTarget,
    ) -> Result<Self, AppError> {
        Ok(Self {
            pool,
            key,
            store,
            github: GithubScanning::new(target.clone())?,
            issues: GithubIssues::new(target.clone())?,
            clock: SystemClock,
            target,
        })
    }
}

impl<G: CodeScanning, I: IssueApi, C: Clock> Publisher<G, I, C> {
    /// A publisher over other clients. Used by the tests.
    #[cfg(test)]
    pub(crate) fn with_parts(
        pool: SqlitePool,
        key: Arc<DerivedKey>,
        store: StoreRoot,
        github: G,
        issues: I,
        clock: C,
    ) -> Self {
        Self {
            pool,
            key,
            store,
            github,
            issues,
            clock,
            target: GithubTarget::default(),
        }
    }
}

/// An early exit from a job: the outcome to report.
type Flow<T> = Result<T, JobOutcome>;

fn failed(text: &str) -> JobOutcome {
    JobOutcome::Failed(text.to_owned())
}

fn permanent(text: &str) -> JobOutcome {
    JobOutcome::Permanent(text.to_owned())
}

fn database(_: AppError) -> JobOutcome {
    JobOutcome::Failed(fixed_text(&AppError::InternalError))
}

/// Maps a GitHub error to the job outcome with a fixed text. A rate limit defers the job. The
/// `message` GitHub sent with a `400`, `403` or `5xx` is dropped.
fn scan_outcome(error: ScanError) -> JobOutcome {
    match error {
        ScanError::RateLimited { until } => JobOutcome::Deferred {
            until,
            reason: "GitHub rate limit reached".to_owned(),
        },
        ScanError::Unauthorized => failed(messages::UNAUTHORIZED),
        ScanError::Forbidden(_) => failed(messages::FORBIDDEN),
        ScanError::NotFound => failed(messages::NOT_FOUND),
        ScanError::TooLarge => permanent(messages::TOO_LARGE),
        ScanError::Rejected(_) => failed(messages::REJECTED),
        ScanError::Upstream(_) | ScanError::DeadlineExceeded => failed(messages::UPSTREAM),
    }
}

/// The delay before the poll with this zero-based index.
fn wait_for(index: u32) -> Duration {
    match index {
        0 => FIRST_WAIT,
        1 => SECOND_WAIT,
        _ => LATER_WAIT,
    }
}

/// Counts the merged findings by severity, one count per (CVE id, package) result.
fn summarize(findings: &[MergedFinding]) -> String {
    let mut counts = [0u64; 5];
    for finding in findings {
        let slot = match finding.severity {
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

/// What one job needs after the database reads and the decryption.
struct Context {
    job_id: String,
    source: SourceRow,
    image_id: String,
    /// The tag of the source's newest observation, and the image's top-level digest.
    tag: String,
    digest: String,
    token: Zeroizing<Vec<u8>>,
}

impl<G: CodeScanning, I: IssueApi, C: Clock> Publisher<G, I, C> {
    /// Runs one `publish` job.
    pub async fn run(&self, job: &ClaimedJob) -> JobOutcome {
        match self.execute(job).await {
            Ok(outcome) | Err(outcome) => outcome,
        }
    }

    async fn execute(&self, job: &ClaimedJob) -> Flow<JobOutcome> {
        let payload: PublishPayload =
            serde_json::from_str(&job.payload).map_err(|_| permanent(MSG_BAD_PAYLOAD))?;
        if payload.kind != "publish"
            || payload.source_id.is_empty()
            || checked_id(&payload.image_id).is_err()
        {
            return Err(permanent(MSG_BAD_PAYLOAD));
        }
        let context = self.load(job, &payload).await?;

        let merged = merged_view::load(&self.pool, &context.image_id)
            .await
            .map_err(database)?;
        if merged.scanners.is_empty() {
            return Ok(JobOutcome::DoneWithNote(messages::NO_RESULT.to_owned()));
        }

        // A retry after a pending wait polls the same upload and never uploads twice.
        let existing = report_db::find_pending_for_job(&self.pool, &job.id)
            .await
            .map_err(database)?;
        let (report_id, sarif_id, git_ref) = match existing {
            Some(report) if report.github_sarif_id.is_some() => {
                // An earlier attempt uploaded this SARIF. It is not this run's own upload, so
                // the legacy retirement does not run for it (#311 slice 6b).
                let sarif_id = report.github_sarif_id.unwrap_or_default();
                (report.id, sarif_id, None)
            }
            existing => {
                let (report_id, sarif_id, git_ref) = self
                    .upload_new(&context, &merged.findings, existing)
                    .await?;
                (report_id, sarif_id, Some(git_ref))
            }
        };
        // `?` returns before the next two steps unless GitHub reported `complete`.
        self.wait_for_processing(&context, &report_id, &sarif_id)
            .await?;
        self.reconcile_issues(&context).await;
        if let Some(git_ref) = git_ref {
            self.retire_legacy(&context, &git_ref).await;
        }
        Ok(JobOutcome::Done)
    }

    /// Loads the source and the GitHub token, and checks the image is still the source's newest
    /// and that its scans have ended.
    async fn load(&self, job: &ClaimedJob, payload: &PublishPayload) -> Flow<Context> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| database(AppError::InternalError))?;
        let Some(source) = source_db::find_by_id(&mut conn, &payload.source_id)
            .await
            .map_err(database)?
        else {
            return Err(JobOutcome::DoneWithNote(messages::SOURCE_GONE.to_owned()));
        };
        // Step 7: older images upload nothing.
        let newest = publish_db::newest_observation(&mut conn, &source.id)
            .await
            .map_err(database)?;
        let Some(newest) = newest.filter(|newest| newest.image_id == payload.image_id) else {
            return Err(JobOutcome::DoneWithNote(messages::NOT_NEWEST.to_owned()));
        };
        if scans_db::image_has_open_runs(&mut conn, &payload.image_id)
            .await
            .map_err(database)?
            || publish_db::image_has_pending_pull(&mut conn, &payload.image_id)
                .await
                .map_err(database)?
        {
            return Err(JobOutcome::DoneWithNote(messages::NOT_READY.to_owned()));
        }
        let credential =
            credential_db::find_owned(&mut conn, &source.user_id, &source.github_cred_id)
                .await
                .map_err(database)?
                .ok_or_else(|| permanent(messages::GONE))?;
        drop(conn);
        let token = decrypt_token(&self.key, &credential).map_err(|_| failed(messages::DECRYPT))?;
        Ok(Context {
            job_id: job.id.clone(),
            source,
            image_id: payload.image_id.clone(),
            tag: newest.tag,
            digest: newest.digest,
            token,
        })
    }

    /// The labels of the first scanned platform whose layout is still stored. Labels are
    /// image-level metadata, so one platform's config is enough.
    async fn read_labels(&self, context: &Context) -> Flow<labels::ImageLabels> {
        let platforms = {
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(|_| database(AppError::InternalError))?;
            publish_db::scanned_platform_ids(&mut conn, &context.image_id)
                .await
                .map_err(database)?
        };
        for platform_id in platforms {
            let layout = self.store.layout_dir(&platform_id).map_err(database)?;
            if !layout.is_dir() {
                continue;
            }
            let read = tokio::task::spawn_blocking(move || labels::read_labels(&layout)).await;
            return match read {
                Ok(Ok(found)) => Ok(found),
                Ok(Err(LabelFault::Unreadable | LabelFault::Malformed)) | Err(_) => {
                    Err(permanent(messages::CONFIG_UNREADABLE))
                }
            };
        }
        Err(permanent(NO_LONGER_STORED))
    }

    /// Reads the labels, builds the SARIF and uploads it. Returns the report id, GitHub's SARIF
    /// id and the full ref the upload used. A pending report left by an earlier attempt that
    /// never uploaded is reused.
    async fn upload_new(
        &self,
        context: &Context,
        findings: &[MergedFinding],
        existing: Option<report_db::ReportRow>,
    ) -> Flow<(String, String, String)> {
        let source = &context.source;
        let labels = self.read_labels(context).await?;
        let revision = labels::require_revision(&labels)
            .map_err(|_| permanent(labels::MSG_NO_REVISION))?
            .to_owned();
        labels::check_source(
            &labels,
            self.target.current().web_url(),
            &source.github_owner,
            &source.github_repo,
        )
        .map_err(|_| permanent(labels::MSG_SOURCE_MISMATCH))?;
        let branch = labels::branch_for(&labels, &source.default_branch);

        let report = merged_view::to_report(findings);
        let document = sarif::convert(
            &report,
            &source.hub_host,
            &source.repository,
            &source.tag_value,
        )
        .map_err(database)?;
        let encoded = match encode_sarif(&document) {
            Ok(encoded) => Some(encoded),
            Err(ScanError::TooLarge) => None,
            Err(other) => return Err(scan_outcome(other)),
        };

        let report_id = match existing {
            Some(report) => report.id,
            None => {
                let id = ids::new_id().map_err(database)?;
                let summary = summarize(findings);
                let new = NewReport {
                    id: &id,
                    source_id: &source.id,
                    image_id: Some(&context.image_id),
                    job_id: &context.job_id,
                    image_tag: &context.tag,
                    image_digest: &context.digest,
                    commit_sha: Some(&revision),
                    vulnerability_summary: &summary,
                };
                let mut conn = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| database(AppError::InternalError))?;
                report_db::insert_pending(&mut conn, &new)
                    .await
                    .map_err(database)?;
                id
            }
        };
        let Some(encoded) = encoded else {
            report_db::finish(
                &self.pool,
                &report_id,
                "failed",
                Some(messages::TOO_LARGE),
                self.clock.now(),
            )
            .await
            .map_err(database)?;
            return Err(permanent(messages::TOO_LARGE));
        };

        let git_ref = format!("refs/heads/{branch}");
        let upload = Upload {
            owner: &source.github_owner,
            repo: &source.github_repo,
            commit_sha: &revision,
            git_ref: &git_ref,
            sarif_b64: &encoded,
        };
        let sarif_id = self
            .github
            .upload(&context.token, &upload, self.clock.now())
            .await
            .map_err(scan_outcome)?;
        report_db::set_sarif_id(&self.pool, &report_id, &sarif_id)
            .await
            .map_err(database)?;
        Ok((report_id, sarif_id, git_ref))
    }

    /// Polls GitHub after 5 s, 10 s, then every 15 s, for at most 300 s in total. `Complete`
    /// marks the report `success`. `Failed` marks it `failed` with a fixed text and fails the job
    /// for good. Still pending after the wait fails the attempt; the retry polls the same upload.
    async fn wait_for_processing(
        &self,
        context: &Context,
        report_id: &str,
        sarif_id: &str,
    ) -> Flow<()> {
        let source = &context.source;
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
                    &context.token,
                    &source.github_owner,
                    &source.github_repo,
                    sarif_id,
                    self.clock.now(),
                )
                .await
                .map_err(scan_outcome)?;
            match processing {
                Processing::Pending => {}
                Processing::Complete => {
                    report_db::finish(&self.pool, report_id, "success", None, self.clock.now())
                        .await
                        .map_err(database)?;
                    return Ok(());
                }
                Processing::Failed(_) => {
                    // GitHub's error list is a response body: it is not copied.
                    report_db::finish(
                        &self.pool,
                        report_id,
                        "failed",
                        Some(messages::PROCESSING_FAILED),
                        self.clock.now(),
                    )
                    .await
                    .map_err(database)?;
                    return Err(permanent(messages::PROCESSING_FAILED));
                }
            }
        }
        Err(failed(messages::PENDING))
    }

    /// Retires the old HarborGate analyses of this source's legacy category (#311 slice 6b). It
    /// runs only after this run's own upload reached `complete`, and it never fails the job: a
    /// database error is logged as fixed text, and the next publish runs the step again. The
    /// GitHub outcomes are logged by `legacy_analyses::retire`.
    async fn retire_legacy(&self, context: &Context, git_ref: &str) {
        let started = self.clock.now();
        let outcome = legacy_analyses::retire(
            &self.pool,
            &self.github,
            &self.clock,
            &context.token,
            &context.source,
            git_ref,
            started,
        )
        .await;
        if outcome.is_err() {
            tracing::warn!(
                "the database failed while retiring legacy analyses; the next publish retries"
            );
        }
    }

    /// Makes the GitHub issues follow the findings that were just published. Nothing here can
    /// fail the job: the report is already `success`, so a retry would upload the SARIF again. A
    /// rate limit, a refused token or a database error is logged as fixed text, and the next
    /// publish reconciles the issues.
    async fn reconcile_issues(&self, context: &Context) {
        let source = &context.source;
        let scan_label = format!("{}/{}:{}", source.hub_host, source.repository, context.tag);
        let rekey = issue_rekey::run(
            &self.pool,
            &self.issues,
            &self.clock,
            &context.token,
            &source.github_owner,
            &source.github_repo,
        )
        .await;
        match rekey {
            Ok(issue_rekey::RekeyOutcome::RateLimited { .. }) => {
                tracing::warn!(
                    "GitHub rate limit reached while re-keying issues; the next publish retries"
                );
                return;
            }
            Ok(issue_rekey::RekeyOutcome::Refused) => {
                tracing::warn!(
                    "GitHub refused the issue re-key; check the token's Issues permission"
                );
                return;
            }
            Ok(issue_rekey::RekeyOutcome::Incomplete { .. }) => {
                tracing::warn!("some issues could not be re-keyed; the next publish retries");
            }
            Err(_) => {
                tracing::warn!(
                    "the database failed while re-keying issues; the next publish retries"
                );
            }
            Ok(
                issue_rekey::RekeyOutcome::AlreadyDone
                | issue_rekey::RekeyOutcome::Completed { .. },
            ) => {}
        }
        let result = issue_lifecycle::reconcile(
            &self.pool,
            &self.issues,
            &context.token,
            source,
            &scan_label,
            self.clock.now(),
        )
        .await;
        match result {
            Ok(issue_lifecycle::Outcome::Complete) => {}
            Ok(issue_lifecycle::Outcome::RateLimited { .. }) => {
                tracing::warn!(
                    "GitHub rate limit reached while updating issues; the next publish retries"
                );
            }
            Ok(issue_lifecycle::Outcome::Refused) => {
                tracing::warn!(
                    "GitHub refused the issue updates; check the token's Issues permission"
                );
            }
            Err(_) => {
                tracing::warn!(
                    "the database failed while updating issues; the next publish retries"
                );
            }
        }
    }
}
