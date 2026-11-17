//! The worker's job handler for the spinoff job kinds (`specs/spinoff-local-scan.md`, section 5
//! and section 6).
//!
//! `discover` runs the discovery service. `pull` runs the pull job (`services::storage::job`),
//! which queues the scans. `scan` runs the scan job and the convert step (`services::scan`), and
//! then the scan alerts (`services::alerts`, #458), which send only once every run of the image
//! has ended.
//! `publish` runs the publish job (`services::publish`). `db_update` runs the daily database refresh
//! (`services::scanner::db_update`). Any other kind fails once, permanently.

use std::sync::Arc;

use serde::Deserialize;

use crate::db::jobs::ClaimedJob;
use crate::services::alerts::Notifier;
use crate::services::discovery::Discovery;
use crate::services::publish::Publisher;
use crate::services::scan::{ScanEnv, run_scan};
use crate::services::scanner::db_update::run_db_update;
use crate::services::storage::StoreRoot;
use crate::services::storage::job::run_pull;
use crate::worker::{JobHandler, JobOutcome, MSG_UNHANDLED};
use sqlx::SqlitePool;

#[derive(Deserialize)]
struct KindOnly {
    kind: Option<String>,
    /// The scan run of a `scan` job.
    run_id: Option<String>,
}

/// Dispatches a claimed job by the `kind` of its payload.
pub struct SpinoffJobs {
    discovery: Arc<Discovery>,
    notifier: Notifier,
    pool: SqlitePool,
    store: StoreRoot,
    scan: ScanEnv,
    publisher: Publisher,
}

impl SpinoffJobs {
    pub fn new(
        discovery: Arc<Discovery>,
        notifier: Notifier,
        pool: SqlitePool,
        store: StoreRoot,
        scan: ScanEnv,
        publisher: Publisher,
    ) -> Self {
        Self {
            discovery,
            notifier,
            pool,
            store,
            scan,
            publisher,
        }
    }
}

impl JobHandler for SpinoffJobs {
    async fn run(&self, job: ClaimedJob) -> JobOutcome {
        let parsed = serde_json::from_str::<KindOnly>(&job.payload).ok();
        let (kind, run_id) = match parsed {
            Some(parsed) => (parsed.kind, parsed.run_id),
            None => (None, None),
        };
        match kind.as_deref() {
            Some("discover") => {
                self.discovery
                    .run_discover(&job.payload, crate::worker::now_secs())
                    .await
            }
            Some("pull") => {
                run_pull(
                    &self.pool,
                    &self.discovery,
                    &self.store,
                    &job,
                    crate::worker::now_secs(),
                )
                .await
            }
            Some("scan") => {
                let outcome = run_scan(
                    &self.pool,
                    &self.scan,
                    &self.store,
                    &job,
                    crate::worker::now_secs(),
                )
                .await;
                // Whatever the outcome: a run that failed for good can be the last open run of
                // its image. A run that will retry is open again, so nothing is sent yet.
                if let Some(run_id) = run_id.as_deref() {
                    self.notifier
                        .spawn_scan_alerts(run_id, crate::worker::now_secs());
                }
                outcome
            }
            Some("publish") => self.publisher.run(&job).await,
            Some("db_update") => run_db_update(&self.pool, &self.scan, &job).await,
            _ => JobOutcome::Permanent(MSG_UNHANDLED.to_owned()),
        }
    }

    /// A discover, pull or scan job that failed for good raises the job-failed alert with fixed
    /// text.
    fn on_give_up(&self, job: &ClaimedJob, now: i64) {
        if let Some(source_id) = job.source_id.as_deref() {
            self.notifier.spawn_job_failed(&job.id, source_id, now);
        }
    }
}
