//! The worker's job handler for the spinoff job kinds (`specs/spinoff-local-scan.md`, section 5
//! and section 6).
//!
//! `discover` runs the discovery service. `pull` runs the pull job (`services::storage::job`),
//! which queues the scans. `scan` runs the scan job and the convert step (`services::scan`).
//! Every other kind (`publish`, `db_update`) has no handler yet and fails once, permanently.

use std::sync::Arc;

use serde::Deserialize;

use crate::db::sync_jobs::ClaimedJob;
use crate::services::alerts::Notifier;
use crate::services::discovery::Discovery;
use crate::services::scan::{ScanEnv, run_scan};
use crate::services::storage::StoreRoot;
use crate::services::storage::job::run_pull;
use crate::worker::{JobHandler, JobOutcome, MSG_UNHANDLED};
use sqlx::SqlitePool;

#[derive(Deserialize)]
struct KindOnly {
    kind: Option<String>,
}

/// Dispatches a claimed job by the `kind` of its payload.
pub struct SpinoffJobs {
    discovery: Arc<Discovery>,
    notifier: Notifier,
    pool: SqlitePool,
    store: StoreRoot,
    scan: ScanEnv,
}

impl SpinoffJobs {
    pub fn new(
        discovery: Arc<Discovery>,
        notifier: Notifier,
        pool: SqlitePool,
        store: StoreRoot,
        scan: ScanEnv,
    ) -> Self {
        Self {
            discovery,
            notifier,
            pool,
            store,
            scan,
        }
    }
}

impl JobHandler for SpinoffJobs {
    async fn run(&self, job: ClaimedJob) -> JobOutcome {
        let kind = serde_json::from_str::<KindOnly>(&job.payload)
            .ok()
            .and_then(|parsed| parsed.kind);
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
                run_scan(
                    &self.pool,
                    &self.scan,
                    &self.store,
                    &job,
                    crate::worker::now_secs(),
                )
                .await
            }
            _ => JobOutcome::Permanent(MSG_UNHANDLED.to_owned()),
        }
    }

    /// A discover, pull or scan job that failed for good raises the sync-failed alert with fixed
    /// text.
    fn on_give_up(&self, job: &ClaimedJob, now: i64) {
        if let Some(source_id) = job.source_id.as_deref() {
            self.notifier.spawn_sync_failed(&job.id, source_id, now);
        }
    }
}
