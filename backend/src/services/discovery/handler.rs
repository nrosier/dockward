//! The worker's job handler for the spinoff job kinds (`specs/spinoff-local-scan.md`, section 5
//! and section 6).
//!
//! `discover` runs the discovery service. `pull` runs the pull job (`services::storage::job`),
//! which queues the scans. `scan` runs the scan job and the convert step (`services::scan`).
//! `publish` runs the publish job (`services::publish`). `db_update` runs the daily database refresh
//! (`services::scanner::db_update`). Any other kind fails once, permanently.

use std::sync::Arc;

use serde::Deserialize;

use crate::db::sync_jobs::ClaimedJob;
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
            Some("publish") => self.publisher.run(&job).await,
            Some("db_update") => run_db_update(&self.pool, &self.scan, &job.payload).await,
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
