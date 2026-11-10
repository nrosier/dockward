//! The worker's job handler for the spinoff job kinds (`specs/spinoff-local-scan.md`, section 5
//! and section 6).
//!
//! `discover` runs the discovery service. `pull` is queued by discovery and is not implemented
//! yet: it fails with a fixed message and retries on the backoff, so a job queued now can
//! succeed once the pull step lands. Every other kind has no handler yet and fails once,
//! permanently, as before.

use std::sync::Arc;

use serde::Deserialize;

use crate::db::sync_jobs::ClaimedJob;
use crate::services::alerts::Notifier;
use crate::services::discovery::Discovery;
use crate::worker::{JobHandler, JobOutcome, MSG_UNHANDLED};

/// The fixed text of a `pull` job until the pull step exists.
pub const MSG_PULL_UNAVAILABLE: &str = "pull is not available yet";

#[derive(Deserialize)]
struct KindOnly {
    kind: Option<String>,
}

/// Dispatches a claimed job by the `kind` of its payload.
pub struct SpinoffJobs {
    discovery: Arc<Discovery>,
    notifier: Notifier,
}

impl SpinoffJobs {
    pub fn new(discovery: Arc<Discovery>, notifier: Notifier) -> Self {
        Self {
            discovery,
            notifier,
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
            Some("pull") => JobOutcome::Failed(MSG_PULL_UNAVAILABLE.to_owned()),
            _ => JobOutcome::Permanent(MSG_UNHANDLED.to_owned()),
        }
    }

    /// A discover or pull job that failed for good raises the sync-failed alert with fixed text.
    fn on_give_up(&self, job: &ClaimedJob, now: i64) {
        if let Some(source_id) = job.source_id.as_deref() {
            self.notifier.spawn_sync_failed(&job.id, source_id, now);
        }
    }
}
