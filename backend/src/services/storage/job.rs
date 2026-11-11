//! The worker's `pull` job (`specs/spinoff-local-scan.md`, section 6, step 3).
//!
//! The payload holds ids and the digest only (section 9). Everything else (hub, repository,
//! credential) is read from the platform row and the job's source. The pull itself is
//! [`pull_platform`]; this module reads the limits, opens the session, and maps every error to
//! one of the fixed strings of section 6. A registry body, URL, header or token never reaches
//! `last_error` or a log.

use sqlx::SqlitePool;

use crate::db::discovery as db;
use crate::db::jobs::ClaimedJob;
use crate::error::AppError;
use crate::services::discovery::{Discovery, MSG_BAD_PAYLOAD, PullPayload, failure, fixed_text};
use crate::services::scan::queue::queue_scans;
use crate::services::storage::StoreRoot;
use crate::services::storage::checked_id;
use crate::services::storage::limits::{self, StoreLimits};
use crate::services::storage::pull::{PullPlan, pull_platform};
use crate::services::storage::repository::{SqlStoreRepository, StoreRepository};
use crate::worker::JobOutcome;

/// Runs one `pull` job.
pub async fn run_pull(
    pool: &SqlitePool,
    discovery: &Discovery,
    store: &StoreRoot,
    job: &ClaimedJob,
    now: i64,
) -> JobOutcome {
    let Ok(payload) = serde_json::from_str::<PullPayload>(&job.payload) else {
        return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned());
    };
    if checked_id(&payload.platform_id).is_err() {
        return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned());
    }
    match pull_once(pool, discovery, store, job, &payload, now).await {
        Ok(Pulled::Stored) => queued_outcome(pool, job, &payload, now, JobOutcome::Done).await,
        Ok(Pulled::AlreadyDone) => {
            let note = JobOutcome::DoneWithNote("already pulled".to_owned());
            queued_outcome(pool, job, &payload, now, note).await
        }
        Err((AppError::ImageTooLarge, _)) => {
            // A larger image cannot shrink, so retrying only repeats the check.
            JobOutcome::Permanent(fixed_text(&AppError::ImageTooLarge))
        }
        Err((error, docker_anonymous)) => failure(&error, docker_anonymous, now),
    }
}

enum Pulled {
    Stored,
    /// The row is not waiting for a pull (stored, evicting or evicted): nothing to do.
    AlreadyDone,
}

/// The pull. The error carries whether the pull was an anonymous Docker Hub one.
async fn pull_once(
    pool: &SqlitePool,
    discovery: &Discovery,
    store: &StoreRoot,
    job: &ClaimedJob,
    payload: &PullPayload,
    now: i64,
) -> Result<Pulled, (AppError, bool)> {
    let target = {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|_| (AppError::InternalError, false))?;
        db::find_platform_target(&mut conn, &payload.platform_id)
            .await
            .map_err(|e| (e, false))?
    };
    let Some(target) = target else {
        return Err((AppError::NotFound, false));
    };
    if target.platform_digest != payload.digest {
        return Err((AppError::InternalError, false));
    }
    match target.state.as_str() {
        "queued" | "failed" => {}
        "stored" | "evicting" | "evicted" => return Ok(Pulled::AlreadyDone),
        _ => return Err((AppError::InternalError, false)),
    }

    let credential = match job.source_id.as_deref() {
        Some(source_id) => discovery
            .credential_for(source_id)
            .await
            .map_err(|e| (e, false))?,
        None => None,
    };
    let docker_anonymous = target.hub_host == "docker.io" && credential.is_none();
    let fail = |e: AppError| (e, docker_anonymous);

    let repo = SqlStoreRepository::new(pool.clone());
    let store_limits = read_limits(&repo).await.map_err(fail)?;
    std::fs::create_dir_all(store.root()).map_err(|_| fail(AppError::InternalError))?;
    let free_bytes = limits::free_bytes_at(store.root()).map_err(fail)?;

    let endpoint = target
        .pull_endpoint
        .clone()
        .unwrap_or_else(|| target.hub_host.clone());
    let mut session = discovery
        .client()
        .session(&endpoint, &target.repository, credential)
        .map_err(fail)?;
    let plan = PullPlan {
        platform_id: &payload.platform_id,
        platform_digest: &payload.digest,
    };
    let outcome = pull_platform(
        &repo,
        store,
        &mut session,
        &plan,
        store_limits,
        free_bytes,
        now,
    )
    .await
    .map_err(fail)?;
    tracing::info!(
        evicted = outcome.evicted,
        pending_evictions = outcome.pending_evictions,
        "image pulled"
    );

    Ok(Pulled::Stored)
}

/// Queues the scans of a stored platform (step 4): one `scan` job per enabled scanner. The
/// trigger is the one discovery recorded on the pull job (decision 17). Called for a fresh pull
/// and for a pull job that finds its image already stored, so a crash between the store and the
/// queueing loses nothing: queueing skips the scanners that already have a run.
async fn queue_after_pull(
    pool: &SqlitePool,
    job: &ClaimedJob,
    payload: &PullPayload,
    now: i64,
) -> Result<usize, AppError> {
    let trigger = match payload.trigger.as_str() {
        "tag_moved" => "tag_moved",
        _ => "first_pull",
    };
    queue_scans(
        pool,
        &payload.platform_id,
        job.source_id.as_deref(),
        trigger,
        now,
    )
    .await
}

/// Queues the scans, and returns `done` when that worked. A queueing failure fails the pull job
/// with a fixed text, so it retries: the image is stored, so the retry only queues the scans.
async fn queued_outcome(
    pool: &SqlitePool,
    job: &ClaimedJob,
    payload: &PullPayload,
    now: i64,
    done: JobOutcome,
) -> JobOutcome {
    match queue_after_pull(pool, job, payload, now).await {
        Ok(queued) => {
            tracing::info!(queued, "scans queued");
            done
        }
        Err(_) => JobOutcome::Failed(fixed_text(&AppError::InternalError)),
    }
}

/// Reads the three limits from `system_config`. An unset or unusable value is the default.
pub(crate) async fn read_limits<R: StoreRepository>(repo: &R) -> Result<StoreLimits, AppError> {
    let max_stored = repo.setting(limits::MAX_STORED_KEY).await?;
    let cap = repo.setting(limits::PULL_CAP_KEY).await?;
    let min_free = repo.setting(limits::MIN_FREE_KEY).await?;
    Ok(StoreLimits {
        max_stored: limits::parse_max_stored(max_stored.as_deref()),
        pull_cap_bytes: limits::parse_positive_u64(cap.as_deref(), limits::DEFAULT_PULL_CAP_BYTES),
        min_free_bytes: limits::parse_positive_u64(
            min_free.as_deref(),
            limits::DEFAULT_MIN_FREE_BYTES,
        ),
    })
}
