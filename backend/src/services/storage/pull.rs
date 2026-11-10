//! The pull of one platform into a stored layout (`specs/spinoff-local-scan.md`, section 6, step 3).
//!
//! Order, for one platform:
//!
//! 1. The free-disk guard: the free space of the store volume must be at least the minimum.
//! 2. The platform manifest is fetched and its digest checked. Its declared size (the manifest,
//!    the config and every layer) must be within the pull cap. No blob is downloaded before this.
//!    Decided (spec author, spinoff): the manifest is fetched first, because the declared size is
//!    only known from it; the manifest is capped at 4 MiB by the registry client.
//! 3. The config and layer blobs are streamed into `images/.tmp/<id>`, each verified by SHA-256
//!    while it streams, with a running byte count against the remaining cap.
//! 4. Only after every blob verifies is the directory renamed to `images/<id>`. The row becomes
//!    `stored` with `pulled_at`, and the oldest images above the maximum are claimed in the same
//!    transaction. The claimed layouts are removed after the commit.
//!
//! A failure before the commit removes `images/.tmp/<id>` (and the final directory, if the rename
//! already happened), and marks the row `failed`. So no directory exists for content that did not
//! verify. A failure after the commit does not fail the pull: the row is stored, and any eviction
//! that did not finish stays `evicting` for the startup repair.

use std::fs;

use crate::error::AppError;
use crate::services::registry::manifest::{Descriptor, Parsed};
use crate::services::registry::transport::{PullSession, sha256_digest_text};
use crate::services::storage::StoreRoot;
use crate::services::storage::eviction;
use crate::services::storage::layout::LayoutWriter;
use crate::services::storage::limits::{self, StoreLimits};
use crate::services::storage::repository::StoreRepository;
use sha2::{Digest, Sha256};

/// The inputs of one pull. The platform row exists already, in `queued` or `failed` state.
pub struct PullPlan<'a> {
    /// The `image_platforms.id` of the row. It also names the layout directory.
    pub platform_id: &'a str,
    /// The platform manifest digest the registry must serve, `sha256:<hex>`.
    pub platform_digest: &'a str,
}

/// What a successful pull reports. Counts and sizes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullOutcome {
    /// Bytes stored for the image: the manifest, the config and the layers.
    pub size_bytes: u64,
    /// Images evicted after this pull.
    pub evicted: usize,
    /// Evictions that did not finish. Their rows stay `evicting` for the startup repair.
    pub pending_evictions: usize,
}

/// The state after a pull's staging succeeded and before the commit: the temporary directory is
/// renamed to its final name, and the row is still `pulling`.
struct Staged {
    total: u64,
}

/// Pulls one platform image into the store. `now` is the Unix time the row is stamped with.
/// `free_bytes` is the free space of the store volume, read by the caller.
pub async fn pull_platform<R: StoreRepository>(
    repo: &R,
    store: &StoreRoot,
    session: &mut PullSession<'_>,
    plan: &PullPlan<'_>,
    limits: StoreLimits,
    free_bytes: u64,
    now: i64,
) -> Result<PullOutcome, AppError> {
    // The free-disk guard runs before any row change or request, so a refusal leaves the row as it
    // was. Every later failure is after the row is `pulling`, and it marks the row `failed`.
    limits::check_free_disk(free_bytes, limits.min_free_bytes)?;
    let staged = match stage(repo, store, session, plan, limits).await {
        Ok(staged) => staged,
        Err(err) => {
            fail_before_commit(repo, store, plan.platform_id).await;
            return Err(err);
        }
    };

    let claims = match repo
        .store_and_claim(
            plan.platform_id,
            size_as_i64(staged.total)?,
            now,
            limits.max_stored,
        )
        .await
    {
        Ok(claims) => claims,
        Err(err) => {
            fail_before_commit(repo, store, plan.platform_id).await;
            return Err(err);
        }
    };

    // Committed: the row is stored. The claimed layouts are removed now. A failure here must not
    // turn a stored image into a failed pull, so each one is attempted and the rest are counted.
    let mut evicted = 0usize;
    let mut pending = 0usize;
    for claim in &claims {
        match eviction::complete_one(repo, store, claim, now).await {
            Ok(()) => evicted += 1,
            Err(_) => pending += 1,
        }
    }
    Ok(PullOutcome {
        size_bytes: staged.total,
        evicted,
        pending_evictions: pending,
    })
}

/// Stages the pull: guards, manifest, blobs, then the rename to the final directory. Leaves the
/// row in `pulling`.
async fn stage<R: StoreRepository>(
    repo: &R,
    store: &StoreRoot,
    session: &mut PullSession<'_>,
    plan: &PullPlan<'_>,
    limits: StoreLimits,
) -> Result<Staged, AppError> {
    repo.begin_pull(plan.platform_id).await?;

    let raw = session.manifest_raw(plan.platform_digest).await?;
    if sha256_digest_text(&Sha256::digest(&raw.bytes)) != plan.platform_digest {
        return Err(AppError::UpstreamContentInvalid);
    }
    let (config, layers) =
        match crate::services::registry::manifest::parse(&raw.media_type, &raw.bytes)? {
            Parsed::Image { config, layers } => (config, layers),
            Parsed::Index(_) => return Err(AppError::UpstreamContentInvalid),
        };

    let manifest_len = raw.bytes.len() as u64;
    let declared = declared_size(manifest_len, &config, &layers)?;
    limits::check_declared_size(declared, limits.pull_cap_bytes)?;

    let tmp = store.tmp_dir(plan.platform_id)?;
    let final_dir = store.layout_dir(plan.platform_id)?;
    if final_dir.exists() {
        return Err(AppError::InternalError);
    }
    let mut writer = LayoutWriter::create(&tmp)?;
    writer.put_manifest(&raw.bytes, &raw.media_type)?;

    let mut remaining = limits.pull_cap_bytes.saturating_sub(manifest_len);
    let mut total = manifest_len;
    for descriptor in std::iter::once(&config).chain(layers.iter()) {
        let written = stream_blob(session, &writer, descriptor, remaining).await?;
        remaining = remaining.saturating_sub(written);
        total = total.saturating_add(written);
    }

    writer.finish()?;
    fs::rename(&tmp, &final_dir).map_err(|_| AppError::InternalError)?;
    Ok(Staged { total })
}

/// Streams one blob into the layout. Its digest is verified on the bytes written, and its length
/// against the descriptor. Returns the bytes written.
async fn stream_blob(
    session: &mut PullSession<'_>,
    writer: &LayoutWriter,
    descriptor: &Descriptor,
    budget: u64,
) -> Result<u64, AppError> {
    let mut sink = writer.blob_sink(&descriptor.digest)?;
    session
        .blob_to(&descriptor.digest, descriptor.size, budget, &mut sink)
        .await?;
    sink.verify(&descriptor.digest)
}

/// Cleans up after a failure before the commit: removes the temporary directory and any final
/// directory the rename created, then marks the row `failed`. Best-effort: the original error is
/// the one the caller returns.
async fn fail_before_commit<R: StoreRepository>(repo: &R, store: &StoreRoot, platform_id: &str) {
    let _ = remove_dir_if_present(store.tmp_dir(platform_id));
    let _ = remove_dir_if_present(store.layout_dir(platform_id));
    let _ = repo.mark_failed(platform_id).await;
}

/// The declared size of an image: the manifest, the config and every layer. A total that does not
/// fit in `u64` is an invalid manifest.
fn declared_size(
    manifest_len: u64,
    config: &Descriptor,
    layers: &[Descriptor],
) -> Result<u64, AppError> {
    layers
        .iter()
        .try_fold(manifest_len.saturating_add(config.size), |acc, layer| {
            acc.checked_add(layer.size)
        })
        .ok_or(AppError::UpstreamContentInvalid)
}

fn size_as_i64(size: u64) -> Result<i64, AppError> {
    i64::try_from(size).map_err(|_| AppError::ImageTooLarge)
}

/// Removes a directory when it exists. A missing directory is not an error.
fn remove_dir_if_present(path: Result<std::path::PathBuf, AppError>) -> Result<(), AppError> {
    let path = path?;
    match fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AppError::InternalError),
    }
}
