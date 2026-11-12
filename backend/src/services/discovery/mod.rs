//! Tag discovery and manifest resolution (`specs/spinoff-local-scan.md`, section 5 and section 6
//! steps 1 and 2; decisions 3, 15, 16, 17, 30).
//!
//! One `discover` job covers one (hub, repository) and every source on it:
//!
//! 1. List the tags (paging by `Link`, with the page cap), match each source's tag value, and
//!    resolve each matching tag to its top-level digest.
//! 2. Resolve each digest that is not yet known: an index lists its platform entries (attestation
//!    entries are skipped by the manifest parser, decision 30), and a single manifest takes its
//!    platform from the image config.
//! 3. In one `BEGIN IMMEDIATE` transaction, insert the image, the tag observation and the platform
//!    rows with `INSERT ... ON CONFLICT DO NOTHING`, and queue one `pull` job for each platform
//!    row that was added. A digest already stored, evicted or in progress has its image row, so
//!    nothing is queued for it again, and two concurrent runs queue one.
//!
//! The network work runs before the transaction, so no database lock is held across a request.
//! A listing that did not finish (error or page cap) records nothing for the missing tail. Nothing
//! here stores a registry body, header or URL: errors map to the fixed strings of section 6
//! ([`fixed_text`]).
//!
//! Decided (spec author): resolve is a step of the discover job, not a job kind, because section
//! 9 lists only `discover`, `pull`, `scan`, `publish` and `db_update` as payload kinds.

pub mod glob;
pub mod handler;
pub mod schedule;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::discovery as db;
use crate::db::job_runs::{self, JobRun};
use crate::db::jobs;
use crate::error::AppError;
use crate::services::ids;
use crate::services::registry::manifest::{self, Parsed};
use crate::services::registry::policy::{AddressPolicy, SystemLookup, parse_opt_out};
use crate::services::registry::transport::{
    Credential, MANIFEST_MAX_BYTES, PullSession, RegistryClient, sha256_digest_text,
};
use crate::worker::JobOutcome;

use glob::TagPattern;

/// The environment variable that names the hubs allowed plain HTTP or private addresses
/// (decisions 14 and 25). Read once at start.
pub const ALLOW_PRIVATE_REGISTRIES_VAR: &str = "DOCKWARD_ALLOW_PRIVATE_REGISTRIES";

/// Decided (spec author): the most new images one discovery run records. The rest are found at
/// the next hourly run, because nothing is recorded for them. Section 13 sets no value.
pub const MAX_NEW_DIGESTS_PER_RUN: usize = 50;
/// Decided (spec author): the most manifests one discovery run fetches. The tag page size (100)
/// and the page cap (100 pages) are the registry client's constants. Section 13 sets no value.
pub const MAX_MANIFEST_FETCHES_PER_RUN: usize = 500;
/// Decided (spec author): how long a registry `429` defers a job. The client keeps `Retry-After`
/// to itself after its own short in-client wait.
pub const RATE_LIMIT_DEFER_SECS: i64 = 300;
/// The longest platform text kept (`os/arch/variant`).
const MAX_PLATFORM_BYTES: usize = 64;

/// The fixed text for an anonymous Docker Hub pull refused for the rate limit (decision 40).
pub const MSG_DOCKER_HUB_RATE_LIMIT: &str = "docker hub rate limit reached";
/// The fixed text for a job payload that cannot be read.
pub(crate) const MSG_BAD_PAYLOAD: &str = "job payload is not valid";
const MSG_INTERNAL: &str = "internal error";

/// The payload of a `discover` job: ids only. `source_id` limits a manual scan to one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverPayload {
    pub kind: String,
    pub hub_id: String,
    pub repository: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

impl DiscoverPayload {
    pub fn new(hub_id: &str, repository: &str, source_id: Option<&str>) -> Self {
        Self {
            kind: "discover".to_owned(),
            hub_id: hub_id.to_owned(),
            repository: repository.to_owned(),
            source_id: source_id.map(str::to_owned),
        }
    }

    /// The JSON text stored in `jobs.payload`. The field order is fixed, so equal payloads
    /// compare equal as text.
    pub fn to_text(&self) -> Result<String, AppError> {
        serde_json::to_string(self).map_err(|_| AppError::InternalError)
    }
}

/// The payload of a `pull` job: the platform row and its digest. The pull job reads the rest from the platform row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullPayload {
    pub kind: String,
    pub platform_id: String,
    pub digest: String,
    /// `first_pull` or `tag_moved` (decision 17), or `manual` for the manual pull route (#335).
    pub trigger: String,
    /// The repository of the discovery run, and the tag that matched. Absent on a job queued
    /// before these fields existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Maps a client error to the fixed `last_error` text of section 6. No registry text is used.
pub fn fixed_text(error: &AppError) -> String {
    match error {
        AppError::UpstreamUnreachable => "registry could not be reached".to_owned(),
        AppError::UpstreamAuthRejected => "registry rejected the credentials".to_owned(),
        AppError::NotFound => "image not found in registry".to_owned(),
        AppError::UpstreamStatus(code) => format!("registry returned status {code}"),
        AppError::UpstreamContentInvalid => "image content did not match its digest".to_owned(),
        AppError::ImageTooLarge => "image is larger than the allowed size".to_owned(),
        AppError::InsufficientDisk => "not enough disk space".to_owned(),
        _ => MSG_INTERNAL.to_owned(),
    }
}

/// The job outcome for a failed run. A `429` defers, except an anonymous Docker Hub pull, which
/// is a failure on the backoff (decision 40). A name outside the grammar cannot heal by retrying.
pub(crate) fn failure(error: &AppError, docker_anonymous: bool, now: i64) -> JobOutcome {
    match error {
        AppError::RateLimited if docker_anonymous => {
            JobOutcome::Failed(MSG_DOCKER_HUB_RATE_LIMIT.to_owned())
        }
        AppError::RateLimited => JobOutcome::Deferred {
            until: now.saturating_add(RATE_LIMIT_DEFER_SECS),
            reason: "registry rate limit".to_owned(),
        },
        AppError::ValidationFailed(_) => JobOutcome::Permanent(fixed_text(&AppError::NotFound)),
        other => JobOutcome::Failed(fixed_text(other)),
    }
}

/// What one matching tag resolved to.
#[derive(Debug, Clone)]
struct Seen {
    source_id: String,
    tag: String,
    digest: String,
    is_index: bool,
}

/// A platform of an image: `os/arch[/variant]` and the platform manifest digest.
type PlatformEntry = (String, String);

/// What the network phase of a discovery run produced.
struct Gathered {
    /// True when the listing ran, so the sources get `last_discovery_at`.
    listed: bool,
    seen: Vec<Seen>,
    /// The platforms of each digest that was not known when the run looked.
    platforms: HashMap<String, Vec<PlatformEntry>>,
    source_ids: Vec<String>,
    /// The error that stopped the run. What was gathered before it is still recorded.
    error: Option<AppError>,
    /// False when the listing or the run stopped early (page cap, refused link, a cap).
    complete: bool,
    docker_anonymous: bool,
}

impl Gathered {
    fn empty() -> Self {
        Self {
            listed: false,
            seen: Vec::new(),
            platforms: HashMap::new(),
            source_ids: Vec::new(),
            error: None,
            complete: true,
            docker_anonymous: false,
        }
    }

    fn failed(error: AppError, docker_anonymous: bool) -> Self {
        Self {
            error: Some(error),
            complete: false,
            docker_anonymous,
            ..Self::empty()
        }
    }
}

/// The result of one discovery run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverReport {
    /// `pull` jobs queued, which is the number of platform rows added.
    pub queued: usize,
    /// False when the listing or the run stopped early. The tail is found at the next run.
    pub complete: bool,
}

/// The discovery service. It holds the pool, the registry client and the credential key.
pub struct Discovery {
    pool: SqlitePool,
    client: Arc<RegistryClient>,
    key: Arc<DerivedKey>,
}

impl Discovery {
    pub fn new(pool: SqlitePool, client: Arc<RegistryClient>, key: Arc<DerivedKey>) -> Self {
        Self { pool, client, key }
    }

    /// Builds the service with the opt-out read from the environment. An invalid value is an
    /// error whose text never repeats the value.
    pub fn from_env(pool: SqlitePool, key: Arc<DerivedKey>) -> Result<Self, AppError> {
        let value = std::env::var(ALLOW_PRIVATE_REGISTRIES_VAR).unwrap_or_default();
        let named = parse_opt_out(&value)?;
        let client = RegistryClient::new(AddressPolicy::new(named, Arc::new(SystemLookup)))?;
        Ok(Self::new(pool, Arc::new(client), key))
    }

    /// A service over `pool` whose client may reach loopback over plain HTTP, for tests.
    #[cfg(test)]
    pub fn for_test_with_pool(pool: SqlitePool) -> Arc<Self> {
        use crate::services::registry::policy::NamedHub;
        let named = vec![NamedHub {
            host: "127.0.0.1".to_owned(),
            plain_http: true,
        }];
        let client = RegistryClient::new(AddressPolicy::new(named, Arc::new(SystemLookup)));
        let key =
            crate::config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .map_err(|_| AppError::InternalError)
                .and_then(|root| crypto::credentials_key(&root));
        match (client, key) {
            (Ok(client), Ok(key)) => Arc::new(Self::new(pool, Arc::new(client), Arc::new(key))),
            _ => panic!("test discovery service"),
        }
    }

    /// Like [`Self::for_test_with_pool`], over a lazy in-memory pool that no test reads.
    #[cfg(test)]
    pub fn for_test() -> Arc<Self> {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        let pool =
            SqlitePoolOptions::new().connect_lazy_with(SqliteConnectOptions::new().in_memory(true));
        Self::for_test_with_pool(pool)
    }

    /// The decrypted credential of a source, or `None`. The token lives in the returned value
    /// only and is zeroized when the session drops it.
    /// The registry client, shared with the pull job.
    pub(crate) fn client(&self) -> &RegistryClient {
        &self.client
    }

    pub(crate) async fn credential_for(
        &self,
        source_id: &str,
    ) -> Result<Option<Credential>, AppError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| AppError::InternalError)?;
        let Some(row) = db::source_credential(&mut conn, source_id).await? else {
            return Ok(None);
        };
        let aad = crypto::aad("source_credentials", "encrypted_token", &row.id);
        let plain = crypto::decrypt(&self.key, &aad, &row.encrypted_token)?;
        let token = String::from_utf8(plain.to_vec()).map_err(|_| AppError::InternalError)?;
        Ok(Some(Credential {
            username: row.username,
            token,
        }))
    }

    /// Runs a `discover` job for the worker and records a `job_runs` row. `now` is Unix seconds.
    pub async fn run_discover(&self, payload_text: &str, now: i64) -> JobOutcome {
        let Ok(payload) = serde_json::from_str::<DiscoverPayload>(payload_text) else {
            return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned());
        };
        match self.discover(&payload, now).await {
            Ok((report, None)) => {
                tracing::info!(
                    queued = report.queued,
                    complete = report.complete,
                    "discovery finished"
                );
                self.record_run(now, report.queued, None).await;
                JobOutcome::Done
            }
            Ok((report, Some((error, docker_anonymous)))) => {
                self.record_run(now, report.queued, Some(fixed_text(&error)))
                    .await;
                failure(&error, docker_anonymous, now)
            }
            Err(error) => {
                self.record_run(now, 0, Some(fixed_text(&error))).await;
                failure(&error, false, now)
            }
        }
    }

    /// Runs discovery for the manual scan route and reports the result. A registry error after
    /// the listing still records what was found, then is returned for the caller to map to 502.
    pub async fn discover_now(
        &self,
        payload: &DiscoverPayload,
        now: i64,
    ) -> Result<DiscoverReport, AppError> {
        match self.discover(payload, now).await {
            Ok((report, None)) => {
                self.record_run(now, report.queued, None).await;
                Ok(report)
            }
            Ok((report, Some((error, _)))) => {
                self.record_run(now, report.queued, Some(fixed_text(&error)))
                    .await;
                Err(error)
            }
            Err(error) => {
                self.record_run(now, 0, Some(fixed_text(&error))).await;
                Err(error)
            }
        }
    }

    /// The run itself. The second value is the error that stopped it, with whether the pull was
    /// an anonymous Docker Hub one, after the gathered part was recorded.
    async fn discover(
        &self,
        payload: &DiscoverPayload,
        now: i64,
    ) -> Result<(DiscoverReport, Option<(AppError, bool)>), AppError> {
        let gathered = self.gather(payload).await?;
        let queued = if gathered.listed {
            self.persist(payload, &gathered, now).await?
        } else {
            0
        };
        let report = DiscoverReport {
            queued,
            complete: gathered.complete,
        };
        let stopped = gathered
            .error
            .map(|error| (error, gathered.docker_anonymous));
        Ok((report, stopped))
    }

    /// Writes the `job_runs` row of one run. A failure to write it is logged and ignored.
    async fn record_run(&self, now: i64, processed: usize, error: Option<String>) {
        let Ok(id) = ids::new_id() else { return };
        let run = JobRun {
            id,
            job_kind: "discover".to_owned(),
            started_at: now,
            finished_at: Some(crate::worker::now_secs()),
            status: if error.is_some() { "failed" } else { "done" }.to_owned(),
            processed_count: i64::try_from(processed).unwrap_or(i64::MAX),
            error_summary: error,
            scanner: None,
        };
        if job_runs::insert(&self.pool, &run).await.is_err() {
            tracing::warn!("could not record a discovery run");
        }
    }

    /// The network phase: list, match, fetch the manifest of each matching tag, and resolve the
    /// platforms of each digest that is not known yet.
    async fn gather(&self, payload: &DiscoverPayload) -> Result<Gathered, AppError> {
        let sources = {
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(|_| AppError::InternalError)?;
            db::sources_for_repository(
                &mut conn,
                &payload.hub_id,
                &payload.repository,
                payload.source_id.as_deref(),
            )
            .await?
        };
        let Some(first) = sources.first() else {
            return Ok(Gathered::empty());
        };
        let endpoint = first
            .pull_endpoint
            .clone()
            .unwrap_or_else(|| first.hub_host.clone());
        let is_docker = first.hub_host == "docker.io";

        // One session per source, each with that source's own credential (decision 35).
        let mut sessions: Vec<PullSession<'_>> = Vec::with_capacity(sources.len());
        let mut has_credential = Vec::with_capacity(sources.len());
        for source in &sources {
            let credential = self.credential_for(&source.id).await?;
            has_credential.push(credential.is_some());
            match self
                .client
                .session(&endpoint, &payload.repository, credential)
            {
                Ok(session) => sessions.push(session),
                Err(error) => return Ok(Gathered::failed(error, false)),
            }
        }
        // The listing uses the first source that has a credential, else the first source.
        let list_index = has_credential.iter().position(|has| *has).unwrap_or(0);
        let docker_anonymous = is_docker && !has_credential.iter().any(|has| *has);
        let source_ids: Vec<String> = sources.iter().map(|source| source.id.clone()).collect();

        let listing = match sessions[list_index].list_tags().await {
            Ok(listing) => listing,
            Err(error) => return Ok(Gathered::failed(error, docker_anonymous)),
        };
        let mut complete = listing.complete;
        let mut tags = listing.tags;
        tags.sort();
        tags.dedup();

        let patterns: Vec<Option<TagPattern>> = sources
            .iter()
            .map(|source| TagPattern::parse(&source.tag_value).ok())
            .collect();

        // Each matching tag goes to the sources whose value matches it. The first matching
        // source's session fetches the manifest once for the tag.
        let mut resolved: HashMap<String, (String, bool)> = HashMap::new();
        let mut platforms: HashMap<String, Vec<PlatformEntry>> = HashMap::new();
        let mut unknown_digests = 0usize;
        let mut hits_by_tag: Vec<(String, Vec<usize>)> = Vec::new();
        let mut error = None;
        let mut fetches = 0usize;
        for tag in tags {
            let hits: Vec<usize> = patterns
                .iter()
                .enumerate()
                .filter(|(_, pattern)| pattern.as_ref().is_some_and(|p| p.matches(&tag)))
                .map(|(index, _)| index)
                .collect();
            if hits.is_empty() {
                continue;
            }
            if fetches >= MAX_MANIFEST_FETCHES_PER_RUN {
                complete = false;
                break;
            }
            fetches += 1;
            let session = &mut sessions[hits[0]];
            let raw = match session.manifest_raw(&tag).await {
                Ok(raw) => raw,
                // A tag deleted between the listing and the fetch skips that tag only.
                Err(AppError::NotFound) => {
                    complete = false;
                    continue;
                }
                Err(other) => {
                    error = Some(other);
                    break;
                }
            };
            let digest = sha256_digest_text(&Sha256::digest(&raw.bytes));
            let parsed = match manifest::parse(&raw.media_type, &raw.bytes) {
                Ok(parsed) => parsed,
                // A manifest this client cannot read skips that tag only.
                Err(AppError::UpstreamContentInvalid) => {
                    complete = false;
                    continue;
                }
                Err(other) => {
                    error = Some(other);
                    break;
                }
            };
            let is_index = matches!(parsed, Parsed::Index(_));
            if !resolved.contains_key(&tag) {
                resolved.insert(tag.clone(), (digest.clone(), is_index));
            }
            let known = {
                let mut conn = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| AppError::InternalError)?;
                db::find_image_id(&mut conn, &payload.hub_id, &payload.repository, &digest)
                    .await?
                    .is_some()
            };
            if !known && !platforms.contains_key(&digest) {
                if unknown_digests >= MAX_NEW_DIGESTS_PER_RUN {
                    resolved.remove(&tag);
                    complete = false;
                    continue;
                }
                match resolve_platforms(session, &digest, parsed).await {
                    Ok(entries) => {
                        unknown_digests += 1;
                        platforms.insert(digest, entries);
                    }
                    Err(AppError::UpstreamContentInvalid | AppError::NotFound) => {
                        resolved.remove(&tag);
                        complete = false;
                        continue;
                    }
                    Err(other) => {
                        resolved.remove(&tag);
                        error = Some(other);
                        break;
                    }
                }
            }
            hits_by_tag.push((tag, hits));
        }

        let mut seen = Vec::new();
        for (tag, hits) in &hits_by_tag {
            let Some((digest, is_index)) = resolved.get(tag) else {
                continue;
            };
            for index in hits {
                seen.push(Seen {
                    source_id: sources[*index].id.clone(),
                    tag: tag.clone(),
                    digest: digest.clone(),
                    is_index: *is_index,
                });
            }
        }
        Ok(Gathered {
            listed: true,
            seen,
            platforms,
            source_ids,
            error,
            complete,
            docker_anonymous,
        })
    }

    /// The write phase, in one `BEGIN IMMEDIATE` transaction. Returns the number of `pull` jobs
    /// queued, one per platform row added.
    async fn persist(
        &self,
        payload: &DiscoverPayload,
        gathered: &Gathered,
        now: i64,
    ) -> Result<usize, AppError> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| AppError::InternalError)?;
        let mut queued = 0usize;
        for item in &gathered.seen {
            let known =
                db::find_image_id(&mut tx, &payload.hub_id, &payload.repository, &item.digest)
                    .await?;
            let (image_id, added) = match known {
                Some(id) => (id, false),
                None => {
                    // An image whose platforms were not resolved is left for the next run.
                    if !gathered.platforms.contains_key(&item.digest) {
                        continue;
                    }
                    let id = ids::new_id()?;
                    let inserted = db::insert_image(
                        &mut tx,
                        &id,
                        &payload.hub_id,
                        &payload.repository,
                        &item.digest,
                        item.is_index,
                        now,
                    )
                    .await?;
                    (id, inserted)
                }
            };
            let image_id = if added {
                image_id
            } else {
                db::find_image_id(&mut tx, &payload.hub_id, &payload.repository, &item.digest)
                    .await?
                    .ok_or(AppError::InternalError)?
            };
            let moved =
                db::tag_has_other_image(&mut tx, &item.source_id, &item.tag, &image_id).await?;
            let recorded =
                db::insert_observation(&mut tx, &item.source_id, &item.tag, &image_id, now).await?;
            if !recorded {
                db::touch_observation(&mut tx, &item.source_id, &item.tag, &image_id, now).await?;
            }
            if !added {
                continue;
            }
            let trigger = if moved { "tag_moved" } else { "first_pull" };
            for (platform, digest) in gathered
                .platforms
                .get(&item.digest)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let platform_id = ids::new_id()?;
                let row =
                    db::insert_platform(&mut tx, &platform_id, &image_id, platform, digest, now)
                        .await?;
                if !row {
                    continue;
                }
                let job = PullPayload {
                    kind: "pull".to_owned(),
                    platform_id,
                    digest: digest.clone(),
                    trigger: trigger.to_owned(),
                    repo_full_name: Some(payload.repository.clone()),
                    tag: Some(item.tag.clone()),
                };
                let text = serde_json::to_string(&job).map_err(|_| AppError::InternalError)?;
                let job_id = ids::new_id()?;
                jobs::enqueue_in(&mut tx, &job_id, Some(&item.source_id), &text, now).await?;
                queued += 1;
            }
        }
        for source_id in &gathered.source_ids {
            db::touch_source(&mut tx, source_id, now).await?;
        }
        tx.commit().await.map_err(|_| AppError::InternalError)?;
        Ok(queued)
    }
}

/// Resolve (section 6, step 2): the platforms of one top-level manifest. An index lists its
/// entries, with attestation entries already skipped by the parser. A single manifest takes its
/// platform from the image config. The returned digests are the platform manifest digests.
pub async fn resolve_platforms(
    session: &mut PullSession<'_>,
    top_digest: &str,
    parsed: Parsed,
) -> Result<Vec<PlatformEntry>, AppError> {
    match parsed {
        Parsed::Index(entries) => entries
            .into_iter()
            .map(|entry| {
                let text = platform_text(
                    &entry.platform.os,
                    &entry.platform.architecture,
                    entry.platform.variant.as_deref(),
                )?;
                Ok((text, entry.descriptor.digest))
            })
            .collect(),
        Parsed::Image { config, .. } => {
            let mut bytes: Vec<u8> = Vec::new();
            session
                .blob_to(
                    &config.digest,
                    config.size,
                    MANIFEST_MAX_BYTES as u64,
                    &mut bytes,
                )
                .await?;
            Ok(vec![(platform_from_config(&bytes)?, top_digest.to_owned())])
        }
    }
}

/// `os/arch[/variant]`, each part limited to lowercase letters, digits, `.`, `_` and `-`. The
/// text comes from a registry, so anything else is refused.
fn platform_text(os: &str, arch: &str, variant: Option<&str>) -> Result<String, AppError> {
    let ok = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
    };
    if !ok(os) || !ok(arch) {
        return Err(AppError::UpstreamContentInvalid);
    }
    let mut text = format!("{os}/{arch}");
    if let Some(variant) = variant.filter(|variant| !variant.is_empty()) {
        if !ok(variant) {
            return Err(AppError::UpstreamContentInvalid);
        }
        text.push('/');
        text.push_str(variant);
    }
    if text.len() > MAX_PLATFORM_BYTES {
        return Err(AppError::UpstreamContentInvalid);
    }
    Ok(text)
}

#[derive(Deserialize)]
struct ConfigPlatform {
    os: Option<String>,
    architecture: Option<String>,
    #[serde(default)]
    variant: Option<String>,
}

/// The platform of a single manifest, from the image config (`os`, `architecture`, `variant`).
fn platform_from_config(bytes: &[u8]) -> Result<String, AppError> {
    let config: ConfigPlatform =
        serde_json::from_slice(bytes).map_err(|_| AppError::UpstreamContentInvalid)?;
    let (Some(os), Some(arch)) = (config.os, config.architecture) else {
        return Err(AppError::UpstreamContentInvalid);
    };
    platform_text(&os, &arch, config.variant.as_deref())
}
