//! Advisory lookup (#379): the CVE id behind a GHSA or GO id that the scanner gave no CVE id for.
//!
//! When a finding carries a GHSA or GO id, no related CVE id, and `vulnerability_aliases` holds
//! none, the id is looked up once at a public advisory source, and the answer is kept forever in
//! `advisory_lookups` (migration 0016):
//!
//! 1. OSV, `GET https://api.osv.dev/v1/vulns/<id>` (GHSA and GO ids, no key). The CVE id is the
//!    alias that starts with `CVE-`.
//! 2. GitHub advisories, `GET https://api.github.com/advisories/<GHSA id>`, only when OSV gave no
//!    answer, and only for a GHSA id. `cve_id` is authoritative. Unauthenticated calls are limited
//!    to 60 per hour, so it is never the first choice.
//!
//! An answer is a CVE id or "none published". A failed, unreachable, rate-limited or unknown
//! (404) lookup is not an answer: nothing is stored, the scan carries on with the id as it is,
//! and a later scan asks again. A resolved pair is recorded in `vulnerability_aliases`, which the
//! scan already reads (#337), so the rest of the scan needs no change.
//!
//! What leaves dockward is one GET per source with the advisory id in the path and no query, no
//! token, no cookie and no other header than `Accept` and `User-Agent`. Only an id that matches
//! the GHSA or GO shape is ever put into a URL. Logs hold the id and the outcome only, never a
//! response body (`specs/security.md`, "Secrets in logs").

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db::advisory_lookups;
use crate::db::scans as scans_db;
use crate::error::AppError;
use crate::services::outbound::{self, OutboundClient, TargetClass};
use crate::services::scanner::parse::{Finding, is_cve_id};

/// The OSV API host.
const OSV_BASE: &str = "https://api.osv.dev";
/// The GitHub API host, always the public one (no token, no configured base URL).
const GITHUB_BASE: &str = "https://api.github.com";
/// One request, so a stalled source cannot hold a scan for long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A response larger than this is not read.
const BODY_MAX_BYTES: usize = 1 << 20;
/// At most this many ids are looked up in one scan. The rest wait for a later scan.
const MAX_LOOKUPS_PER_SCAN: usize = 50;

/// The stored `source` of an answer.
const SOURCE_OSV: &str = "osv";
const SOURCE_GITHUB: &str = "github";

#[derive(Debug, Clone)]
enum Mode {
    /// The two public hosts. Tests never build it (`ScanEnv::under` uses `Off` in tests).
    #[cfg_attr(test, allow(dead_code))]
    Live,
    /// No lookup is made: every id stays as the scanner gave it. Tests only.
    #[cfg(test)]
    Off,
    /// Loopback TLS servers stand in for the two hosts. Tests only.
    #[cfg(test)]
    Local {
        osv: String,
        github: String,
        root: reqwest::Certificate,
    },
}

/// The advisory lookup of the scan step. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AdvisoryLookup {
    mode: Mode,
}

/// What one source said about one id.
enum Reply {
    /// The source knows the id: its CVE id, or `None` when it publishes none.
    Answer(Option<String>),
    /// The source gave no usable answer (not found, an unreadable body). Another source may.
    NoAnswer,
    /// The source cannot be used now (unreachable, a server error, rate limited). It is skipped
    /// for the rest of this scan.
    Down,
}

/// The outcome of one request.
enum Fetched {
    Body(Vec<u8>),
    NotFound,
    Failed,
}

#[derive(Deserialize)]
struct OsvVulnerability {
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Deserialize)]
struct GithubAdvisory {
    cve_id: Option<String>,
}

impl AdvisoryLookup {
    /// The production setup: OSV, then GitHub advisories.
    #[cfg_attr(test, allow(dead_code))]
    pub fn live() -> Self {
        Self { mode: Mode::Live }
    }

    /// A setup that never makes a request. Used by tests that need no lookup.
    #[cfg(test)]
    pub fn off() -> Self {
        Self { mode: Mode::Off }
    }

    /// A setup that asks two loopback TLS servers, `https://127.0.0.1:<port>`, trusting `root`.
    #[cfg(test)]
    pub fn local(osv_port: u16, github_port: u16, root: reqwest::Certificate) -> Self {
        Self {
            mode: Mode::Local {
                osv: format!("https://127.0.0.1:{osv_port}"),
                github: format!("https://127.0.0.1:{github_port}"),
                root,
            },
        }
    }

    fn client(&self) -> Option<(OutboundClient, &str, &str)> {
        match &self.mode {
            #[cfg(test)]
            Mode::Off => None,
            Mode::Live => outbound::client(TargetClass::Advisory, false)
                .ok()
                .map(|client| (client, OSV_BASE, GITHUB_BASE)),
            #[cfg(test)]
            Mode::Local { osv, github, root } => {
                outbound::client_trusting(TargetClass::Advisory, true, root.clone())
                    .ok()
                    .map(|client| (client, osv.as_str(), github.as_str()))
            }
        }
    }

    /// Looks up the GHSA and GO ids of `findings` that have no CVE id yet, and records each
    /// answer. Never fails the caller: a database or network problem leaves the ids as they are.
    pub async fn resolve(&self, pool: &SqlitePool, findings: &[Finding], now: i64) {
        let pending: BTreeSet<&str> = findings
            .iter()
            .filter(|finding| !is_cve_id(&finding.cve_id) && finding.alias.is_none())
            .map(|finding| finding.cve_id.as_str())
            .filter(|id| is_advisory_id(id))
            .collect();
        if pending.is_empty() {
            return;
        }
        if self.run(pool, &pending, now).await.is_err() {
            tracing::warn!("an advisory lookup could not be recorded");
        }
    }

    async fn run(
        &self,
        pool: &SqlitePool,
        pending: &BTreeSet<&str>,
        now: i64,
    ) -> Result<(), AppError> {
        let Some((http, osv_base, github_base)) = self.client() else {
            return Ok(());
        };
        let (mut osv_up, mut github_up) = (true, true);
        let mut asked = 0;
        for id in pending {
            // Cached answers and recorded aliases cost no request.
            {
                let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
                if scans_db::alias_primary(&mut conn, id).await?.is_some() {
                    continue;
                }
                if let Some(cached) = advisory_lookups::get(&mut conn, id).await? {
                    if let Some(cve) = cached {
                        scans_db::record_alias(&mut conn, id, &cve).await?;
                    }
                    continue;
                }
            }
            if asked >= MAX_LOOKUPS_PER_SCAN || (!osv_up && !github_up) {
                break;
            }
            asked += 1;
            let found = ask(
                &http,
                (osv_base, github_base),
                id,
                (&mut osv_up, &mut github_up),
            )
            .await;
            let Some((cve, source)) = found else {
                tracing::warn!(advisory_id = %id, outcome = "unavailable", "advisory lookup");
                continue;
            };
            let mut tx = pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map_err(|_| AppError::InternalError)?;
            advisory_lookups::put(&mut tx, id, cve.as_deref(), source, now).await?;
            if let Some(cve) = &cve {
                scans_db::record_alias(&mut tx, id, cve).await?;
            }
            tx.commit().await.map_err(|_| AppError::InternalError)?;
            let outcome = if cve.is_some() { "resolved" } else { "no_cve" };
            tracing::info!(advisory_id = %id, outcome, source, "advisory lookup");
        }
        Ok(())
    }
}

/// Asks OSV, then (for a GHSA id) GitHub. `None` when neither answered.
async fn ask(
    http: &OutboundClient,
    (osv_base, github_base): (&str, &str),
    id: &str,
    (osv_up, github_up): (&mut bool, &mut bool),
) -> Option<(Option<String>, &'static str)> {
    if *osv_up {
        let reply = match fetch(http, &format!("{osv_base}/v1/vulns/{id}")).await {
            Fetched::Body(body) => osv_reply(&body),
            Fetched::NotFound => Reply::NoAnswer,
            Fetched::Failed => Reply::Down,
        };
        match reply {
            Reply::Answer(cve) => return Some((cve, SOURCE_OSV)),
            Reply::Down => *osv_up = false,
            Reply::NoAnswer => {}
        }
    }
    // GitHub advisories hold GHSA ids only.
    if *github_up && id.starts_with("GHSA-") {
        let reply = match fetch(http, &format!("{github_base}/advisories/{id}")).await {
            Fetched::Body(body) => github_reply(&body),
            Fetched::NotFound => Reply::NoAnswer,
            Fetched::Failed => Reply::Down,
        };
        match reply {
            Reply::Answer(cve) => return Some((cve, SOURCE_GITHUB)),
            Reply::Down => *github_up = false,
            Reply::NoAnswer => {}
        }
    }
    None
}

/// One GET. Only `Accept` and `User-Agent` are set by dockward. A status other than 200 and 404,
/// a transport error and an oversized body are `Failed`.
async fn fetch(http: &OutboundClient, url: &str) -> Fetched {
    let Ok(url) = reqwest::Url::parse(url) else {
        return Fetched::Failed;
    };
    let Ok(request) = http.get(&url) else {
        return Fetched::Failed;
    };
    let sent = request
        .header("accept", "application/json")
        .header("user-agent", "Dockward")
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await;
    let Ok(mut response) = sent else {
        return Fetched::Failed;
    };
    match response.status().as_u16() {
        200 => {}
        404 => return Fetched::NotFound,
        _ => return Fetched::Failed,
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > BODY_MAX_BYTES {
                    return Fetched::Failed;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Fetched::Body(body),
            Err(_) => return Fetched::Failed,
        }
    }
}

fn osv_reply(body: &[u8]) -> Reply {
    match serde_json::from_slice::<OsvVulnerability>(body) {
        Ok(found) => Reply::Answer(found.aliases.into_iter().find(|alias| is_valid_cve(alias))),
        Err(_) => Reply::NoAnswer,
    }
}

fn github_reply(body: &[u8]) -> Reply {
    match serde_json::from_slice::<GithubAdvisory>(body) {
        Ok(GithubAdvisory { cve_id: None }) => Reply::Answer(None),
        Ok(GithubAdvisory { cve_id: Some(cve) }) if is_valid_cve(&cve) => Reply::Answer(Some(cve)),
        Ok(_) | Err(_) => Reply::NoAnswer,
    }
}

/// True for the id shapes that are put into a URL: `GHSA-xxxx-xxxx-xxxx` (lowercase letters and
/// digits) and `GO-YYYY-N...`.
fn is_advisory_id(id: &str) -> bool {
    if let Some(rest) = id.strip_prefix("GHSA-") {
        let parts: Vec<&str> = rest.split('-').collect();
        return parts.len() == 3
            && parts.iter().all(|part| {
                part.len() == 4
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            });
    }
    if let Some(rest) = id.strip_prefix("GO-") {
        let mut parts = rest.split('-');
        let (Some(year), Some(number), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        return year.len() == 4
            && year.bytes().all(|byte| byte.is_ascii_digit())
            && (1..=10).contains(&number.len())
            && number.bytes().all(|byte| byte.is_ascii_digit());
    }
    false
}

/// True for `CVE-YYYY-N...` with four or more digits after the year, so only a well-formed id
/// from an advisory is stored.
fn is_valid_cve(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let (Some(year), Some(number), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && (4..=12).contains(&number.len())
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests;
