//! Download, verify and install a scanner on the data volume, and roll back (#403, phase 2 of
//! #390). Admin-triggered only, never automatic.
//!
//! Install of `scanner`, in order. Any failure stops here, leaves the pointers and the scanner in
//! use unchanged, removes the staging folder, and is logged with the scanner key, the version and
//! a fixed outcome word only (never a URL, a path or a response body):
//!
//! 1. Ask `api.github.com` for the latest stable release (no token), as the daily check does.
//!    It must be newer than the bundled scanner and than a downloaded version in use.
//! 2. Download `<scanner>_<v>_checksums.txt` and its `.sigstore.json` bundle, and verify the
//!    bundle over the checksums file against the pinned upstream release identity
//!    ([`verify::release_identity`]).
//! 3. Download the Linux amd64 archive into `scanners/<scanner>/.install/`, hashing it on the
//!    way, and compare its SHA-256 with its line in the verified checksums file.
//! 4. Unpack only the scanner binary (mode 0755) and move it to `scanners/<scanner>/<v>/`.
//! 5. Under the live selection: [`ScannerVolume::record_current`], then re-run the selection, so
//!    the next scan and `GET /api/v1/about` use the new version.
//!
//! Downloads use the guarded client with the class [`TargetClass::ScannerDownload`]: HTTPS only,
//! the hosts `github.com` and `release-assets.githubusercontent.com` only, no token, and the
//! resolved-address check. The client follows no redirect by itself; this module follows at most
//! [`MAX_REDIRECTS`] hops and each hop passes the same host check. Every download has a size cap
//! and a timeout.
//!
//! Install and rollback are serialised by one lock; a second request while one runs is refused
//! (`scanner_busy`). Scans never take this lock and keep running with the old binary while an
//! install downloads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::Scanner;
use super::selection::ScannerPrograms;
use super::upstream_check::{GITHUB_BASE, fetch_latest, upstream_repo};
use super::version::Version;
use super::volume::{ScannerVolume, Slot};
use crate::services::outbound::{self, OutboundClient, TargetClass};

pub mod archive;
pub mod verify;

use verify::{BundleVerifier, SigstoreVerifier};

/// The web host the release downloads start from.
const DOWNLOAD_BASE: &str = "https://github.com";
/// Redirect hops followed per download. GitHub answers one (to the release-asset host).
pub const MAX_REDIRECTS: usize = 3;
/// The staging folder under `scanners/<scanner>`. Removed after every install.
const STAGING: &str = ".install";

/// Size caps and timeouts. The scanner archives are tens of MB (Trivy v0.76.2 is 52 MB, Grype
/// v0.121.3 is 33 MB; the Trivy binary inside is 176 MB).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub archive_bytes: u64,
    pub binary_bytes: u64,
    pub checksums_bytes: u64,
    pub bundle_bytes: u64,
    pub archive_timeout: Duration,
    pub small_timeout: Duration,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        archive_bytes: 200 << 20,
        binary_bytes: 600 << 20,
        checksums_bytes: 64 << 10,
        bundle_bytes: 256 << 10,
        archive_timeout: Duration::from_secs(600),
        small_timeout: Duration::from_secs(30),
    };
}

/// Why an install or a rollback did not happen. [`Self::kind`] is the fixed word returned to the
/// admin and written to the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    Busy,
    NoPrevious,
    NoBroken,
    UnsupportedPlatform,
    BundledUnknown,
    ReleaseUnavailable,
    NotNewer,
    AlreadyInstalled,
    DownloadFailed,
    DownloadTooLarge,
    ChecksumMissing,
    ChecksumMismatch,
    SignatureInvalid,
    ArchiveRefused,
    Storage,
}

impl InstallError {
    pub fn kind(self) -> &'static str {
        match self {
            InstallError::Busy => "scanner_busy",
            InstallError::NoPrevious => "no_previous_version",
            InstallError::NoBroken => "no_broken_mark",
            InstallError::UnsupportedPlatform => "unsupported_platform",
            InstallError::BundledUnknown => "bundled_version_unknown",
            InstallError::ReleaseUnavailable => "release_unavailable",
            InstallError::NotNewer => "not_newer_than_bundled",
            InstallError::AlreadyInstalled => "already_installed",
            InstallError::DownloadFailed => "download_failed",
            InstallError::DownloadTooLarge => "download_too_large",
            InstallError::ChecksumMissing => "checksum_missing",
            InstallError::ChecksumMismatch => "checksum_mismatch",
            InstallError::SignatureInvalid => "signature_invalid",
            InstallError::ArchiveRefused => "archive_refused",
            InstallError::Storage => "storage_failed",
        }
    }
}

#[derive(Debug, Clone)]
enum Mode {
    /// The public GitHub hosts. Tests never build it.
    #[cfg_attr(test, allow(dead_code))]
    Live,
    /// Nothing is reachable: every request fails. Test states that never install use it.
    #[cfg_attr(not(test), allow(dead_code))]
    Offline,
    /// A loopback TLS server stands in for `api.github.com` and `github.com`. Tests only.
    #[cfg(test)]
    Local {
        base: String,
        root: reqwest::Certificate,
    },
}

/// The installer. One per process, shared by the admin routes.
#[derive(Debug)]
pub struct Installer {
    programs: Arc<ScannerPrograms>,
    volume: ScannerVolume,
    bundled: [Option<Version>; 2],
    mode: Mode,
    verifier: Arc<dyn BundleVerifier>,
    limits: Limits,
    lock: tokio::sync::Mutex<()>,
}

fn index(scanner: Scanner) -> usize {
    match scanner {
        Scanner::Trivy => 0,
        Scanner::Grype => 1,
    }
}

/// The asset names of one release.
struct Assets {
    archive: String,
    checksums: String,
    bundle: String,
}

fn assets(scanner: Scanner, version: Version) -> Assets {
    let archive = match scanner {
        Scanner::Trivy => format!("trivy_{version}_Linux-64bit.tar.gz"),
        Scanner::Grype => format!("grype_{version}_linux_amd64.tar.gz"),
    };
    let checksums = format!("{}_{version}_checksums.txt", scanner.key());
    let bundle = format!("{checksums}.sigstore.json");
    Assets {
        archive,
        checksums,
        bundle,
    }
}

impl Installer {
    /// The production installer against the public GitHub hosts.
    #[cfg_attr(test, allow(dead_code))]
    pub fn live(
        data_dir: &Path,
        programs: Arc<ScannerPrograms>,
        bundled: [Option<Version>; 2],
    ) -> Self {
        Self::build(
            data_dir,
            programs,
            bundled,
            Mode::Live,
            Arc::new(SigstoreVerifier),
        )
    }

    /// An installer that reaches nothing. For test states that do not install.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn offline(data_dir: &Path) -> Self {
        Self::build(
            data_dir,
            Arc::new(ScannerPrograms::bundled(data_dir)),
            [None; 2],
            Mode::Offline,
            Arc::new(SigstoreVerifier),
        )
    }

    /// An installer that downloads from `https://127.0.0.1:<port>`, trusting `root`, and checks
    /// bundles with `verifier`. Tests only.
    #[cfg(test)]
    pub fn local(
        data_dir: &Path,
        programs: Arc<ScannerPrograms>,
        bundled: [Option<Version>; 2],
        port: u16,
        root: reqwest::Certificate,
        verifier: Arc<dyn BundleVerifier>,
    ) -> Self {
        let mode = Mode::Local {
            base: format!("https://127.0.0.1:{port}"),
            root,
        };
        Self::build(data_dir, programs, bundled, mode, verifier)
    }

    /// The same installer with other caps. Tests only.
    #[cfg(test)]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    fn build(
        data_dir: &Path,
        programs: Arc<ScannerPrograms>,
        bundled: [Option<Version>; 2],
        mode: Mode,
        verifier: Arc<dyn BundleVerifier>,
    ) -> Self {
        Self {
            programs,
            volume: ScannerVolume::under(data_dir),
            bundled,
            mode,
            verifier,
            limits: Limits::DEFAULT,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The release client and API base, and the download client and web base.
    fn clients(&self) -> Option<(OutboundClient, String, OutboundClient, String)> {
        match &self.mode {
            Mode::Live => Some((
                outbound::client(TargetClass::ScannerRelease, false).ok()?,
                GITHUB_BASE.to_owned(),
                outbound::client(TargetClass::ScannerDownload, false).ok()?,
                DOWNLOAD_BASE.to_owned(),
            )),
            Mode::Offline => None,
            #[cfg(test)]
            Mode::Local { base, root } => Some((
                outbound::client_trusting(TargetClass::ScannerRelease, true, root.clone()).ok()?,
                base.clone(),
                outbound::client_trusting(TargetClass::ScannerDownload, true, root.clone()).ok()?,
                base.clone(),
            )),
        }
    }

    /// Installs the latest stable release of `scanner` if its checksum and its Sigstore bundle
    /// verify. Returns the version now in use.
    pub async fn install(&self, scanner: Scanner) -> Result<Version, InstallError> {
        let Ok(_guard) = self.lock.try_lock() else {
            log_outcome(scanner, None, Err(InstallError::Busy), "scanner install");
            return Err(InstallError::Busy);
        };
        let mut attempted = None;
        let outcome = self.install_locked(scanner, &mut attempted).await;
        // The staging folder never outlives an install, whatever the outcome.
        let _ = remove_dir(&self.staging(scanner));
        log_outcome(scanner, attempted, outcome, "scanner install");
        outcome
    }

    async fn install_locked(
        &self,
        scanner: Scanner,
        attempted: &mut Option<Version>,
    ) -> Result<Version, InstallError> {
        if matches!(self.mode, Mode::Live) && std::env::consts::ARCH != "x86_64" {
            // Only the Linux amd64 archive is fetched (#403).
            return Err(InstallError::UnsupportedPlatform);
        }
        let bundled = self.bundled[index(scanner)].ok_or(InstallError::BundledUnknown)?;
        let (release_http, api_base, download_http, web_base) =
            self.clients().ok_or(InstallError::ReleaseUnavailable)?;
        let repo = upstream_repo(scanner);
        let latest = fetch_latest(
            &release_http,
            &format!("{api_base}/repos/{repo}/releases/latest"),
        )
        .await
        .ok_or(InstallError::ReleaseUnavailable)?;
        *attempted = Some(latest);
        if latest <= bundled {
            return Err(InstallError::NotNewer);
        }
        if let Some(current) = self.volume.read(scanner, Slot::Current).version()
            && current >= latest
            && self.volume.has_binary(scanner, current)
        {
            return Err(InstallError::AlreadyInstalled);
        }

        let names = assets(scanner, latest);
        let base = format!("{web_base}/{repo}/releases/download/{}", latest.tagged());
        let limits = self.limits;
        let checksums = download_bytes(
            &download_http,
            &format!("{base}/{}", names.checksums),
            limits.checksums_bytes,
            limits.small_timeout,
        )
        .await?;
        let bundle = download_bytes(
            &download_http,
            &format!("{base}/{}", names.bundle),
            limits.bundle_bytes,
            limits.small_timeout,
        )
        .await?;
        let identity = verify::release_identity(scanner, latest);
        if !self.verifier.verify(&checksums, &bundle, &identity) {
            return Err(InstallError::SignatureInvalid);
        }
        let expected = archive::expected_sha256(&checksums, &names.archive)
            .ok_or(InstallError::ChecksumMissing)?;

        let staging = self.staging(scanner);
        remove_dir(&staging)?;
        let unpacked = staging.join("bin");
        std::fs::create_dir_all(&unpacked).map_err(|_| InstallError::Storage)?;
        let archive_path = staging.join("archive.tar.gz");
        let digest = download_file(
            &download_http,
            &format!("{base}/{}", names.archive),
            &archive_path,
            limits.archive_bytes,
            limits.archive_timeout,
        )
        .await?;
        if digest != expected {
            return Err(InstallError::ChecksumMismatch);
        }

        let binary = unpacked.join(scanner.key());
        let max = limits.binary_bytes;
        let source = archive_path.clone();
        let extracted = tokio::task::spawn_blocking(move || {
            let file =
                std::fs::File::open(&source).map_err(|_| archive::ArchiveFault::Unreadable)?;
            archive::extract_binary(std::io::BufReader::new(file), scanner.key(), &binary, max)
        })
        .await
        .map_err(|_| InstallError::Storage)?;
        if let Err(fault) = extracted {
            tracing::warn!(
                scanner = scanner.key(),
                version = %latest.tagged(),
                fault = fault.text(),
                "scanner archive refused"
            );
            return Err(match fault {
                archive::ArchiveFault::Write => InstallError::Storage,
                _ => InstallError::ArchiveRefused,
            });
        }

        // Only now does anything outside the staging folder change.
        let target = self.volume.version_dir(scanner, latest);
        remove_dir(&target)?;
        std::fs::rename(&unpacked, &target).map_err(|_| InstallError::Storage)?;
        if self.volume.record_current(scanner, latest).is_err() {
            // A folder that no pointer names is not kept.
            let named = [Slot::Current, Slot::Previous]
                .into_iter()
                .any(|slot| self.volume.read(scanner, slot).version() == Some(latest));
            if !named {
                let _ = remove_dir(&target);
            }
            return Err(InstallError::Storage);
        }
        self.programs
            .reselect(scanner, self.bundled[index(scanner)]);
        Ok(latest)
    }

    /// Switches `scanner` back to its previous downloaded version. Returns the version now
    /// current. Refused when no previous version with a binary is kept.
    pub async fn rollback(&self, scanner: Scanner) -> Result<Version, InstallError> {
        let Ok(_guard) = self.lock.try_lock() else {
            log_outcome(scanner, None, Err(InstallError::Busy), "scanner rollback");
            return Err(InstallError::Busy);
        };
        let outcome = match self.volume.rollback(scanner) {
            Ok(version) => {
                self.programs
                    .reselect(scanner, self.bundled[index(scanner)]);
                Ok(version)
            }
            Err(crate::error::AppError::NotFound) => Err(InstallError::NoPrevious),
            Err(_) => Err(InstallError::Storage),
        };
        log_outcome(scanner, outcome.ok(), outcome, "scanner rollback");
        outcome
    }

    /// Removes the broken mark of the downloaded version that failed to launch, so it can be
    /// selected again. Returns that version. Refused when no version is marked broken.
    pub async fn clear_broken(&self, scanner: Scanner) -> Result<Version, InstallError> {
        let Ok(_guard) = self.lock.try_lock() else {
            log_outcome(
                scanner,
                None,
                Err(InstallError::Busy),
                "scanner clear broken",
            );
            return Err(InstallError::Busy);
        };
        let outcome = match self
            .programs
            .clear_broken(scanner, self.bundled[index(scanner)])
        {
            Ok(Some(version)) => Ok(version),
            Ok(None) => Err(InstallError::NoBroken),
            Err(_) => Err(InstallError::Storage),
        };
        log_outcome(scanner, outcome.ok(), outcome, "scanner clear broken");
        outcome
    }

    fn staging(&self, scanner: Scanner) -> PathBuf {
        self.volume.scanner_dir(scanner).join(STAGING)
    }
}

fn log_outcome(
    scanner: Scanner,
    version: Option<Version>,
    outcome: Result<Version, InstallError>,
    message: &'static str,
) {
    let version = version.map(|v| v.tagged());
    let version = version.as_deref().unwrap_or("none");
    match outcome {
        Ok(_) => tracing::info!(
            scanner = scanner.key(),
            version,
            outcome = "installed",
            "{message}"
        ),
        Err(err) => tracing::warn!(
            scanner = scanner.key(),
            version,
            outcome = err.kind(),
            "{message}"
        ),
    }
}

fn remove_dir(path: &Path) -> Result<(), InstallError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Storage),
    }
}

/// GETs `url`, following up to [`MAX_REDIRECTS`] redirects, each through the guarded client's
/// host check. Returns the final `200` response. The URLs are never logged: the release-asset
/// redirect carries a signed query.
async fn fetch(
    http: &OutboundClient,
    url: &str,
    timeout: Duration,
) -> Result<reqwest::Response, InstallError> {
    let mut url = reqwest::Url::parse(url).map_err(|_| InstallError::DownloadFailed)?;
    for _ in 0..=MAX_REDIRECTS {
        let response = http
            .get(&url)
            .map_err(|_| InstallError::DownloadFailed)?
            .header("user-agent", "Dockward")
            .header("accept", "application/octet-stream")
            .timeout(timeout)
            .send()
            .await
            .map_err(|_| InstallError::DownloadFailed)?;
        let status = response.status();
        if status.as_u16() == 200 {
            return Ok(response);
        }
        if !status.is_redirection() {
            return Err(InstallError::DownloadFailed);
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(InstallError::DownloadFailed)?;
        url = url
            .join(location)
            .map_err(|_| InstallError::DownloadFailed)?;
    }
    Err(InstallError::DownloadFailed)
}

/// Refuses a response whose declared length is over `max`.
fn check_length(response: &reqwest::Response, max: u64) -> Result<(), InstallError> {
    match response.content_length() {
        Some(length) if length > max => Err(InstallError::DownloadTooLarge),
        _ => Ok(()),
    }
}

/// A small download held in memory, at most `max` bytes.
async fn download_bytes(
    http: &OutboundClient,
    url: &str,
    max: u64,
    timeout: Duration,
) -> Result<Vec<u8>, InstallError> {
    let mut response = fetch(http, url, timeout).await?;
    check_length(&response, max)?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| InstallError::DownloadFailed)?
    {
        if (body.len() + chunk.len()) as u64 > max {
            return Err(InstallError::DownloadTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A download streamed to `dest`, at most `max` bytes. Returns its SHA-256.
async fn download_file(
    http: &OutboundClient,
    url: &str,
    dest: &Path,
    max: u64,
    timeout: Duration,
) -> Result<[u8; 32], InstallError> {
    let mut response = fetch(http, url, timeout).await?;
    check_length(&response, max)?;
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|_| InstallError::Storage)?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| InstallError::DownloadFailed)?
    {
        total += chunk.len() as u64;
        if total > max {
            return Err(InstallError::DownloadTooLarge);
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|_| InstallError::Storage)?;
    }
    file.sync_all().await.map_err(|_| InstallError::Storage)?;
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) mod tests;
