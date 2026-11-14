//! Install and rollback tests (#403). A loopback TLS server stands in for `api.github.com`,
//! `github.com` and the release-asset host: no test reaches the network. The Sigstore check is the
//! [`BundleVerifier`] seam; the real verifier is tested on the real upstream bundles in
//! `verify.rs`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::archive::tests::{Entry, file, tar_gz};
use super::*;
use crate::services::outbound::socket_tests::loopback_tls_server_bytes;
use crate::services::scanner::selection::Selected;
use crate::services::scanner::volume::tests::{ExpectTestOk, place, temp_data_dir, v};

pub(crate) const BUNDLED: [Option<Version>; 2] = [
    Some(Version::from_parts(0, 76, 2)),
    Some(Version::from_parts(0, 121, 3)),
];

/// The fixture binary inside the release archive.
pub(crate) const BINARY: &[u8] = b"#!/bin/sh\necho 'Version: 0.77.0'\n";

/// One verifier call: the artifact, the bundle and the identity asked for.
pub(crate) type Call = (Vec<u8>, Vec<u8>, String);

/// A verifier that records the identity it was asked for and answers `accept`.
#[derive(Debug, Default)]
pub(crate) struct FakeVerifier {
    pub accept: bool,
    pub seen: Mutex<Vec<Call>>,
}

impl BundleVerifier for FakeVerifier {
    fn verify(&self, artifact: &[u8], bundle_json: &[u8], identity: &str) -> bool {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((artifact.to_vec(), bundle_json.to_vec(), identity.to_owned()));
        }
        self.accept
    }
}

pub(crate) fn verifier(accept: bool) -> Arc<FakeVerifier> {
    Arc::new(FakeVerifier {
        accept,
        seen: Mutex::default(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the fake upstream serves for Trivy.
#[derive(Clone)]
pub(crate) struct Upstream {
    pub tag: String,
    pub archive: Vec<u8>,
    /// The checksums file; `None` builds the correct one from `archive`.
    pub checksums: Option<String>,
    /// The full response for the archive download; `None` serves `archive` with a 200.
    pub archive_response: Option<Vec<u8>>,
}

impl Upstream {
    pub(crate) fn good() -> Self {
        Self {
            tag: "v0.77.0".to_owned(),
            archive: tar_gz(&[file("LICENSE", b"x"), file("trivy", BINARY)]),
            checksums: None,
            archive_response: None,
        }
    }
}

fn response(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn redirect(location: &str) -> Vec<u8> {
    response("302 Found", &format!("Location: {location}\r\n"), b"")
}

/// Serves `upstream` and returns the port, the trust root and the request paths seen. Each
/// release download answers `302` to an `/assets/` path with a signed-looking query, as GitHub
/// does; the asset is served there.
pub(crate) async fn serve(
    upstream: Upstream,
) -> (u16, reqwest::Certificate, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = Arc::clone(&seen);
    let version = upstream.tag.trim_start_matches('v').to_owned();
    let archive_name = format!("trivy_{version}_Linux-64bit.tar.gz");
    let checksums = upstream.checksums.clone().unwrap_or_else(|| {
        let digest = Sha256::digest(&upstream.archive);
        format!(
            "{}  trivy_{version}_FreeBSD-64bit.tar.gz\n{}  {archive_name}\n",
            "0".repeat(64),
            hex(&digest)
        )
    });
    let download = format!("/aquasecurity/trivy/releases/download/{}/", upstream.tag);
    let (port, root) = loopback_tls_server_bytes(move |head| {
        let target = head
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        if let Ok(mut seen) = record.lock() {
            seen.push(target.clone());
        }
        if target == "/repos/aquasecurity/trivy/releases/latest" {
            let body = format!(
                r#"{{"tag_name":"{}","prerelease":false,"draft":false}}"#,
                upstream.tag
            );
            return response("200 OK", "", body.as_bytes());
        }
        if let Some(asset) = target.strip_prefix(&download) {
            return redirect(&format!("/assets/{asset}?sig=SECRET-SIGNED-QUERY"));
        }
        let Some(asset) = target
            .strip_prefix("/assets/")
            .and_then(|rest| rest.split('?').next())
        else {
            return response("404 Not Found", "", b"");
        };
        if asset == archive_name {
            return upstream
                .archive_response
                .clone()
                .unwrap_or_else(|| response("200 OK", "", &upstream.archive));
        }
        if asset == format!("trivy_{version}_checksums.txt") {
            return response("200 OK", "", checksums.as_bytes());
        }
        if asset == format!("trivy_{version}_checksums.txt.sigstore.json") {
            return response("200 OK", "", br#"{"mediaType":"fixture"}"#);
        }
        response("404 Not Found", "", b"")
    })
    .await;
    (port, root, seen)
}

struct Fx {
    dir: PathBuf,
    installer: Installer,
    programs: Arc<ScannerPrograms>,
    verifier: Arc<FakeVerifier>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fx {
    fn volume(&self) -> ScannerVolume {
        ScannerVolume::under(&self.dir)
    }

    fn pointers(&self) -> (Option<Version>, Option<Version>) {
        let volume = self.volume();
        (
            volume.read(Scanner::Trivy, Slot::Current).version(),
            volume.read(Scanner::Trivy, Slot::Previous).version(),
        )
    }

    fn staging_gone(&self) -> bool {
        !self
            .volume()
            .scanner_dir(Scanner::Trivy)
            .join(STAGING)
            .exists()
    }
}

/// A data dir where Trivy 0.76.5 is the downloaded current version, and an installer against
/// `upstream`.
async fn fx(name: &str, upstream: Upstream, accept: bool) -> Fx {
    let dir = temp_data_dir(name);
    let volume = ScannerVolume::under(&dir);
    place(&volume, Scanner::Trivy, v("0.76.5"), "old");
    volume
        .record_current(Scanner::Trivy, v("0.76.5"))
        .expect_test_ok();
    let programs = Arc::new(ScannerPrograms::bundled(&dir).select_at_startup(BUNDLED));
    let (port, root, seen) = serve(upstream).await;
    let verifier = verifier(accept);
    let installer = Installer::local(
        &dir,
        programs.clone(),
        BUNDLED,
        port,
        root,
        verifier.clone(),
    );
    Fx {
        dir,
        installer,
        programs,
        verifier,
        seen,
    }
}

/// Nothing changed: 0.76.5 is current with no previous, no 0.77.0 folder, no staging folder,
/// and the old binary still runs.
fn assert_unchanged(fx: &Fx) {
    assert_eq!(fx.pointers(), (Some(v("0.76.5")), None));
    assert!(
        !fx.volume()
            .version_dir(Scanner::Trivy, v("0.77.0"))
            .exists()
    );
    assert!(fx.staging_gone(), "the partial folder is removed");
    assert_eq!(
        fx.programs.state(Scanner::Trivy).selected,
        Selected::Downloaded(v("0.76.5"))
    );
}

#[tokio::test]
async fn a_verified_install_is_recorded_as_current_and_the_old_current_becomes_previous() {
    let fx = fx("install-ok", Upstream::good(), true).await;
    assert_eq!(fx.installer.install(Scanner::Trivy).await, Ok(v("0.77.0")));
    assert_eq!(fx.pointers(), (Some(v("0.77.0")), Some(v("0.76.5"))));
    let binary = fx.volume().binary_path(Scanner::Trivy, v("0.77.0"));
    assert_eq!(std::fs::read(&binary).ok(), Some(BINARY.to_vec()));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&binary).map(|m| m.permissions().mode() & 0o111);
    assert_eq!(mode.ok(), Some(0o111), "the binary is executable");
    // Only the binary is unpacked.
    let names: Vec<_> = std::fs::read_dir(fx.volume().version_dir(Scanner::Trivy, v("0.77.0")))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, vec![std::ffi::OsString::from("trivy")]);
    assert!(fx.staging_gone());
    // The live selection follows, so the next scan runs the new binary.
    let (path, selected) = fx.programs.program(Scanner::Trivy);
    assert_eq!(selected, Selected::Downloaded(v("0.77.0")));
    assert_eq!(path, binary);
    // The bundle was checked over the checksums file for the pinned identity of this tag.
    let seen = fx
        .verifier
        .seen
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default();
    assert_eq!(seen.len(), 1);
    assert!(String::from_utf8_lossy(&seen[0].0).contains("trivy_0.77.0_Linux-64bit.tar.gz"));
    assert_eq!(
        seen[0].2,
        "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.77.0"
    );
    // Every asset came through the redirect, as on GitHub.
    let paths = fx.seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with("/assets/trivy_0.77.0_Linux-64bit.tar.gz?"))
    );
}

#[tokio::test]
async fn a_second_install_of_the_same_version_is_refused() {
    let fx = fx("install-again", Upstream::good(), true).await;
    assert_eq!(fx.installer.install(Scanner::Trivy).await, Ok(v("0.77.0")));
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::AlreadyInstalled)
    );
    assert_eq!(fx.pointers(), (Some(v("0.77.0")), Some(v("0.76.5"))));
}

#[tokio::test]
async fn a_checksum_mismatch_installs_nothing() {
    let mut upstream = Upstream::good();
    upstream.checksums = Some(format!(
        "{}  trivy_0.77.0_Linux-64bit.tar.gz\n",
        "ab".repeat(32)
    ));
    let fx = fx("install-mismatch", upstream, true).await;
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::ChecksumMismatch)
    );
    assert_unchanged(&fx);
}

#[tokio::test]
async fn a_checksums_file_without_the_archive_line_installs_nothing() {
    let mut upstream = Upstream::good();
    upstream.checksums = Some(format!("{}  other.tar.gz\n", "ab".repeat(32)));
    let fx = fx("install-no-line", upstream, true).await;
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::ChecksumMissing)
    );
    assert_unchanged(&fx);
    // Refused before the archive was fetched.
    let paths = fx.seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert!(!paths.iter().any(|p| p.contains("Linux-64bit.tar.gz")));
}

#[tokio::test]
async fn a_bad_or_wrong_identity_bundle_installs_nothing() {
    // The seam refuses: a bundle that does not verify, or one for another identity.
    let fx = fx("install-bad-bundle", Upstream::good(), false).await;
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::SignatureInvalid)
    );
    assert_unchanged(&fx);
    let paths = fx.seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert!(
        !paths.iter().any(|p| p.contains("Linux-64bit.tar.gz")),
        "the archive is not fetched when the bundle fails"
    );

    // The real verifier, given the served bundle: refused too.
    let (port, root, _) = serve(Upstream::good()).await;
    let installer = Installer::local(
        &fx.dir,
        fx.programs.clone(),
        BUNDLED,
        port,
        root,
        Arc::new(SigstoreVerifier),
    );
    assert_eq!(
        installer.install(Scanner::Trivy).await,
        Err(InstallError::SignatureInvalid)
    );
    assert_unchanged(&fx);
}

#[tokio::test]
async fn a_failed_download_leaves_the_current_scanner_and_removes_the_partial_folder() {
    // A server error, and a body cut short after part of the archive was written.
    let cut = {
        let mut out =
            b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n".to_vec();
        out.extend_from_slice(&[7u8; 4096]);
        out
    };
    for (name, reply) in [
        (
            "install-500",
            response("500 Internal Server Error", "", b""),
        ),
        ("install-cut", cut),
        ("install-loop", redirect("/assets/loop")),
    ] {
        let mut upstream = Upstream::good();
        upstream.archive_response = Some(reply);
        let fx = fx(name, upstream, true).await;
        assert_eq!(
            fx.installer.install(Scanner::Trivy).await,
            Err(InstallError::DownloadFailed),
            "{name}"
        );
        assert_unchanged(&fx);
    }
}

#[tokio::test]
async fn an_unreachable_release_check_installs_nothing() {
    let dir = temp_data_dir("install-offline");
    let installer = Installer::offline(&dir);
    assert_eq!(
        installer.install(Scanner::Trivy).await,
        Err(InstallError::BundledUnknown)
    );
    let installer = Installer::build(
        &dir,
        Arc::new(ScannerPrograms::bundled(&dir)),
        BUNDLED,
        Mode::Offline,
        verifier(true),
    );
    assert_eq!(
        installer.install(Scanner::Trivy).await,
        Err(InstallError::ReleaseUnavailable)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_oversize_download_is_refused() {
    let small = Limits {
        archive_bytes: 64,
        ..Limits::DEFAULT
    };
    // Declared too large by Content-Length.
    let fx_declared = fx("install-big", Upstream::good(), true).await;
    let (port, root, _) = serve(Upstream::good()).await;
    let capped = Installer::local(
        &fx_declared.dir,
        fx_declared.programs.clone(),
        BUNDLED,
        port,
        root,
        verifier(true),
    )
    .with_limits(small);
    assert_eq!(
        capped.install(Scanner::Trivy).await,
        Err(InstallError::DownloadTooLarge)
    );
    assert_unchanged(&fx_declared);

    // No length declared: the stream is cut at the cap.
    let mut upstream = Upstream::good();
    let mut streamed = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    streamed.extend_from_slice(&upstream.archive);
    upstream.archive_response = Some(streamed);
    let fx_streamed = fx("install-big-stream", upstream.clone(), true).await;
    let (port, root, _) = serve(upstream).await;
    let capped = Installer::local(
        &fx_streamed.dir,
        fx_streamed.programs.clone(),
        BUNDLED,
        port,
        root,
        verifier(true),
    )
    .with_limits(small);
    assert_eq!(
        capped.install(Scanner::Trivy).await,
        Err(InstallError::DownloadTooLarge)
    );
    assert_unchanged(&fx_streamed);

    // An oversize checksums file is refused the same way.
    let tiny = Limits {
        checksums_bytes: 8,
        ..Limits::DEFAULT
    };
    let (port, root, _) = serve(Upstream::good()).await;
    let capped = Installer::local(
        &fx_streamed.dir,
        fx_streamed.programs.clone(),
        BUNDLED,
        port,
        root,
        verifier(true),
    )
    .with_limits(tiny);
    assert_eq!(
        capped.install(Scanner::Trivy).await,
        Err(InstallError::DownloadTooLarge)
    );
}

#[tokio::test]
async fn a_path_traversal_entry_in_the_archive_is_refused() {
    let mut upstream = Upstream::good();
    upstream.archive = tar_gz(&[
        Entry {
            path: b"../../current",
            kind: tar::EntryType::Regular,
            body: b"9.9.9\n",
        },
        file("trivy", BINARY),
    ]);
    let fx = fx("install-traversal", upstream, true).await;
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::ArchiveRefused)
    );
    assert_unchanged(&fx);
}

#[tokio::test]
async fn a_release_not_newer_than_the_bundled_scanner_is_not_installed() {
    let mut upstream = Upstream::good();
    upstream.tag = "v0.76.2".to_owned();
    let fx = fx("install-not-newer", upstream, true).await;
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::NotNewer)
    );
    assert_unchanged(&fx);
}

#[tokio::test]
async fn install_and_rollback_are_serialised() {
    let fx = fx("install-busy", Upstream::good(), true).await;
    let guard = fx.installer.lock.try_lock();
    assert!(guard.is_ok());
    assert_eq!(
        fx.installer.install(Scanner::Trivy).await,
        Err(InstallError::Busy)
    );
    assert_eq!(
        fx.installer.rollback(Scanner::Trivy).await,
        Err(InstallError::Busy)
    );
    drop(guard);
    assert_unchanged(&fx);
}

#[tokio::test]
async fn rollback_swaps_back_and_without_a_previous_version_is_refused() {
    let fx = fx("install-rollback", Upstream::good(), true).await;
    // Only 0.76.5 is kept: nothing to roll back to.
    assert_eq!(
        fx.installer.rollback(Scanner::Trivy).await,
        Err(InstallError::NoPrevious)
    );
    assert_unchanged(&fx);

    assert_eq!(fx.installer.install(Scanner::Trivy).await, Ok(v("0.77.0")));
    assert_eq!(fx.installer.rollback(Scanner::Trivy).await, Ok(v("0.76.5")));
    assert_eq!(fx.pointers(), (Some(v("0.76.5")), Some(v("0.77.0"))));
    assert_eq!(
        fx.programs.state(Scanner::Trivy).selected,
        Selected::Downloaded(v("0.76.5"))
    );
    // A second rollback returns to the newer one.
    assert_eq!(fx.installer.rollback(Scanner::Trivy).await, Ok(v("0.77.0")));
    assert_eq!(
        fx.programs.state(Scanner::Trivy).selected,
        Selected::Downloaded(v("0.77.0"))
    );
}

#[tokio::test]
async fn an_install_changes_only_its_own_scanner() {
    let fx = fx("install-own", Upstream::good(), true).await;
    assert_eq!(fx.installer.install(Scanner::Trivy).await, Ok(v("0.77.0")));
    assert!(!fx.volume().exists(Scanner::Grype));
    assert_eq!(
        fx.programs.state(Scanner::Grype).selected,
        Selected::Bundled
    );
}
