//! The Sigstore check of an upstream checksums file (#403, decision 1: the Rust
//! `sigstore-verify` crate, no cosign binary).
//!
//! The bundle (`<scanner>_<version>_checksums.txt.sigstore.json`) must verify over the exact
//! bytes of the checksums file, its Fulcio certificate must chain to the Sigstore public-good
//! trust root, its transparency log entry must verify, and the certificate identity must be the
//! upstream release workflow pinned below, issued by GitHub Actions.
//!
//! Trust root: the public-good `trusted_root.json` that `sigstore-trust-root` 0.16.0 embeds
//! (`SIGSTORE_PRODUCTION_TRUSTED_ROOT`). Nothing is fetched: the TUF feature is off, so the
//! check needs no network. A Sigstore key rotation therefore needs a crate update.

use sigstore_verify::trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
use sigstore_verify::types::Bundle;
use sigstore_verify::{IdentityMatcher, VerificationPolicy, Verifier};

use super::super::Scanner;
use super::super::version::Version;

/// The OIDC issuer of the upstream release certificates: GitHub Actions. Read on 2026-11-14 from
/// the Fulcio extension `1.3.6.1.4.1.57264.1.1` of the Trivy v0.76.2 and Grype v0.121.3
/// checksums bundles.
pub const RELEASE_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The certificate identity (the SAN URI) the release workflow of `scanner` signs with.
///
/// Source, read on 2026-11-14 from the certificate of each upstream checksums bundle:
/// - Trivy v0.76.2 and v0.76.1: `https://github.com/aquasecurity/trivy/.github/workflows/
///   reusable-release.yaml@refs/tags/v<version>`. The tag is part of the identity, so the
///   identity is pinned to the version being installed.
/// - Grype v0.121.3 and v0.121.2: `https://github.com/anchore/grype/.github/workflows/
///   release.yaml@refs/heads/main`. Grype releases from `main`, so the identity has no tag.
///
/// Both were checked against the live bundles with this verifier (`fixtures/`, and the tests
/// below). If upstream changes its workflow, the check fails closed and nothing installs.
pub fn release_identity(scanner: Scanner, version: Version) -> String {
    match scanner {
        Scanner::Trivy => format!(
            "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v{version}"
        ),
        Scanner::Grype => {
            "https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main"
                .to_owned()
        }
    }
}

/// Verifies a Sigstore bundle over an artifact for an exact identity. A seam: tests replace it.
pub trait BundleVerifier: Send + Sync + std::fmt::Debug {
    /// True only when `bundle_json` verifies over `artifact` and its certificate names
    /// `identity`, issued by [`RELEASE_ISSUER`]. Any failure is `false`; nothing is logged.
    fn verify(&self, artifact: &[u8], bundle_json: &[u8], identity: &str) -> bool;
}

/// The production verifier: `sigstore-verify` against the embedded public-good trust root.
#[derive(Debug, Clone, Copy, Default)]
pub struct SigstoreVerifier;

impl BundleVerifier for SigstoreVerifier {
    fn verify(&self, artifact: &[u8], bundle_json: &[u8], identity: &str) -> bool {
        let Ok(text) = std::str::from_utf8(bundle_json) else {
            return false;
        };
        let Ok(bundle) = Bundle::from_json(text) else {
            return false;
        };
        let Ok(root) = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT) else {
            return false;
        };
        let Ok(verifier) = Verifier::new(&root) else {
            return false;
        };
        let policy =
            VerificationPolicy::new(IdentityMatcher::Uri(identity.to_owned()), RELEASE_ISSUER);
        verifier.verify(artifact, &bundle, &policy).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRIVY_SUMS: &[u8] = include_bytes!("fixtures/trivy_0.76.2_checksums.txt");
    const TRIVY_BUNDLE: &[u8] = include_bytes!("fixtures/trivy_0.76.2_checksums.txt.sigstore.json");
    const GRYPE_SUMS: &[u8] = include_bytes!("fixtures/grype_0.121.3_checksums.txt");
    const GRYPE_BUNDLE: &[u8] =
        include_bytes!("fixtures/grype_0.121.3_checksums.txt.sigstore.json");

    fn v(text: &str) -> Version {
        match Version::parse(text) {
            Some(version) => version,
            None => panic!("{text}"),
        }
    }

    #[test]
    fn the_real_upstream_bundles_verify_for_the_pinned_identities() {
        // The live bundles of the bundled releases, downloaded 2026-11-14. Offline: the trust
        // root is embedded and the bundle carries its log inclusion proof.
        let trivy = release_identity(Scanner::Trivy, v("0.76.2"));
        let grype = release_identity(Scanner::Grype, v("0.121.3"));
        assert!(SigstoreVerifier.verify(TRIVY_SUMS, TRIVY_BUNDLE, &trivy));
        assert!(SigstoreVerifier.verify(GRYPE_SUMS, GRYPE_BUNDLE, &grype));
    }

    #[test]
    fn a_wrong_identity_is_refused() {
        // Another tag, the other scanner's workflow, and an attacker's fork.
        for identity in [
            release_identity(Scanner::Trivy, v("0.76.3")),
            release_identity(Scanner::Grype, v("0.121.3")),
            "https://github.com/evil/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.2"
                .to_owned(),
        ] {
            assert!(
                !SigstoreVerifier.verify(TRIVY_SUMS, TRIVY_BUNDLE, &identity),
                "{identity}"
            );
        }
    }

    #[test]
    fn a_tampered_checksums_file_or_a_bad_bundle_is_refused() {
        let identity = release_identity(Scanner::Trivy, v("0.76.2"));
        let mut tampered = TRIVY_SUMS.to_vec();
        tampered[0] ^= 1;
        assert!(!SigstoreVerifier.verify(&tampered, TRIVY_BUNDLE, &identity));
        // The other release's bundle does not cover these bytes.
        let grype = release_identity(Scanner::Grype, v("0.121.3"));
        assert!(!SigstoreVerifier.verify(TRIVY_SUMS, GRYPE_BUNDLE, &grype));
        for bundle in [&b""[..], b"{}", b"not json", &TRIVY_BUNDLE[..100]] {
            assert!(!SigstoreVerifier.verify(TRIVY_SUMS, bundle, &identity));
        }
    }
}
