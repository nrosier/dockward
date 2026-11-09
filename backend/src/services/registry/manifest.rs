//! Manifest and image index parsing for the registry client (`specs/spinoff-local-scan.md`,
//! sections 3 and 6; decision 3).
//!
//! The parser takes untrusted bytes. Every digest must be a `sha256:` digest, and a malformed
//! document is `UpstreamContentInvalid`. Attestation entries (platform `unknown/unknown`) are
//! skipped. An index entry without a platform is skipped too, because it cannot be labelled
//! per platform. A nested index is refused.

use serde::Deserialize;

use crate::error::AppError;
use crate::services::registry::grammar::is_sha256_digest;

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The `Accept` header for a manifest request: every index and manifest type this client reads.
pub const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// A content descriptor: a media type, a `sha256:` digest and a byte size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// The platform of an index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}

/// One platform manifest listed by an image index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub descriptor: Descriptor,
    pub platform: Platform,
}

/// A parsed manifest or index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// An image index: one entry per platform, attestation entries removed.
    Index(Vec<IndexEntry>),
    /// A single-platform image manifest: its config and its layers, in order.
    Image {
        config: Descriptor,
        layers: Vec<Descriptor>,
    },
}

#[derive(Deserialize)]
struct RawDescriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Deserialize)]
struct RawPlatform {
    os: String,
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Deserialize)]
struct RawIndexEntry {
    #[serde(flatten)]
    descriptor: RawDescriptor,
    #[serde(default)]
    platform: Option<RawPlatform>,
}

#[derive(Deserialize)]
struct RawIndex {
    manifests: Vec<RawIndexEntry>,
}

#[derive(Deserialize)]
struct RawImage {
    config: RawDescriptor,
    layers: Vec<RawDescriptor>,
}

#[derive(Deserialize)]
struct RawBodyType {
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
}

/// Parses a manifest or index. `content_type` is the response media type (parameters
/// stripped). When it is not a known type, the body's `mediaType` field decides.
pub fn parse(content_type: &str, body: &[u8]) -> Result<Parsed, AppError> {
    let kind = match kind_of(content_type) {
        Some(kind) => kind,
        None => {
            let declared: RawBodyType = serde_json::from_slice(body).map_err(|_| invalid())?;
            declared
                .media_type
                .as_deref()
                .and_then(kind_of)
                .ok_or_else(invalid)?
        }
    };
    match kind {
        Kind::Index => parse_index(body),
        Kind::Image => parse_image(body),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Index,
    Image,
}

fn kind_of(media_type: &str) -> Option<Kind> {
    match media_type {
        OCI_INDEX | DOCKER_LIST => Some(Kind::Index),
        OCI_MANIFEST | DOCKER_MANIFEST => Some(Kind::Image),
        _ => None,
    }
}

fn parse_index(body: &[u8]) -> Result<Parsed, AppError> {
    let raw: RawIndex = serde_json::from_slice(body).map_err(|_| invalid())?;
    let mut entries = Vec::new();
    for entry in raw.manifests {
        let Some(platform) = entry.platform else {
            continue;
        };
        if platform.os == "unknown" && platform.architecture == "unknown" {
            continue;
        }
        let descriptor = descriptor(entry.descriptor)?;
        if kind_of(&descriptor.media_type) == Some(Kind::Index) {
            return Err(invalid());
        }
        entries.push(IndexEntry {
            descriptor,
            platform: Platform {
                os: platform.os,
                architecture: platform.architecture,
                variant: platform.variant,
            },
        });
    }
    Ok(Parsed::Index(entries))
}

fn parse_image(body: &[u8]) -> Result<Parsed, AppError> {
    let raw: RawImage = serde_json::from_slice(body).map_err(|_| invalid())?;
    let config = descriptor(raw.config)?;
    let layers = raw
        .layers
        .into_iter()
        .map(descriptor)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Parsed::Image { config, layers })
}

fn descriptor(raw: RawDescriptor) -> Result<Descriptor, AppError> {
    if !is_sha256_digest(&raw.digest) {
        return Err(invalid());
    }
    Ok(Descriptor {
        media_type: raw.media_type,
        digest: raw.digest,
        size: raw.size,
    })
}

fn invalid() -> AppError {
    AppError::UpstreamContentInvalid
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn index_keeps_platforms_and_skips_attestations() {
        let body = format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"{OCI_MANIFEST}","digest":"{DIGEST_A}","size":10,
                  "platform":{{"os":"linux","architecture":"amd64"}}}},
                {{"mediaType":"{OCI_MANIFEST}","digest":"{DIGEST_B}","size":11,
                  "platform":{{"os":"unknown","architecture":"unknown"}}}},
                {{"mediaType":"{OCI_MANIFEST}","digest":"{DIGEST_B}","size":12,
                  "platform":{{"os":"linux","architecture":"arm","variant":"v7"}}}}
            ]}}"#
        );
        let Ok(Parsed::Index(entries)) = parse(OCI_INDEX, body.as_bytes()) else {
            panic!("index should parse");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].platform.architecture, "amd64");
        assert_eq!(entries[0].platform.variant, None);
        assert_eq!(entries[1].platform.variant.as_deref(), Some("v7"));
        assert_eq!(entries[1].descriptor.size, 12);
    }

    #[test]
    fn image_manifest_yields_config_and_layers() {
        let body = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{DIGEST_A}","size":3}},
                "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{DIGEST_B}","size":7}}]}}"#
        );
        let Ok(Parsed::Image { config, layers }) = parse(OCI_MANIFEST, body.as_bytes()) else {
            panic!("manifest should parse");
        };
        assert_eq!(config.digest, DIGEST_A);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].size, 7);
    }

    #[test]
    fn unknown_content_type_falls_back_to_the_body_media_type() {
        let body = format!(
            r#"{{"mediaType":"{DOCKER_MANIFEST}","config":{{"digest":"{DIGEST_A}","size":1}},"layers":[]}}"#
        );
        assert!(matches!(
            parse("application/json", body.as_bytes()),
            Ok(Parsed::Image { .. })
        ));
    }

    #[test]
    fn non_sha256_digests_and_nested_indexes_are_refused() {
        let bad_digest = r#"{"config":{"digest":"md5:abc","size":1},"layers":[]}"#;
        assert_eq!(
            parse(OCI_MANIFEST, bad_digest.as_bytes()),
            Err(AppError::UpstreamContentInvalid)
        );
        let nested = format!(
            r#"{{"manifests":[{{"mediaType":"{OCI_INDEX}","digest":"{DIGEST_A}","size":1,
                "platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#
        );
        assert_eq!(
            parse(OCI_INDEX, nested.as_bytes()),
            Err(AppError::UpstreamContentInvalid)
        );
    }

    #[test]
    fn malformed_bodies_are_content_invalid_not_panics() {
        for body in [&b"not json"[..], b"{}", b"[]", b""] {
            assert_eq!(
                parse(OCI_MANIFEST, body),
                Err(AppError::UpstreamContentInvalid)
            );
        }
        assert_eq!(
            parse("text/html", b"<html>"),
            Err(AppError::UpstreamContentInvalid)
        );
    }
}
