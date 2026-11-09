//! The name, tag, digest and hub-host grammars of the registry client
//! (`specs/spinoff-local-scan.md`, sections 2, 3 and 5).
//!
//! Every repository, tag, reference and hub host is checked here before a request is built,
//! so no request carries text outside these grammars.

use crate::error::AppError;

/// The longest repository name the client sends. The OCI grammar sets no length; 255 bytes
/// is the limit the registries apply in practice.
pub const MAX_REPOSITORY_BYTES: usize = 255;
/// The longest exact tag or pattern: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` is 128 bytes.
const MAX_TAG_BYTES: usize = 128;
/// The longest DNS name, without the port.
const MAX_HOSTNAME_BYTES: usize = 253;

/// The host that the client connects to for a stored hub host. Docker Hub is stored as
/// `docker.io` (decision 11), and its pulls and token requests go to `registry-1.docker.io`.
/// This is the only place the mapping lives.
pub fn pull_host(stored: &str) -> &str {
    if stored == "docker.io" {
        "registry-1.docker.io"
    } else {
        stored
    }
}

/// The hostname of a `host[:port]` string, without the port.
pub fn hub_name(host: &str) -> &str {
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

/// Checks a stored hub host: a lowercase DNS name with an optional `:port`, and nothing else
/// (no scheme, userinfo, path, query or fragment). Decision 7 and section 2.
pub fn validate_hub_host(host: &str) -> Result<(), AppError> {
    let name = match host.rsplit_once(':') {
        Some((name, port)) => {
            let port_ok = !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|p| p != 0);
            if !port_ok {
                return Err(bad_hub());
            }
            name
        }
        None => host,
    };
    if name.is_empty() || name.len() > MAX_HOSTNAME_BYTES {
        return Err(bad_hub());
    }
    if name.split('.').all(valid_hostname_label) {
        Ok(())
    } else {
        Err(bad_hub())
    }
}

fn valid_hostname_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Checks a repository name against the OCI grammar
/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*`, with the
/// length bound. A name with `:` or `@` fails the grammar, so a digest cannot be smuggled in.
pub fn validate_repository(name: &str) -> Result<(), AppError> {
    if name.is_empty() || name.len() > MAX_REPOSITORY_BYTES {
        return Err(bad_repository());
    }
    if name.split('/').all(valid_name_component) {
        Ok(())
    } else {
        Err(bad_repository())
    }
}

/// One path component of a repository name: alphanumeric runs joined by `.`, `_`, `__` or
/// one or more `-`.
fn valid_name_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let len = bytes.len();
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let mut i = 0;
    loop {
        let start = i;
        while i < len && is_lower_alnum(bytes[i]) {
            i += 1;
        }
        if i == start {
            return false;
        }
        if i == len {
            return true;
        }
        match bytes[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < len && bytes[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < len && bytes[i] == b'-' {
                    i += 1;
                }
            }
            _ => return false,
        }
        if i == len {
            return false;
        }
    }
}

/// Checks an exact tag against `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`. Case-sensitive.
pub fn validate_tag(tag: &str) -> Result<(), AppError> {
    let bytes = tag.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    let rest_ok = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if first_ok && rest_ok && bytes.len() <= MAX_TAG_BYTES {
        Ok(())
    } else {
        Err(bad_tag())
    }
}

/// True when `text` is `sha256:` followed by 64 lowercase hex digits.
pub fn is_sha256_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A manifest reference: an exact tag, or a `sha256:` digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reference<'a> {
    Tag(&'a str),
    Digest(&'a str),
}

/// Classifies and checks a reference. A reference with `:` is a digest and must be a
/// `sha256:` digest; anything else is an exact tag.
pub fn parse_reference(text: &str) -> Result<Reference<'_>, AppError> {
    if text.contains(':') {
        if is_sha256_digest(text) {
            Ok(Reference::Digest(text))
        } else {
            Err(bad_reference())
        }
    } else {
        validate_tag(text)?;
        Ok(Reference::Tag(text))
    }
}

fn bad_hub() -> AppError {
    AppError::ValidationFailed("The hub host is not valid.".to_owned())
}

fn bad_repository() -> AppError {
    AppError::ValidationFailed("The repository name is not valid.".to_owned())
}

fn bad_tag() -> AppError {
    AppError::ValidationFailed("The tag is not valid.".to_owned())
}

fn bad_reference() -> AppError {
    AppError::ValidationFailed("The image reference is not valid.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_maps_to_its_pull_host_and_others_are_unchanged() {
        assert_eq!(pull_host("docker.io"), "registry-1.docker.io");
        assert_eq!(pull_host("ghcr.io"), "ghcr.io");
        assert_eq!(
            pull_host("registry.example.com:5000"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn hub_hosts_accept_dns_names_with_optional_port() {
        for host in [
            "ghcr.io",
            "docker.io",
            "registry.example.com:5000",
            "a-b.c1",
        ] {
            assert!(validate_hub_host(host).is_ok(), "{host} should pass");
        }
    }

    #[test]
    fn hub_hosts_refuse_schemes_userinfo_paths_and_uppercase() {
        for host in [
            "",
            "Ghcr.io",
            "https://ghcr.io",
            "user@ghcr.io",
            "ghcr.io/path",
            "ghcr.io:",
            "ghcr.io:0",
            "ghcr.io:99999",
            "ghcr.io?x=1",
            "-bad.io",
            "bad-.io",
            "bad..io",
            ".leading.io",
        ] {
            assert!(validate_hub_host(host).is_err(), "{host} should fail");
        }
    }

    #[test]
    fn repository_grammar_matches_the_oci_rules() {
        for name in [
            "library/alpine",
            "a",
            "team/app",
            "a.b/c_d/e__f",
            "a---b/c",
            "x1/y2-z3",
        ] {
            assert!(validate_repository(name).is_ok(), "{name} should pass");
        }
        for name in [
            "",
            "Library/alpine",
            "a..b",
            "a._b",
            "a_.b",
            "a___b",
            "a-.b",
            "a.-b",
            "/a",
            "a/",
            "a//b",
            "a:b",
            "a@sha256",
            "a b",
            "a?x",
        ] {
            assert!(validate_repository(name).is_err(), "{name} should fail");
        }
    }

    #[test]
    fn tags_follow_the_tag_grammar_and_are_case_sensitive() {
        assert!(validate_tag("latest").is_ok());
        assert!(validate_tag("1.2.3-rc1").is_ok());
        assert!(validate_tag("_hidden").is_ok());
        assert!(validate_tag("Upper").is_ok());
        assert!(validate_tag("-leading").is_err());
        assert!(validate_tag(".leading").is_err());
        assert!(validate_tag("has space").is_err());
        assert!(validate_tag("has:colon").is_err());
        assert!(validate_tag(&"a".repeat(129)).is_err());
        assert!(validate_tag(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn references_are_tags_or_sha256_digests_only() {
        assert_eq!(parse_reference("v1").ok(), Some(Reference::Tag("v1")));
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            parse_reference(&digest).ok(),
            Some(Reference::Digest(&digest))
        );
        assert!(parse_reference(&format!("sha512:{}", "a".repeat(64))).is_err());
        assert!(parse_reference(&format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(parse_reference("sha256:short").is_err());
    }

    #[test]
    fn hub_name_strips_only_the_port() {
        assert_eq!(hub_name("localhost:5000"), "localhost");
        assert_eq!(hub_name("ghcr.io"), "ghcr.io");
    }
}
