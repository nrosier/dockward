//! The OCI labels a publish reads (`specs/integrations.md`, "OCI labels";
//! `specs/spinoff-local-scan.md`, section 6 step 6).
//!
//! The labels are `config.Labels` of the image config of a stored layout. Labels are image-level
//! metadata, so one platform's config is enough. The rules are the ones the Harbor-era sync used:
//! the revision label is required, the source label must match the GitHub target when present,
//! and the Dockward branch label (`io.github.nrosier.dockward.branch`) overrides the source's
//! default branch. The legacy HarborGate branch label is still read when the Dockward one is
//! absent or empty.
//!
//! The layout is a directory this program wrote: `index.json` names the platform manifest, the
//! manifest names the config blob, and every blob is a file named by its digest hex. A path is
//! built only from a digest that passed the 64-hex check, never from any other text. Nothing here
//! returns file content in an error.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::error::AppError;
use crate::services::storage::layout::BLOBS_SHA256;

/// OCI label carrying the commit SHA. Required.
pub const LABEL_REVISION: &str = "org.opencontainers.image.revision";
/// OCI label naming the source repository. Checked against the source when present.
pub const LABEL_SOURCE: &str = "org.opencontainers.image.source";
/// Dockward branch label. Overrides the source's `default_branch` when present.
pub const LABEL_BRANCH: &str = "io.github.nrosier.dockward.branch";
/// Legacy HarborGate branch label. Still read when `LABEL_BRANCH` is absent or empty, with a
/// deprecation warning; it never falls back to `default_branch` while set and non-empty.
pub const LEGACY_LABEL_BRANCH: &str = "io.github.nrosier.harborgate.branch";
/// The fixed text of the deprecation warning logged when only the legacy branch label is set.
/// It names no label value.
pub const MSG_LEGACY_BRANCH_LABEL: &str =
    "the image uses the deprecated HarborGate branch label; use the Dockward branch label instead.";

/// The most bytes read from one of the layout's JSON files. The registry client caps a manifest
/// and a config at the same size when it pulls them.
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

/// The labels HarborGate reads from one image.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageLabels {
    pub revision: Option<String>,
    pub source: Option<String>,
    pub branch: Option<String>,
}

/// Why the labels could not be read from a layout. The caller maps this to a fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelFault {
    /// The layout directory or one of its files is missing or unreadable.
    Unreadable,
    /// A file is there but is not the JSON the layout format requires.
    Malformed,
}

/// The hex of a `sha256:<hex>` digest, or `None` when the text is anything else.
fn digest_hex(digest: &str) -> Option<&str> {
    let hex = digest.strip_prefix("sha256:")?;
    (hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(hex)
}

fn read_json(path: &Path) -> Result<Value, LabelFault> {
    let meta = fs::metadata(path).map_err(|_| LabelFault::Unreadable)?;
    if !meta.is_file() || meta.len() > MAX_JSON_BYTES {
        return Err(LabelFault::Malformed);
    }
    let bytes = fs::read(path).map_err(|_| LabelFault::Unreadable)?;
    serde_json::from_slice(&bytes).map_err(|_| LabelFault::Malformed)
}

fn blob_path(layout: &Path, digest: &str) -> Result<std::path::PathBuf, LabelFault> {
    let hex = digest_hex(digest).ok_or(LabelFault::Malformed)?;
    Ok(layout.join(BLOBS_SHA256).join(hex))
}

/// Reads the labels from the layout at `layout`: `index.json`, the platform manifest, then the
/// config blob. Blocking file reads; call from a blocking context.
pub fn read_labels(layout: &Path) -> Result<ImageLabels, LabelFault> {
    let index = read_json(&layout.join("index.json"))?;
    let manifest_digest = index
        .pointer("/manifests/0/digest")
        .and_then(Value::as_str)
        .ok_or(LabelFault::Malformed)?;
    let manifest = read_json(&blob_path(layout, manifest_digest)?)?;
    let config_digest = manifest
        .pointer("/config/digest")
        .and_then(Value::as_str)
        .ok_or(LabelFault::Malformed)?;
    let config = read_json(&blob_path(layout, config_digest)?)?;
    Ok(parse_labels(&config))
}

/// The labels of an image config JSON: the string members of `config.Labels`. Anything that is
/// not a string member adds nothing. The branch is the Dockward label when non-empty, else the
/// legacy HarborGate label when non-empty (logging `MSG_LEGACY_BRANCH_LABEL`), else `None`.
pub fn parse_labels(config: &Value) -> ImageLabels {
    let mut labels: BTreeMap<&str, &str> = BTreeMap::new();
    if let Some(Value::Object(map)) = config.pointer("/config/Labels") {
        for (key, value) in map {
            if let Value::String(text) = value {
                labels.insert(key.as_str(), text.as_str());
            }
        }
    }
    let get = |key: &str| labels.get(key).map(|text| (*text).to_owned());
    let non_empty = |key: &str| get(key).filter(|text| !text.is_empty());
    let branch = match non_empty(LABEL_BRANCH) {
        Some(branch) => Some(branch),
        None => {
            let legacy = non_empty(LEGACY_LABEL_BRANCH);
            if legacy.is_some() {
                tracing::warn!("{MSG_LEGACY_BRANCH_LABEL}");
            }
            legacy
        }
    };
    ImageLabels {
        revision: get(LABEL_REVISION),
        source: get(LABEL_SOURCE),
        branch,
    }
}

/// Fails the publish when the commit SHA label is missing (`specs/integrations.md`). Never guess
/// the SHA.
pub fn require_revision(labels: &ImageLabels) -> Result<&str, AppError> {
    labels
        .revision
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::ValidationFailed(MSG_NO_REVISION.to_owned()))
}

/// The fixed text of a missing revision label.
pub const MSG_NO_REVISION: &str =
    "the image has no org.opencontainers.image.revision label, so the commit is unknown.";
/// The fixed text of a source label that names another repository.
pub const MSG_SOURCE_MISMATCH: &str =
    "the image source label does not match this source's GitHub repository.";

/// Compares the `source` label with the source's GitHub target, case-insensitively and ignoring a
/// trailing `/` or `.git` (`specs/integrations.md`). Absent means proceed.
pub fn check_source(
    labels: &ImageLabels,
    web_url: &str,
    owner: &str,
    repo: &str,
) -> Result<(), AppError> {
    let Some(source) = labels.source.as_deref() else {
        return Ok(());
    };
    let expected = normalize_source(&format!("{web_url}/{owner}/{repo}"));
    if normalize_source(source) == expected {
        Ok(())
    } else {
        Err(AppError::ValidationFailed(MSG_SOURCE_MISMATCH.to_owned()))
    }
}

fn normalize_source(value: &str) -> String {
    let lowered = value.trim().to_ascii_lowercase();
    let trimmed = lowered.trim_end_matches('/');
    trimmed.strip_suffix(".git").unwrap_or(trimmed).to_owned()
}

/// The branch to upload to: the Dockward branch label (or the legacy one, already resolved into
/// `labels.branch` by `parse_labels`), otherwise the source's default branch.
pub fn branch_for(labels: &ImageLabels, default_branch: &str) -> String {
    labels
        .branch
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(default_branch)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> Value {
        json!({"config": {"Labels": {
            LABEL_REVISION: "0123456789abcdef0123456789abcdef01234567",
            LABEL_SOURCE: "https://github.com/Octo/App.git/",
            LABEL_BRANCH: "release",
            "other": 5
        }}})
    }

    #[test]
    fn labels_are_read_from_config_labels() {
        let labels = parse_labels(&config());
        assert_eq!(
            labels.revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(labels.branch.as_deref(), Some("release"));
        assert!(check_source(&labels, "https://github.com", "octo", "app").is_ok());
        assert!(check_source(&labels, "https://github.com", "octo", "other").is_err());
        assert_eq!(branch_for(&labels, "main"), "release");
        assert_eq!(branch_for(&ImageLabels::default(), "main"), "main");
    }

    #[test]
    fn a_missing_revision_is_refused_and_a_missing_source_proceeds() {
        let labels = parse_labels(&json!({"config": {}}));
        assert!(require_revision(&labels).is_err());
        assert!(check_source(&labels, "https://github.com", "o", "r").is_ok());
        let empty = ImageLabels {
            revision: Some(String::new()),
            ..ImageLabels::default()
        };
        assert!(require_revision(&empty).is_err());
    }

    fn branch_config(entries: &[(&str, &str)]) -> Value {
        let labels: serde_json::Map<String, Value> = entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), json!(value)))
            .collect();
        json!({"config": {"Labels": labels}})
    }

    #[test]
    fn the_dockward_branch_label_is_read() {
        let labels = parse_labels(&branch_config(&[(LABEL_BRANCH, "release")]));
        assert_eq!(labels.branch.as_deref(), Some("release"));
        assert_eq!(branch_for(&labels, "main"), "release");
    }

    #[test]
    fn the_legacy_branch_label_alone_is_read_with_the_warning_path() {
        let labels = parse_labels(&branch_config(&[(LEGACY_LABEL_BRANCH, "legacy-release")]));
        assert_eq!(labels.branch.as_deref(), Some("legacy-release"));
        assert_eq!(branch_for(&labels, "main"), "legacy-release");
        assert!(!MSG_LEGACY_BRANCH_LABEL.contains("legacy-release"));
        assert!(!MSG_LEGACY_BRANCH_LABEL.contains(LEGACY_LABEL_BRANCH));
    }

    #[test]
    fn the_dockward_label_wins_when_both_are_set() {
        let labels = parse_labels(&branch_config(&[
            (LABEL_BRANCH, "new-release"),
            (LEGACY_LABEL_BRANCH, "legacy-release"),
        ]));
        assert_eq!(labels.branch.as_deref(), Some("new-release"));
    }

    #[test]
    fn an_empty_dockward_label_falls_back_to_the_legacy_then_the_default() {
        let legacy = parse_labels(&branch_config(&[
            (LABEL_BRANCH, ""),
            (LEGACY_LABEL_BRANCH, "legacy-release"),
        ]));
        assert_eq!(branch_for(&legacy, "main"), "legacy-release");

        let neither = parse_labels(&branch_config(&[
            (LABEL_BRANCH, ""),
            (LEGACY_LABEL_BRANCH, ""),
        ]));
        assert_eq!(neither.branch, None);
        assert_eq!(branch_for(&neither, "main"), "main");
    }

    #[test]
    fn neither_label_uses_the_default_branch() {
        let labels = parse_labels(&branch_config(&[]));
        assert_eq!(branch_for(&labels, "trunk"), "trunk");
    }

    #[test]
    fn a_digest_with_a_path_in_it_never_reaches_the_file_system() {
        assert!(digest_hex("sha256:../../etc/passwd").is_none());
        assert!(digest_hex(&format!("sha256:{}", "A".repeat(64))).is_none());
        assert!(digest_hex(&format!("sha256:{}", "a".repeat(64))).is_some());
    }
}
