//! Harbor webhook parsing and filtering (`specs/integrations.md`, Harbor webhook).
//!
//! The body is parsed once. A top-level `specversion` marks CloudEvents. Otherwise the
//! default Harbor JSON shape is used. Both produce one [`ScanEvent`]. A job is created
//! only for a vulnerability scan of the mapping's repository.

use serde_json::Value;

use crate::error::AppError;

/// The validated event stored in `sync_jobs.payload`. It holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScanEvent {
    /// `<project>/<repository>`, as Harbor reports it.
    pub repo_full_name: String,
    /// The artifact digest, `sha256:<hex>`.
    pub digest: String,
    /// The first tag. Always non-empty: an untagged event is ignored (`specs/integrations.md`).
    pub tag: String,
}

/// What a valid body means for the mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Store a `sync_jobs` row with this event.
    Queue(ScanEvent),
    /// Valid, but not a vulnerability scan of this repository. Nothing is stored.
    Ignore,
}

/// Parses the body and decides. Returns `400` for a body that is not JSON or matches
/// neither format. `repo_full_name` is the mapping's `<harbor_project>/<harbor_repository>`.
/// The event's `repository.repo_full_name`, read in either payload format, or `None` when the
/// body does not name one. A project webhook uses it to choose the mapping (#132). The body
/// is validated by `classify` after the mapping is chosen.
pub fn event_repository(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?;
    let data = if object.contains_key("specversion") {
        value.get("data").cloned().unwrap_or(Value::Null)
    } else {
        value.get("event_data").cloned().unwrap_or(Value::Null)
    };
    string_at(&data, &["repository", "repo_full_name"])
}

pub fn classify(body: &[u8], repo_full_name: &str) -> Result<Outcome, AppError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| bad_request())?;
    let object = value.as_object().ok_or_else(bad_request)?;
    let (event_type, data) = if object.contains_key("specversion") {
        // CloudEvents: the type and the payload sit under `type` and `data`.
        (
            string_at(&value, &["type"]),
            value.get("data").cloned().unwrap_or(Value::Null),
        )
    } else {
        // Harbor default: the type is top-level and the payload is under `event_data`.
        if !object.contains_key("type") {
            return Err(bad_request());
        }
        (
            string_at(&value, &["type"]),
            value.get("event_data").cloned().unwrap_or(Value::Null),
        )
    };
    let is_scan_completed = matches!(
        event_type.as_deref(),
        Some("SCANNING_COMPLETED") | Some("harbor.scan.completed")
    );
    if !is_scan_completed {
        return Ok(Outcome::Ignore);
    }
    let scan_type = string_at(&data, &["scan", "scan_type"]);
    if scan_type.as_deref() != Some("vulnerability") {
        return Ok(Outcome::Ignore);
    }
    let repo = string_at(&data, &["repository", "repo_full_name"]);
    if repo.as_deref() != Some(repo_full_name) {
        return Ok(Outcome::Ignore);
    }
    let Some(digest) = string_at(&data, &["resources", "0", "digest"]) else {
        return Err(bad_request());
    };
    // An untagged event is pushed by digest. CVEs are tracked per tag, so nothing is queued.
    let tag = match string_at(&data, &["resources", "0", "tag"]) {
        Some(tag) if !tag.is_empty() => tag,
        _ => return Ok(Outcome::Ignore),
    };
    Ok(Outcome::Queue(ScanEvent {
        repo_full_name: repo_full_name.to_owned(),
        digest,
        tag,
    }))
}

/// Walks a JSON path of object keys or array indexes and returns the string at the end.
fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = match current {
            Value::Object(map) => map.get(*key)?,
            Value::Array(items) => items.get(key.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    current.as_str().map(str::to_owned)
}

fn bad_request() -> AppError {
    AppError::InvalidRequest("The request body is not a Harbor event.".to_owned())
}

/// Compares two equal-length byte strings without an early exit on the first difference.
/// Used for the digests of the webhook auth secret and the mapping token.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "proj/app";

    /// A default-format scan event for a vulnerability scan of `REPO`.
    fn default_vuln() -> &'static str {
        r#"{
          "type": "SCANNING_COMPLETED",
          "occur_at": 1700000000,
          "operator": "admin",
          "event_data": {
            "repository": {"repo_full_name": "proj/app", "name": "app"},
            "resources": [{"digest": "sha256:aaaa", "tag": "1.2.3"}],
            "scan": {"scan_type": "vulnerability"}
          }
        }"#
    }

    /// The same event in the CloudEvents format.
    fn cloudevents_vuln() -> &'static str {
        r#"{
          "specversion": "1.0",
          "type": "harbor.scan.completed",
          "source": "harbor",
          "data": {
            "repository": {"repo_full_name": "proj/app", "name": "app"},
            "resources": [{"digest": "sha256:aaaa", "tag": "1.2.3"}],
            "scan": {"scan_type": "vulnerability"}
          }
        }"#
    }

    #[test]
    fn default_format_queues_a_job() {
        let outcome = classify(default_vuln().as_bytes(), REPO).unwrap();
        assert_eq!(
            outcome,
            Outcome::Queue(ScanEvent {
                repo_full_name: REPO.to_owned(),
                digest: "sha256:aaaa".to_owned(),
                tag: "1.2.3".to_owned(),
            })
        );
    }

    #[test]
    fn untagged_event_is_ignored() {
        // A missing tag and an empty tag both mean the image was pushed by digest.
        let missing = default_vuln().replace(r#", "tag": "1.2.3""#, "");
        assert_eq!(missing.matches("\"tag\"").count(), 0, "fixture");
        assert_eq!(classify(missing.as_bytes(), REPO).unwrap(), Outcome::Ignore);
        let empty = default_vuln().replace("1.2.3", "");
        assert_eq!(classify(empty.as_bytes(), REPO).unwrap(), Outcome::Ignore);
        // A tagged event still queues, so the rule is not too broad.
        assert!(matches!(
            classify(default_vuln().as_bytes(), REPO).unwrap(),
            Outcome::Queue(_)
        ));
    }

    #[test]
    fn cloudevents_format_produces_the_same_event() {
        let default = classify(default_vuln().as_bytes(), REPO).unwrap();
        let cloud = classify(cloudevents_vuln().as_bytes(), REPO).unwrap();
        assert_eq!(default, cloud);
    }

    #[test]
    fn an_sbom_event_is_ignored() {
        let body = default_vuln().replace("vulnerability", "sbom");
        assert_eq!(classify(body.as_bytes(), REPO).unwrap(), Outcome::Ignore);
    }

    #[test]
    fn another_repository_in_the_same_project_is_ignored() {
        let body = default_vuln().replace("proj/app", "proj/other");
        assert_eq!(classify(body.as_bytes(), REPO).unwrap(), Outcome::Ignore);
    }

    #[test]
    fn a_different_event_type_is_ignored() {
        let body = default_vuln().replace("SCANNING_COMPLETED", "PUSH_ARTIFACT");
        assert_eq!(classify(body.as_bytes(), REPO).unwrap(), Outcome::Ignore);
    }

    #[test]
    fn a_body_that_is_not_json_is_a_bad_request() {
        assert!(classify(b"not json", REPO).is_err());
    }

    #[test]
    fn a_json_object_in_neither_format_is_a_bad_request() {
        assert!(classify(br#"{"hello": "world"}"#, REPO).is_err());
    }

    #[test]
    fn constant_time_eq_matches_equal_values_only() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}

use sqlx::SqlitePool;

use crate::db::mappings as mapping_db;
use crate::db::sync_jobs;
use crate::services::mappings::digest;

/// The result of one webhook request, for the route to turn into a status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A `sync_jobs` row was stored (`202`).
    Queued,
    /// The event is valid but not for this repository or not a vulnerability scan (`202`).
    Ignored,
}

/// Looks up the mapping that owns `token` by its digest. Returns `None` for an unknown
/// token. The token is hashed before lookup. This is the only step that runs before the
/// route's per-token budget is charged.
pub async fn find_mapping(pool: &SqlitePool, token: &str) -> Result<Option<String>, AppError> {
    mapping_db::find_by_token_hash(pool, &digest(token)).await
}

/// Checks an `Authorization` value against a stored secret digest, in constant time. The value
/// must be `Bearer <secret>`; the prefix is stripped before hashing (`specs/integrations.md`).
/// Shared by mapping and project webhooks, so both check the secret the same way.
pub fn secret_matches(stored_digest: &str, authorization: Option<&str>) -> bool {
    let Some(presented) = authorization.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    constant_time_eq(digest(presented).as_bytes(), stored_digest.as_bytes())
}

/// Handles one webhook body for an already-found mapping (`specs/integrations.md`). A bad
/// `Authorization` value returns `401`, the same as an unknown token. The secret is
/// compared by digest in constant time.
pub async fn receive_for(
    pool: &SqlitePool,
    mapping_id: &str,
    authorization: Option<&str>,
    body: &[u8],
    now: i64,
    new_job_id: &str,
) -> Result<Received, AppError> {
    let unauthorized = || AppError::InvalidCredentials;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let row = mapping_db::find_by_id(&mut conn, mapping_id)
        .await?
        .ok_or_else(unauthorized)?;
    if !secret_matches(&row.webhook_auth_secret_hash, authorization) {
        return Err(unauthorized());
    }
    let repo_full_name = format!("{}/{}", row.harbor_project, row.harbor_repository);
    queue_event(pool, mapping_id, &repo_full_name, body, now, new_job_id).await
}

/// Classifies one event for a mapping's repository and queues it if it is a tagged vulnerability
/// scan. The caller has already checked the `Authorization` secret: the mapping's own for a
/// mapping webhook, or the project's for a project webhook (#132). Both routes share this, so
/// the event rules are the same.
pub async fn queue_event(
    pool: &SqlitePool,
    mapping_id: &str,
    repo_full_name: &str,
    body: &[u8],
    now: i64,
    new_job_id: &str,
) -> Result<Received, AppError> {
    match classify(body, repo_full_name)? {
        Outcome::Ignore => Ok(Received::Ignored),
        Outcome::Queue(event) => {
            let payload = serde_json::to_string(&event).map_err(|_| AppError::InternalError)?;
            sync_jobs::enqueue(pool, new_job_id, mapping_id, &payload, now).await?;
            Ok(Received::Queued)
        }
    }
}
