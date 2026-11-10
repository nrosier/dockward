//! Per-source registry credentials (`specs/spinoff-local-scan.md`, section 2; decisions 35, 41,
//! 42 and 43). A source has at most one credential: a username and a token. The token is a
//! `v1:` ciphertext with AAD `source_credentials:encrypted_token:<id>`, write-only through the
//! API, never logged, never returned, never put in an audit row.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::auth::crypto::{self, DerivedKey};
use crate::db::hubs;
use crate::db::image_sources as db;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::discovery::Discovery;
use crate::services::ids;
use crate::services::registry::transport::Credential;
use crate::services::sessions::AuthUser;
use crate::services::sources::{self, Need};
use crate::services::time;

const MAX_TOKEN_BYTES: usize = 4096;
const MAX_USERNAME_BYTES: usize = 255;
/// Fine-grained GitHub tokens start with this prefix; `ghcr.io` does not accept them
/// (decision 43).
const FINE_GRAINED_PREFIX: &str = "github_pat_";

/// `PUT .../credential` body. `Debug` is hand-written so the token is never printed.
#[derive(Deserialize)]
pub struct CredentialInput {
    pub username: String,
    pub token: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for CredentialInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialInput(redacted)")
    }
}

impl Drop for CredentialInput {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

/// The response of a save. It has no token field.
#[derive(Debug, Serialize)]
pub struct CredentialView {
    pub source_id: String,
    pub username: String,
    pub expires_at: Option<String>,
}

/// `POST .../credential/test` body.
#[derive(Debug, Deserialize)]
pub struct TestInput {
    pub repository: String,
}

/// The result of a credential test. `detail` is a fixed string.
#[derive(Debug, Serialize)]
pub struct TestResult {
    pub ok: bool,
    pub detail: String,
}

fn invalid(text: &str) -> AppError {
    AppError::ValidationFailed(text.to_owned())
}

fn validate(input: &CredentialInput, hub_host: &str) -> Result<(), AppError> {
    let name = input.username.as_str();
    if name.is_empty() || name.len() > MAX_USERNAME_BYTES || name.chars().any(char::is_control) {
        return Err(invalid("username is required."));
    }
    if input.token.is_empty() || input.token.len() > MAX_TOKEN_BYTES {
        return Err(invalid("token is required."));
    }
    if input.token.chars().any(char::is_control) {
        return Err(invalid("token is not valid."));
    }
    if hub_host == "ghcr.io" && input.token.starts_with(FINE_GRAINED_PREFIX) {
        return Err(invalid(
            "ghcr.io needs a personal access token (classic) with read:packages.",
        ));
    }
    Ok(())
}

/// Saves the owner's credential for a source. Returns whether a row was created (`201`) or
/// replaced (`200`).
pub async fn put(
    pool: &SqlitePool,
    key: &DerivedKey,
    actor: &Actor,
    user: &AuthUser,
    source_id: &str,
    input: CredentialInput,
) -> Result<(CredentialView, bool), AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let source = sources::load(&mut tx, user, source_id, Need::Write).await?;
    validate(&input, &source.hub_host)?;
    let existing = db::credential_id(&mut tx, source_id).await?;
    let created = existing.is_none();
    let row_id = match existing {
        Some(id) => id,
        None => ids::new_id()?,
    };
    let aad = crypto::aad("source_credentials", "encrypted_token", &row_id);
    let sealed = crypto::encrypt(key, &aad, input.token.as_bytes())?;
    db::upsert_credential(
        &mut tx,
        &row_id,
        source_id,
        &input.username,
        &sealed,
        input.expires_at,
    )
    .await?;
    audit::record(
        &mut tx,
        actor,
        if created {
            "credential.create"
        } else {
            "credential.rotate"
        },
        &format!("source_credential:{source_id}"),
        Some(&serde_json::json!({
            "hub": source.hub_host,
            "repository": source.repository,
        })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    let view = CredentialView {
        source_id: source_id.to_owned(),
        username: input.username.clone(),
        expires_at: input.expires_at.map(time::rfc3339).transpose()?,
    };
    Ok((view, created))
}

/// Removes the owner's credential. On `docker.io` the source falls back to anonymous pulls and
/// is not blocked (decision 42). A source with no credential is `404`.
pub async fn remove(
    pool: &SqlitePool,
    actor: &Actor,
    user: &AuthUser,
    source_id: &str,
) -> Result<(), AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let source = sources::load(&mut tx, user, source_id, Need::Write).await?;
    if db::delete_credential(&mut tx, source_id).await? == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        actor,
        "credential.delete",
        &format!("source_credential:{source_id}"),
        Some(&serde_json::json!({
            "hub": source.hub_host,
            "repository": source.repository,
        })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(())
}

/// The fixed text of a test that reached the registry and was refused.
fn refusal(error: &AppError) -> Option<&'static str> {
    match error {
        AppError::UpstreamAuthRejected => Some("registry rejected the credentials"),
        AppError::NotFound => Some("repository not found or not visible to this credential"),
        AppError::RateLimited => Some("registry rate limit reached"),
        _ => None,
    }
}

/// Tests the source's credential against the repository the caller names (decision 41): `GET
/// /v2/` and a pull token for that repository. With no credential it runs anonymously. The
/// result is `ok` or a fixed failure text; the token never leaves the server. A registry that
/// cannot be reached is the error `502`.
pub async fn test(
    pool: &SqlitePool,
    discovery: &Discovery,
    user: &AuthUser,
    source_id: &str,
    input: &TestInput,
) -> Result<TestResult, AppError> {
    let (source, endpoint) = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        let source = sources::load(&mut conn, user, source_id, Need::Write).await?;
        let hub = hubs::find(&mut conn, &source.hub_id)
            .await?
            .ok_or(AppError::InternalError)?;
        (source, hub.pull_endpoint.unwrap_or(hub.host))
    };
    let credential: Option<Credential> = discovery.credential_for(&source.id).await?;
    let anonymous = credential.is_none();
    let mut session = discovery
        .client()
        .session(&endpoint, &input.repository, credential)?;
    match session.check_access().await {
        Ok(()) => Ok(TestResult {
            ok: true,
            detail: if anonymous {
                "an anonymous pull works for this repository".to_owned()
            } else {
                "the credential can pull this repository".to_owned()
            },
        }),
        Err(error) => match refusal(&error) {
            Some(text) => Ok(TestResult {
                ok: false,
                detail: text.to_owned(),
            }),
            None => Err(error),
        },
    }
}
