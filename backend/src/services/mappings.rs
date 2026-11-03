//! Mapping CRUD, the webhook token and auth secret, and rotation. Sources:
//! `specs/api.md` (Mappings), `specs/integrations.md` (Webhook URL token, Secret value),
//! `specs/database.md` (`repo_mappings`).
//!
//! The webhook token and auth secret are 256-bit values from a CSPRNG, base64url
//! encoded without padding. Only their SHA-256 digests (lowercase hex) are stored.
//! They are returned once, at create and at rotation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::credentials as cred_db;
use crate::db::mappings::{self as db, MappingRow};
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::credential_probe::{self, GithubProbe, HarborProbe};
use crate::services::credentials::{self, SERVICE_HARBOR};
use crate::services::{
    ids,
    pagination::{Page, Pagination},
    time,
};

/// Sort keys the list route accepts. The first is the default.
const SORTS: &[&str] = &["harbor_repository", "created_at"];

/// Severities the spec allows for `min_issue_severity`.
const SEVERITIES: &[&str] = &["CRITICAL", "HIGH"];

/// The `Mapping` object (`specs/api.md`). It never has the webhook URL.
#[derive(Debug, Serialize)]
pub struct Mapping {
    pub id: String,
    pub user_id: String,
    pub harbor_cred_id: String,
    pub github_cred_id: String,
    pub harbor_base_url: String,
    pub harbor_project: String,
    pub harbor_repository: String,
    pub github_owner: String,
    pub github_repo: String,
    pub default_branch: String,
    pub auto_create_issues: bool,
    pub min_issue_severity: String,
    pub created_at: Option<String>,
}

/// The create response: the mapping plus the two values shown once.
#[derive(Serialize)]
pub struct Created {
    pub mapping: Mapping,
    pub webhook_url: String,
    pub auth_secret: String,
}

/// `Debug` hides the shown-once values.
impl std::fmt::Debug for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Created")
            .field("mapping", &self.mapping)
            .field("webhook_url", &"<redacted>")
            .field("auth_secret", &"<redacted>")
            .finish()
    }
}

/// A create request. Field names are the API names.
#[derive(Debug, Clone, Deserialize)]
pub struct NewMapping {
    pub harbor_cred_id: String,
    pub github_cred_id: String,
    pub harbor_project: String,
    pub harbor_repository: String,
    pub github_owner: String,
    pub github_repo: String,
    pub default_branch: Option<String>,
    pub auto_create_issues: Option<bool>,
    pub min_issue_severity: Option<String>,
}

/// Query parameters for the list route.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub all_users: bool,
}

/// Generates 256 random bits from the OS CSPRNG, base64url without padding.
pub fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 of `value` as lowercase hex.
pub fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The webhook URL for a token. The base is `HARBORGATE_PUBLIC_URL`, never the
/// request's `Host` header.
pub fn webhook_url(public_url: &str, token: &str) -> String {
    format!(
        "{}/api/v1/webhooks/harbor/{token}",
        public_url.trim_end_matches('/')
    )
}

fn validate_text(name: &str, value: &str) -> Result<(), AppError> {
    if value.trim().is_empty() || value.len() > 255 {
        return Err(AppError::ValidationFailed(format!(
            "{name} must be 1 to 255 characters."
        )));
    }
    Ok(())
}

fn validate_severity(value: &str) -> Result<(), AppError> {
    if SEVERITIES.contains(&value) {
        Ok(())
    } else {
        Err(AppError::ValidationFailed(
            "min_issue_severity must be CRITICAL or HIGH.".to_owned(),
        ))
    }
}

fn to_mapping(row: MappingRow) -> Result<Mapping, AppError> {
    Ok(Mapping {
        id: row.id,
        user_id: row.user_id,
        harbor_cred_id: row.harbor_cred_id,
        github_cred_id: row.github_cred_id,
        harbor_base_url: row.harbor_base_url,
        harbor_project: row.harbor_project,
        harbor_repository: row.harbor_repository,
        github_owner: row.github_owner,
        github_repo: row.github_repo,
        default_branch: row.default_branch,
        auto_create_issues: row.auto_create_issues.unwrap_or(false),
        min_issue_severity: row
            .min_issue_severity
            .unwrap_or_else(|| "CRITICAL".to_owned()),
        created_at: row.created_at.map(time::rfc3339).transpose()?,
    })
}

/// The Harbor base URL of a credential the caller owns. The mapping copies it, so a
/// later credential change cannot move the mapping to another instance.
async fn harbor_base_of(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    cred_id: &str,
) -> Result<String, AppError> {
    let row = cred_db::find_owned(conn, user_id, cred_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.service_type != SERVICE_HARBOR {
        return Err(AppError::ValidationFailed(
            "harbor_cred_id must be a harbor credential.".to_owned(),
        ));
    }
    row.base_url.ok_or(AppError::InternalError)
}

/// Checks that `cred_id` is a GitHub credential the caller owns.
async fn check_github(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    cred_id: &str,
) -> Result<(), AppError> {
    let row = cred_db::find_owned(conn, user_id, cred_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.service_type != crate::services::credentials::SERVICE_GITHUB {
        return Err(AppError::ValidationFailed(
            "github_cred_id must be a github credential.".to_owned(),
        ));
    }
    Ok(())
}

/// Checks that the Harbor robot can read the repository. Any status other than `200`
/// is a `422`, so a mapping to an unreadable repository is never stored.
async fn check_harbor_repository<P: HarborProbe>(
    conn: &mut sqlx::SqliteConnection,
    credentials_key: &DerivedKey,
    probe: &P,
    user_id: &str,
    harbor_cred_id: &str,
    project: &str,
    repository: &str,
) -> Result<(), AppError> {
    let row = cred_db::find_owned(conn, user_id, harbor_cred_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let base = reqwest::Url::parse(row.base_url.as_deref().ok_or(AppError::InternalError)?)
        .map_err(|_| AppError::InternalError)?;
    let username = row.username.clone().ok_or(AppError::InternalError)?;
    let secret = credentials::decrypt_token(credentials_key, &row)?;
    let status = probe
        .artifacts_status(&base, &username, &secret, project, repository)
        .await?;
    if status == 200 {
        Ok(())
    } else {
        Err(AppError::ValidationFailed(
            "the Harbor robot cannot read this repository.".to_owned(),
        ))
    }
}

/// Runs the code scanning probe for the GitHub repository before the mapping is stored.
/// `unavailable` is `422 code_scanning_unavailable`. Other failures are reported
/// through `AppError` without storing anything (`specs/security.md`, "GitHub token scope").
async fn check_code_scanning<G: GithubProbe>(
    conn: &mut sqlx::SqliteConnection,
    credentials_key: &DerivedKey,
    github_probe: &G,
    user_id: &str,
    github_cred_id: &str,
    owner: &str,
    repo: &str,
) -> Result<(), AppError> {
    let row = cred_db::find_owned(conn, user_id, github_cred_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let token = credentials::decrypt_token(credentials_key, &row)?;
    let response = github_probe
        .get(
            &credential_probe::github_code_scanning_path(owner, repo),
            &token,
        )
        .await?;
    match credential_probe::code_scanning_state(&response) {
        credential_probe::CodeScanningState::Ready
        | credential_probe::CodeScanningState::NoAnalysisYet => Ok(()),
        credential_probe::CodeScanningState::Unavailable => Err(AppError::CodeScanningUnavailable),
        credential_probe::CodeScanningState::Failed => Err(AppError::ValidationFailed(
            credential_probe::github_code_scanning_check(&response).detail,
        )),
    }
}

/// Runs the issues probe on the mapping's repository when `auto_create_issues` is on.
/// Only `200` passes. A `403` is `422` naming the Issues permission. Any other result,
/// including a network error, is `422` with the check detail. Nothing is stored in
/// either case (`specs/security.md`, "GitHub token scope"; decision on #21, 2026-11-03).
async fn check_issues<G: GithubProbe>(
    conn: &mut sqlx::SqliteConnection,
    credentials_key: &DerivedKey,
    github_probe: &G,
    user_id: &str,
    github_cred_id: &str,
    owner: &str,
    repo: &str,
) -> Result<(), AppError> {
    let row = cred_db::find_owned(conn, user_id, github_cred_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let token = credentials::decrypt_token(credentials_key, &row)?;
    let response = github_probe
        .get(&credential_probe::github_issues_path(owner, repo), &token)
        .await
        .map_err(|error| match error {
            AppError::UpstreamUnreachable => AppError::ValidationFailed(
                "the GitHub issues check could not reach GitHub.".to_owned(),
            ),
            other => other,
        })?;
    if response.status == 200 {
        return Ok(());
    }
    if response.status == 403 {
        return Err(AppError::ValidationFailed(
            "the GitHub token lacks the Issues permission needed for auto-created issues"
                .to_owned(),
        ));
    }
    Err(AppError::ValidationFailed(
        credential_probe::github_issues_check(&response).detail,
    ))
}

/// Creates a mapping for `user_id`. Returns the mapping and the two values shown
/// once. Writes `mapping.create`.
// Eight arguments: the two probes are injected separately so tests can fake each one.
#[allow(clippy::too_many_arguments)]
pub async fn create<P: HarborProbe, G: GithubProbe>(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    probe: &P,
    github_probe: &G,
    actor: &Actor,
    user_id: &str,
    public_url: &str,
    input: NewMapping,
) -> Result<Created, AppError> {
    validate_text("harbor_project", &input.harbor_project)?;
    validate_text("harbor_repository", &input.harbor_repository)?;
    validate_text("github_owner", &input.github_owner)?;
    validate_text("github_repo", &input.github_repo)?;
    let severity = input
        .min_issue_severity
        .clone()
        .unwrap_or_else(|| "CRITICAL".to_owned());
    validate_severity(&severity)?;

    let id = ids::new_id();
    let token = new_secret();
    let secret = new_secret();
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let harbor_base = harbor_base_of(&mut tx, user_id, &input.harbor_cred_id).await?;
    check_github(&mut tx, user_id, &input.github_cred_id).await?;
    // The repository must be readable with the Harbor robot before anything is stored.
    check_harbor_repository(
        &mut tx,
        credentials_key,
        probe,
        user_id,
        &input.harbor_cred_id,
        &input.harbor_project,
        &input.harbor_repository,
    )
    .await?;
    check_code_scanning(
        &mut tx,
        credentials_key,
        github_probe,
        user_id,
        &input.github_cred_id,
        &input.github_owner,
        &input.github_repo,
    )
    .await?;
    if input.auto_create_issues.unwrap_or(false) {
        check_issues(
            &mut tx,
            credentials_key,
            github_probe,
            user_id,
            &input.github_cred_id,
            &input.github_owner,
            &input.github_repo,
        )
        .await?;
    }
    if let Some((other_id, other_user)) = db::find_conflict(
        &mut tx,
        &harbor_base,
        &input.harbor_project,
        &input.harbor_repository,
        &input.github_owner,
        &input.github_repo,
        &id,
    )
    .await?
    {
        return Err(conflict_error(&other_id, &other_user, user_id));
    }
    let row = MappingRow {
        id: id.clone(),
        user_id: user_id.to_owned(),
        harbor_cred_id: input.harbor_cred_id.clone(),
        github_cred_id: input.github_cred_id.clone(),
        harbor_base_url: harbor_base,
        harbor_project: input.harbor_project.clone(),
        harbor_repository: input.harbor_repository.clone(),
        github_owner: input.github_owner.clone(),
        github_repo: input.github_repo.clone(),
        webhook_token_hash: digest(&token),
        webhook_auth_secret_hash: digest(&secret),
        auto_create_issues: Some(input.auto_create_issues.unwrap_or(false)),
        min_issue_severity: Some(severity),
        default_branch: input
            .default_branch
            .clone()
            .unwrap_or_else(|| "main".to_owned()),
        created_at: None,
    };
    db::insert(&mut tx, &row).await?;
    audit::record(
        &mut tx,
        actor,
        "mapping.create",
        &format!("mapping:{id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    let stored = load_owned(pool, user_id, &id).await?;
    Ok(Created {
        mapping: stored,
        webhook_url: webhook_url(public_url, &token),
        auth_secret: secret,
    })
}

/// Builds the `409` for a duplicate. The body names the other mapping only when the
/// caller owns it. Otherwise it is generic, so another tenant's mapping is not revealed.
fn conflict_error(other_id: &str, other_user: &str, caller: &str) -> AppError {
    if other_user == caller {
        AppError::Conflict(format!(
            "another mapping ({other_id}) already uses this Harbor repository or GitHub target."
        ))
    } else {
        AppError::Conflict("this Harbor repository or GitHub target is already mapped.".to_owned())
    }
}

/// Returns one owned mapping as the API object.
pub async fn load_owned(pool: &SqlitePool, user_id: &str, id: &str) -> Result<Mapping, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let row = db::find_owned(&mut conn, user_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    to_mapping(row)
}

/// Returns one page of mappings. `all_users` is honored only for admins; the route
/// checks the role before calling this.
pub async fn list(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListQuery,
) -> Result<Page<Mapping>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        SORTS,
    )?;
    let scope = if query.all_users { None } else { Some(user_id) };
    let filter = db::ListFilter {
        user_id: scope,
        sort: &paging.sort,
        sort_sign: if paging.ascending { 1 } else { -1 },
        limit: paging.page_size,
        offset: paging.offset(),
    };
    let rows = db::list_owned(pool, &filter).await?;
    let total = db::count_owned(pool, scope).await?;
    let items = rows
        .into_iter()
        .map(to_mapping)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page {
        items,
        page: paging.page,
        page_size: paging.page_size,
        total,
    })
}

/// Rotates the webhook token. The old token stops working immediately, because only
/// the new digest is stored. Writes `mapping.webhook_token_rotate`.
pub async fn rotate_webhook_token(
    pool: &SqlitePool,
    actor: &Actor,
    user_id: &str,
    public_url: &str,
    id: &str,
) -> Result<String, AppError> {
    let token = new_secret();
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let changed = db::set_token_hash(&mut tx, user_id, id, &digest(&token)).await?;
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        actor,
        "mapping.webhook_token_rotate",
        &format!("mapping:{id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(webhook_url(public_url, &token))
}

/// Rotates the auth secret. The old secret stops working immediately. Writes
/// `mapping.auth_secret_rotate`.
pub async fn rotate_auth_secret(
    pool: &SqlitePool,
    actor: &Actor,
    user_id: &str,
    id: &str,
) -> Result<String, AppError> {
    let secret = new_secret();
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let changed = db::set_auth_secret_hash(&mut tx, user_id, id, &digest(&secret)).await?;
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        actor,
        "mapping.auth_secret_rotate",
        &format!("mapping:{id}"),
        None,
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(secret)
}

/// Deletes one owned mapping. Writes `mapping.delete`.
pub async fn delete(
    pool: &SqlitePool,
    actor: &Actor,
    user_id: &str,
    id: &str,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|_| AppError::InternalError)?;
    let mapping = db::find_owned(&mut tx, user_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    // Open GitHub issues are left on GitHub. Their numbers are listed in the audit
    // entry so the operator can close them (`specs/api.md`, Mappings).
    let open = db::open_issue_numbers(&mut tx, &mapping.github_owner, &mapping.github_repo).await?;
    let removed = db::delete_owned(&mut tx, user_id, id).await?;
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    db::delete_github_issues(&mut tx, &mapping.github_owner, &mapping.github_repo).await?;
    let details = serde_json::json!({ "open_issue_numbers": open });
    audit::record(
        &mut tx,
        actor,
        "mapping.delete",
        &format!("mapping:{id}"),
        Some(&details),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::models::role::Role;

    /// A probe that answers every artifacts request with one fixed status. No socket.
    struct ArtifactsStatus(u16);

    impl HarborProbe for ArtifactsStatus {
        async fn users_current(
            &self,
            _base: &reqwest::Url,
            _username: &str,
            _secret: &[u8],
        ) -> Result<u16, AppError> {
            Ok(200)
        }

        async fn artifacts_status(
            &self,
            _base: &reqwest::Url,
            _username: &str,
            _secret: &[u8],
            _project: &str,
            _repository: &str,
        ) -> Result<u16, AppError> {
            Ok(self.0)
        }
    }

    const READABLE: ArtifactsStatus = ArtifactsStatus(200);
    /// A GitHub probe whose code scanning answer is ready. No socket.
    const GH_READY: GithubFixed = GithubFixed(200, "");
    /// A GitHub probe that answers every request with one fixed status and message.
    struct GithubFixed(u16, &'static str);

    impl GithubProbe for GithubFixed {
        async fn get(
            &self,
            _path: &str,
            _token: &[u8],
        ) -> Result<credential_probe::GithubResponse, AppError> {
            Ok(credential_probe::GithubResponse {
                status: self.0,
                message: self.1.to_owned(),
                accepted_permissions: None,
            })
        }
    }
    use crate::services::credentials::{self, NewCredential, SERVICE_GITHUB, SERVICE_HARBOR};
    use crate::services::users as user_service;

    // Test values only. Fixed fake secrets and a fixed root key.
    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PUBLIC: &str = "https://harborgate.example.com";
    const HARBOR_URL: &str = "https://harbor.example.com";

    fn key() -> crate::auth::crypto::DerivedKey {
        let root = config::parse_encryption_key(ROOT).unwrap();
        crate::auth::crypto::credentials_key(&root).unwrap()
    }

    async fn fresh_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("harborgate-maps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (crate::db::open(&dir).await.unwrap(), dir)
    }

    fn actor(id: &str) -> Actor {
        Actor {
            user_id: Some(id.to_owned()),
            username: format!("name-{id}"),
        }
    }

    async fn user(pool: &SqlitePool, name: &str) -> String {
        user_service::create_local(
            pool,
            &Actor::cli(),
            name,
            None,
            "test-password-fifteen",
            Role::User,
        )
        .await
        .unwrap()
    }

    /// A Harbor and a GitHub credential for `owner`. Returns their ids.
    async fn creds(pool: &SqlitePool, owner: &str) -> (String, String) {
        let harbor = credentials::create(
            pool,
            &key(),
            &actor(owner),
            owner,
            NewCredential {
                service_type: SERVICE_HARBOR.to_owned(),
                label: "h".to_owned(),
                base_url: Some(HARBOR_URL.to_owned()),
                username: Some("robot$harborgate".to_owned()),
                token: "test-harbor-secret".to_owned(),
                expires_at: None,
            },
            false,
        )
        .await
        .unwrap();
        let github = credentials::create(
            pool,
            &key(),
            &actor(owner),
            owner,
            NewCredential {
                service_type: SERVICE_GITHUB.to_owned(),
                label: "g".to_owned(),
                base_url: None,
                username: None,
                token: "test-github-secret".to_owned(),
                expires_at: None,
            },
            false,
        )
        .await
        .unwrap();
        (harbor.id, github.id)
    }

    fn input(harbor_cred: &str, github_cred: &str, repo: &str, gh_repo: &str) -> NewMapping {
        NewMapping {
            harbor_cred_id: harbor_cred.to_owned(),
            github_cred_id: github_cred.to_owned(),
            harbor_project: "proj".to_owned(),
            harbor_repository: repo.to_owned(),
            github_owner: "owner".to_owned(),
            github_repo: gh_repo.to_owned(),
            default_branch: None,
            auto_create_issues: None,
            min_issue_severity: None,
        }
    }

    #[test]
    fn secrets_are_256_bit_base64url() {
        let token = new_secret();
        // 32 bytes encode to 43 base64url characters without padding.
        assert_eq!(token.len(), 43);
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(token, new_secret());
    }

    #[test]
    fn digest_is_lowercase_sha256_hex() {
        // Known vector: SHA-256 of "abc".
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn webhook_url_uses_the_public_url() {
        assert_eq!(
            webhook_url("https://harborgate.example.com/", "tok"),
            "https://harborgate.example.com/api/v1/webhooks/harbor/tok"
        );
    }

    #[test]
    fn severity_accepts_only_critical_or_high() {
        assert!(validate_severity("CRITICAL").is_ok());
        assert!(validate_severity("HIGH").is_ok());
        assert!(validate_severity("MEDIUM").is_err());
    }

    #[tokio::test]
    async fn create_returns_url_and_secret_once_and_stores_only_digests() {
        let (pool, dir) = fresh_pool("create").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        let created = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        // The stored row holds digests, never the raw values.
        let row = db::find_owned(
            &mut pool.acquire().await.unwrap(),
            &owner,
            &created.mapping.id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.webhook_token_hash.len(), 64);
        assert!(!created.webhook_url.ends_with(&row.webhook_token_hash));
        assert!(!format!("{:?}", created).contains(&created.auth_secret));
        assert!(created.webhook_url.starts_with(PUBLIC));
        // The mapping object itself never carries the URL or the secret.
        let json = serde_json::to_string(&created.mapping).unwrap();
        assert!(!json.contains("webhook"));
        assert!(!json.contains(&created.auth_secret));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rotation_invalidates_the_old_token_and_secret() {
        let (pool, dir) = fresh_pool("rotate").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        let created = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        let old_hash = db::find_owned(
            &mut pool.acquire().await.unwrap(),
            &owner,
            &created.mapping.id,
        )
        .await
        .unwrap()
        .unwrap()
        .webhook_token_hash;
        let new_url =
            rotate_webhook_token(&pool, &actor(&owner), &owner, PUBLIC, &created.mapping.id)
                .await
                .unwrap();
        let new_token = new_url.rsplit('/').next().unwrap().to_owned();
        let row = db::find_owned(
            &mut pool.acquire().await.unwrap(),
            &owner,
            &created.mapping.id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(row.webhook_token_hash, old_hash);
        assert_eq!(row.webhook_token_hash, digest(&new_token));
        // The old token's digest no longer matches any mapping.
        assert!(
            db::find_by_token_hash(&pool, &old_hash)
                .await
                .unwrap()
                .is_none()
        );

        let new_secret = rotate_auth_secret(&pool, &actor(&owner), &owner, &created.mapping.id)
            .await
            .unwrap();
        let row = db::find_owned(
            &mut pool.acquire().await.unwrap(),
            &owner,
            &created.mapping.id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.webhook_auth_secret_hash, digest(&new_secret));
        assert_ne!(new_secret, created.auth_secret);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn duplicate_harbor_repository_is_a_conflict() {
        let (pool, dir) = fresh_pool("dup-harbor").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh1"),
        )
        .await
        .unwrap();
        // Same Harbor repository, different GitHub target.
        let result = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh2"),
        )
        .await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn duplicate_github_target_is_a_conflict() {
        let (pool, dir) = fresh_pool("dup-github").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo1", "gh"),
        )
        .await
        .unwrap();
        let result = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo2", "gh"),
        )
        .await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn conflict_names_the_mapping_only_for_its_owner() {
        let (pool, dir) = fresh_pool("names").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let (h, g) = creds(&pool, &owner).await;
        let first = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        let (oh, og) = creds(&pool, &other).await;
        // The other tenant collides with the owner's mapping: the message stays generic.
        let err = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&other),
            &other,
            PUBLIC,
            input(&oh, &og, "repo", "gh"),
        )
        .await
        .unwrap_err();
        match err {
            AppError::Conflict(message) => {
                assert!(
                    !message.contains(&first.mapping.id),
                    "leaked another tenant's id"
                );
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        // The owner colliding with their own mapping may see its id.
        let own = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap_err();
        match own {
            AppError::Conflict(message) => assert!(message.contains(&first.mapping.id)),
            other => panic!("expected conflict, got {other:?}"),
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn another_user_gets_not_found_for_a_mapping() {
        let (pool, dir) = fresh_pool("tenancy").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let (h, g) = creds(&pool, &owner).await;
        let created = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        assert!(matches!(
            load_owned(&pool, &other, &created.mapping.id).await,
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            rotate_webhook_token(&pool, &actor(&other), &other, PUBLIC, &created.mapping.id).await,
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            delete(&pool, &actor(&other), &other, &created.mapping.id).await,
            Err(AppError::NotFound)
        ));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_unreadable_harbor_repository_is_rejected_and_nothing_is_stored() {
        let (pool, dir) = fresh_pool("unreadable").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        // 404 from Harbor: the robot cannot see the repository.
        let result = create(
            &pool,
            &key(),
            &ArtifactsStatus(404),
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await;
        assert!(matches!(result, Err(AppError::ValidationFailed(_))));
        let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repo_mappings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, 0, "a rejected mapping must not be stored");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_credential_of_another_user_is_not_found() {
        let (pool, dir) = fresh_pool("cred-owner").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let (h, g) = creds(&pool, &owner).await;
        let result = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&other),
            &other,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotFound)));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A GitHub probe that records each path, so a test can check which repository and
    /// endpoint the save-time probe used. No socket.
    struct RecordingGithub {
        calls: std::sync::Mutex<Vec<String>>,
        status: u16,
        message: &'static str,
    }

    impl GithubProbe for RecordingGithub {
        async fn get(
            &self,
            path: &str,
            _token: &[u8],
        ) -> Result<credential_probe::GithubResponse, AppError> {
            self.calls.lock().unwrap().push(path.to_owned());
            Ok(credential_probe::GithubResponse {
                status: self.status,
                message: self.message.to_owned(),
                accepted_permissions: None,
            })
        }
    }

    #[tokio::test]
    async fn save_rejects_unavailable_code_scanning_and_stores_nothing() {
        let (pool, dir) = fresh_pool("cs-unavailable").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        let github = GithubFixed(403, "Code scanning is not enabled for this repository.");
        let result = create(
            &pool,
            &key(),
            &READABLE,
            &github,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await;
        assert!(matches!(result, Err(AppError::CodeScanningUnavailable)));
        let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repo_mappings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, 0);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn save_probes_the_mapping_repository_with_the_code_scanning_endpoint() {
        let (pool, dir) = fresh_pool("cs-path").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        let github = RecordingGithub {
            calls: std::sync::Mutex::new(Vec::new()),
            status: 404,
            message: "no analysis found",
        };
        create(
            &pool,
            &key(),
            &READABLE,
            &github,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        let calls = github.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec!["repos/owner/gh/code-scanning/alerts?per_page=1".to_owned()]
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A GitHub probe that answers the issues path and the code scanning path with
    /// different fixed responses, and records every path. No socket.
    struct PathGithub {
        calls: std::sync::Mutex<Vec<String>>,
        scanning: (u16, &'static str),
        issues: (u16, &'static str),
    }

    impl GithubProbe for PathGithub {
        async fn get(
            &self,
            path: &str,
            _token: &[u8],
        ) -> Result<credential_probe::GithubResponse, AppError> {
            self.calls.lock().unwrap().push(path.to_owned());
            let (status, message) = if path.contains("/issues") {
                self.issues
            } else {
                self.scanning
            };
            Ok(credential_probe::GithubResponse {
                status,
                message: message.to_owned(),
                accepted_permissions: None,
            })
        }
    }

    #[tokio::test]
    async fn auto_issues_without_issues_permission_is_422_and_stores_nothing() {
        let (pool, dir) = fresh_pool("issues-403").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        // Code scanning is healthy, so only the Issues answer decides the save.
        let github = PathGithub {
            calls: std::sync::Mutex::new(Vec::new()),
            scanning: (404, "no analysis found"),
            issues: (403, "Resource not accessible by personal access token"),
        };
        let mut new = input(&h, &g, "repo", "gh");
        new.auto_create_issues = Some(true);
        let result = create(
            &pool,
            &key(),
            &READABLE,
            &github,
            &actor(&owner),
            &owner,
            PUBLIC,
            new,
        )
        .await;
        match result {
            Err(AppError::ValidationFailed(detail)) => {
                assert!(detail.contains("Issues permission"), "{detail}");
            }
            _ => panic!("a 403 on the issues probe must be 422 validation_failed"),
        }
        let stored = db::count_owned(&pool, Some(&owner)).await.unwrap();
        assert_eq!(stored, 0, "a rejected save must store nothing");
        let calls = github.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|path| path == "repos/owner/gh/issues?per_page=1"),
            "{calls:?}"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn auto_issues_off_skips_the_issues_probe() {
        let (pool, dir) = fresh_pool("issues-off").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        // A 403 on issues would reject the save if the probe ran. It must not run.
        let github = PathGithub {
            calls: std::sync::Mutex::new(Vec::new()),
            scanning: (404, "no analysis found"),
            issues: (403, "Resource not accessible by personal access token"),
        };
        create(
            &pool,
            &key(),
            &READABLE,
            &github,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        let calls = github.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec!["repos/owner/gh/code-scanning/alerts?per_page=1".to_owned()],
            "only the code scanning probe runs when auto-create is off"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Inserts one `github_issues` row for the given repository and number.
    async fn issue(pool: &SqlitePool, repo: &str, number: i64, status: &str) {
        sqlx::query(
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url, status)
             VALUES (?, 'owner', ?, ?, ?, 'https://github.example/issue', ?)",
        )
        .bind(format!("issue-{repo}-{number}"))
        .bind(repo)
        .bind(format!("CVE-2026-{number:04}"))
        .bind(number)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delete_removes_github_issue_rows_and_lists_open_numbers() {
        let (pool, dir) = fresh_pool("delete-issues").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        let created = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo", "gh"),
        )
        .await
        .unwrap();
        issue(&pool, "gh", 7, "open").await;
        issue(&pool, "gh", 9, "open").await;
        issue(&pool, "gh", 8, "closed").await;
        issue(&pool, "other", 3, "open").await;

        delete(&pool, &actor(&owner), &owner, &created.mapping.id)
            .await
            .unwrap();

        let left: Vec<String> = sqlx::query_scalar(
            "SELECT github_repo FROM github_issues ORDER BY github_repo, github_issue_number",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        // Only the other repository's row survives, because it has no owning mapping here.
        assert_eq!(left, vec!["other".to_owned()]);
        let details: String =
            sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'mapping.delete'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(&details).unwrap();
        assert_eq!(value["open_issue_numbers"], serde_json::json!([7, 9]));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
