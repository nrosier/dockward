//! Mapping CRUD, the webhook token and auth secret, and rotation. Sources:
//! `specs/api.md` (Mappings), `specs/integrations.md` (Webhook URL token, Secret value),
//! `specs/database.md` (`repo_mappings`).
//!
//! The webhook token and auth secret are 256-bit values from a CSPRNG, base64url
//! encoded without padding. Only their SHA-256 digests (lowercase hex) are stored.
//! They are returned once, at create and at rotation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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
const SORTS: &[&str] = &[
    "harbor_repository",
    "created_at",
    "harbor_project",
    "github_owner",
    "github_repo",
    "open_issues",
    "last_sync_at",
];

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

/// The create response: the mapping plus the two values shown once. `auth_secret` is the
/// full `Authorization` header value (`Bearer <secret>`), which Harbor sends as is.
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

/// A partial update (`PUT /mappings/:id`). Each field is optional, and `None` leaves it
/// unchanged. The field names are the create field names. Unknown fields are ignored,
/// as the create route ignores them.
#[derive(Clone, Default, Deserialize)]
pub struct MappingPatch {
    pub harbor_cred_id: Option<String>,
    pub github_cred_id: Option<String>,
    pub harbor_project: Option<String>,
    pub harbor_repository: Option<String>,
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
    pub default_branch: Option<String>,
    pub auto_create_issues: Option<bool>,
    pub min_issue_severity: Option<String>,
}

/// The two outbound probes a mapping write uses. Grouped so the write functions keep
/// a short argument list. Tests pass fakes.
pub struct Probes<'a, P: HarborProbe, G: GithubProbe> {
    pub harbor: &'a P,
    pub github: &'a G,
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
pub fn new_secret() -> Result<String, AppError> {
    let bytes = ids::os_random_bytes::<32>()?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
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

/// A Harbor project is one name with no `/`. A repository may have `/` between its
/// components. Both follow Harbor's naming rule (`credential_probe::valid_harbor_name`).
fn validate_harbor_names(project: &str, repository: &str) -> Result<(), AppError> {
    if project.contains('/') || !credential_probe::valid_harbor_name(project) {
        return Err(AppError::ValidationFailed(
            "harbor_project must be a lowercase Harbor project name.".to_owned(),
        ));
    }
    if !credential_probe::valid_harbor_name(repository) {
        return Err(AppError::ValidationFailed(
            "harbor_repository must be a lowercase Harbor repository name.".to_owned(),
        ));
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
    let base = credentials::base_for_join(row.base_url.as_deref().ok_or(AppError::InternalError)?)?;
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
    validate_harbor_names(&input.harbor_project, &input.harbor_repository)?;
    validate_text("github_owner", &input.github_owner)?;
    validate_text("github_repo", &input.github_repo)?;
    let severity = input
        .min_issue_severity
        .clone()
        .unwrap_or_else(|| "CRITICAL".to_owned());
    validate_severity(&severity)?;

    let id = ids::new_id()?;
    let token = new_secret()?;
    let secret = new_secret()?;
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
        // The value Harbor sends as the Authorization header, ready to paste.
        auth_secret: format!("Bearer {secret}"),
    })
}

/// Updates one owned mapping from a partial patch. Only changed fields are validated
/// and probed. The webhook token and auth secret are not touched, and no shown-once
/// value is returned. Writes `mapping.update` with the changed field names only, in the
/// same transaction as the change.
///
/// The work runs in three phases. Validation, the ownership reads and the outbound probes
/// run on a plain connection, with no write lock held, so a slow probe does not block other
/// writers. Then one `BEGIN IMMEDIATE` transaction reads the row under the lock, reapplies
/// the patch to that row, and rechecks the owners and the collision before the write. A
/// change to a probed field during the probes is `409`, because the probes checked a
/// different combination. A UNIQUE violation at the write is also `409`.
pub async fn update<P: HarborProbe, G: GithubProbe>(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    probes: Probes<'_, P, G>,
    actor: &Actor,
    user_id: &str,
    id: &str,
    patch: MappingPatch,
) -> Result<Mapping, AppError> {
    // Phase 1 and 2: no transaction. Each step takes its own connection.
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    let current = db::find_owned(&mut conn, user_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (mut next, changed) = apply_patch(&current, &patch)?;
    let harbor_changed = patch.harbor_cred_id.is_some()
        || patch.harbor_project.is_some()
        || patch.harbor_repository.is_some();
    let github_changed = patch.github_cred_id.is_some()
        || patch.github_owner.is_some()
        || patch.github_repo.is_some();
    let issues_on = next.auto_create_issues.unwrap_or(false);
    let issues_turned_on = issues_on && current.auto_create_issues != Some(true);
    // Ownership first: a foreign credential is `404` before any probe runs.
    check_update_owners(&mut conn, user_id, &patch, &mut next).await?;
    // Probe again only for the parts that changed. A Harbor repository change, or a Harbor
    // credential change, re-checks the repository. A GitHub target change re-checks code
    // scanning. Turning issues on, or changing the GitHub target while they are on, re-checks
    // the Issues permission.
    if harbor_changed {
        check_harbor_repository(
            &mut conn,
            credentials_key,
            probes.harbor,
            user_id,
            &next.harbor_cred_id,
            &next.harbor_project,
            &next.harbor_repository,
        )
        .await?;
    }
    if github_changed {
        check_code_scanning(
            &mut conn,
            credentials_key,
            probes.github,
            user_id,
            &next.github_cred_id,
            &next.github_owner,
            &next.github_repo,
        )
        .await?;
    }
    if issues_on && (github_changed || issues_turned_on) {
        check_issues(
            &mut conn,
            credentials_key,
            probes.github,
            user_id,
            &next.github_cred_id,
            &next.github_owner,
            &next.github_repo,
        )
        .await?;
    }
    drop(conn);

    // Phase 3: one write transaction. It takes the write lock at BEGIN, so the checks below
    // see the state that the write will change.
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let locked = db::find_owned(&mut tx, user_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if changed.is_empty() {
        tx.commit().await.map_err(|_| AppError::InternalError)?;
        return to_mapping(locked);
    }
    // The probes validated the probed fields of `current`. If one of them changed under the
    // lock, the probes checked a different combination than the one this write would store.
    if probed_fields_changed(&current, &locked) {
        return Err(AppError::Conflict(
            "the mapping changed, try again.".to_owned(),
        ));
    }
    // Reapply the patch to the row read under the lock, so a concurrent write to a field the
    // patch does not name is kept.
    let (mut next, _) = apply_patch(&locked, &patch)?;
    check_update_owners(&mut tx, user_id, &patch, &mut next).await?;
    let target_changed =
        harbor_changed || patch.github_owner.is_some() || patch.github_repo.is_some();
    if target_changed {
        let collision = db::find_conflict(
            &mut tx,
            &next.harbor_base_url,
            &next.harbor_project,
            &next.harbor_repository,
            &next.github_owner,
            &next.github_repo,
            id,
        )
        .await?;
        if let Some((other_id, other_user)) = collision {
            return Err(conflict_error(&other_id, &other_user, user_id));
        }
    }

    let written = db::update_owned(&mut tx, user_id, &next)
        .await
        .map_err(|err| match err {
            // A UNIQUE violation is the same collision as the check above. The id of the
            // other mapping is unknown here, so the message is the generic one.
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(
                    "this Harbor repository or GitHub target is already mapped.".to_owned(),
                )
            }
            _ => AppError::InternalError,
        })?;
    if written == 0 {
        return Err(AppError::NotFound);
    }
    let details = serde_json::json!({ "changed_fields": changed });
    audit::record(
        &mut tx,
        actor,
        "mapping.update",
        &format!("mapping:{id}"),
        Some(&details),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    to_mapping(load_row_owned(pool, user_id, id).await?)
}

/// True when a field the Harbor and GitHub probes read differs between two reads of the
/// same mapping. Those fields are the Harbor project and repository, the GitHub owner and
/// repository, and the two credential ids.
fn probed_fields_changed(before: &MappingRow, after: &MappingRow) -> bool {
    before.harbor_cred_id != after.harbor_cred_id
        || before.github_cred_id != after.github_cred_id
        || before.harbor_project != after.harbor_project
        || before.harbor_repository != after.harbor_repository
        || before.github_owner != after.github_owner
        || before.github_repo != after.github_repo
}

/// Applies a patch to a copy of `current`. Validates each changed field with the create
/// rules and returns the new row with the names of the changed fields. Does no I/O.
fn apply_patch(
    current: &MappingRow,
    patch: &MappingPatch,
) -> Result<(MappingRow, Vec<&'static str>), AppError> {
    let mut next = current.clone();
    let mut changed: Vec<&'static str> = Vec::new();
    if let Some(value) = patch.harbor_project.as_deref() {
        validate_text("harbor_project", value)?;
        next.harbor_project = value.to_owned();
        changed.push("harbor_project");
    }
    if let Some(value) = patch.harbor_repository.as_deref() {
        validate_text("harbor_repository", value)?;
        next.harbor_repository = value.to_owned();
        changed.push("harbor_repository");
    }
    if patch.harbor_project.is_some() || patch.harbor_repository.is_some() {
        validate_harbor_names(&next.harbor_project, &next.harbor_repository)?;
    }
    if let Some(value) = patch.github_owner.as_deref() {
        validate_text("github_owner", value)?;
        next.github_owner = value.to_owned();
        changed.push("github_owner");
    }
    if let Some(value) = patch.github_repo.as_deref() {
        validate_text("github_repo", value)?;
        next.github_repo = value.to_owned();
        changed.push("github_repo");
    }
    if let Some(value) = patch.default_branch.as_deref() {
        validate_text("default_branch", value)?;
        next.default_branch = value.to_owned();
        changed.push("default_branch");
    }
    if let Some(value) = patch.min_issue_severity.as_deref() {
        validate_severity(value)?;
        next.min_issue_severity = Some(value.to_owned());
        changed.push("min_issue_severity");
    }
    if let Some(value) = patch.auto_create_issues {
        next.auto_create_issues = Some(value);
        changed.push("auto_create_issues");
    }
    if let Some(value) = patch.harbor_cred_id.as_deref() {
        next.harbor_cred_id = value.to_owned();
        changed.push("harbor_cred_id");
    }
    if let Some(value) = patch.github_cred_id.as_deref() {
        next.github_cred_id = value.to_owned();
        changed.push("github_cred_id");
    }
    Ok((next, changed))
}

/// Checks that both credentials the mapping uses are owned by the caller. A foreign or
/// unknown credential is `404`. This runs for every update, not only when the patch names
/// a credential, so a credential moved to another user during the probes is refused. When
/// the patch names the Harbor credential, its base URL is copied into `next`.
async fn check_update_owners(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    patch: &MappingPatch,
    next: &mut MappingRow,
) -> Result<(), AppError> {
    let base = harbor_base_of(conn, user_id, &next.harbor_cred_id).await?;
    if patch.harbor_cred_id.is_some() {
        next.harbor_base_url = base;
    }
    check_github(conn, user_id, &next.github_cred_id).await
}

/// Reads one owned row. Used after a write, so the response shows the stored values.
async fn load_row_owned(
    pool: &SqlitePool,
    user_id: &str,
    id: &str,
) -> Result<MappingRow, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    db::find_owned(&mut conn, user_id, id)
        .await?
        .ok_or(AppError::NotFound)
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
    let token = new_secret()?;
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
    let secret = new_secret()?;
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
    // The value Harbor sends as the Authorization header, ready to paste.
    Ok(format!("Bearer {secret}"))
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
        let token = new_secret().unwrap_or_default();
        // 32 bytes encode to 43 base64url characters without padding.
        assert_eq!(token.len(), 43);
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(token, new_secret().unwrap_or_default());
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
    async fn invalid_harbor_repository_is_422() {
        let (pool, dir) = fresh_pool("bad-name").await;
        let owner = user(&pool, "owner").await;
        let (h, g) = creds(&pool, &owner).await;
        // `?` changes the request path, so the name is refused before any Harbor call.
        let result = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&owner),
            &owner,
            PUBLIC,
            input(&h, &g, "repo?x", "gh"),
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        let err = result.err().unwrap();
        assert!(matches!(err, AppError::ValidationFailed(_)), "{err:?}");
        assert_eq!(err.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
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
        // The shown value is the Authorization header. Verification strips `Bearer `
        // and hashes the rest, so the stored digest must match the bare secret.
        let bare = new_secret
            .strip_prefix("Bearer ")
            .expect("rotation returns the Authorization header value");
        assert_eq!(row.webhook_auth_secret_hash, digest(bare));
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

    /// A mapping for `owner` with the given Harbor repository and GitHub repo. Returns its id.
    async fn mapping_for(pool: &SqlitePool, owner: &str, repo: &str, gh_repo: &str) -> String {
        let (h, g) = creds(pool, owner).await;
        create(
            pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(owner),
            owner,
            PUBLIC,
            input(&h, &g, repo, gh_repo),
        )
        .await
        .unwrap()
        .mapping
        .id
    }

    /// Reads one owned mapping row, for a test that needs its credential ids.
    async fn load_owned_row(pool: &SqlitePool, owner: &str, id: &str) -> MappingRow {
        db::find_owned(&mut pool.acquire().await.unwrap(), owner, id)
            .await
            .unwrap()
            .unwrap()
    }

    /// A patch with every field unset.
    fn no_change() -> MappingPatch {
        MappingPatch::default()
    }

    /// Runs `update` with the given probes and patch.
    async fn update_with<P: HarborProbe, G: GithubProbe>(
        pool: &SqlitePool,
        probes: Probes<'_, P, G>,
        owner: &str,
        id: &str,
        patch: MappingPatch,
    ) -> Result<Mapping, AppError> {
        update(pool, &key(), probes, &actor(owner), owner, id, patch).await
    }

    #[tokio::test]
    async fn update_collision_names_the_mapping_only_for_its_owner() {
        let (pool, dir) = fresh_pool("update-collide").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let first = mapping_for(&pool, &owner, "repo-a", "gh-a").await;
        let second = mapping_for(&pool, &owner, "repo-b", "gh-b").await;
        let (oh, og) = creds(&pool, &other).await;
        let other_id = create(
            &pool,
            &key(),
            &READABLE,
            &GH_READY,
            &actor(&other),
            &other,
            PUBLIC,
            input(&oh, &og, "repo-c", "gh-c"),
        )
        .await
        .unwrap()
        .mapping
        .id;
        let probes = || Probes {
            harbor: &READABLE,
            github: &GH_READY,
        };

        // The owner moves their second mapping onto a repository the first one uses. The
        // 409 names the first mapping, because the owner owns it.
        let own = update_with(
            &pool,
            probes(),
            &owner,
            &second,
            MappingPatch {
                harbor_repository: Some("repo-a".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        match own {
            AppError::Conflict(message) => assert!(message.contains(&first)),
            other => panic!("expected conflict, got {other:?}"),
        }

        // The owner moves a mapping onto the other tenant's repository. The 409 is generic,
        // so the other tenant's mapping id is not revealed.
        let foreign = update_with(
            &pool,
            probes(),
            &owner,
            &second,
            MappingPatch {
                harbor_repository: Some("repo-c".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        match foreign {
            AppError::Conflict(message) => {
                assert!(!message.contains(&other_id), "leaked another tenant's id");
                assert_eq!(
                    message,
                    "this Harbor repository or GitHub target is already mapped."
                );
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn update_rejects_invalid_values_with_422() {
        let (pool, dir) = fresh_pool("update-422").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let probes = || Probes {
            harbor: &READABLE,
            github: &GH_READY,
        };
        let cases = [
            MappingPatch {
                harbor_repository: Some("repo?x".to_owned()),
                ..no_change()
            },
            MappingPatch {
                harbor_project: Some("proj/x".to_owned()),
                ..no_change()
            },
            MappingPatch {
                github_owner: Some("   ".to_owned()),
                ..no_change()
            },
            MappingPatch {
                min_issue_severity: Some("MEDIUM".to_owned()),
                ..no_change()
            },
        ];
        for patch in cases {
            let err = update_with(&pool, probes(), &owner, &id, patch)
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::ValidationFailed(_)), "{err:?}");
            assert_eq!(err.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        }
        // Nothing was stored by the refused writes.
        let stored = load_owned(&pool, &owner, &id).await.unwrap();
        assert_eq!(stored.harbor_repository, "repo");
        assert_eq!(stored.min_issue_severity, "CRITICAL");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn update_keeps_webhook_token_and_secret_and_returns_no_secret() {
        let (pool, dir) = fresh_pool("update-keep-secrets").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let before = db::find_owned(&mut pool.acquire().await.unwrap(), &owner, &id)
            .await
            .unwrap()
            .unwrap();
        let updated = update_with(
            &pool,
            Probes {
                harbor: &READABLE,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_repository: Some("repo-two".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap();
        let after = db::find_owned(&mut pool.acquire().await.unwrap(), &owner, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.harbor_repository, "repo-two");
        assert_eq!(after.webhook_token_hash, before.webhook_token_hash);
        assert_eq!(
            after.webhook_auth_secret_hash,
            before.webhook_auth_secret_hash
        );
        // The response is the Mapping object, which never carries a secret or the URL.
        let json = serde_json::to_string(&updated).unwrap();
        assert!(!json.contains("webhook"));
        assert!(!json.contains("Bearer"));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn update_writes_an_audit_row_with_field_names_only() {
        let (pool, dir) = fresh_pool("update-audit").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        update_with(
            &pool,
            Probes {
                harbor: &READABLE,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_repository: Some("repo-two".to_owned()),
                default_branch: Some("trunk".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap();
        let row: (String, String) =
            sqlx::query_as("SELECT action, details FROM audit_log WHERE action = 'mapping.update'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "mapping.update");
        let details: serde_json::Value = serde_json::from_str(&row.1).unwrap();
        assert_eq!(
            details["changed_fields"],
            serde_json::json!(["harbor_repository", "default_branch"])
        );
        // The values are not recorded, only the names.
        assert!(!row.1.contains("repo-two"));
        assert!(!row.1.contains("trunk"));
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn update_of_another_users_mapping_is_not_found() {
        let (pool, dir) = fresh_pool("update-tenancy").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let err = update_with(
            &pool,
            Probes {
                harbor: &READABLE,
                github: &GH_READY,
            },
            &other,
            &id,
            MappingPatch {
                harbor_repository: Some("repo-two".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound), "{err:?}");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_foreign_harbor_credential_in_an_update_is_not_found() {
        let (pool, dir) = fresh_pool("update-foreign-harbor").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let (other_harbor, _) = creds(&pool, &other).await;
        let err = update_with(
            &pool,
            Probes {
                harbor: &READABLE,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_cred_id: Some(other_harbor),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(err, AppError::NotFound), "{err:?}");
    }

    #[tokio::test]
    async fn a_foreign_github_credential_in_an_update_is_not_found() {
        let (pool, dir) = fresh_pool("update-foreign-github").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let (_, other_github) = creds(&pool, &other).await;
        let err = update_with(
            &pool,
            Probes {
                harbor: &READABLE,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                github_cred_id: Some(other_github),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(err, AppError::NotFound), "{err:?}");
    }

    /// A Harbor probe that writes a competing mapping through the pool while the owner's
    /// update is still probing. The competing mapping takes the Harbor repository the
    /// update is moving to. No socket.
    struct CompetingWriteHarbor {
        pool: SqlitePool,
        user_id: String,
        harbor_cred: String,
        github_cred: String,
    }

    impl HarborProbe for CompetingWriteHarbor {
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
            // A second writer commits the competing row during the probe.
            sqlx::query(
                "INSERT INTO repo_mappings (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project, harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash)
                 VALUES ('competing', ?, ?, ?, ?, 'proj', 'moved', 'gh-competing', 'gh-competing', 'competing-token', 'competing-secret')",
            )
            .bind(&self.user_id)
            .bind(&self.harbor_cred)
            .bind(&self.github_cred)
            .bind(HARBOR_URL)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::InternalError)?;
            Ok(200)
        }
    }

    #[tokio::test]
    async fn a_competing_write_during_the_probe_is_a_409_not_a_500() {
        let (pool, dir) = fresh_pool("update-race").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let (h, g) = creds(&pool, &owner).await;
        let harbor = CompetingWriteHarbor {
            pool: pool.clone(),
            user_id: owner.clone(),
            harbor_cred: h,
            github_cred: g,
        };
        let err = update_with(
            &pool,
            Probes {
                harbor: &harbor,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_repository: Some("moved".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        assert_eq!(err.status(), axum::http::StatusCode::CONFLICT);
    }

    /// A Harbor probe that changes one untouched column, `default_branch`, on the mapping
    /// while the update is probing. The update does not name that column. No socket.
    struct ConcurrentDefaultBranchHarbor {
        pool: SqlitePool,
        mapping_id: String,
    }

    impl HarborProbe for ConcurrentDefaultBranchHarbor {
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
            sqlx::query("UPDATE repo_mappings SET default_branch = 'concurrent' WHERE id = ?")
                .bind(&self.mapping_id)
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::InternalError)?;
            Ok(200)
        }
    }

    /// A PUT that changes only `harbor_repository`, while a concurrent write changes
    /// `default_branch` during the probe. The concurrent value must be kept in the stored
    /// row. The request may instead fail with `409`, but it must never revert the
    /// concurrent write.
    #[tokio::test]
    async fn a_concurrent_write_to_an_untouched_field_is_not_lost() {
        let (pool, dir) = fresh_pool("update-lost-write").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let harbor = ConcurrentDefaultBranchHarbor {
            pool: pool.clone(),
            mapping_id: id.clone(),
        };
        let result = update_with(
            &pool,
            Probes {
                harbor: &harbor,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_repository: Some("repo-two".to_owned()),
                ..no_change()
            },
        )
        .await;
        let stored = load_owned(&pool, &owner, &id).await.unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(_) => assert_eq!(stored.default_branch, "concurrent"),
            Err(err) => {
                assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
                assert_eq!(stored.default_branch, "concurrent");
            }
        }
    }

    /// Probe that changes `harbor_project` on the mapping during the probe. That field is
    /// probed, so the update must refuse with `409` rather than store an unprobed combination.
    struct ConcurrentProjectHarbor {
        pool: SqlitePool,
        mapping_id: String,
    }

    impl HarborProbe for ConcurrentProjectHarbor {
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
            sqlx::query("UPDATE repo_mappings SET harbor_project = 'other-proj' WHERE id = ?")
                .bind(&self.mapping_id)
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::InternalError)?;
            Ok(200)
        }
    }

    /// A probed field changed during the probes is `409`, with the fixed text.
    #[tokio::test]
    async fn a_probed_field_changed_during_the_probe_is_a_409() {
        let (pool, dir) = fresh_pool("update-probed-changed").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let harbor = ConcurrentProjectHarbor {
            pool: pool.clone(),
            mapping_id: id.clone(),
        };
        let err = update_with(
            &pool,
            Probes {
                harbor: &harbor,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_repository: Some("repo-two".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        let stored = load_owned(&pool, &owner, &id).await.unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.status(), axum::http::StatusCode::CONFLICT, "{err:?}");
        assert_eq!(err.message(), "the mapping changed, try again.");
        assert_eq!(stored.harbor_repository, "repo");
    }

    /// Harbor credential change: the stored Harbor base URL is the new credential's base,
    /// not the old one.
    #[tokio::test]
    async fn a_harbor_credential_change_refreshes_the_base_url() {
        let (pool, dir) = fresh_pool("update-base-url").await;
        let owner = user(&pool, "owner").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        let (_, g) = creds(&pool, &owner).await;
        let new_harbor = credentials::create(
            &pool,
            &key(),
            &actor(&owner),
            &owner,
            NewCredential {
                service_type: SERVICE_HARBOR.to_owned(),
                label: "h2".to_owned(),
                base_url: Some("https://harbor-two.example.com".to_owned()),
                username: Some("robot$hg".to_owned()),
                token: "test-harbor-secret".to_owned(),
                expires_at: None,
            },
            false,
        )
        .await
        .unwrap();
        let _ = g;
        update_with(
            &pool,
            Probes {
                harbor: &READABLE,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_cred_id: Some(new_harbor.id),
                ..no_change()
            },
        )
        .await
        .unwrap();
        let stored = load_owned(&pool, &owner, &id).await.unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(stored.harbor_base_url, "https://harbor-two.example.com");
    }

    /// A Harbor probe that transfers the caller's Harbor credential to another user while
    /// the update is probing. The phase-3 ownership recheck must refuse it. No socket.
    struct TransferCredentialHarbor {
        pool: SqlitePool,
        credential_id: String,
        new_owner: String,
    }

    impl HarborProbe for TransferCredentialHarbor {
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
            sqlx::query("UPDATE user_credentials SET user_id = ? WHERE id = ?")
                .bind(&self.new_owner)
                .bind(&self.credential_id)
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::InternalError)?;
            Ok(200)
        }
    }

    /// A credential that moves to another user during the probe is refused by the
    /// phase-3 ownership recheck, with `404`.
    #[tokio::test]
    async fn a_credential_transferred_during_the_probe_is_not_found() {
        let (pool, dir) = fresh_pool("update-transfer").await;
        let owner = user(&pool, "owner").await;
        let other = user(&pool, "other").await;
        let id = mapping_for(&pool, &owner, "repo", "gh").await;
        // The Harbor credential the mapping actually uses, not a new one.
        let mapped_harbor = load_owned_row(&pool, &owner, &id).await.harbor_cred_id;
        let harbor = TransferCredentialHarbor {
            pool: pool.clone(),
            credential_id: mapped_harbor,
            new_owner: other.clone(),
        };
        let err = update_with(
            &pool,
            Probes {
                harbor: &harbor,
                github: &GH_READY,
            },
            &owner,
            &id,
            MappingPatch {
                harbor_repository: Some("repo-two".to_owned()),
                ..no_change()
            },
        )
        .await
        .unwrap_err();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(err, AppError::NotFound), "{err:?}");
    }
}
