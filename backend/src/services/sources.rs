//! Image sources (`specs/spinoff-local-scan.md`, sections 5, 9 and 10; decisions 33 and 37).
//!
//! A source is a hub, a repository and one tag value, plus the GitHub target and issue
//! settings. A user sees only their own sources; an admin reads all and changes none. Editing a
//! value deletes nothing already recorded (section 5). Deleting a source removes what only it
//! observed (section 9). No response carries a token: a source carries `has_credential` only.

use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};

use crate::db::credentials as github_credentials;
use crate::db::hubs;
use crate::db::image_sources::{self as db, SourceFull, SourceWrite};
use crate::error::AppError;
use crate::models::role::Role;
use crate::services::audit::{self, Actor};
use crate::services::credential_probe::valid_github_name;
use crate::services::discovery::glob::TagPattern;
use crate::services::discovery::schedule::queue_source_discovery;
use crate::services::ids;
use crate::services::pagination::{Page, Pagination};
use crate::services::registry::grammar::validate_repository;
use crate::services::sessions::AuthUser;
use crate::services::storage::{StoreRoot, eviction};
use crate::services::time;
use crate::worker::now_secs;

/// Sort keys the list route accepts. The first is the default.
const SORTS: &[&str] = &["created_at", "repository"];
/// The most tags a preview returns.
pub const PREVIEW_LIMIT: usize = 100;
const MAX_BRANCH_BYTES: usize = 255;
/// The longest display name, in characters (#323).
const MAX_NAME_CHARS: usize = 80;

/// What the caller needs from a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Owner, or any admin.
    Read,
    /// Owner only. An admin who tries gets `403`.
    Write,
}

/// The `Source` object. It carries `has_credential` and never a token.
#[derive(Debug, Serialize)]
pub struct Source {
    pub id: String,
    pub user_id: String,
    pub hub_id: String,
    pub hub_host: String,
    pub repository: String,
    /// The display name (#323), or `null` until one is set.
    pub name: Option<String>,
    pub tag_value: String,
    pub github_cred_id: String,
    pub github_owner: String,
    pub github_repo: String,
    pub default_branch: String,
    pub auto_create_issues: bool,
    pub min_issue_severity: String,
    pub has_credential: bool,
    /// True while the source is on `docker.io` with no credential: it pulls anonymously
    /// (decision 42). Derived, not stored.
    pub anonymous_pull: bool,
    pub last_discovery_at: Option<String>,
    /// `queued` or `running` while a discover job scoped to this source is pending, else `idle`.
    pub discovery_status: String,
}

fn view(row: SourceFull) -> Result<Source, AppError> {
    let anonymous_pull = row.hub_host == "docker.io" && !row.has_credential;
    Ok(Source {
        id: row.id,
        user_id: row.user_id,
        hub_id: row.hub_id,
        hub_host: row.hub_host,
        repository: row.repository,
        name: row.name,
        tag_value: row.tag_value,
        github_cred_id: row.github_cred_id,
        github_owner: row.github_owner,
        github_repo: row.github_repo,
        default_branch: row.default_branch,
        auto_create_issues: row.auto_create_issues,
        min_issue_severity: row.min_issue_severity,
        has_credential: row.has_credential,
        anonymous_pull,
        last_discovery_at: row.last_discovery_at.map(time::rfc3339).transpose()?,
        discovery_status: row.discovery_status,
    })
}

/// The create and update body.
#[derive(Debug, Deserialize)]
pub struct SourceInput {
    pub hub_id: String,
    pub repository: String,
    pub tag_value: String,
    pub github_cred_id: String,
    pub github_owner: String,
    pub github_repo: String,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub auto_create_issues: Option<bool>,
    #[serde(default)]
    pub min_issue_severity: Option<String>,
    /// The display name (#323). Optional; empty or blank means unset.
    #[serde(default)]
    pub name: Option<String>,
}

/// Raw list query values.
#[derive(Debug, Default)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub all_users: bool,
}

fn invalid(text: &str) -> AppError {
    AppError::ValidationFailed(text.to_owned())
}

fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_BRANCH_BYTES
        && !name.starts_with(['/', '-', '.'])
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

/// The display name: trimmed, `None` when empty. At most 80 characters and no control
/// characters (#323).
fn checked_name(name: Option<&str>) -> Result<Option<String>, AppError> {
    let trimmed = name.unwrap_or("").trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_NAME_CHARS {
        return Err(invalid("The name is longer than 80 characters."));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(invalid("The name contains a control character."));
    }
    Ok(Some(trimmed.to_owned()))
}

/// The fields checked against their grammars, with the defaults filled in.
struct Checked {
    default_branch: String,
    auto_create_issues: bool,
    min_issue_severity: String,
    name: Option<String>,
}

fn check(input: &SourceInput) -> Result<Checked, AppError> {
    validate_repository(&input.repository)?;
    TagPattern::parse(&input.tag_value)?;
    if !valid_github_name(&input.github_owner) || !valid_github_name(&input.github_repo) {
        return Err(invalid("The GitHub owner or repository is not valid."));
    }
    let default_branch = input
        .default_branch
        .clone()
        .unwrap_or_else(|| "main".to_owned());
    if !valid_branch(&default_branch) {
        return Err(invalid("The default branch is not valid."));
    }
    let min_issue_severity = input
        .min_issue_severity
        .clone()
        .unwrap_or_else(|| "CRITICAL".to_owned());
    if !matches!(min_issue_severity.as_str(), "CRITICAL" | "HIGH") {
        return Err(invalid("min_issue_severity must be CRITICAL or HIGH."));
    }
    Ok(Checked {
        default_branch,
        auto_create_issues: input.auto_create_issues.unwrap_or(false),
        min_issue_severity,
        name: checked_name(input.name.as_deref())?,
    })
}

/// Checks that the hub exists and the GitHub credential is the caller's. Both are `404`.
async fn check_references(
    conn: &mut SqliteConnection,
    user_id: &str,
    input: &SourceInput,
) -> Result<(), AppError> {
    hubs::find(conn, &input.hub_id)
        .await?
        .ok_or(AppError::NotFound)?;
    github_credentials::find_owned(conn, user_id, &input.github_cred_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(())
}

/// The source `id` for `user`. A source the caller may not see is `404`, the same as a missing
/// one. An admin may read any source; a write by an admin is `403`.
pub async fn load(
    conn: &mut SqliteConnection,
    user: &AuthUser,
    id: &str,
    need: Need,
) -> Result<SourceFull, AppError> {
    let row = db::find(conn, id).await?.ok_or(AppError::NotFound)?;
    if row.user_id == user.id {
        return Ok(row);
    }
    match (user.role, need) {
        (Role::Admin, Need::Read) => Ok(row),
        (Role::Admin, Need::Write) => Err(AppError::Forbidden),
        (Role::User, _) => Err(AppError::NotFound),
    }
}

/// One page of sources. `scope=all` is honored for admins by the route.
pub async fn list(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListQuery,
) -> Result<Page<Source>, AppError> {
    let paging = Pagination::parse(
        query.page,
        query.page_size,
        query.sort.as_deref(),
        query.order.as_deref(),
        SORTS,
    )?;
    let scope = if query.all_users { None } else { Some(user_id) };
    let rows = db::list(
        pool,
        scope,
        &paging.sort,
        if paging.ascending { 1 } else { -1 },
        paging.page_size,
        paging.offset(),
    )
    .await?;
    Ok(Page {
        items: rows.into_iter().map(view).collect::<Result<_, _>>()?,
        page: paging.page,
        page_size: paging.page_size,
        total: db::count(pool, scope).await?,
    })
}

/// One source.
pub async fn get(pool: &SqlitePool, user: &AuthUser, id: &str) -> Result<Source, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    view(load(&mut conn, user, id, Need::Read).await?)
}

/// Creates a source for `user`. The same hub, repository and tag value is `409`.
pub async fn create(
    pool: &SqlitePool,
    actor: &Actor,
    user: &AuthUser,
    input: SourceInput,
) -> Result<Source, AppError> {
    let checked = check(&input)?;
    let id = ids::new_id()?;
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    check_references(&mut tx, &user.id, &input).await?;
    let write = SourceWrite {
        hub_id: &input.hub_id,
        repository: &input.repository,
        tag_value: &input.tag_value,
        github_cred_id: &input.github_cred_id,
        github_owner: &input.github_owner,
        github_repo: &input.github_repo,
        default_branch: &checked.default_branch,
        auto_create_issues: checked.auto_create_issues,
        min_issue_severity: &checked.min_issue_severity,
        name: checked.name.as_deref(),
    };
    db::insert(&mut tx, &id, &user.id, &write).await?;
    let created = db::find(&mut tx, &id)
        .await?
        .ok_or(AppError::InternalError)?;
    queue_source_discovery(&mut tx, &id, &input.hub_id, &input.repository, now_secs()).await?;
    audit::record(
        &mut tx,
        actor,
        "source.create",
        &format!("source:{id}"),
        Some(&serde_json::json!({
            "hub": created.hub_host,
            "repository": created.repository,
            "tag_value": created.tag_value,
        })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    view(created)
}

/// Updates the owner's source. Nothing already recorded is deleted; new matches are pulled at
/// the next discovery.
pub async fn update(
    pool: &SqlitePool,
    actor: &Actor,
    user: &AuthUser,
    id: &str,
    input: SourceInput,
) -> Result<Source, AppError> {
    let checked = check(&input)?;
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let before = load(&mut tx, user, id, Need::Write).await?;
    check_references(&mut tx, &user.id, &input).await?;
    let write = SourceWrite {
        hub_id: &input.hub_id,
        repository: &input.repository,
        tag_value: &input.tag_value,
        github_cred_id: &input.github_cred_id,
        github_owner: &input.github_owner,
        github_repo: &input.github_repo,
        default_branch: &checked.default_branch,
        auto_create_issues: checked.auto_create_issues,
        min_issue_severity: &checked.min_issue_severity,
        name: checked.name.as_deref(),
    };
    db::update(&mut tx, id, &write).await?;
    let updated = db::find(&mut tx, id)
        .await?
        .ok_or(AppError::InternalError)?;
    // Only the fields that change discovery queue a run; a rename does not (#331).
    let discovery_changed = before.hub_id != updated.hub_id
        || before.repository != updated.repository
        || before.tag_value != updated.tag_value;
    if discovery_changed {
        queue_source_discovery(&mut tx, id, &input.hub_id, &input.repository, now_secs()).await?;
    }
    audit::record(
        &mut tx,
        actor,
        "source.update",
        &format!("source:{id}"),
        Some(&serde_json::json!({
            "hub": updated.hub_host,
            "repository": updated.repository,
            "tag_value": updated.tag_value,
        })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    view(updated)
}

/// Deletes the owner's source (section 9). Refused with `409` while a job of the source is
/// running or an image only it observes is being pulled, evicted or scanned. Open GitHub issues
/// stay open and are listed in the audit row. Layouts are removed after the commit.
pub async fn delete(
    pool: &SqlitePool,
    store: &StoreRoot,
    actor: &Actor,
    user: &AuthUser,
    id: &str,
) -> Result<(), AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    let source = load(&mut tx, user, id, Need::Write).await?;
    if db::has_running_job(&mut tx, id).await? {
        return Err(AppError::Conflict(
            "a job of this source is running. Try again when it ends.".to_owned(),
        ));
    }
    let issues = db::open_issues(&mut tx, id).await?;
    let observed = db::observed_image_ids(&mut tx, id).await?;
    db::delete(&mut tx, id).await?;
    let mut layouts = Vec::new();
    for image_id in observed {
        if db::image_observed(&mut tx, &image_id).await? {
            continue;
        }
        if db::image_busy(&mut tx, &image_id).await? {
            return Err(AppError::Conflict(
                "an image of this source is being pulled or scanned. Try again when it ends."
                    .to_owned(),
            ));
        }
        layouts.extend(db::platform_ids(&mut tx, &image_id).await?);
        db::delete_image(&mut tx, &image_id).await?;
    }
    let open_issues: Vec<serde_json::Value> = issues
        .into_iter()
        .map(|(cve_id, number)| serde_json::json!({ "cve_id": cve_id, "issue": number }))
        .collect();
    audit::record(
        &mut tx,
        actor,
        "source.delete",
        &format!("source:{id}"),
        Some(&serde_json::json!({
            "hub": source.hub_host,
            "repository": source.repository,
            "tag_value": source.tag_value,
            "github_owner": source.github_owner,
            "github_repo": source.github_repo,
            "open_issues": open_issues,
        })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    for platform_id in layouts {
        if eviction::remove_layout(store, &platform_id).is_err() {
            tracing::warn!("could not remove a layout of a deleted source");
        }
    }
    Ok(())
}

/// The result of a tag preview.
#[derive(Debug, Serialize)]
pub struct Preview {
    pub matches: Vec<String>,
    pub truncated: bool,
}

/// The tags the source's last discoveries recorded that match its current value. It does not
/// contact the registry and records nothing.
pub async fn preview(pool: &SqlitePool, source: &SourceFull) -> Result<Preview, AppError> {
    let pattern = TagPattern::parse(&source.tag_value)?;
    let mut matches: Vec<String> = db::observed_tags(pool, &source.id)
        .await?
        .into_iter()
        .filter(|tag| pattern.matches(tag))
        .collect();
    let truncated = matches.len() > PREVIEW_LIMIT;
    matches.truncate(PREVIEW_LIMIT);
    Ok(Preview { matches, truncated })
}
