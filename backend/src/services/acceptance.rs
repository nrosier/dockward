//! CVE acceptance (`specs/cve-lifecycle.md`, "Acceptance"; `specs/api.md`, CVEs).
//!
//! [`accept`] records a risk acceptance for a CVE on a source the caller owns, and
//! [`unaccept`] revokes it softly. An acceptance applies to the whole source, never to one
//! tag. Accepting does not close an open GitHub issue: it adds a comment. Both actions are
//! audited, in the same transaction as the change.
//!
//! The GitHub token is only passed on to the client. Nothing here logs it, an error value or
//! a response body: every log line is fixed text.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::auth::crypto::DerivedKey;
use crate::db::acceptances::{self as acceptance_db, AcceptanceRow, NewAcceptance};
use crate::db::credentials as credential_db;
use crate::db::github_issues as issue_db;
use crate::db::sources::{self as source_db, SourceRow};
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::credentials::decrypt_token;
use crate::services::issue_lifecycle::IssueApi;
use crate::services::{ids, time};

/// The longest reason, in characters (`specs/api.md`, accept). The reason may be empty (#351).
const MAX_REASON_CHARS: usize = 1000;

/// `9999-12-31T23:59:59Z`, the last instant [`time::rfc3339`] can format.
const MAX_UNIX_SECS: i64 = 253_402_300_799;

/// The longest CVE id or source id the routes accept, in bytes. Same as the issue route.
const MAX_ID_BYTES: usize = 128;

/// The body of `POST /api/v1/cves/:id/accept`. `expires_at` is an RFC 3339 `date-time`
/// (`specs/api.md`, Conventions) or empty for an acceptance that does not expire.
#[derive(Debug, Default, serde::Deserialize)]
pub struct AcceptInput {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// The acceptance as the accept route answers with it.
#[derive(Debug, Serialize)]
pub struct Acceptance {
    pub id: String,
    pub source_id: String,
    pub cve_id: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
}

impl Acceptance {
    fn from_row(row: AcceptanceRow) -> Result<Self, AppError> {
        Ok(Self {
            id: row.id,
            source_id: row.source_id,
            cve_id: row.cve_id,
            reason: row.reason,
            created_by: row.created_by_username,
            created_at: row.created_at.map(time::rfc3339).transpose()?,
            expires_at: row.expires_at.map(time::rfc3339).transpose()?,
        })
    }
}

/// The caller of an accept or un-accept: the user row id and the name stored with the
/// acceptance.
pub struct Caller<'a> {
    pub id: &'a str,
    pub username: &'a str,
}

impl Caller<'_> {
    fn actor(&self) -> Actor {
        Actor {
            user_id: Some(self.id.to_owned()),
            username: self.username.to_owned(),
        }
    }
}

fn valid_cve_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Splits the route id `<source_id>:<cve_id>`, with the same rules as the issue route: any
/// other shape, an empty part, a part over 128 bytes, or a character outside the allowed set
/// is `404`, before any database call.
fn split_id(id: &str) -> Result<(&str, &str), AppError> {
    match id.split_once(':') {
        Some((source_id, cve_id)) if valid_source_id(source_id) && valid_cve_id(cve_id) => {
            Ok((source_id, cve_id))
        }
        _ => Err(AppError::NotFound),
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an RFC 3339 `date-time` (`2026-11-02T09:30:00Z`, optional fraction, `Z` or a
/// `+hh:mm` offset) into Unix seconds. Anything else is `None`.
pub(crate) fn parse_rfc3339(text: &str) -> Option<i64> {
    if !text.is_ascii() || text.len() < 20 || text.len() > 40 {
        return None;
    }
    let b = text.as_bytes();
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = text.get(from..to)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' {
        return None;
    }
    if b[16] != b':' {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut rest = 19;
    if b[rest] == b'.' {
        let digits = b[rest + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        rest += 1 + digits;
    }
    let offset = match text.get(rest..)? {
        "Z" | "z" => 0,
        zone if zone.len() == 6 && matches!(zone.as_bytes()[0], b'+' | b'-') => {
            if zone.as_bytes()[3] != b':' {
                return None;
            }
            // `rest + 1..rest + 3` and `rest + 4..rest + 6` must be ASCII digits: `str::parse`
            // alone would take a sign, so `++5:30` or `+-5:30` would pass.
            let (oh, om) = (num(rest + 1, rest + 3)?, num(rest + 4, rest + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let seconds = oh * 3600 + om * 60;
            if zone.as_bytes()[0] == b'-' {
                -seconds
            } else {
                seconds
            }
        }
        _ => return None,
    };
    // A day past the end of its month would roll over silently, so check it.
    let days = days_from_civil(year, month, day);
    let next = if month == 12 {
        days_from_civil(year + 1, 1, 1)
    } else {
        days_from_civil(year, month + 1, 1)
    };
    if days_from_civil(year, month, 1) + day > next {
        return None;
    }
    let unix = days * 86_400 + hour * 3600 + minute * 60 + second.min(59) - offset;
    // `time::rfc3339` formats only 1970 to 9999 here, so a value outside that range would be a
    // 500 later; refuse it now so it is a 422.
    (0..=MAX_UNIX_SECS).contains(&unix).then_some(unix)
}

/// The text of the comment on an open issue. `@` is followed by a zero-width space, so the
/// reason cannot mention a GitHub user or team.
fn comment_text(username: &str, reason: &str) -> String {
    let text = if reason.is_empty() {
        format!("Risk accepted by {username}.")
    } else {
        format!("Risk accepted by {username}: {reason}")
    };
    text.replace('@', "@\u{200b}")
}

/// The audit target for a CVE on a source: the route id.
fn audit_target(source_id: &str, cve_id: &str) -> String {
    format!("cve:{source_id}:{cve_id}")
}

async fn owned_source(
    pool: &SqlitePool,
    user_id: &str,
    source_id: &str,
) -> Result<SourceRow, AppError> {
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    source_db::find_owned(&mut conn, user_id, source_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Begins a `BEGIN IMMEDIATE` transaction, so the check for an active acceptance and the
/// insert cannot interleave with a second writer (see `services::oidc::begin_sign_in`).
async fn begin(pool: &SqlitePool) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, AppError> {
    pool.begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)
}

/// `POST /api/v1/cves/:id/accept` for the owner of the source.
///
/// - `404` for a malformed id, a source the caller does not own, or a CVE the source has
///   no finding for.
/// - `422` for a reason over 1000 characters, an `expires_at` that is not an
///   RFC 3339 time, or one that is not in the future.
/// - One transaction: an expired but unrevoked acceptance of the CVE is revoked first, with
///   `revoked_by` the caller, and audited as `cve.unaccept` (`{"reason":"expired",
///   "system":true}`). Then `409` when an active acceptance exists, else the insert and a
///   `cve.accept` audit row.
/// - After the commit, an open `github_issues` row gets a comment. That step is best effort:
///   a failure is logged as fixed text and does not undo the acceptance. The issue stays open.
pub async fn accept<G: IssueApi>(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    gh: &G,
    caller: &Caller<'_>,
    id: &str,
    input: AcceptInput,
    now: i64,
) -> Result<Acceptance, AppError> {
    let (source_id, requested) = split_id(id)?;
    let source = owned_source(pool, caller.id, source_id).await?;
    // #337: an alias in the id names the record of its primary id.
    let primary = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        crate::db::findings::primary_id(&mut conn, requested).await?
    };
    let cve_id = primary.as_str();

    let reason = input.reason.trim();
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(AppError::ValidationFailed(format!(
            "The reason can have at most {MAX_REASON_CHARS} characters."
        )));
    }
    let expires_at = match input.expires_at.as_deref() {
        None => None,
        Some(text) => {
            let at = parse_rfc3339(text).ok_or_else(|| {
                AppError::ValidationFailed(
                    "expires_at must be an RFC 3339 date-time, such as 2026-11-02T09:30:00Z."
                        .to_owned(),
                )
            })?;
            if at <= now {
                return Err(AppError::ValidationFailed(
                    "expires_at must be in the future.".to_owned(),
                ));
            }
            Some(at)
        }
    };

    let actor = caller.actor();
    let target = audit_target(&source.id, cve_id);
    let new_id = ids::new_id()?;
    // Read before the write lock, so a 404 does not take it.
    {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        if issue_db::findings_for_cve(&mut conn, &source.id, cve_id)
            .await?
            .is_empty()
        {
            return Err(AppError::NotFound);
        }
    }
    let mut tx = begin(pool).await?;
    for expired in acceptance_db::expired_unrevoked(&mut tx, &source.id, cve_id, now).await? {
        acceptance_db::revoke(&mut tx, &expired, caller.id, now).await?;
        audit::record(
            &mut tx,
            &actor,
            "cve.unaccept",
            &target,
            Some(&serde_json::json!({"reason": "expired", "system": true})),
        )
        .await?;
    }
    let already = || AppError::Conflict("This CVE is already accepted.".to_owned());
    if acceptance_db::active(&mut tx, &source.id, cve_id, now)
        .await?
        .is_some()
    {
        return Err(already());
    }
    let stored = acceptance_db::insert(
        &mut tx,
        &NewAcceptance {
            id: &new_id,
            source_id: &source.id,
            cve_id,
            reason,
            created_by: caller.id,
            created_by_username: caller.username,
            created_at: now,
            expires_at,
        },
    )
    .await?;
    if !stored {
        return Err(already());
    }
    audit::record(
        &mut tx,
        &actor,
        "cve.accept",
        &target,
        Some(&serde_json::json!({
            "cve_id": cve_id,
            "source_id": source.id,
            "expires_at": expires_at.map(time::rfc3339).transpose()?,
        })),
    )
    .await?;
    let row = acceptance_db::active(&mut tx, &source.id, cve_id, now)
        .await?
        .ok_or(AppError::InternalError)?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;

    comment_on_open_issue(
        pool,
        credentials_key,
        gh,
        &source,
        cve_id,
        &comment_text(caller.username, reason),
        now,
    )
    .await;
    Acceptance::from_row(row)
}

/// Adds the acceptance comment to the CVE's issue when its row is open. It never closes the
/// issue. Every failure is swallowed after one fixed-text log line, because the acceptance is
/// already committed.
async fn comment_on_open_issue<G: IssueApi>(
    pool: &SqlitePool,
    credentials_key: &DerivedKey,
    gh: &G,
    source: &SourceRow,
    cve_id: &str,
    text: &str,
    now: i64,
) {
    let sent = async {
        let (row, credential) = {
            let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
            let row = issue_db::find(&mut conn, &source.github_owner, &source.github_repo, cve_id)
                .await?;
            let credential =
                credential_db::find_owned(&mut conn, &source.user_id, &source.github_cred_id)
                    .await?;
            (row, credential)
        };
        let Some(row) = row.filter(|row| row.status == "open") else {
            return Ok(false);
        };
        let credential = credential.ok_or(AppError::NotFound)?;
        let number = u64::try_from(row.github_issue_number).map_err(|_| AppError::InternalError)?;
        let token = decrypt_token(credentials_key, &credential)?;
        gh.comment(
            &token,
            &source.github_owner,
            &source.github_repo,
            number,
            text,
            now,
        )
        .await
        .map_err(|_| AppError::UpstreamUnreachable)?;
        Ok::<bool, AppError>(true)
    }
    .await;
    if sent.is_err() {
        tracing::warn!("the acceptance comment on the GitHub issue failed; the acceptance stands");
    }
}

/// `POST /api/v1/cves/:id/unaccept` for the owner of the source. `404` when the id is
/// malformed, the source is not the caller's, or no acceptance is active. Soft revoke with
/// `revoked_by` the caller, audited as `cve.unaccept` (`{"reason":"manual"}`). No GitHub call.
pub async fn unaccept(
    pool: &SqlitePool,
    caller: &Caller<'_>,
    id: &str,
    now: i64,
) -> Result<(), AppError> {
    let (source_id, requested) = split_id(id)?;
    let source = owned_source(pool, caller.id, source_id).await?;
    // #337: an alias in the id names the record of its primary id.
    let primary = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        crate::db::findings::primary_id(&mut conn, requested).await?
    };
    let cve_id = primary.as_str();
    let mut tx = begin(pool).await?;
    let active = acceptance_db::active(&mut tx, &source.id, cve_id, now)
        .await?
        .ok_or(AppError::NotFound)?;
    if !acceptance_db::revoke(&mut tx, &active.id, caller.id, now).await? {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &caller.actor(),
        "cve.unaccept",
        &audit_target(&source.id, cve_id),
        Some(&serde_json::json!({"reason": "manual"})),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;

    use super::*;
    use crate::api::admin::test_support::{seed_github, seed_source, seed_user, test_state};
    use crate::api::state::AppState;
    use crate::db;
    use crate::services::issue_lifecycle::test_support::{FakeGithub, FakeIssues};

    const CVE: &str = "CVE-2026-0001";
    const ID: &str = "m1:CVE-2026-0001";
    const NOW: i64 = 1_000_000;

    struct Fixture {
        state: AppState,
        dir: std::path::PathBuf,
        github: Arc<FakeGithub>,
        gh: FakeIssues,
    }

    impl Fixture {
        async fn new(name: &str) -> Self {
            let (state, dir) = test_state(&format!("accept-{name}")).await;
            for id in ["u1", "u2", "u9"] {
                seed_user(&state.pool, id, "user").await;
            }
            seed_github(&state.pool, "u1", "cg", "github").await;
            seed_source(&state.pool, "u1", "m1", "cg", "octo", "app").await;
            let mut conn = state.pool.acquire().await.unwrap();
            db::findings::upsert(
                &mut conn,
                &db::findings::Finding {
                    id: &ids::new_id().unwrap_or_default(),
                    source_id: "m1",
                    image_tag: "v1",
                    cve_id: CVE,
                    package: Some("openssl"),
                    severity: "CRITICAL",
                    fixed_in_version: None,
                    description: None,
                    alias: None,
                    now: 10,
                },
            )
            .await
            .unwrap();
            drop(conn);
            let github = Arc::new(FakeGithub::default());
            Self {
                state,
                dir,
                github: github.clone(),
                gh: FakeIssues(github),
            }
        }

        async fn accept(
            &self,
            who: &str,
            id: &str,
            reason: &str,
            expires_at: Option<&str>,
        ) -> Result<Acceptance, AppError> {
            accept(
                &self.state.pool,
                &self.state.credentials_key,
                &self.gh,
                &Caller {
                    id: who,
                    username: who,
                },
                id,
                AcceptInput {
                    reason: reason.to_owned(),
                    expires_at: expires_at.map(str::to_owned),
                },
                NOW,
            )
            .await
        }

        async fn unaccept(&self, who: &str, id: &str, now: i64) -> Result<(), AppError> {
            unaccept(
                &self.state.pool,
                &Caller {
                    id: who,
                    username: who,
                },
                id,
                now,
            )
            .await
        }

        async fn count(&self, sql: &'static str) -> i64 {
            sqlx::query_scalar(sql)
                .fetch_one(&self.state.pool)
                .await
                .unwrap()
        }

        /// Stores a `github_issues` row for the CVE, and the issue in the fake GitHub.
        async fn issue(&self, status: &str) {
            let mut conn = self.state.pool.acquire().await.unwrap();
            db::github_issues::insert(
                &mut conn,
                &db::github_issues::NewIssue {
                    id: "gi1",
                    github_owner: "octo",
                    github_repo: "app",
                    cve_id: CVE,
                    github_issue_number: 1,
                    github_issue_url: "https://github.com/octo/app/issues/1",
                },
            )
            .await
            .unwrap();
            db::github_issues::set_status(&mut conn, "gi1", status)
                .await
                .unwrap();
            self.github.with(|s| {
                s.issues
                    .push(crate::services::issue_lifecycle::test_support::Issue {
                        number: 1,
                        body: String::new(),
                        open: status == "open",
                        title: String::new(),
                        labels: Vec::new(),
                    })
            });
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// #337: a request that names the GHSA id resolves to the CVE record, so the acceptance
    /// is stored under the CVE id and the unaccept by either id finds it.
    #[tokio::test]
    async fn accepting_by_the_ghsa_id_applies_to_the_cve_record() {
        let f = Fixture::new("ghsa").await;
        sqlx::query(
            "INSERT INTO vulnerability_aliases (alias, primary_id) VALUES ('GHSA-aaaa-bbbb-cccc', ?)",
        )
        .bind(CVE)
        .execute(&f.state.pool)
        .await
        .unwrap();

        let row = f
            .accept("u1", "m1:GHSA-aaaa-bbbb-cccc", "patched upstream", None)
            .await
            .unwrap();
        assert_eq!(row.cve_id, CVE);
        assert!(matches!(
            f.accept("u1", ID, "again", None).await,
            Err(AppError::Conflict(_))
        ));
        f.unaccept("u1", "m1:GHSA-aaaa-bbbb-cccc", NOW + 1)
            .await
            .unwrap();
        assert_eq!(
            f.count("SELECT COUNT(*) FROM cve_acceptances WHERE revoked_at IS NULL")
                .await,
            0
        );
    }

    #[tokio::test]
    async fn accept_unaccept_accept_again_succeeds() {
        let f = Fixture::new("cycle").await;

        let first = f
            .accept("u1", ID, "vendor patch is scheduled", None)
            .await
            .unwrap();
        f.unaccept("u1", ID, NOW + 1).await.unwrap();
        let again = f.accept("u1", ID, "accepted again", None).await.unwrap();

        assert_ne!(first.id, again.id);
        assert_eq!(first.cve_id, CVE);
        assert_eq!(first.created_by, "u1");
        assert_eq!(again.reason, "accepted again");
        // The soft revoke kept the first row.
        assert_eq!(f.count("SELECT COUNT(*) FROM cve_acceptances").await, 2);
        assert_eq!(
            f.count("SELECT COUNT(*) FROM cve_acceptances WHERE revoked_at IS NOT NULL AND revoked_by = 'u1'")
                .await,
            1
        );
        // Un-accepting twice finds nothing active the second time.
        f.unaccept("u1", ID, NOW + 2).await.unwrap();
        assert_eq!(
            f.unaccept("u1", ID, NOW + 3).await.unwrap_err(),
            AppError::NotFound
        );
    }

    #[tokio::test]
    async fn accepting_twice_is_409() {
        let f = Fixture::new("twice").await;
        f.accept("u1", ID, "first", None).await.unwrap();

        let second = f.accept("u1", ID, "second", None).await.unwrap_err();

        assert_eq!(second.status(), StatusCode::CONFLICT);
        assert_eq!(f.count("SELECT COUNT(*) FROM cve_acceptances").await, 1);
        assert_eq!(
            f.count("SELECT COUNT(*) FROM audit_log WHERE action = 'cve.accept'")
                .await,
            1
        );
        // An acceptance that has not expired yet still blocks.
        f.unaccept("u1", ID, NOW + 1).await.unwrap();
        f.accept("u1", ID, "future", Some("1970-02-01T00:00:00Z"))
            .await
            .unwrap();
        let blocked = f.accept("u1", ID, "again", None).await.unwrap_err();
        assert_eq!(blocked.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn expired_acceptance_is_system_revoked_by_the_new_accepter() {
        let f = Fixture::new("expired").await;
        // An old acceptance by another user, expired at 500 (before NOW) and never revoked.
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username, created_at, expires_at)
             VALUES ('old', 'm1', ?, 'old reason', 'u9', 'u9', 100, 500)",
        )
        .bind(CVE)
        .execute(&f.state.pool)
        .await
        .unwrap();

        let fresh = f.accept("u1", ID, "new reason", None).await.unwrap();

        let (revoked_at, revoked_by): (Option<i64>, Option<String>) =
            sqlx::query_as("SELECT revoked_at, revoked_by FROM cve_acceptances WHERE id = 'old'")
                .fetch_one(&f.state.pool)
                .await
                .unwrap();
        assert_eq!(revoked_at, Some(NOW));
        assert_eq!(
            revoked_by.as_deref(),
            Some("u1"),
            "the new accepter, not u9"
        );
        let (actor, target, details): (String, String, String) = sqlx::query_as(
            "SELECT actor_username, target, details FROM audit_log WHERE action = 'cve.unaccept'",
        )
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
        assert_eq!(actor, "u1");
        assert_eq!(target, "cve:m1:CVE-2026-0001");
        let details: serde_json::Value = serde_json::from_str(&details).unwrap();
        assert_eq!(
            details,
            serde_json::json!({"reason": "expired", "system": true})
        );
        // The new acceptance is the only active one.
        let active: i64 = f
            .count("SELECT COUNT(*) FROM cve_acceptances WHERE revoked_at IS NULL")
            .await;
        assert_eq!(active, 1);
        assert_eq!(fresh.reason, "new reason");
    }

    #[tokio::test]
    async fn empty_reason_is_allowed_and_a_past_expiry_is_422() {
        let f = Fixture::new("validation").await;
        let exactly = "x".repeat(1000);
        let cases: [Option<&str>; 4] = [
            Some("1970-01-01T00:00:00Z"),
            Some("1970-01-12T13:46:40Z"), // exactly NOW: not in the future
            Some("not a date"),
            Some("2026-02-30T00:00:00Z"),
        ];
        for expires_at in cases {
            let error = f.accept("u1", ID, "reason", expires_at).await.unwrap_err();
            assert_eq!(
                error.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "expires_at {expires_at:?}"
            );
        }
        assert_eq!(f.count("SELECT COUNT(*) FROM cve_acceptances").await, 0);
        assert_eq!(f.count("SELECT COUNT(*) FROM audit_log").await, 0);

        // The limits themselves are accepted: 1000 characters, and one second ahead.
        f.accept("u1", ID, &exactly, Some("1970-01-12T13:46:41Z"))
            .await
            .unwrap();
        let stored: Option<i64> = sqlx::query_scalar("SELECT expires_at FROM cve_acceptances")
            .fetch_one(&f.state.pool)
            .await
            .unwrap();
        assert_eq!(stored, Some(NOW + 1));
    }

    #[tokio::test]
    async fn accept_with_an_empty_note_succeeds() {
        let f = Fixture::new("empty-note").await;
        for note in ["", "   "] {
            let accepted = f.accept("u1", ID, note, None).await.unwrap();
            assert_eq!(accepted.reason, "");
            f.unaccept("u1", ID, NOW + 1).await.unwrap();
        }
        let stored: String = sqlx::query_scalar("SELECT reason FROM cve_acceptances LIMIT 1")
            .fetch_one(&f.state.pool)
            .await
            .unwrap();
        assert_eq!(stored, "");
    }

    #[tokio::test]
    async fn a_note_over_1000_characters_is_refused() {
        let f = Fixture::new("long-note").await;
        let error = f
            .accept("u1", ID, &"x".repeat(1001), None)
            .await
            .unwrap_err();
        assert_eq!(error.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(f.count("SELECT COUNT(*) FROM cve_acceptances").await, 0);
    }

    #[tokio::test]
    async fn detail_shows_the_active_acceptance_note_and_who_and_when() {
        let f = Fixture::new("detail-note").await;
        f.accept("u1", ID, "vendor patch is scheduled", None)
            .await
            .unwrap();
        let reader = crate::services::cves::Reader {
            user_id: "u1",
            is_admin: false,
        };
        let detail = crate::services::cves::detail(&f.state.pool, &reader, ID, NOW + 1)
            .await
            .unwrap();
        let acceptance = detail.acceptance.unwrap();
        assert_eq!(acceptance.reason, "vendor patch is scheduled");
        assert_eq!(acceptance.created_by, "u1");
        assert_eq!(
            acceptance.created_at.as_deref(),
            Some(time::rfc3339(NOW).unwrap().as_str())
        );
    }

    #[tokio::test]
    async fn un_accept_makes_the_cve_active_again_and_audits_it() {
        let f = Fixture::new("unaccept-active").await;
        f.accept("u1", ID, "", None).await.unwrap();
        let reader = crate::services::cves::Reader {
            user_id: "u1",
            is_admin: false,
        };
        let before = crate::services::cves::detail(&f.state.pool, &reader, ID, NOW + 1)
            .await
            .unwrap();
        assert!(before.summary.accepted);

        f.unaccept("u1", ID, NOW + 2).await.unwrap();

        let after = crate::services::cves::detail(&f.state.pool, &reader, ID, NOW + 3)
            .await
            .unwrap();
        assert!(!after.summary.accepted);
        assert!(after.acceptance.is_none());
        let audited = f
            .count("SELECT COUNT(*) FROM audit_log WHERE action = 'cve.unaccept' AND actor_username = 'u1'")
            .await;
        assert_eq!(audited, 1);
    }

    #[tokio::test]
    async fn accept_comments_on_open_issue_and_does_not_close_it() {
        let f = Fixture::new("comment").await;
        f.issue("open").await;

        f.accept("u1", ID, "patched next sprint", None)
            .await
            .unwrap();

        let writes = f.github.writes();
        assert_eq!(
            writes.len(),
            1,
            "one comment and nothing else: {}",
            writes.len()
        );
        let (method, path, body) = &writes[0];
        assert_eq!(*method, "POST");
        assert_eq!(path, "repos/octo/app/issues/1/comments");
        assert_eq!(body["body"], "Risk accepted by u1: patched next sprint");
        assert!(f.github.with(|s| s.issues[0].open), "the issue stays open");
        let status: String = sqlx::query_scalar("SELECT status FROM github_issues")
            .fetch_one(&f.state.pool)
            .await
            .unwrap();
        assert_eq!(status, "open");
    }

    #[tokio::test]
    async fn a_github_failure_or_a_closed_issue_does_not_change_the_acceptance() {
        // No issue row: no GitHub call.
        let none = Fixture::new("no-issue").await;
        none.accept("u1", ID, "no issue yet", None).await.unwrap();
        assert_eq!(none.github.requests(), 0);

        // A closed issue is not commented on.
        let closed = Fixture::new("closed-issue").await;
        closed.issue("closed").await;
        closed
            .accept("u1", ID, "closed already", None)
            .await
            .unwrap();
        assert_eq!(closed.github.requests(), 0);

        // A refused token on an open issue: the acceptance still stands.
        let refused = Fixture::new("refused").await;
        refused.issue("open").await;
        refused.github.with(|s| s.unauthorized = true);
        refused
            .accept("u1", ID, "github is down", None)
            .await
            .unwrap();
        assert_eq!(refused.github.requests(), 1);
        assert_eq!(
            refused
                .count("SELECT COUNT(*) FROM cve_acceptances WHERE revoked_at IS NULL")
                .await,
            1
        );
        assert!(refused.github.with(|s| s.issues[0].open));

        // Un-accept makes no GitHub call.
        let unaccept_only = Fixture::new("unaccept-no-github").await;
        unaccept_only.issue("open").await;
        unaccept_only.accept("u1", ID, "r", None).await.unwrap();
        let before = unaccept_only.github.requests();
        unaccept_only.unaccept("u1", ID, NOW + 1).await.unwrap();
        assert_eq!(unaccept_only.github.requests(), before);
    }

    #[tokio::test]
    async fn accept_and_unaccept_are_audited() {
        let f = Fixture::new("audit").await;

        f.accept("u1", ID, "kept private", Some("1970-02-01T00:00:00Z"))
            .await
            .unwrap();
        f.unaccept("u1", ID, NOW + 1).await.unwrap();

        let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT action, actor_username, target, details FROM audit_log ORDER BY rowid",
        )
        .fetch_all(&f.state.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "cve.accept");
        assert_eq!(rows[1].0, "cve.unaccept");
        for row in &rows {
            assert_eq!(row.1, "u1");
            assert_eq!(row.2, "cve:m1:CVE-2026-0001");
        }
        let accept: serde_json::Value =
            serde_json::from_str(rows[0].3.as_deref().unwrap()).unwrap();
        assert_eq!(
            accept,
            serde_json::json!({
                "cve_id": CVE,
                "source_id": "m1",
                "expires_at": "1970-02-01T00:00:00Z",
            })
        );
        let unaccept: serde_json::Value =
            serde_json::from_str(rows[1].3.as_deref().unwrap()).unwrap();
        assert_eq!(unaccept, serde_json::json!({"reason": "manual"}));
        // The reason is free text and stays out of the audit log.
        assert!(
            rows.iter()
                .all(|row| !row.3.as_deref().unwrap_or("").contains("kept private"))
        );
    }

    #[tokio::test]
    async fn foreign_unknown_and_malformed_ids_are_404() {
        let f = Fixture::new("not-found").await;
        for (who, id) in [
            ("u2", ID),
            ("u1", "m1:CVE-2026-9999"),
            ("u1", "m2:CVE-2026-0001"),
            ("u1", "no-colon"),
            ("u1", "m1:"),
            ("u1", "m1:CVE 2026"),
        ] {
            let accept = f.accept(who, id, "reason", None).await.unwrap_err();
            assert_eq!(accept, AppError::NotFound, "accept {who} {id:?}");
            let unaccept = f.unaccept(who, id, NOW).await.unwrap_err();
            assert_eq!(unaccept, AppError::NotFound, "unaccept {who} {id:?}");
        }
        assert_eq!(f.count("SELECT COUNT(*) FROM cve_acceptances").await, 0);
    }

    #[test]
    fn rfc3339_parsing() {
        // The reference instant 2001-09-09T01:46:40Z, written in several ways.
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2001-09-09T01:46:40Z"), Some(1_000_000_000));
        assert_eq!(parse_rfc3339("2001-09-09t01:46:40z"), Some(1_000_000_000));
        assert_eq!(
            parse_rfc3339("2001-09-09T01:46:40.123Z"),
            Some(1_000_000_000)
        );
        assert_eq!(
            parse_rfc3339("2001-09-09T03:46:40+02:00"),
            Some(1_000_000_000)
        );
        assert_eq!(
            parse_rfc3339("2001-09-09T07:16:40+05:30"),
            Some(1_000_000_000)
        );
        assert_eq!(
            parse_rfc3339("2001-09-08T20:16:40-05:30"),
            Some(1_000_000_000)
        );
        // Second 60 (a leap second) is clamped to 59.
        assert_eq!(
            parse_rfc3339("2001-09-09T01:46:60Z"),
            Some(1_000_000_000 + 19)
        );
        // Leap days: only a real leap year has February 29.
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        assert_eq!(parse_rfc3339("2100-02-29T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("1900-02-29T00:00:00Z"), None);
        // The range the formatter can write back: 1970-01-01 to 9999-12-31T23:59:59Z.
        assert_eq!(parse_rfc3339("9999-12-31T23:59:59Z"), Some(MAX_UNIX_SECS));
        assert_eq!(
            parse_rfc3339("9999-12-31T23:59:59+01:00"),
            Some(MAX_UNIX_SECS - 3600)
        );
        assert_eq!(parse_rfc3339("9999-12-31T23:59:59-01:00"), None);
        assert_eq!(parse_rfc3339("1969-12-31T23:59:59Z"), None);
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00+01:00"), None);
        assert_eq!(parse_rfc3339("0000-01-01T00:00:00Z"), None);
        // Every value that parses can be formatted again.
        assert!(time::rfc3339(MAX_UNIX_SECS).is_ok());
        assert!(time::rfc3339(MAX_UNIX_SECS + 1).is_err());
        // Length: 40 characters is the most accepted, 41 is refused.
        let forty = format!("2001-09-09T01:46:40.{}Z", "0".repeat(19));
        assert_eq!(forty.len(), 40);
        assert_eq!(parse_rfc3339(&forty), Some(1_000_000_000));
        let long = format!("2001-09-09T01:46:40.{}Z", "0".repeat(20));
        assert_eq!(long.len(), 41);
        let non_ascii = "2001-09-09T01:46:40\u{e9}\u{e9}\u{e9}";
        for bad in [
            "",
            "2001-09-09",
            "2001-09-09 01:46:40Z",
            "2001-09-09T01:46:40",
            "2001-13-09T01:46:40Z",
            "2001-00-09T01:46:40Z",
            "2001-09-00T01:46:40Z",
            "2001-02-29T01:46:40Z",
            "2001-04-31T01:46:40Z",
            "2001-09-09T24:00:00Z",
            "2001-09-09T24:46:40Z",
            "2001-09-09T01:60:40Z",
            "2001-09-09T01:46:61Z",
            "2001-09-09T01:46:40+0200",
            "2001-09-09T01:46:40.Z",
            "2001-09-09T01:46:40+24:00",
            "2001-09-09T01:46:40+02:60",
            // Signs and other characters in the offset digits.
            "2001-09-09T01:46:40++5:30",
            "2001-09-09T01:46:40+-5:30",
            "2001-09-09T01:46:40-+5:30",
            "2001-09-09T01:46:40--5:30",
            "2001-09-09T01:46:40+05:+5",
            "2001-09-09T01:46:40+05:-5",
            "2001-09-09T01:46:40+0a:30",
            "2001-09-09T01:46:40+05;30",
            // Signs in the date and time digits.
            "+001-09-09T01:46:40Z",
            "2001-+9-09T01:46:40Z",
            "2001-09-09T+1:46:40Z",
            // Too long (41 characters), and non-ASCII.
            long.as_str(),
            "2001-09-09T01:46:40ZZ",
            non_ascii,
        ] {
            assert_eq!(parse_rfc3339(bad), None, "input of {} bytes", bad.len());
        }
    }

    #[tokio::test]
    async fn an_expiry_past_year_9999_is_422_not_500() {
        let f = Fixture::new("year-overflow").await;

        for text in ["9999-12-31T23:59:59-01:00", "9999-12-31T23:59:59-23:59"] {
            let error = f.accept("u1", ID, "reason", Some(text)).await.unwrap_err();
            assert_eq!(error.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        assert_eq!(f.count("SELECT COUNT(*) FROM cve_acceptances").await, 0);
        assert_eq!(f.count("SELECT COUNT(*) FROM audit_log").await, 0);

        // The last instant that can be written back is accepted and answers with it.
        let last = f
            .accept("u1", ID, "reason", Some("9999-12-31T23:59:59Z"))
            .await
            .unwrap();
        assert_eq!(last.expires_at.as_deref(), Some("9999-12-31T23:59:59Z"));
    }

    #[test]
    fn the_comment_cannot_mention_a_user() {
        let text = comment_text("alice", "ask @bob and @org/team");
        assert!(!text.contains("@b") && !text.contains("@o"));
        assert!(text.starts_with("Risk accepted by alice: "));
    }
}
