//! Pure rules for the admin health route (`specs/api.md`, Health). The route handler in
//! `api/admin.rs` runs the probes and passes the answers here. This module makes no
//! network call and reads no database, so it never sees a token.
//!
//! Sources: `specs/api.md` (Health), `specs/security.md` ("GitHub token scope"),
//! `specs/integrations.md` (robot expiry).

use serde::Serialize;

use crate::error::AppError;
use crate::services::credential_probe::{
    self, Check, CodeScanningState, GithubResponse, ISSUES_PERMISSION_MISSING,
};
use crate::services::time;

/// Seconds in one day, for `days_left`.
const SECS_PER_DAY: i64 = 86_400;

/// One check row: `{"credential_id","label","ok","reachable","missing_permissions",
/// "code_scanning","target","detail"}` (`specs/api.md`, Health). Holds no token.
#[derive(Serialize)]
pub struct HealthCheck {
    pub credential_id: String,
    pub label: String,
    pub ok: bool,
    pub reachable: bool,
    pub missing_permissions: Vec<&'static str>,
    pub code_scanning: Option<&'static str>,
    pub target: Option<String>,
    pub detail: String,
}

/// One Harbor credential's robot expiry.
#[derive(Serialize)]
pub struct RobotAccount {
    pub credential_id: String,
    pub label: String,
    pub expires_at: Option<String>,
    pub days_left: Option<i64>,
}

/// The health body without the `request` block, which the handler adds.
#[derive(Serialize)]
pub struct HealthReport {
    pub harbor: Vec<HealthCheck>,
    pub github: Vec<HealthCheck>,
    pub robot_accounts: Vec<RobotAccount>,
}

/// The three GitHub answers for one mapping target. Each is the probe's own result, so
/// a transport failure (`UpstreamUnreachable`) is kept apart from a status code.
pub struct GithubAnswers {
    pub repo: Result<GithubResponse, AppError>,
    pub code_scanning: Result<GithubResponse, AppError>,
    pub issues: Result<GithubResponse, AppError>,
}

/// Builds the Harbor check for one credential from its probe result. `UpstreamUnreachable`
/// means Harbor did not answer. Any other error is returned unchanged.
pub fn harbor_health(
    credential_id: &str,
    label: &str,
    outcome: Result<Check, AppError>,
) -> Result<HealthCheck, AppError> {
    match outcome {
        Ok(check) => Ok(HealthCheck {
            credential_id: credential_id.to_owned(),
            label: label.to_owned(),
            ok: check.ok,
            reachable: true,
            missing_permissions: Vec::new(),
            code_scanning: None,
            target: None,
            detail: check.detail,
        }),
        Err(AppError::UpstreamUnreachable) => Ok(HealthCheck {
            credential_id: credential_id.to_owned(),
            label: label.to_owned(),
            ok: false,
            reachable: false,
            missing_permissions: Vec::new(),
            code_scanning: None,
            target: None,
            detail: "Harbor did not answer".to_owned(),
        }),
        Err(other) => Err(other),
    }
}

/// Builds the GitHub check for one mapping target from its three probe answers
/// (`specs/security.md`, "GitHub token scope"). Any `UpstreamUnreachable` makes the
/// target unreachable. Any other error is returned unchanged.
pub fn github_health(
    credential_id: &str,
    label: &str,
    owner: &str,
    repo: &str,
    answers: GithubAnswers,
) -> Result<HealthCheck, AppError> {
    let target = Some(format!("{owner}/{repo}"));
    let (repo_response, scanning, issues) =
        match (answers.repo, answers.code_scanning, answers.issues) {
            (Ok(repo_response), Ok(scanning), Ok(issues)) => (repo_response, scanning, issues),
            (repo_result, scanning_result, issues_result) => {
                for failure in [
                    repo_result.err(),
                    scanning_result.err(),
                    issues_result.err(),
                ]
                .into_iter()
                .flatten()
                {
                    if failure != AppError::UpstreamUnreachable {
                        return Err(failure);
                    }
                }
                return Ok(HealthCheck {
                    credential_id: credential_id.to_owned(),
                    label: label.to_owned(),
                    ok: false,
                    reachable: false,
                    missing_permissions: Vec::new(),
                    code_scanning: None,
                    target,
                    detail: "GitHub did not answer".to_owned(),
                });
            }
        };

    let repo_check = credential_probe::github_repo_check(&repo_response);
    let scanning_check = credential_probe::github_code_scanning_check(&scanning);
    let issues_check = credential_probe::github_issues_check(&issues);
    let scanning_state = credential_probe::code_scanning_state(&scanning);

    let mut missing_permissions = Vec::new();
    if repo_response.status == 403 {
        missing_permissions.push("metadata");
    }
    if scanning.status == 403 && scanning_state == CodeScanningState::Failed {
        missing_permissions.push("code_scanning_alerts");
    }
    if issues_check.warning == Some(ISSUES_PERMISSION_MISSING) {
        missing_permissions.push("issues");
    }

    let code_scanning = match scanning_state {
        CodeScanningState::Ready => Some("ok"),
        CodeScanningState::NoAnalysisYet => Some("no_analysis_yet"),
        CodeScanningState::Unavailable => Some("unavailable"),
        CodeScanningState::Failed => None,
    };
    let ok = repo_check.ok
        && scanning_check.ok
        && issues_check.ok
        && issues_check.warning.is_none()
        && missing_permissions.is_empty();
    let detail = if ok {
        String::new()
    } else {
        [&repo_check, &scanning_check, &issues_check]
            .into_iter()
            .filter(|check| !check.ok || check.warning.is_some())
            .map(|check| check.detail.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    };

    Ok(HealthCheck {
        credential_id: credential_id.to_owned(),
        label: label.to_owned(),
        ok,
        reachable: true,
        missing_permissions,
        code_scanning,
        target,
        detail,
    })
}

/// Whole days until `expires_at`, rounded up: `ceil((expires_at - now) / 86400)`.
/// A value at or before `now` gives `0` or less.
pub fn days_left(expires_at: i64, now: i64) -> i64 {
    let remaining = expires_at.saturating_sub(now);
    remaining
        .saturating_add(SECS_PER_DAY - 1)
        .div_euclid(SECS_PER_DAY)
}

/// Builds the robot account entry for one Harbor credential. `expires_at` and `days_left`
/// are `null` when the credential has no expiry.
pub fn robot_account(
    credential_id: &str,
    label: &str,
    expires_at: Option<i64>,
    now: i64,
) -> Result<RobotAccount, AppError> {
    let expires_text = expires_at.map(time::rfc3339).transpose()?;
    Ok(RobotAccount {
        credential_id: credential_id.to_owned(),
        label: label.to_owned(),
        expires_at: expires_text,
        days_left: expires_at.map(|at| days_left(at, now)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gh(status: u16, message: &str, needed: Option<&str>) -> GithubResponse {
        GithubResponse {
            status,
            message: message.to_owned(),
            accepted_permissions: needed.map(str::to_owned),
        }
    }

    fn answers(
        repo: GithubResponse,
        scanning: GithubResponse,
        issues: GithubResponse,
    ) -> GithubAnswers {
        GithubAnswers {
            repo: Ok(repo),
            code_scanning: Ok(scanning),
            issues: Ok(issues),
        }
    }

    #[test]
    fn code_scanning_states_map_to_api_values() {
        // 200 is ready, 404 "no analysis found" is healthy, and a disabled 403 is unavailable.
        let cases = [
            (gh(200, "", None), Some("ok"), true),
            (
                gh(404, "no analysis found", None),
                Some("no_analysis_yet"),
                true,
            ),
            (
                gh(
                    403,
                    "Code scanning is not enabled for this repository.",
                    Some("security_events=read"),
                ),
                Some("unavailable"),
                false,
            ),
        ];
        for (scanning, expected, ok) in cases {
            let check = github_health(
                "g-1",
                "github",
                "octo",
                "app",
                answers(gh(200, "", None), scanning, gh(200, "", None)),
            )
            .unwrap();
            assert_eq!(check.code_scanning, expected);
            assert_eq!(check.ok, ok);
            // A disabled feature is not a missing permission.
            assert!(check.missing_permissions.is_empty());
        }
    }

    #[test]
    fn issues_403_lists_issues_as_missing() {
        let check = github_health(
            "g-1",
            "github",
            "octo",
            "app",
            answers(
                gh(200, "", None),
                gh(404, "no analysis found", None),
                gh(
                    403,
                    "Resource not accessible by personal access token",
                    Some("issues=read"),
                ),
            ),
        )
        .unwrap();
        assert_eq!(check.missing_permissions, vec!["issues"]);
        // The issues warning makes the target not ok, but the target is still reachable.
        assert!(!check.ok);
        assert!(check.reachable);
        assert!(check.detail.contains("Issues permission"));
        assert_eq!(check.target.as_deref(), Some("octo/app"));
    }

    #[test]
    fn upstream_unreachable_sets_reachable_false() {
        let harbor = harbor_health("h-1", "harbor", Err(AppError::UpstreamUnreachable)).unwrap();
        assert!(!harbor.reachable);
        assert!(!harbor.ok);
        assert_eq!(harbor.detail, "Harbor did not answer");
        assert_eq!(harbor.code_scanning, None);
        assert_eq!(harbor.target, None);

        let github = github_health(
            "g-1",
            "github",
            "octo",
            "app",
            GithubAnswers {
                repo: Ok(gh(200, "", None)),
                code_scanning: Err(AppError::UpstreamUnreachable),
                issues: Ok(gh(200, "", None)),
            },
        )
        .unwrap();
        assert!(!github.reachable);
        assert!(!github.ok);
        assert_eq!(github.code_scanning, None);
    }

    #[test]
    fn other_probe_errors_are_returned() {
        let outcome = harbor_health("h-1", "harbor", Err(AppError::InternalError));
        assert_eq!(outcome.err(), Some(AppError::InternalError));
    }

    #[test]
    fn harbor_answer_is_reachable_and_carries_the_probe_result() {
        let check = Check {
            name: "harbor_robot",
            ok: true,
            detail: "the robot account credential works".to_owned(),
            warning: None,
        };
        let health = harbor_health("h-1", "harbor", Ok(check)).unwrap();
        assert!(health.reachable);
        assert!(health.ok);
        assert_eq!(health.detail, "the robot account credential works");
    }

    /// Seeds two Harbor credentials for two users, and checks that `report` yields one
    /// Harbor check per credential, with its id and label. No socket is opened.
    #[tokio::test]
    async fn one_harbor_check_per_harbor_credential() {
        use crate::api::admin::report;
        use crate::api::admin::test_support as fake;

        let (state, dir) = fake::test_state("one-harbor").await;
        fake::seed_user(&state.pool, "u-a", "user").await;
        fake::seed_user(&state.pool, "u-b", "user").await;
        fake::seed_harbor(&state.pool, "u-a", "h-a", "harbor a", None).await;
        fake::seed_harbor(&state.pool, "u-b", "h-b", "harbor b", None).await;

        let harbor = fake::FixedHarbor(412);
        let github = fake::FixedGithub::default();
        let result = report(&state, &harbor, &github, 1_000_000).await.unwrap();
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        let ids: Vec<&str> = result
            .harbor
            .iter()
            .map(|check| check.credential_id.as_str())
            .collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(ids.contains(&"h-a") && ids.contains(&"h-b"), "{ids:?}");
        assert!(
            result
                .harbor
                .iter()
                .all(|check| check.reachable && check.ok)
        );
        assert!(result.harbor.iter().all(|check| check.target.is_none()));
        assert_eq!(result.robot_accounts.len(), 2);
    }

    /// Seeds two mappings with two different GitHub targets, and checks that `report`
    /// yields one GitHub check per mapping target, probed with that target's path.
    #[tokio::test]
    async fn one_github_check_per_mapping_target() {
        use crate::api::admin::report;
        use crate::api::admin::test_support as fake;

        let (state, dir) = fake::test_state("one-github").await;
        fake::seed_user(&state.pool, "u-a", "user").await;
        fake::seed_harbor(&state.pool, "u-a", "h-1", "harbor", None).await;
        fake::seed_harbor(&state.pool, "u-a", "h-2", "harbor two", None).await;
        fake::seed_github(&state.pool, "u-a", "g-1", "github").await;
        fake::seed_mapping(&state.pool, "u-a", "m-1", "h-1", "g-1", "octo", "app").await;
        fake::seed_mapping(&state.pool, "u-a", "m-2", "h-2", "g-1", "octo", "lib").await;

        let harbor = fake::FixedHarbor(412);
        let github = fake::FixedGithub::default();
        let result = report(&state, &harbor, &github, 1_000_000).await.unwrap();
        let calls = github.calls.lock().unwrap().clone();
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(result.github.len(), 2);
        let targets: Vec<Option<&str>> = result
            .github
            .iter()
            .map(|check| check.target.as_deref())
            .collect();
        assert_eq!(targets, vec![Some("octo/app"), Some("octo/lib")]);
        assert!(
            result
                .github
                .iter()
                .all(|check| check.credential_id == "g-1")
        );
        // Three probes per target, in order: repository, code scanning, issues.
        assert_eq!(calls.len(), 6, "{calls:?}");
        assert_eq!(calls[0], "repos/octo/app");
        assert_eq!(calls[3], "repos/octo/lib");
    }

    #[test]
    fn robot_accounts_have_days_left_and_null_without_expiry() {
        let now = 1_000_000;
        let none = robot_account("r-1", "no expiry", None, now).unwrap();
        assert_eq!(none.expires_at, None);
        assert_eq!(none.days_left, None);

        let ten_days =
            robot_account("r-2", "ten days", Some(now + 10 * SECS_PER_DAY), now).unwrap();
        assert_eq!(ten_days.days_left, Some(10));
        assert_eq!(ten_days.expires_at.as_deref(), Some("1970-01-22T13:46:40Z"));

        // Any part of a day counts as a whole day, so the value rounds up.
        let just_over =
            robot_account("r-3", "over", Some(now + 10 * SECS_PER_DAY + 1), now).unwrap();
        assert_eq!(just_over.days_left, Some(11));
        let one_second = robot_account("r-4", "soon", Some(now + 1), now).unwrap();
        assert_eq!(one_second.days_left, Some(1));
    }
}
