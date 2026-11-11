//! Retires the old HarborGate Code Scanning analyses (#311 slice 6b, `specs/integrations.md`,
//! "GitHub SARIF and issues").
//!
//! The rename uploads under a new tool and category, so the analyses of the old category stay in
//! Code Scanning. This runs once per source and legacy category, after this publish's own upload
//! reached `complete`. Two steps, in this order:
//!
//! 1. Carry dismissals over. The old HarborGate alerts of the legacy category are grouped by rule
//!    id, across the refs. A group is clear when every old alert in it is dismissed with the same
//!    reason. Each open new Dockward alert of the new category with that rule id is dismissed with
//!    that reason and the first old comment. A mixed group is left alone. Every carry-over write
//!    happens before the first delete.
//! 2. Delete. The HarborGate analyses of exactly the legacy category that GitHub reports as
//!    deletable are deleted, newest first, on every ref. Each delete is confirmed by following
//!    `confirm_delete_url` until it returns null. The list is read again and repeated until no
//!    deletable analysis of the category remains.
//!
//! Every write waits one second after the write before it. The run stops with `Incomplete` once
//! more than [`MAX_WAIT`] (the publish budget) has passed since `started`. Only a clean pass stores
//! the `analysis_retirements` row and writes the audit row. Any other outcome leaves no row, so the
//! next publish runs the step again. Confirm links are followed only through the guarded GitHub
//! client, on the configured API host (`github_scanning::follow_confirm_with`).
//!
//! Logs carry fixed text only. The token and GitHub's response bodies never reach a log, an audit
//! row or an error string.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::json;
use sqlx::SqlitePool;

use crate::db::github_rekeys;
use crate::db::sources::SourceRow;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::github_scanning::{
    Alert, AlertQuery, Analysis, DISMISSAL_REASONS, Dismissal, ScanError,
};
use crate::services::publish::{Clock, CodeScanning, MAX_WAIT};
use crate::services::sarif::{self, LEGACY_TOOL_NAME, TOOL_NAME};

/// The audit action of a completed retirement (`services/audit.rs`, `ACTIONS`).
pub const AUDIT_ACTION: &str = "github.retire_analyses";

/// The pause before each write except the first, so the retirement stays under GitHub's
/// secondary rate limits.
const PAUSE: Duration = Duration::from_secs(1);

/// The most passes of list-then-delete before the step gives up. A pass deletes every deletable
/// analysis it lists, so a second pass sees only what GitHub refused to remove.
const MAX_PASSES: usize = 50;

/// The most confirm-delete steps one analysis may take before the step gives up.
const MAX_CONFIRM_STEPS: usize = 10;

/// The fixed log text when GitHub refuses the token or the request (401, 403).
const REFUSED_LOG: &str = "GitHub refused the legacy analysis retirement; remove the GitHub configuration from the tool status page";
/// The fixed log text when GitHub is rate limiting.
const RATE_LIMITED_LOG: &str =
    "GitHub rate limit reached while retiring legacy analyses; the next publish retries";
/// The fixed log text when the step cannot finish.
const INCOMPLETE_LOG: &str =
    "the legacy analyses could not all be retired; the next publish retries";

/// How one [`retire`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireOutcome {
    /// A row already exists for the repository and legacy category, so nothing was called.
    AlreadyDone,
    /// Every step succeeded. `deleted` is the number of analyses removed and `carried` the
    /// number of dismissals written to the new alerts.
    Completed { deleted: u32, carried: u32 },
    /// A call failed or the budget ran out. No row was written.
    Incomplete,
    /// GitHub is rate limiting. The step stopped and no row was written.
    RateLimited { until: i64 },
    /// GitHub refused the token or the request. The step stopped and no row was written.
    Refused,
}

/// An early exit from the steps: the outcome that ends the run.
type Flow<T> = Result<T, RetireOutcome>;

/// Maps a GitHub error to the outcome that ends the run. Rate limits and refused tokens stop the
/// run with their own outcome; any other failure is `Incomplete`.
fn halt(error: &ScanError) -> RetireOutcome {
    match error {
        ScanError::RateLimited { until } => RetireOutcome::RateLimited { until: *until },
        ScanError::Unauthorized | ScanError::Forbidden(_) => RetireOutcome::Refused,
        _ => RetireOutcome::Incomplete,
    }
}

/// Converts a GitHub result into a [`Flow`].
fn check<T>(result: Result<T, ScanError>) -> Flow<T> {
    result.map_err(|error| halt(&error))
}

/// The state of one run: the GitHub client, the clock, the repository and the pacing.
struct Run<'a, G, C> {
    gh: &'a G,
    clock: &'a C,
    token: &'a [u8],
    owner: &'a str,
    repo: &'a str,
    started: i64,
    /// True once a write has been made, so the next write waits [`PAUSE`] first.
    wrote: bool,
}

impl<G: CodeScanning, C: Clock> Run<'_, G, C> {
    /// Stops the run once more than the publish budget has passed since it started.
    fn within_budget(&self) -> Flow<()> {
        let elapsed = self.clock.now().saturating_sub(self.started);
        let budget = i64::try_from(MAX_WAIT.as_secs()).unwrap_or(i64::MAX);
        if elapsed > budget {
            Err(RetireOutcome::Incomplete)
        } else {
            Ok(())
        }
    }

    /// Waits before a write, except the first, and checks the budget.
    async fn before_write(&mut self) -> Flow<()> {
        if self.wrote {
            self.clock.sleep(PAUSE).await;
        }
        self.wrote = true;
        self.within_budget()
    }

    /// The HarborGate analyses of this repository, all pages.
    async fn legacy_analyses(&self) -> Flow<Vec<Analysis>> {
        self.within_budget()?;
        check(
            self.gh
                .list_analyses(
                    self.token,
                    self.owner,
                    self.repo,
                    LEGACY_TOOL_NAME,
                    self.clock.now(),
                )
                .await,
        )
    }

    /// The alerts of one tool, state and ref, all pages.
    async fn alerts(&self, tool: &str, state: &str, git_ref: &str) -> Flow<Vec<Alert>> {
        self.within_budget()?;
        let query = AlertQuery {
            tool_name: tool,
            state,
            git_ref,
        };
        check(
            self.gh
                .list_alerts(self.token, self.owner, self.repo, query, self.clock.now())
                .await,
        )
    }

    /// Dismisses one new alert.
    async fn dismiss(&mut self, number: u64, reason: &str, comment: Option<&str>) -> Flow<()> {
        self.before_write().await?;
        let dismissal = Dismissal { reason, comment };
        check(
            self.gh
                .dismiss_alert(
                    self.token,
                    self.owner,
                    self.repo,
                    number,
                    dismissal,
                    self.clock.now(),
                )
                .await,
        )
    }

    /// Deletes one analysis, then follows its confirm-delete links until none is returned.
    async fn delete_chain(&mut self, id: u64) -> Flow<()> {
        self.before_write().await?;
        let mut next = check(
            self.gh
                .delete_analysis(self.token, self.owner, self.repo, id, self.clock.now())
                .await,
        )?;
        let mut steps = 0usize;
        while let Some(path) = next {
            steps += 1;
            if steps > MAX_CONFIRM_STEPS {
                return Err(RetireOutcome::Incomplete);
            }
            self.before_write().await?;
            next = check(
                self.gh
                    .follow_confirm(self.token, &path, self.clock.now())
                    .await,
            )?;
        }
        Ok(())
    }
}

/// Whether a category reported by GitHub is `want`. A trailing `/` is ignored, because the new
/// SARIF category is written with one and GitHub may echo it either way.
fn same_category(reported: Option<&str>, want: &str) -> bool {
    reported.map(|text| text.trim_end_matches('/')) == Some(want)
}

/// Dismisses the new open alerts whose rule has a clear old group. Returns the number of
/// dismissals written. Every write here happens before any delete.
async fn carry_over<G: CodeScanning, C: Clock>(
    run: &mut Run<'_, G, C>,
    refs: &[String],
    legacy: &str,
    new: &str,
) -> Flow<u32> {
    // The old alerts of the legacy category, grouped by rule id, open and dismissed alike.
    let mut old: BTreeMap<String, Vec<Alert>> = BTreeMap::new();
    for git_ref in refs {
        for state in ["open", "dismissed"] {
            for alert in run.alerts(LEGACY_TOOL_NAME, state, git_ref).await? {
                if same_category(alert.category.as_deref(), legacy) {
                    old.entry(alert.rule_id.clone()).or_default().push(alert);
                }
            }
        }
    }

    // A clear group: every old alert is dismissed, and all with the same reason.
    let mut plan: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
    for (rule, alerts) in &old {
        let Some(reason) = alerts[0].dismissed_reason.clone() else {
            continue;
        };
        if !DISMISSAL_REASONS.contains(&reason.as_str()) {
            continue;
        }
        let same = alerts.iter().all(|alert| {
            alert.state == "dismissed" && alert.dismissed_reason.as_deref() == Some(reason.as_str())
        });
        if same {
            plan.insert(rule.clone(), (reason, alerts[0].dismissed_comment.clone()));
        }
    }
    if plan.is_empty() {
        return Ok(0);
    }

    // Only open new alerts are dismissed, so an already-dismissed one is skipped. An alert that
    // appears under two refs is dismissed once.
    let mut done: BTreeSet<u64> = BTreeSet::new();
    let mut carried = 0u32;
    for git_ref in refs {
        for alert in run.alerts(TOOL_NAME, "open", git_ref).await? {
            if alert.state != "open" || !same_category(alert.category.as_deref(), new) {
                continue;
            }
            let Some((reason, comment)) = plan.get(&alert.rule_id) else {
                continue;
            };
            if !done.insert(alert.number) {
                continue;
            }
            run.dismiss(alert.number, reason, comment.as_deref())
                .await?;
            carried += 1;
        }
    }
    Ok(carried)
}

/// Deletes the deletable analyses of the legacy category, on every ref, until none remain.
/// Returns the number of analyses removed.
async fn delete_legacy<G: CodeScanning, C: Clock>(
    run: &mut Run<'_, G, C>,
    legacy: &str,
) -> Flow<u32> {
    let mut deleted = 0u32;
    for _ in 0..MAX_PASSES {
        let mut candidates: Vec<Analysis> = run
            .legacy_analyses()
            .await?
            .into_iter()
            .filter(|analysis| {
                analysis.tool_name.as_deref() == Some(LEGACY_TOOL_NAME)
                    && analysis.category.as_deref() == Some(legacy)
                    && analysis.deletable
            })
            .collect();
        if candidates.is_empty() {
            return Ok(deleted);
        }
        // Newest first. GitHub sends `created_at` as ISO 8601, so text order is time order.
        candidates.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        for analysis in &candidates {
            run.delete_chain(analysis.id).await?;
            deleted += 1;
        }
    }
    Err(RetireOutcome::Incomplete)
}

/// The two steps, in order. Returns `(deleted, carried)`.
async fn steps<G: CodeScanning, C: Clock>(
    run: &mut Run<'_, G, C>,
    git_ref: &str,
    legacy: &str,
    new: &str,
) -> Flow<(u32, u32)> {
    // The refs to check: every ref the legacy analyses ran on, and the ref this publish uploaded.
    let mut refs: BTreeSet<String> = run
        .legacy_analyses()
        .await?
        .into_iter()
        .filter(|analysis| same_category(analysis.category.as_deref(), legacy))
        .filter_map(|analysis| analysis.git_ref)
        .collect();
    refs.insert(git_ref.to_owned());
    let refs: Vec<String> = refs.into_iter().collect();

    let carried = carry_over(run, &refs, legacy, new).await?;
    let deleted = delete_legacy(run, legacy).await?;
    Ok((deleted, carried))
}

/// Retires the legacy analyses of one source's repository and legacy category. See the module
/// docs. `git_ref` is the full ref this publish uploaded to. `started` is the Unix time the step
/// began, and the budget is measured from it. `Err` is a database failure.
pub async fn retire<G: CodeScanning, C: Clock>(
    pool: &SqlitePool,
    gh: &G,
    clock: &C,
    token: &[u8],
    source: &SourceRow,
    git_ref: &str,
    started: i64,
) -> Result<RetireOutcome, AppError> {
    let owner = source.github_owner.as_str();
    let repo = source.github_repo.as_str();
    let legacy = sarif::legacy_category(&source.hub_host, &source.repository, &source.tag_value);
    if github_rekeys::analyses_done(pool, owner, repo, &legacy).await? {
        return Ok(RetireOutcome::AlreadyDone);
    }
    // The new category has no trailing `/`, as the legacy one has none.
    let new_with_slash =
        sarif::automation_id(&source.hub_host, &source.repository, &source.tag_value);
    let new = new_with_slash.trim_end_matches('/');

    let mut run = Run {
        gh,
        clock,
        token,
        owner,
        repo,
        started,
        wrote: false,
    };
    let (deleted, carried) = match steps(&mut run, git_ref, &legacy, new).await {
        Ok(counts) => counts,
        Err(outcome) => {
            log_outcome(outcome);
            return Ok(outcome);
        }
    };

    // Two writes, each on its own pooled connection: the row, then the audit row. They are not
    // one transaction, as in the issue re-key. A failure between them leaves the row without the
    // audit row, and the next publish returns `AlreadyDone`.
    github_rekeys::insert_analyses_done(pool, owner, repo, &legacy, deleted, carried, clock.now())
        .await?;
    let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
    audit::record(
        &mut conn,
        &Actor::system(),
        AUDIT_ACTION,
        &format!("{owner}/{repo}"),
        Some(&json!({"analyses": deleted, "dismissals": carried})),
    )
    .await?;
    Ok(RetireOutcome::Completed { deleted, carried })
}

/// Logs the fixed text for an outcome that ended the run without a row.
fn log_outcome(outcome: RetireOutcome) {
    match outcome {
        RetireOutcome::Refused => tracing::warn!("{REFUSED_LOG}"),
        RetireOutcome::RateLimited { .. } => tracing::warn!("{RATE_LIMITED_LOG}"),
        RetireOutcome::Incomplete => tracing::warn!("{INCOMPLETE_LOG}"),
        RetireOutcome::AlreadyDone | RetireOutcome::Completed { .. } => {}
    }
}

#[cfg(test)]
mod tests;
