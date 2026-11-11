-- GitHub re-key bookkeeping (#311, slice 4). Records what the one-time re-key of HarborGate
-- GitHub data has done, so it runs once per repository and is safe to re-run.
-- GitHub owner and repository names are case-insensitive, so both keys use NOCASE.
-- Timestamps are integer unix seconds, as in 0001_init.sql.

-- One row per repository once its issues have been re-keyed (label renamed, old issues adopted).
CREATE TABLE IF NOT EXISTS issue_rekeys (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    label_result TEXT NOT NULL CHECK (label_result IN ('renamed', 'absent', 'kept')),
    issues_rekeyed INTEGER NOT NULL CHECK (issues_rekeyed >= 0),
    completed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (github_owner, github_repo)
);

-- One row per repository and legacy SARIF category once its old HarborGate analyses have been
-- retired (dismissals carried over, old analyses deleted).
CREATE TABLE IF NOT EXISTS analysis_retirements (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    legacy_category TEXT NOT NULL,
    analyses_deleted INTEGER NOT NULL CHECK (analyses_deleted >= 0),
    dismissals_carried INTEGER NOT NULL CHECK (dismissals_carried >= 0),
    completed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (github_owner, github_repo, legacy_category)
);

-- The carry-over plan of one repository and legacy category, written before the first delete
-- (#311 slice 6b). A retry reads it instead of recomputing from analyses that may be gone. One
-- row per rule that is carried; `applied` is set once that dismissal has been written.
CREATE TABLE IF NOT EXISTS alert_carryovers (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    legacy_category TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    comment TEXT,
    planned_at INTEGER NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)),
    PRIMARY KEY (github_owner, github_repo, legacy_category, rule_id)
);

-- The refs the legacy analyses ran on, recorded with the plan so a retry uses the same set even
-- after the analyses are deleted (#311 slice 6b).
CREATE TABLE IF NOT EXISTS carryover_refs (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    legacy_category TEXT NOT NULL,
    git_ref TEXT NOT NULL,
    PRIMARY KEY (github_owner, github_repo, legacy_category, git_ref)
);
