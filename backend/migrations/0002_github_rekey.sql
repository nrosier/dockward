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
