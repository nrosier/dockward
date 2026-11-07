-- no-transaction
-- Several mappings may target one GitHub repository (#185, decided 2026-11-06). Drops
-- UNIQUE (github_owner, github_repo) from repo_mappings. The Harbor uniqueness
-- UNIQUE (harbor_base_url, harbor_project, harbor_repository) and every other column and
-- constraint stay as in 0001. Existing rows are copied unchanged.
--
-- SQLite cannot drop a UNIQUE constraint in place, so the table is rebuilt. sync_jobs,
-- sync_reports, cve_findings and cve_acceptances reference repo_mappings with ON DELETE
-- CASCADE: with foreign keys on, DROP TABLE would delete their rows. Foreign keys are
-- therefore switched off for the rebuild, which SQLite only allows outside a transaction,
-- hence "no-transaction" above and the explicit BEGIN and COMMIT. This is the procedure in
-- https://www.sqlite.org/lang_altertable.html ("Making Other Kinds Of Table Schema Changes").
-- repo_mappings has no explicit indexes, triggers or views to recreate; its autoindexes come
-- from the UNIQUE constraints in the new definition.
PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE repo_mappings_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harbor_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    github_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    harbor_base_url TEXT NOT NULL,
    harbor_project TEXT NOT NULL,
    harbor_repository TEXT NOT NULL,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    webhook_token_hash TEXT UNIQUE NOT NULL,
    webhook_auth_secret_hash TEXT NOT NULL,
    auto_create_issues BOOLEAN DEFAULT FALSE,
    min_issue_severity TEXT DEFAULT 'CRITICAL' CHECK (min_issue_severity IN ('CRITICAL', 'HIGH')),
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at INTEGER DEFAULT (unixepoch()),
    -- One mapping per Harbor repository per Harbor instance. No constraint on the GitHub
    -- target (#185).
    UNIQUE (harbor_base_url, harbor_project, harbor_repository)
);

INSERT INTO repo_mappings_new
    (id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project,
     harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash,
     auto_create_issues, min_issue_severity, default_branch, created_at)
SELECT id, user_id, harbor_cred_id, github_cred_id, harbor_base_url, harbor_project,
       harbor_repository, github_owner, github_repo, webhook_token_hash, webhook_auth_secret_hash,
       auto_create_issues, min_issue_severity, default_branch, created_at
FROM repo_mappings;

DROP TABLE repo_mappings;
ALTER TABLE repo_mappings_new RENAME TO repo_mappings;

COMMIT;

PRAGMA foreign_keys = ON;
