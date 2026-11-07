# Database

Purpose: schema reference for SQLite and the decisions behind each table.

## Source of truth

- `backend/migrations/0001_init.sql` is the schema reference. The schema below is the design. The migration must match it.
- SQLx SQLite with WAL mode. Use `SqlitePool`.
- Source for SQLite behaviour used below: SQLite foreign key documentation (https://www.sqlite.org/foreignkeys.html) and CREATE TABLE / CREATE INDEX documentation (https://www.sqlite.org/lang_createtable.html, https://www.sqlite.org/lang_createindex.html).
- Foreign key enforcement is OFF by default in SQLite (verified against the SQLite foreign key documentation). Every connection must run `PRAGMA foreign_keys = ON`. Verified (2026-11-03): SQLx's `SqliteConnectOptions` sets `foreign_keys = ON` by default (`sqlx-sqlite/src/options/mod.rs`). The implementation still sets it explicitly, so a change in that default cannot switch enforcement off. The SQLite bundled by `libsqlite3-sys` is 3.54.1 (verified (2026-11-03)), which is newer than the 3.38.0 that `unixepoch()` needs (SQLite 3.38.0 release notes).
- In SQLite, NULL values are distinct for UNIQUE constraints (verified, SQLite CREATE TABLE documentation). A UNIQUE constraint on a nullable column does not stop multiple NULL rows.

## Schema

```sql
-- System Configuration (OIDC, App Settings)
-- Decided (2026-11-03, delegated) keys are listed under "system_config keys" below.
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE,
    updated_at INTEGER DEFAULT (unixepoch())
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT, -- Argon2id PHC string; NULL for OIDC-only users. See security.md.
    role TEXT NOT NULL DEFAULT 'user', -- 'admin' | 'user'
    auth_provider TEXT NOT NULL DEFAULT 'local', -- 'local' | 'oidc'
    oidc_issuer TEXT,  -- Decided (2026-11-03, delegated): issuer URL that asserted this user; NULL for local users
    oidc_subject TEXT, -- Decided (2026-11-03, delegated): OIDC `sub` claim; NULL for local users
    token_version INTEGER NOT NULL DEFAULT 0, -- Decided (2026-11-03): session revocation counter. See security.md, Sessions.
    created_at INTEGER DEFAULT (unixepoch()),
    -- Decided (2026-11-03, delegated): sub is locally unique and never reassigned within an issuer (OpenID Connect Core 1.0, section 2).
    -- NULLs are distinct, so local users (both columns NULL) do not collide.
    UNIQUE (oidc_issuer, oidc_subject)
);

-- Service Credentials (Encrypted)
CREATE TABLE IF NOT EXISTS user_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_type TEXT NOT NULL, -- 'harbor' | 'github'
    label TEXT NOT NULL,
    base_url TEXT,  -- Harbor credentials only. HTTPS. See integrations.md.
    username TEXT,  -- Decided (2026-11-03, delegated): Harbor robot account name (for example robot$<name>). NULL for GitHub credentials.
    encrypted_token TEXT NOT NULL, -- "v1:" ciphertext. See security.md, "Ciphertext format".
    expires_at INTEGER, -- Decided (2026-11-03, delegated): Harbor robot expiry. NULL for GitHub credentials unless the operator records one.
    created_at INTEGER DEFAULT (unixepoch())
);

-- Repository Mappings
CREATE TABLE IF NOT EXISTS repo_mappings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harbor_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    github_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    harbor_base_url TEXT NOT NULL, -- Decided (2026-11-03): normalized copy of the Harbor credential's base_url; part of the Harbor uniqueness key
    harbor_project TEXT NOT NULL,
    harbor_repository TEXT NOT NULL,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    webhook_token_hash TEXT UNIQUE NOT NULL, -- Decided (2026-11-03): SHA-256 hex of the URL path token (base64url, >= 256 bits). The token is not stored. See integrations.md.
    webhook_auth_secret_hash TEXT NOT NULL, -- Decided (2026-11-03): SHA-256 hex of the auth header secret; the secret is shown once and not stored
    auto_create_issues BOOLEAN DEFAULT FALSE,
    min_issue_severity TEXT DEFAULT 'CRITICAL' CHECK (min_issue_severity IN ('CRITICAL', 'HIGH')), -- Decided (2026-11-03, delegated) CHECK: integrations.md allows only CRITICAL or HIGH
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at INTEGER DEFAULT (unixepoch()),
    -- Scheduled scan (#191, migration 0008). Times are UTC.
    scan_schedule TEXT NOT NULL DEFAULT 'off' CHECK (scan_schedule IN ('off', 'daily', 'weekly')),
    scan_minute INTEGER NOT NULL DEFAULT 0 CHECK (scan_minute BETWEEN 0 AND 1439), -- minute of the UTC day
    scan_weekday INTEGER NOT NULL DEFAULT 1 CHECK (scan_weekday BETWEEN 1 AND 7), -- ISO weekday, weekly only
    scan_last_slot INTEGER, -- Unix seconds of the last slot handled; set to the save time when the schedule changes
    UNIQUE (harbor_base_url, harbor_project, harbor_repository) -- one mapping per Harbor repository per Harbor instance. No constraint on the GitHub target (Decided 2026-11-06, user, #185). default_branch sets the SARIF upload branch only.
);

-- Sync Jobs (durable queue for webhook-triggered syncs and polling)
-- payload must never contain tokens or header secrets
-- Created before sync_reports because sync_reports references it.
CREATE TABLE IF NOT EXISTS sync_jobs (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER,
    last_error TEXT,
    payload TEXT NOT NULL, -- JSON: validated event, no secrets; "kind" absent = sync, "resolve" = digest fan-out
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
);

-- Sync Reports & Logs (one row per processed image digest and tag)
CREATE TABLE IF NOT EXISTS sync_reports (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL, -- links the report to the job that produced it
    harbor_repository TEXT NOT NULL,
    image_tag TEXT NOT NULL,
    image_digest TEXT NOT NULL, -- Harbor artifact digest, for example sha256:<hex>
    commit_sha TEXT,
    vulnerability_summary TEXT NOT NULL, -- JSON string: {"critical": 0, "high": 2, ...}
    sarif_status TEXT NOT NULL, -- 'pending' | 'success' | 'failed'
    github_sarif_id TEXT,
    error_message TEXT,
    synced_at INTEGER DEFAULT (unixepoch()),
    image_push_time INTEGER, -- migration 0006 (#196)
    cve_ids TEXT, -- migration 0008 (#191): JSON array of the scan's distinct CVE ids, set on success
    new_cve_ids TEXT -- migration 0008 (#191): JSON array of ids not in the digest's last result; scheduled scans only
);
CREATE INDEX IF NOT EXISTS idx_sync_reports_digest
    ON sync_reports (mapping_id, harbor_repository, image_tag, image_digest, sarif_status);

-- Harbor scanners seen by HarborGate (#224, migration 0009). Names and versions for display only.
-- Decided (2026-11-07, user, #224 d12): the Harbor scanner registration UUID is the key; the name is shown.
CREATE TABLE IF NOT EXISTS harbor_scanners (
    harbor_base_url TEXT NOT NULL, -- normalized, as in repo_mappings.harbor_base_url
    uuid TEXT NOT NULL,            -- Harbor scanner registration uuid
    name TEXT NOT NULL,
    vendor TEXT,
    version TEXT,
    disabled INTEGER NOT NULL DEFAULT 0,
    last_seen_at INTEGER NOT NULL, -- Unix seconds of the last successful read that listed it
    removed_at INTEGER,            -- set when a complete scanner list no longer has it
    PRIMARY KEY (harbor_base_url, uuid)
);

-- One stored report per (mapping, image digest, scanner). A new scan by the same scanner replaces the row
-- and its findings in one transaction (Decided 2026-11-07, user, #224 d2, d9). No run history is kept.
CREATE TABLE IF NOT EXISTS scanner_reports (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    image_digest TEXT NOT NULL,
    scanner_uuid TEXT NOT NULL,    -- a Harbor registration uuid, or the literal 'unknown' (see "Decisions")
    scanner_name TEXT,             -- snapshot from the report's scanner object; NULL for 'unknown'
    scanner_vendor TEXT,
    scanner_version TEXT,
    image_push_time INTEGER,       -- Unix milliseconds, as sync_reports.image_push_time (#196)
    stored_at INTEGER NOT NULL,    -- Unix seconds; the retention clock
    UNIQUE (mapping_id, image_digest, scanner_uuid)
);

-- The findings of one stored report, one row per (CVE id, package).
CREATE TABLE IF NOT EXISTS scanner_findings (
    report_id TEXT NOT NULL REFERENCES scanner_reports(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL DEFAULT '', -- '' when the scanner gives no package; the merge key uses it as is
    version TEXT,
    fixed_in_version TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    cvss_v3 REAL,                    -- preferred_cvss.score_v3, for the SARIF security-severity
    description TEXT,                -- at most 4,000 characters, as cve_findings.description
    PRIMARY KEY (report_id, cve_id, package)
);

-- One scanner switch per Harbor project at a time (Decided 2026-11-07, user, #224 d11). Rules: backend.md.
CREATE TABLE IF NOT EXISTS project_scanner_locks (
    harbor_base_url TEXT NOT NULL,
    harbor_project TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES sync_jobs(id) ON DELETE CASCADE, -- the job that holds the lock
    mapping_id TEXT REFERENCES repo_mappings(id) ON DELETE SET NULL, -- whose credential the restore uses
    chosen_scanner_uuid TEXT NOT NULL,
    previous_scanner_uuid TEXT,      -- NULL when Harbor reported none; nothing to restore then
    state TEXT NOT NULL CHECK (state IN ('switched', 'restore_pending')),
    acquired_at INTEGER NOT NULL,
    wait_started_at INTEGER,         -- Unix seconds of the first report poll; the 5-minute ceiling counts from it
    PRIMARY KEY (harbor_base_url, harbor_project)
);
CREATE INDEX IF NOT EXISTS idx_scanner_reports_digest ON scanner_reports (mapping_id, image_digest);

-- Tracked GitHub Issues (one open or closed issue per repo and CVE)
-- Rows are never deleted by tag cleanup or retention. The rows are owned by the single mapping for that GitHub repository. A mapping delete removes them. See "Decisions".
CREATE TABLE IF NOT EXISTS github_issues (
    id TEXT PRIMARY KEY,
    sync_report_id TEXT REFERENCES sync_reports(id) ON DELETE SET NULL, -- the report that created the issue; nullable
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    github_issue_number INTEGER NOT NULL,
    github_issue_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at INTEGER DEFAULT (unixepoch()),
    -- one row per (repo, cve_id); the single mapping for the repo owns it (Decided 2026-11-03)
    UNIQUE (github_owner, github_repo, cve_id)
);

-- CVE Findings
-- one row per (mapping_id, harbor_repository, image_tag, cve_id)
-- "accepted" is not stored here. It is derived from cve_acceptances. See "Decisions".
CREATE TABLE IF NOT EXISTS cve_findings (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    harbor_repository TEXT NOT NULL,
    image_tag TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    fixed_in_version TEXT, -- Decided (2026-11-03, delegated): Harbor vulnerability item fixed_version; NULL when unknown
    description TEXT, -- Decided (2026-11-03, user, #35): Harbor vulnerability item description, at most 4,000 characters; NULL when absent. Added by migrations/0002_cve_description.sql
    first_seen_at INTEGER DEFAULT (unixepoch()),
    last_seen_at INTEGER DEFAULT (unixepoch()),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed')), -- stored states only
    github_issue_id TEXT REFERENCES github_issues(id) ON DELETE SET NULL, -- pointer to the (repo, cve) issue
    UNIQUE (mapping_id, harbor_repository, image_tag, cve_id)
);

-- CVE Acceptances (accepted risk, applies to the whole mapping)
CREATE TABLE IF NOT EXISTS cve_acceptances (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL, -- Decided (2026-11-03, delegated): SET NULL (was NOT NULL without ON DELETE) so user deletion works
    created_by_username TEXT NOT NULL, -- Decided (2026-11-03, delegated): snapshot so attribution survives user deletion
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER,
    revoked_at INTEGER,  -- Decided (2026-11-03, delegated): soft revoke (un-accept)
    revoked_by TEXT REFERENCES users(id) ON DELETE SET NULL, -- Decided (2026-11-03, delegated)
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
-- Decided (2026-11-03, delegated): at most one active acceptance per mapping and CVE.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_acceptances_active
    ON cve_acceptances (mapping_id, cve_id) WHERE revoked_at IS NULL;

-- Audit Log (admin and security-relevant actions)
-- details must never contain tokens or key material
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL, -- Decided (2026-11-03, delegated): SET NULL so user deletion works
    actor_username TEXT NOT NULL, -- Decided (2026-11-03, delegated): snapshot of the actor's username at write time
    action TEXT NOT NULL, -- one value from the "Audit action vocabulary" below
    target TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    details TEXT -- JSON
);

-- Alert Channels (admin-configured SMTP and webhook destinations)
-- Decided (2026-11-03, delegated). Alert scope is Decided (2026-11-03): all tenants, admin-owned channels. See alerts.md.
CREATE TABLE IF NOT EXISTS alert_channels (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('smtp', 'webhook')),
    config_encrypted TEXT NOT NULL, -- "v1:" ciphertext of the JSON config (host, port, user, password, URL, and so on)
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Job Runs (housekeeping run history for the admin Jobs tab)
-- Decided 2026-11-03. Holds counts and error text only, never secrets.
-- Kept 90 days, like sync_reports.
CREATE TABLE IF NOT EXISTS job_runs (
    id TEXT PRIMARY KEY,
    job_kind TEXT NOT NULL CHECK (job_kind IN ('cleanup', 'retention', 'poll')),
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    status TEXT NOT NULL CHECK (status IN ('done', 'failed')),
    processed_count INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT -- NULL when status is 'done'; error text only, never secrets
);

-- Alert Deliveries (24-hour dedupe log)
-- Decided (2026-11-03, delegated). The 24-hour window is enforced by checking sent_at. See "Decisions".
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
    dedupe_key TEXT NOT NULL, -- CVE id for new CRITICAL CVE alerts; sync_failed:<sync_job_id> for sync failures (see alerts.md)
    sent_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (channel_id, dedupe_key)
);

-- Project Webhooks (one Harbor webhook per Harbor base URL and project, #132)
-- Decided 2026-11-05. Holds the owner and the digests of the project token and secret. The values are shown once and never stored in plain text.
CREATE TABLE IF NOT EXISTS project_webhooks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- owner; the user-deletion hook transfers it first (integrations.md)
    harbor_base_url TEXT NOT NULL,
    harbor_project TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    rotated_at INTEGER, -- NULL until the first rotation. No column default (Decided 2026-11-06, user, #145; migration 0005 drops the insert-time default)
    UNIQUE (harbor_base_url, harbor_project)
);

-- Project Webhook Unmatched (events for a repository no mapping on the project covers, counted per repository)
-- Decided 2026-11-05. No event body is stored.
CREATE TABLE IF NOT EXISTS project_webhook_unmatched (
    project_webhook_id TEXT NOT NULL REFERENCES project_webhooks(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (project_webhook_id, repository)
);

-- Picker Hidden Items (per-user hide list for the mapping pickers)
-- Decided (2026-11-05, user, #126): hidden items are keyed by Harbor base URL. A row is keyed by user, source, and the item's full name, and for harbor source also the Harbor base URL. Not built yet; needs its own migration.
-- A row changes only the user's own pickers. It never changes a mapping, a sync, or another user's view.
CREATE TABLE IF NOT EXISTS picker_hidden_items (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('harbor', 'github')),
    harbor_base_url TEXT, -- harbor: the credential's base_url the item was hidden on (user_credentials.base_url); NULL for github
    full_name TEXT NOT NULL, -- harbor: '<project>' or '<project>/<repository>'; github: '<owner>/<repo>' lowercased. See integrations.md, "Hide and restore".
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK ((source = 'harbor') = (harbor_base_url IS NOT NULL))
);
-- Uniqueness: one partial unique index per source. A plain UNIQUE over the nullable harbor_base_url would not stop duplicate github rows, because SQLite treats NULLs as distinct.
CREATE UNIQUE INDEX IF NOT EXISTS picker_hidden_items_harbor_key ON picker_hidden_items (user_id, harbor_base_url, full_name) WHERE source = 'harbor';
CREATE UNIQUE INDEX IF NOT EXISTS picker_hidden_items_github_key ON picker_hidden_items (user_id, full_name) WHERE source = 'github';
```

## system_config keys

Decided (2026-11-03, delegated). Each key is a row in `system_config`. Values are stored as TEXT.

- `oidc.issuer_url`: HTTPS issuer URL. `is_encrypted = 0`. Rules in [security.md](security.md).
- `oidc.client_id`: `is_encrypted = 0`.
- `oidc.client_secret_encrypted`: `is_encrypted = 1`. Value is a "v1:" ciphertext.
- `oidc.role_claim`: name of the claim that carries groups (for example `groups`). `is_encrypted = 0`.
- `oidc.admin_group`: group value that grants `admin`. `is_encrypted = 0`.
- `oidc.user_group`: group value that grants `user`. `is_encrypted = 0`.
- `github.api_base_url`: custom GitHub API base URL (Decided 2026-11-06, user, #184). Empty or missing means `https://api.github.com`. `is_encrypted = 0`. Rules in [integrations.md](integrations.md), "GitHub base URL".
- `github.web_url`: custom GitHub web URL (Decided 2026-11-06, user, #184). Empty or missing means `https://github.com`. `is_encrypted = 0`.
- `auth.oidc_only_users`: `true` or `false`; a missing row means `false`. `is_encrypted = 0`. The rule is in [security.md](security.md), "Local login" (Decided (2026-11-03)).

Source for the OIDC claim model: OpenID Connect Core 1.0 (https://openid.net/specs/openid-connect-core-1_0.html). The group claim name is operator-defined; OIDC Core does not define one.

## Audit action vocabulary

Decided (2026-11-03) for `restore.run`: the offline restore command appends one `audit_log` row with this action to the restored database, after it replaces the database. `details` holds the backup file name, the backup `created_at`, and the actor, recorded as `cli` (the operator running the command).

`audit_log.action` must be one of these values. Add a value here before writing it.

- `user.create`
- `user.delete`
- `user.role_change`
- `oidc.config_change`
- `credential.create`
- `credential.rotate` (token replacement)
- `credential.delete`
- `cve.accept`
- `cve.unaccept`
- `mapping.create`
- `mapping.update`
- `mapping.delete`
- `mapping.webhook_token_rotate`
- `mapping.auth_secret_rotate`
- `project_webhook.create`
- `project_webhook.token_rotate`
- `project_webhook.secret_rotate`
- `project_webhook.owner_transfer`
- `alert.config_change`
- `backup.run`
- `restore.run`
- `key.rotate`
- `retention.run`
- `sync_job.retry` (manual retry of a failed sync job; `details` is `{"job_id","mapping_id"}`; Decided (2026-11-03, delegated))
- `log.level_change` (application log level change; `details` is `{"old","new"}`, each one of `info`, `debug`, `trace`; target `log_level`; the automatic revert to `info` uses the actor `system`. Decided (2026-11-05, user, #136). The application log itself is an in-memory buffer and has no table; see [security.md](security.md), "Application log")
- `mapping.scan` (a scan of one tag started from the mapping page; `details` is `{"mapping_id","tag","scanner_uuid"}`, ids and the tag only; Decided (2026-11-07, delegated, #224))
- `mapping.pull` (manual scan pull from Harbor for one mapping; `details` is `{"mapping_id","queued"}`, the number of jobs queued, and no values; Decided (2026-11-05, user, #131))

No value is added for the mapping pickers (Decided 2026-11-05, #126, issue "Auditing"): listing, suggesting, hiding, and restoring write no audit row, because hiding is a user preference. A mapping saved from a picked value or a suggestion writes `mapping.create` or `mapping.update` as before.

Source: none external. The list follows the audit examples in [frontend.md](frontend.md) (Admin, Audit log) and the events in [security.md](security.md). The vocabulary is a local convention, so it is Decided (2026-11-03, delegated).

## Table decisions

- **Naming:** use `harbor_repository` everywhere for the Harbor repository. Do not add an image-named column for it.
- **Mapping:** one mapping per Harbor repository per Harbor instance. A GitHub repository may be the target of several mappings, each from a different Harbor repository (Decided 2026-11-06, user, #185). A mapping holds its own webhook token and auth header secret digests, GitHub owner, repo, and `default_branch` (default `main`).
- **Credentials:** `user_credentials.encrypted_token` is AES-256-GCM encrypted in the "v1:" format. Never store plaintext tokens.
- **Audit:** `audit_log.details` never contains tokens or key material. Every accept and un-accept is audited.
- **Sync jobs:** `sync_jobs.payload` holds the validated event only. It never contains tokens or header secrets.
- **Retention:** `sync_reports` and related logs (including `scanner_reports`, see Decisions) are kept 90 days. `sync_jobs` is kept 90 days (Decided 2026-11-03). `job_runs` is kept 90 days (Decided 2026-11-03). `alert_deliveries` is kept 30 days (Decided 2026-11-03). `audit_log` is kept 365 days. See [cve-lifecycle.md](cve-lifecycle.md) for the per-tag limit.
- Decided (2026-11-03, delegated): `CHECK` constraints on enumerated TEXT columns (`sync_jobs.status`, `github_issues.status`, `cve_findings.status` and `severity`, `repo_mappings.min_issue_severity`, `alert_channels.kind`, `job_runs.job_kind` and `job_runs.status`). Source: SQLite CREATE TABLE documentation, CHECK constraints (https://www.sqlite.org/lang_createtable.html). The index `idx_sync_reports_digest` is Decided (2026-11-03, delegated) for the polling dedupe lookup; no external source.
- Decided (2026-11-05, user, #129): showing, filtering and manually logging every severity needs no constraint change and no migration. `cve_findings.severity` already allows all five values (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), and the findings were always stored at every severity. `repo_mappings.min_issue_severity` keeps `CHECK (min_issue_severity IN ('CRITICAL', 'HIGH'))`, because it governs automatic issues only and the user decided automatic issues stay CRITICAL and HIGH. Manual logging at any severity reads no column that has a severity constraint, and the `github_issues` table has no severity column. The issue body of #129 assumed a constraint change; the decision recorded on the issue made it unnecessary.
- Decided (2026-11-05, user, #126): `picker_hidden_items` holds one row per user, source, and full name, and for harbor source also per Harbor base URL, enforced by the two partial unique indexes in the table definition; a repeated hide is a no-op that returns the existing row. Decided (2026-11-05, user, #126): a hidden Harbor name is hidden only on the Harbor base URL it was hidden on, so the table stores `harbor_base_url` (the credential's `base_url`, NULL for github source) and no credential id. The `CHECK` ties `harbor_base_url` to `source`. `ON DELETE CASCADE` on `user_id` removes a deleted user's rows (the user deletion order is unchanged, because no other table references this one); `source` has a `CHECK` like the other enumerated columns; the table is not covered by retention, because rows are user-managed and capped at 1,000 per user by the application ([integrations.md](integrations.md), "Hide and restore"). The table is included in backups like every other table. Picker lists themselves are never stored: the 5-minute cache is in memory.
- **Source for the 90 and 365 day values:** these are the user's decided retention rules, not external standards.

## Decisions

- Decided: 2026-11-02, changed 2026-11-03. The per-mapping auth header secret is stored only as a SHA-256 digest in `repo_mappings.webhook_auth_secret_hash` (TEXT NOT NULL), and the webhook token only as `repo_mappings.webhook_token_hash`. Both are shown once, are rotatable, and are never logged. See [integrations.md](integrations.md).
- Decided: 2026-11-02, changed 2026-11-03. One mapping per Harbor repository per Harbor instance, enforced with `UNIQUE (harbor_base_url, harbor_project, harbor_repository)` on `repo_mappings`, and no constraint on the GitHub target (Decided 2026-11-06, user, #185). Two tenants on different Harbor instances can map repositories with the same project and repository names. Decided (2026-11-03, delegated): `harbor_base_url` is copied from the Harbor credential on mapping create and update, normalized (lowercase scheme and host, no default port, no trailing slash). Changing a Harbor credential's `base_url` while a mapping uses it returns `409 conflict` ([api.md](api.md)).
- Decided (2026-11-03): timestamps. Every time column is `INTEGER` UTC Unix seconds, with defaults from `unixepoch()` (SQLite 3.38.0 or later; https://www.sqlite.org/lang_datefunc.html). Comparisons are numeric, for example `sent_at < unixepoch() - 86400`. No time is stored as text. The API formats times as RFC 3339 UTC strings ([api.md](api.md), Conventions).
- Decided: 2026-11-02. `github_issues` has `UNIQUE (github_owner, github_repo, cve_id)`, so only one row per repo and CVE can exist. The table has no repo id column, so `github_owner` and `github_repo` columns were added to it.
- Decided: `github_issues.sync_report_id` is nullable and uses `ON DELETE SET NULL`. Deleting a `sync_reports` row never deletes its issue row. Tag cleanup and retention never delete `github_issues` rows. This resolves the conflict between the old `ON DELETE CASCADE` and the rule in [cve-lifecycle.md](cve-lifecycle.md) that issues are not changed when tags are pruned.
- Decided: `cve_findings.github_issue_id` uses `ON DELETE SET NULL`. Every tracked tag row for one CVE in one mapping points to the same `github_issues` row for that repo and CVE. Deleting a tag's `cve_findings` rows does not affect the issue. The pointer is a convenience. The `(github_owner, github_repo, cve_id)` lookup is authoritative.
- Decided: `repo_mappings.harbor_cred_id` and `repo_mappings.github_cred_id` are NOT NULL, because the setup guide ([docs/SETUP.md](../docs/SETUP.md), section 5) requires both. They use `ON DELETE RESTRICT`. A credential in use cannot be deleted. The API returns a conflict error when a delete is blocked.
- Decided (2026-11-03, delegated): a credential must belong to the same user as the mapping that references it. The application checks this on write. Source: none external; follows the tenancy rule in [security.md](security.md) (users see only their own credentials).
- Decided (2026-11-03): Jobs tab storage is the `job_runs` table (see the schema above). It has `job_kind` (`cleanup`, `retention`, `poll`) and `status` (`done`, `failed`) with CHECK constraints. The table holds counts and error text only, never secrets.
- Decided: `sync_reports.sync_job_id` links each report to its job (nullable, `ON DELETE SET NULL`). The overall sync status is `sync_jobs.status`, not a column on this table (Decided 2026-11-03, see Decisions section).
- Decided: `sync_reports.image_digest` is NOT NULL. Polling skips an image whose digest already has a successful sync for that mapping and tag. "Successful" means `sync_jobs.status = 'done'` and `sarif_status = 'success'` on the linked report (Decided 2026-11-03, see Decisions section). Decided (2026-11-05, user, #132): fan-out from a resolve job does not use this success rule. It skips a tag only when a `queued` or `running` sync job for the same mapping, digest and tag exists, so a rescan re-syncs a synced tag.
- Decided (2026-11-07, #191): migration 0008 adds the scan schedule to `repo_mappings` (`scan_schedule` default `off`, `scan_minute`, `scan_weekday`, `scan_last_slot`) and the CVE id lists to `sync_reports` (`cve_ids`, `new_cve_ids`). Existing mappings get the schedule off; existing reports keep NULL lists. A scan job is a `sync_jobs` row whose payload is `{"kind":"scan","repo_full_name","trigger":"schedule"}`; the sync job it queues carries `"trigger":"schedule"`. No other table changes. Rules in [integrations.md](integrations.md), "Scheduled scan".
- Decided (2026-11-07, user, #224 d2, d9, d12): migration 0009 adds `harbor_scanners`, `scanner_reports`, `scanner_findings` and `project_scanner_locks` (schema above). Nothing is added to `sync_reports` or `cve_findings`; `cve_findings` stays one row per (mapping, repository, tag, CVE) and is recomputed from the union of the digest's scanner reports ([cve-lifecycle.md](cve-lifecycle.md)).
- Decided (2026-11-07, user, #224 d2): the storage rule is one report per (image digest, scanner UUID), scoped to the mapping. The older rule "one report per digest" in this file means `sync_reports`, which stays one row per processed (digest, tag) sync and is the SARIF upload record, not the findings store. A scan by a different scanner never replaces another scanner's `scanner_reports` row. Repeat scans of one digest by the same scanner replace its row and findings (d9).
- **Migration 0009, existing rows** (Decided 2026-11-07, delegated, #224; no Harbor call is possible in a migration, so no row can be given a real scanner UUID):
  1. For each (mapping, `image_digest`) with at least one `sync_reports` row at `sarif_status = 'success'`, insert one `scanner_reports` row with `scanner_uuid = 'unknown'`, `scanner_name` NULL, `image_push_time` and `stored_at` from the latest such `sync_reports` row (`synced_at`).
  2. For that digest's latest successful tag, copy its `cve_findings` rows with `status = 'open'` into `scanner_findings` (cve id, package, fixed-in version, severity, description; version and CVSS NULL). Fixed rows are not copied.
  3. Reports with no `cve_findings` (a clean image) get a `scanner_reports` row and no findings.
  4. `harbor_scanners` and `project_scanner_locks` start empty.
  The first normal sync of a digest that has a readable current scanner replaces the `unknown` row ([integrations.md](integrations.md), "Scanner reports and scan launch"). So the single-scanner case keeps working: before and after the migration the digest has one report, issues and counts do not change, and with Scanner Read the report is named from the next sync. Without Scanner Read it stays `unknown`, counts as one scanner, and the issue body omits the "Found by" line ([integrations.md](integrations.md), "GitHub issues"). The migration is reversible only by dropping the four tables.
- Decided (2026-11-07, delegated, #224): retention. `scanner_reports` rows follow the 90-day rule by `stored_at`; they are also deleted when the tag pruning or retention leaves no `sync_reports` row for (mapping, digest), and with the mapping. A scanner removed from Harbor has its reports deleted ([integrations.md](integrations.md)). `harbor_scanners` rows are not deleted by retention (names only; at most a handful per Harbor).
- Decided (2026-11-07, delegated, #224): a stored `scanner_findings` row is the scanner's own view. The merged view is never stored; it is a query over `scanner_findings` joined to `scanner_reports` for one (mapping, digest), grouped by (`cve_id`, `package`).
- Decided (2026-11-05, user, #132): a resolve job is a `sync_jobs` row whose payload JSON is `{"kind":"resolve","repo_full_name","digest"}` with no `tag`. A payload with no `kind` is a sync job. No schema change and no migration: `payload` is already free JSON, and `kind` is read from it as `trigger` is.
- Decided (2026-11-06, user, #179): the mapping-save project webhook check reads `project_webhooks` through `UNIQUE (harbor_base_url, harbor_project)`. No schema change and no migration.
- Decided (2026-11-03, delegated): `user_credentials.username` (nullable) and `user_credentials.expires_at` (nullable) are added for the Harbor robot account. Harbor robot accounts expire after 30 days by default. Source: Harbor robot account documentation, https://goharbor.io/docs/latest/administration/robot-accounts/ (fetched in this session; the default expiry text is confirmed). The expiry is configurable through the `robot_token_duration` system setting (Harbor API swagger, `robot_token_duration`, "robot account token duration in days"). The Harbor robot username form is `<prefix><name>` for system robots and `<prefix><project>+<name>` for project robots, with the configurable prefix defaulting to `robot$` (verified (2026-11-03) in `src/controller/robot/controller.go`).
- Decided (2026-11-03, delegated): `cve_findings.fixed_in_version` is nullable. Source: Harbor API swagger, `VulnerabilityItem.fixed_version` (https://github.com/goharbor/harbor, `api/v2.0/swagger.yaml`).
- Decided (2026-11-03, delegated): the tracked tag set for a mapping is derived from `sync_reports`, not from `cve_findings`. A tag that has zero CVEs is still tracked, and it is counted toward the 10-tag limit. Its last scan date is `sync_reports.synced_at` for the latest successful sync of that tag. This keeps "last scan date per tag" consistent with the tag limit. Source: internal, from [cve-lifecycle.md](cve-lifecycle.md).
- Decided (2026-11-03, delegated): an accepting action does not change `cve_findings` status. `cve_findings.status` stores only `open` or `fixed`. A CVE shows as `accepted` in the API and UI when it has an active acceptance. An active acceptance is one where `revoked_at IS NULL` and (`expires_at IS NULL` or `expires_at > now`). The row is never stored as `accepted`.
- Decided (2026-11-03, delegated): un-accept sets `cve_acceptances.revoked_at` and `revoked_by`. The row is kept for the audit trail. The partial unique index allows a new acceptance after revoke.
- Decided (2026-11-03, delegated): an acceptance whose `expires_at` has passed still has `revoked_at IS NULL`, which would block the partial unique index. When a new acceptance is created for the same mapping and CVE, the application first sets `revoked_at` and `revoked_by` on the expired row (system revoke, audited as `cve.unaccept` with reason `expired`). Both steps run in one transaction. Decided (2026-11-03, user): `revoked_by` on a system revoke is the user creating the new acceptance, so the `CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))` holds without a schema change. The audit row has `details` `{"reason": "expired", "system": true}`.
- Decided (2026-11-03, delegated): `cve_acceptances.created_by`, `cve_acceptances.revoked_by`, and `audit_log.actor_user_id` use `ON DELETE SET NULL`, and the `*_username` snapshot columns keep attribution after a user is deleted. Without this, deleting a user who accepted a CVE or acted in the audit log would fail on the foreign key. Source: none external; SQLite foreign key documentation for SET NULL behaviour.
- Decided (2026-11-03, delegated): user deletion is one transaction in this order: delete the user's `repo_mappings`, then the user's `user_credentials`, then the `users` row. SQLite checks RESTRICT immediately and the order of cascaded deletes is not something the schema can control. Source: SQLite foreign key documentation (RESTRICT is checked as the field is updated).
- Decided (2026-11-03, delegated): `alert_deliveries` has `UNIQUE (channel_id, dedupe_key)`, so one row exists per channel and key. The 24-hour window is enforced by the write, not by the constraint: send only if no row exists or the existing `sent_at` is older than 24 hours, then upsert `sent_at`. Use `INSERT ... ON CONFLICT (channel_id, dedupe_key) DO UPDATE SET sent_at = excluded.sent_at WHERE alert_deliveries.sent_at < unixepoch() - 86400` and send only when one row was changed. Source: SQLite UPSERT documentation, https://www.sqlite.org/lang_upsert.html (the `ON CONFLICT ... DO UPDATE ... WHERE` form). Verified (2026-11-03) in the SQLite UPSERT documentation: when the `WHERE` clause is false, the DO UPDATE becomes a no-op, so the change count is 0 and no alert is sent. A test still covers it.
- Decided (2026-11-06, user, #185): a GitHub repository (`github_owner`, `github_repo`) may be the target of several mappings, each for a different Harbor repository, regardless of branch. Uniqueness is on the Harbor side only: `UNIQUE (harbor_base_url, harbor_project, harbor_repository)` on `repo_mappings` stays. This withdraws the 2026-11-03 rule of one mapping per GitHub repository and its `UNIQUE (github_owner, github_repo)`. Migration: the next migration after 0006 drops `UNIQUE (github_owner, github_repo)` from `repo_mappings`. Existing rows stay valid, and no data is changed. A second mapping for the same Harbor repository is still refused. Any user may create a mapping to a GitHub repository, instance-wide. [docs/SETUP.md](../docs/SETUP.md) matches this decision.
- Decided (2026-11-06, user, #185): `github_issues` is shared. One row is keyed by `(github_owner, github_repo, cve_id)` and serves every mapping that targets that GitHub repository. Deleting a mapping never closes or deletes a shared issue, and never changes it on GitHub. The issue closes only when no remaining mapping reports the CVE (see [cve-lifecycle.md](cve-lifecycle.md)).
- Decided (2026-11-03): `alert_deliveries` rows are kept 30 days. The cleanup worker deletes older rows. This is longer than the 24-hour dedupe window.
- Decided (2026-11-03): `sync_jobs` rows are kept 90 days. The cleanup worker deletes older rows. This matches `sync_reports`.
- Decided (2026-11-03): `sync_jobs.status` is the only overall sync status (`queued`, `running`, `done`, `failed`). `sync_reports.sarif_status` records only the SARIF upload result (`pending`, `success`, `failed`). A "successful sync" for the polling dedupe rule above is a `sync_jobs` row with `status = 'done'` and a `sync_reports` row with `sarif_status = 'success'`. The dashboard and the Failed syncs tab read `sync_jobs.status`. The job status value is `done`, not `success`, everywhere.
- Decided (2026-11-06, user, #196): migration 0006 adds `sync_reports.image_push_time INTEGER` (Harbor push time of the scanned tag, Unix milliseconds, NULL for older reports) and `github_issues.closed_manually INTEGER NOT NULL DEFAULT 0`. The first picks the newest scanned digest; the second records an issue closed by hand on GitHub.
