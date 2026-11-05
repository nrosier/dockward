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
    UNIQUE (harbor_base_url, harbor_project, harbor_repository), -- one mapping per Harbor repository per Harbor instance
    UNIQUE (github_owner, github_repo) -- one mapping per GitHub repository, regardless of branch. default_branch sets the SARIF upload branch only.
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
    payload TEXT NOT NULL, -- JSON: validated event, no secrets
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
    synced_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_sync_reports_digest
    ON sync_reports (mapping_id, harbor_repository, image_tag, image_digest, sarif_status);

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
```

## system_config keys

Decided (2026-11-03, delegated). Each key is a row in `system_config`. Values are stored as TEXT.

- `oidc.issuer_url`: HTTPS issuer URL. `is_encrypted = 0`. Rules in [security.md](security.md).
- `oidc.client_id`: `is_encrypted = 0`.
- `oidc.client_secret_encrypted`: `is_encrypted = 1`. Value is a "v1:" ciphertext.
- `oidc.role_claim`: name of the claim that carries groups (for example `groups`). `is_encrypted = 0`.
- `oidc.admin_group`: group value that grants `admin`. `is_encrypted = 0`.
- `oidc.user_group`: group value that grants `user`. `is_encrypted = 0`.
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
- `alert.config_change`
- `backup.run`
- `restore.run`
- `key.rotate`
- `retention.run`
- `sync_job.retry` (manual retry of a failed sync job; `details` is `{"job_id","mapping_id"}`; Decided (2026-11-03, delegated))
- `log.level_change` (application log level change; `details` is `{"old","new"}`, each one of `info`, `debug`, `trace`; target `log_level`; the automatic revert to `info` uses the actor `system`. Decided (2026-11-05, user, #136). The application log itself is an in-memory buffer and has no table; see [security.md](security.md), "Application log")
- `mapping.pull` (manual scan pull from Harbor for one mapping; `details` is `{"mapping_id","queued"}`, the number of jobs queued, and no values; Decided (2026-11-05, user, #131))

Source: none external. The list follows the audit examples in [frontend.md](frontend.md) (Admin, Audit log) and the events in [security.md](security.md). The vocabulary is a local convention, so it is Decided (2026-11-03, delegated).

## Table decisions

- **Naming:** use `harbor_repository` everywhere for the Harbor repository. Do not add an image-named column for it.
- **Mapping:** one mapping per Harbor repository per Harbor instance, and one mapping per GitHub repository (regardless of branch). A mapping holds its own webhook token and auth header secret digests, GitHub owner, repo, and `default_branch` (default `main`).
- **Credentials:** `user_credentials.encrypted_token` is AES-256-GCM encrypted in the "v1:" format. Never store plaintext tokens.
- **Audit:** `audit_log.details` never contains tokens or key material. Every accept and un-accept is audited.
- **Sync jobs:** `sync_jobs.payload` holds the validated event only. It never contains tokens or header secrets.
- **Retention:** `sync_reports` and related logs are kept 90 days. `sync_jobs` is kept 90 days (Decided 2026-11-03). `job_runs` is kept 90 days (Decided 2026-11-03). `alert_deliveries` is kept 30 days (Decided 2026-11-03). `audit_log` is kept 365 days. See [cve-lifecycle.md](cve-lifecycle.md) for the per-tag limit.
- Decided (2026-11-03, delegated): `CHECK` constraints on enumerated TEXT columns (`sync_jobs.status`, `github_issues.status`, `cve_findings.status` and `severity`, `repo_mappings.min_issue_severity`, `alert_channels.kind`, `job_runs.job_kind` and `job_runs.status`). Source: SQLite CREATE TABLE documentation, CHECK constraints (https://www.sqlite.org/lang_createtable.html). The index `idx_sync_reports_digest` is Decided (2026-11-03, delegated) for the polling dedupe lookup; no external source.
- Decided (2026-11-05, user, #129): showing, filtering and manually logging every severity needs no constraint change and no migration. `cve_findings.severity` already allows all five values (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), and the findings were always stored at every severity. `repo_mappings.min_issue_severity` keeps `CHECK (min_issue_severity IN ('CRITICAL', 'HIGH'))`, because it governs automatic issues only and the user decided automatic issues stay CRITICAL and HIGH. Manual logging at any severity reads no column that has a severity constraint, and the `github_issues` table has no severity column. The issue body of #129 assumed a constraint change; the decision recorded on the issue made it unnecessary.
- **Source for the 90 and 365 day values:** these are the user's decided retention rules, not external standards.

## Decisions

- Decided: 2026-11-02, changed 2026-11-03. The per-mapping auth header secret is stored only as a SHA-256 digest in `repo_mappings.webhook_auth_secret_hash` (TEXT NOT NULL), and the webhook token only as `repo_mappings.webhook_token_hash`. Both are shown once, are rotatable, and are never logged. See [integrations.md](integrations.md).
- Decided: 2026-11-02, changed 2026-11-03. One mapping per Harbor repository per Harbor instance, enforced with `UNIQUE (harbor_base_url, harbor_project, harbor_repository)` on `repo_mappings`, in addition to the GitHub target UNIQUE. Two tenants on different Harbor instances can map repositories with the same project and repository names. Decided (2026-11-03, delegated): `harbor_base_url` is copied from the Harbor credential on mapping create and update, normalized (lowercase scheme and host, no default port, no trailing slash). Changing a Harbor credential's `base_url` while a mapping uses it returns `409 conflict` ([api.md](api.md)).
- Decided (2026-11-03): timestamps. Every time column is `INTEGER` UTC Unix seconds, with defaults from `unixepoch()` (SQLite 3.38.0 or later; https://www.sqlite.org/lang_datefunc.html). Comparisons are numeric, for example `sent_at < unixepoch() - 86400`. No time is stored as text. The API formats times as RFC 3339 UTC strings ([api.md](api.md), Conventions).
- Decided: 2026-11-02. `github_issues` has `UNIQUE (github_owner, github_repo, cve_id)`, so only one row per repo and CVE can exist. The table has no repo id column, so `github_owner` and `github_repo` columns were added to it.
- Decided: `github_issues.sync_report_id` is nullable and uses `ON DELETE SET NULL`. Deleting a `sync_reports` row never deletes its issue row. Tag cleanup and retention never delete `github_issues` rows. This resolves the conflict between the old `ON DELETE CASCADE` and the rule in [cve-lifecycle.md](cve-lifecycle.md) that issues are not changed when tags are pruned.
- Decided: `cve_findings.github_issue_id` uses `ON DELETE SET NULL`. Every tracked tag row for one CVE in one mapping points to the same `github_issues` row for that repo and CVE. Deleting a tag's `cve_findings` rows does not affect the issue. The pointer is a convenience. The `(github_owner, github_repo, cve_id)` lookup is authoritative.
- Decided: `repo_mappings.harbor_cred_id` and `repo_mappings.github_cred_id` are NOT NULL, because the setup guide ([docs/SETUP.md](../docs/SETUP.md), section 5) requires both. They use `ON DELETE RESTRICT`. A credential in use cannot be deleted. The API returns a conflict error when a delete is blocked.
- Decided (2026-11-03, delegated): a credential must belong to the same user as the mapping that references it. The application checks this on write. Source: none external; follows the tenancy rule in [security.md](security.md) (users see only their own credentials).
- Decided (2026-11-03): Jobs tab storage is the `job_runs` table (see the schema above). It has `job_kind` (`cleanup`, `retention`, `poll`) and `status` (`done`, `failed`) with CHECK constraints. The table holds counts and error text only, never secrets.
- Decided: `sync_reports.sync_job_id` links each report to its job (nullable, `ON DELETE SET NULL`). The overall sync status is `sync_jobs.status`, not a column on this table (Decided 2026-11-03, see Decisions section).
- Decided: `sync_reports.image_digest` is NOT NULL. Polling skips an image whose digest already has a successful sync for that mapping and tag. "Successful" means `sync_jobs.status = 'done'` and `sarif_status = 'success'` on the linked report (Decided 2026-11-03, see Decisions section).
- Decided (2026-11-03, delegated): `user_credentials.username` (nullable) and `user_credentials.expires_at` (nullable) are added for the Harbor robot account. Harbor robot accounts expire after 30 days by default. Source: Harbor robot account documentation, https://goharbor.io/docs/latest/administration/robot-accounts/ (fetched in this session; the default expiry text is confirmed). The expiry is configurable through the `robot_token_duration` system setting (Harbor API swagger, `robot_token_duration`, "robot account token duration in days"). The Harbor robot username form is `<prefix><name>` for system robots and `<prefix><project>+<name>` for project robots, with the configurable prefix defaulting to `robot$` (verified (2026-11-03) in `src/controller/robot/controller.go`).
- Decided (2026-11-03, delegated): `cve_findings.fixed_in_version` is nullable. Source: Harbor API swagger, `VulnerabilityItem.fixed_version` (https://github.com/goharbor/harbor, `api/v2.0/swagger.yaml`).
- Decided (2026-11-03, delegated): the tracked tag set for a mapping is derived from `sync_reports`, not from `cve_findings`. A tag that has zero CVEs is still tracked, and it is counted toward the 10-tag limit. Its last scan date is `sync_reports.synced_at` for the latest successful sync of that tag. This keeps "last scan date per tag" consistent with the tag limit. Source: internal, from [cve-lifecycle.md](cve-lifecycle.md).
- Decided (2026-11-03, delegated): an accepting action does not change `cve_findings` status. `cve_findings.status` stores only `open` or `fixed`. A CVE shows as `accepted` in the API and UI when it has an active acceptance. An active acceptance is one where `revoked_at IS NULL` and (`expires_at IS NULL` or `expires_at > now`). The row is never stored as `accepted`.
- Decided (2026-11-03, delegated): un-accept sets `cve_acceptances.revoked_at` and `revoked_by`. The row is kept for the audit trail. The partial unique index allows a new acceptance after revoke.
- Decided (2026-11-03, delegated): an acceptance whose `expires_at` has passed still has `revoked_at IS NULL`, which would block the partial unique index. When a new acceptance is created for the same mapping and CVE, the application first sets `revoked_at` and `revoked_by` on the expired row (system revoke, audited as `cve.unaccept` with reason `expired`). Both steps run in one transaction. Decided (2026-11-03, user): `revoked_by` on a system revoke is the user creating the new acceptance, so the `CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))` holds without a schema change. The audit row has `details` `{"reason": "expired", "system": true}`.
- Decided (2026-11-03, delegated): `cve_acceptances.created_by`, `cve_acceptances.revoked_by`, and `audit_log.actor_user_id` use `ON DELETE SET NULL`, and the `*_username` snapshot columns keep attribution after a user is deleted. Without this, deleting a user who accepted a CVE or acted in the audit log would fail on the foreign key. Source: none external; SQLite foreign key documentation for SET NULL behaviour.
- Decided (2026-11-03, delegated): user deletion is one transaction in this order: delete the user's `repo_mappings`, then the user's `user_credentials`, then the `users` row. SQLite checks RESTRICT immediately and the order of cascaded deletes is not something the schema can control. Source: SQLite foreign key documentation (RESTRICT is checked as the field is updated).
- Decided (2026-11-03, delegated): `alert_deliveries` has `UNIQUE (channel_id, dedupe_key)`, so one row exists per channel and key. The 24-hour window is enforced by the write, not by the constraint: send only if no row exists or the existing `sent_at` is older than 24 hours, then upsert `sent_at`. Use `INSERT ... ON CONFLICT (channel_id, dedupe_key) DO UPDATE SET sent_at = excluded.sent_at WHERE alert_deliveries.sent_at < unixepoch() - 86400` and send only when one row was changed. Source: SQLite UPSERT documentation, https://www.sqlite.org/lang_upsert.html (the `ON CONFLICT ... DO UPDATE ... WHERE` form). Verified (2026-11-03) in the SQLite UPSERT documentation: when the `WHERE` clause is false, the DO UPDATE becomes a no-op, so the change count is 0 and no alert is sent. A test still covers it.
- Decided (2026-11-03): one mapping per GitHub repository. A GitHub repository (`github_owner`, `github_repo`) can be the target of only one mapping, regardless of branch. Enforced with `UNIQUE (github_owner, github_repo)` on `repo_mappings`. This replaces the earlier `UNIQUE (github_owner, github_repo, default_branch)`. Because of this, `github_issues` keyed on `(github_owner, github_repo, cve_id)` has exactly one owning mapping, so deleting a mapping removes only its own `github_issues` rows and cannot affect another mapping. Two mappings for the same repo on different branches are NOT allowed. A user who needs two branches uses two GitHub repos. [docs/SETUP.md](../docs/SETUP.md) matches this decision.
- Decided (2026-11-03): `alert_deliveries` rows are kept 30 days. The cleanup worker deletes older rows. This is longer than the 24-hour dedupe window.
- Decided (2026-11-03): `sync_jobs` rows are kept 90 days. The cleanup worker deletes older rows. This matches `sync_reports`.
- Decided (2026-11-03): `sync_jobs.status` is the only overall sync status (`queued`, `running`, `done`, `failed`). `sync_reports.sarif_status` records only the SARIF upload result (`pending`, `success`, `failed`). A "successful sync" for the polling dedupe rule above is a `sync_jobs` row with `status = 'done'` and a `sync_reports` row with `sarif_status = 'success'`. The dashboard and the Failed syncs tab read `sync_jobs.status`. The job status value is `done`, not `success`, everywhere.
