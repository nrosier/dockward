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
