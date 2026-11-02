# Database

Purpose: schema reference for SQLite and the decisions behind each table.

## Source of truth

- `backend/migrations/0001_init.sql` is the schema reference. The schema below is copied from the current design.
- SQLx SQLite with WAL mode. Use `SqlitePool`.

## Schema

```sql
-- System Configuration (OIDC, App Settings)
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user', -- 'admin' | 'user'
    auth_provider TEXT NOT NULL DEFAULT 'local', -- 'local' | 'oidc'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Service Credentials (Encrypted)
CREATE TABLE IF NOT EXISTS user_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_type TEXT NOT NULL, -- 'harbor' | 'github'
    label TEXT NOT NULL,
    base_url TEXT,
    encrypted_token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Repository Mappings
CREATE TABLE IF NOT EXISTS repo_mappings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harbor_cred_id TEXT REFERENCES user_credentials(id),
    github_cred_id TEXT REFERENCES user_credentials(id),
    harbor_project TEXT NOT NULL,
    harbor_repository TEXT NOT NULL,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    webhook_token TEXT UNIQUE NOT NULL,
    webhook_auth_secret_encrypted TEXT NOT NULL, -- AES-256-GCM ciphertext; shown once, rotatable, never logged
    auto_create_issues BOOLEAN DEFAULT FALSE,
    min_issue_severity TEXT DEFAULT 'CRITICAL',
default_branch TEXT NOT NULL DEFAULT 'main',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (harbor_project, harbor_repository), -- one mapping per Harbor repository
    UNIQUE (github_owner, github_repo, default_branch)
);

-- Sync Reports & Logs
CREATE TABLE IF NOT EXISTS sync_reports (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    harbor_repository TEXT NOT NULL,
    image_tag TEXT NOT NULL,
    commit_sha TEXT,
    vulnerability_summary TEXT NOT NULL, -- JSON string: {"critical": 0, "high": 2, ...}
    sarif_status TEXT NOT NULL, -- 'pending' | 'success' | 'failed'
    github_sarif_id TEXT,
    error_message TEXT,
    synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tracked GitHub Issues
CREATE TABLE IF NOT EXISTS github_issues (
    id TEXT PRIMARY KEY,
    sync_report_id TEXT NOT NULL REFERENCES sync_reports(id) ON DELETE CASCADE,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    github_issue_number INTEGER NOT NULL,
    github_issue_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- 'open' | 'closed'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- one row per (repo, cve_id); enforced by the constraint below
    UNIQUE (github_owner, github_repo, cve_id)
);

-- CVE Findings
-- one row per (mapping_id, harbor_repository, image_tag, cve_id)
CREATE TABLE IF NOT EXISTS cve_findings (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    harbor_repository TEXT NOT NULL,
    image_tag TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package TEXT,
    severity TEXT NOT NULL,
    first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'open', -- 'open' | 'fixed' | 'accepted'
    github_issue_id TEXT REFERENCES github_issues(id),
    UNIQUE (mapping_id, harbor_repository, image_tag, cve_id)
);

-- CVE Acceptances (accepted risk)
CREATE TABLE IF NOT EXISTS cve_acceptances (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

-- Audit Log (admin actions)
-- details must never contain tokens or key material
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT -- JSON
);

-- Sync Jobs (durable queue for webhook-triggered syncs)
-- payload must never contain tokens or header secrets
CREATE TABLE IF NOT EXISTS sync_jobs (
    id TEXT PRIMARY KEY,
    mapping_id TEXT NOT NULL REFERENCES repo_mappings(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued', -- status: queued | running | done | failed
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at DATETIME,
    last_error TEXT,
    payload TEXT NOT NULL, -- JSON: validated event, no secrets
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Table decisions

- **Naming:** use `harbor_repository` everywhere for the Harbor repository. Do not add an image-named column for it.
- **Mapping:** one mapping per Harbor repository. A mapping holds its own `webhook_token`, auth header secret, GitHub owner, repo, and `default_branch` (default `main`).
- **Credentials:** `user_credentials.encrypted_token` is AES-256-GCM encrypted. Never store plaintext tokens.
- **Audit:** `audit_log.details` never contains tokens or key material. Every accept and un-accept is audited.
- **Sync jobs:** `sync_jobs.payload` holds the validated event only. It never contains tokens or header secrets.
- **Retention:** `sync_reports` and related logs are kept 90 days. `audit_log` is kept 365 days. See [cve-lifecycle.md](cve-lifecycle.md) for the per-tag limit.

## Decisions

- Decided: 2026-11-02. The per-mapping auth header secret is stored in `repo_mappings.webhook_auth_secret_encrypted` (TEXT NOT NULL, AES-256-GCM ciphertext). It is shown once in the UI, is rotatable, and is never logged.
- Decided: 2026-11-02. One mapping per Harbor repository is enforced in the schema with `UNIQUE (harbor_project, harbor_repository)` on `repo_mappings`, in addition to the existing GitHub target UNIQUE.
- Decided: 2026-11-02. `github_issues` has `UNIQUE (github_owner, github_repo, cve_id)`, so only one row per repo and CVE can exist. The table has no repo id column, so `github_owner` and `github_repo` columns were added to it.
