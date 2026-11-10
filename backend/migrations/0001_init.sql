-- Spinoff clean-slate schema (specs/spinoff-local-scan.md, section 9; decisions 21, 32, 33-47).
-- Fresh installs only. There is no import from, and no upgrade path for, a HarborGate database.
-- A database that holds the `repo_mappings` table is refused at pool open, before this file runs
-- (src/db/mod.rs, LEGACY_DATABASE_ERROR).
--
-- Column changes from the HarborGate schema (all migrations 0001 to 0010 were folded into this file):
--   system_config        kept. New keys: images.max_stored, scanners.enabled, scanner and pull limits.
--   users                kept.
--   user_credentials     GitHub only. service_type, base_url and username dropped.
--   hubs                 new. Host is the only identifier and the only name (decision 45). No display name.
--                        pull_endpoint is custom-only (decision 44). Default hubs are not removable (decision 13).
--   image_sources        new. Replaces repo_mappings. Hub, repository (full path), tag value (exact or pattern).
--                        Unique on (hub_id, repository, tag_value) with no user (decision 37).
--   source_credentials   new. One optional credential per source (decision 35).
--   images, tag_observations, image_platforms, scanner_databases, scan_runs, scanner_findings,
--   publish_reports      new (section 9). publish_reports replaces sync_reports.
--   sync_jobs            mapping_id becomes nullable source_id (NULL for db_update). Kinds: discover, pull,
--                        scan, publish, db_update.
--   github_issues        sync_report_id becomes publish_report_id. Unique on (github_owner, github_repo, cve_id).
--                        closed_manually added (migration 0006 of HarborGate, kept).
--   cve_findings         mapping_id and harbor_repository replaced by source_id. Unique on
--                        (source_id, image_tag, cve_id). description kept.
--   cve_acceptances      mapping_id becomes source_id.
--   job_runs             job_kind values: cleanup, retention, discover, db_update (the poll kind is gone).
--   audit_log, alert_channels, alert_deliveries: kept unchanged.

-- System Configuration (OIDC, App Settings, scan settings)
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
    oidc_issuer TEXT,  -- issuer URL that asserted this user; NULL for local users
    oidc_subject TEXT, -- OIDC `sub` claim; NULL for local users
    token_version INTEGER NOT NULL DEFAULT 0, -- session revocation counter. See security.md, Sessions.
    created_at INTEGER DEFAULT (unixepoch()),
    -- sub is locally unique and never reassigned within an issuer (OpenID Connect Core 1.0, section 2).
    -- NULLs are distinct, so local users (both columns NULL) do not collide.
    UNIQUE (oidc_issuer, oidc_subject)
);

-- Registries. Host is canonical and is the only name (decision 45). Docker Hub is stored as docker.io.
CREATE TABLE IF NOT EXISTS hubs (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL UNIQUE,            -- 'ghcr.io', 'docker.io', or a custom host
    pull_endpoint TEXT,                   -- custom hubs only; NULL means the stored host (decision 44)
    kind TEXT NOT NULL CHECK (kind IN ('default', 'custom')),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (pull_endpoint IS NULL OR kind = 'custom')
);

-- GitHub credentials (Encrypted). GitHub only.
CREATE TABLE IF NOT EXISTS user_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    encrypted_token TEXT NOT NULL, -- "v1:" ciphertext. See security.md, "Ciphertext format".
    expires_at INTEGER, -- NULL unless the operator records one
    created_at INTEGER DEFAULT (unixepoch())
);

-- Where an image is and where its results go. Owned by user_id. The namespace is the first
-- segment of repository and is not stored (decision 33).
CREATE TABLE IF NOT EXISTS image_sources (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,             -- full path; the first segment is the namespace
    tag_value TEXT NOT NULL,              -- exact tag, or a pattern with * or ?
    github_cred_id TEXT NOT NULL REFERENCES user_credentials(id) ON DELETE RESTRICT,
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    auto_create_issues BOOLEAN NOT NULL DEFAULT FALSE,
    min_issue_severity TEXT NOT NULL DEFAULT 'CRITICAL' CHECK (min_issue_severity IN ('CRITICAL', 'HIGH')),
    last_discovery_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (hub_id, repository, tag_value)  -- source identity (decision 37)
);

-- At most one credential per source (decision 35). No hub-level or namespace-level credential.
CREATE TABLE IF NOT EXISTS source_credentials (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL UNIQUE REFERENCES image_sources(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    encrypted_token TEXT NOT NULL,        -- "v1:", AAD source_credentials:encrypted_token:<id>
    expires_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One image per (hub, repository, top-level digest): an index or a single manifest.
CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY,
    hub_id TEXT NOT NULL REFERENCES hubs(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,
    digest TEXT NOT NULL,                 -- sha256:<hex>
    is_index BOOLEAN NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (hub_id, repository, digest)
);

-- Which digest a source's tag pointed to, and when discovery first saw it.
CREATE TABLE IF NOT EXISTS tag_observations (
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    first_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (source_id, tag, image_id)
);

-- One platform manifest = one OCI layout on disk. Kept after eviction.
CREATE TABLE IF NOT EXISTS image_platforms (
    id TEXT PRIMARY KEY,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,               -- os/arch[/variant]
    platform_digest TEXT NOT NULL,        -- sha256:<hex> of the platform manifest
    state TEXT NOT NULL CHECK (state IN ('queued', 'pulling', 'stored', 'evicting', 'evicted', 'failed')),
    size_bytes INTEGER,
    pulled_at INTEGER,                    -- set when 'stored'; the eviction clock
    evicted_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (image_id, platform_digest)
);
CREATE INDEX IF NOT EXISTS idx_image_platforms_evict ON image_platforms (state, pulled_at, id);

-- Per scanner: the vulnerability database in use and when it was built.
CREATE TABLE IF NOT EXISTS scanner_databases (
    scanner TEXT PRIMARY KEY CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    built_at INTEGER,
    checked_at INTEGER
);

-- Job queue for discovery, pulls, scans, publishing and database refreshes.
-- payload must never contain tokens or secrets: ids and the tag only.
CREATE TABLE IF NOT EXISTS sync_jobs (
    id TEXT PRIMARY KEY,
    source_id TEXT REFERENCES image_sources(id) ON DELETE CASCADE, -- NULL for a db_update job
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER,
    last_error TEXT,
    payload TEXT NOT NULL, -- JSON: kind (discover, pull, scan, publish, db_update) and ids; no secrets
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
);

-- One scan of one platform image by one scanner. Append-only history.
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    image_platform_id TEXT NOT NULL REFERENCES image_platforms(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    db_built_at INTEGER,
    trigger TEXT NOT NULL CHECK (trigger IN ('first_pull', 'tag_moved', 'db_update')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT                            -- one fixed string from section 6
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_current ON scan_runs (image_platform_id, scanner, status, finished_at);

-- Findings of one scan run, as parsed from the scanner's JSON.
CREATE TABLE IF NOT EXISTS scanner_findings (
    run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL DEFAULT '', -- '' when the scanner gives no package; the merge key uses it as is
    version TEXT,
    fixed_in_version TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    cvss_v3 REAL,                         -- preferred CVSS v3 score, for the SARIF security-severity
    description TEXT,                     -- at most 4,000 characters
    PRIMARY KEY (run_id, cve_id, package)
);

-- SARIF upload record per published image.
CREATE TABLE IF NOT EXISTS publish_reports (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    image_id TEXT REFERENCES images(id) ON DELETE SET NULL,
    sync_job_id TEXT REFERENCES sync_jobs(id) ON DELETE SET NULL,
    image_tag TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    commit_sha TEXT,
    vulnerability_summary TEXT NOT NULL,  -- JSON
    sarif_status TEXT NOT NULL CHECK (sarif_status IN ('pending', 'success', 'failed')),
    github_sarif_id TEXT,
    error_message TEXT,
    synced_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Tracked GitHub Issues (one open or closed issue per repo and CVE).
-- Rows are never deleted by retention. A source delete does not remove them. See cve-lifecycle.md.
CREATE TABLE IF NOT EXISTS github_issues (
    id TEXT PRIMARY KEY,
    publish_report_id TEXT REFERENCES publish_reports(id) ON DELETE SET NULL, -- the publish that created the issue; nullable
    github_owner TEXT NOT NULL,
    github_repo TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    github_issue_number INTEGER NOT NULL,
    github_issue_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at INTEGER DEFAULT (unixepoch()),
    closed_manually INTEGER NOT NULL DEFAULT 0
    CHECK (closed_manually IN (0, 1)),
    -- one row per (repo, cve_id); sources that target the same GitHub repository share it (decision 47)
    UNIQUE (github_owner, github_repo, cve_id)
);

-- CVE Findings
-- one row per (source_id, image_tag, cve_id): the merged view of the tag's current image.
-- "accepted" is not stored here. It is derived from cve_acceptances.
CREATE TABLE IF NOT EXISTS cve_findings (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    image_tag TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    fixed_in_version TEXT, -- NULL when unknown
    first_seen_at INTEGER DEFAULT (unixepoch()),
    last_seen_at INTEGER DEFAULT (unixepoch()),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed')), -- stored states only
    github_issue_id TEXT REFERENCES github_issues(id) ON DELETE SET NULL, -- pointer to the (repo, cve) issue
    description TEXT,
    UNIQUE (source_id, image_tag, cve_id)
);

-- CVE Acceptances (accepted risk, applies to the whole image source)
CREATE TABLE IF NOT EXISTS cve_acceptances (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_by_username TEXT NOT NULL, -- snapshot so attribution survives user deletion
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER,
    revoked_at INTEGER,  -- soft revoke (un-accept)
    revoked_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
-- At most one active acceptance per source and CVE.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_acceptances_active
    ON cve_acceptances (source_id, cve_id) WHERE revoked_at IS NULL;

-- Audit Log (admin and security-relevant actions)
-- details must never contain tokens or key material
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_username TEXT NOT NULL, -- snapshot of the actor's username at write time
    action TEXT NOT NULL, -- one value from the audit action vocabulary (specs/spinoff-local-scan.md, section 9)
    target TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    details TEXT -- JSON
);

-- Alert Channels (admin-configured SMTP and webhook destinations)
CREATE TABLE IF NOT EXISTS alert_channels (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('smtp', 'webhook')),
    config_encrypted TEXT NOT NULL, -- "v1:" ciphertext of the JSON config (host, port, user, password, URL, and so on)
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Job Runs (housekeeping run history for the admin Jobs tab)
-- Holds counts and error text only, never secrets.
CREATE TABLE IF NOT EXISTS job_runs (
    id TEXT PRIMARY KEY,
    job_kind TEXT NOT NULL CHECK (job_kind IN ('cleanup', 'retention', 'discover', 'db_update')),
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    status TEXT NOT NULL CHECK (status IN ('done', 'failed')),
    processed_count INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT -- NULL when status is 'done'; error text only, never secrets
);

-- Alert Deliveries (24-hour dedupe log)
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
    dedupe_key TEXT NOT NULL, -- CVE id for new CRITICAL CVE alerts; sync_failed:<sync_job_id> for sync failures (see alerts.md)
    sent_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (channel_id, dedupe_key)
);

-- Default hubs (decisions 7, 11, 13). Inserted here; the query layer refuses to delete a row
-- whose kind is 'default'. Docker Hub is stored as docker.io and pulled from registry-1.docker.io.
INSERT OR IGNORE INTO hubs (id, host, kind)
VALUES ('hub-default-ghcr', 'ghcr.io', 'default');
INSERT OR IGNORE INTO hubs (id, host, kind)
VALUES ('hub-default-docker', 'docker.io', 'default');
