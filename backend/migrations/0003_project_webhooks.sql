-- One Harbor webhook per project (#132). Decided 2026-11-05.
-- A row holds the owner and the digests of the project token and secret. The values are
-- shown once and never stored in plain text, as for mapping tokens.
CREATE TABLE IF NOT EXISTS project_webhooks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harbor_base_url TEXT NOT NULL,
    harbor_project TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    rotated_at INTEGER DEFAULT (unixepoch()),
    UNIQUE (harbor_base_url, harbor_project)
);

-- Events for a repository that no mapping on the project covers, counted per repository.
-- No event body is stored (#132).
CREATE TABLE IF NOT EXISTS project_webhook_unmatched (
    project_webhook_id TEXT NOT NULL REFERENCES project_webhooks(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (project_webhook_id, repository)
);
