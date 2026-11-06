-- Remove the insert-time default from project_webhooks.rotated_at (#145, decided 2026-11-06).
-- rotated_at is NULL until the first rotation; the API writes NULL on create. SQLite cannot drop
-- a column default in place, so the table is rebuilt. Same columns and constraints as 0003.
--
-- project_webhook_unmatched references project_webhooks with ON DELETE CASCADE, and dropping
-- the old table deletes its rows with foreign keys on. The unmatched rows are therefore kept in
-- a side table and put back once the new table has taken the name.
CREATE TABLE project_webhook_unmatched_keep AS SELECT * FROM project_webhook_unmatched;

CREATE TABLE project_webhooks_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    harbor_base_url TEXT NOT NULL,
    harbor_project TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    rotated_at INTEGER,
    UNIQUE (harbor_base_url, harbor_project)
);

INSERT INTO project_webhooks_new
    (id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash, created_at, rotated_at)
SELECT id, user_id, harbor_base_url, harbor_project, token_hash, secret_hash, created_at, rotated_at
FROM project_webhooks;

DROP TABLE project_webhooks;
ALTER TABLE project_webhooks_new RENAME TO project_webhooks;

INSERT INTO project_webhook_unmatched (project_webhook_id, repository, count, last_seen_at)
SELECT project_webhook_id, repository, count, last_seen_at FROM project_webhook_unmatched_keep;
DROP TABLE project_webhook_unmatched_keep;
