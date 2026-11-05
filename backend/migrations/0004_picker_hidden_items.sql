-- Per-user hide list for the mapping pickers (#126). Decided 2026-11-05.
-- A row changes only the user's own pickers. It never changes a mapping, a sync, or another
-- user's view. Harbor rows are keyed by the Harbor base URL they were hidden on (the
-- credential's normalized base_url); GitHub rows have no base URL.
CREATE TABLE IF NOT EXISTS picker_hidden_items (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('harbor', 'github')),
    harbor_base_url TEXT,
    full_name TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK ((source = 'harbor') = (harbor_base_url IS NOT NULL))
);

-- One partial unique index per source. A plain UNIQUE over the nullable harbor_base_url would
-- not stop duplicate github rows, because SQLite treats NULLs as distinct.
CREATE UNIQUE INDEX IF NOT EXISTS picker_hidden_items_harbor_key
    ON picker_hidden_items (user_id, harbor_base_url, full_name) WHERE source = 'harbor';
CREATE UNIQUE INDEX IF NOT EXISTS picker_hidden_items_github_key
    ON picker_hidden_items (user_id, full_name) WHERE source = 'github';
