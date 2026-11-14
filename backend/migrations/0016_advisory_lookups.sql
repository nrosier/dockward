-- #379: the answer of an advisory lookup, per GHSA or GO id, kept forever. When a scanner reports
-- a GHSA or GO id with no CVE id, Dockward asks OSV (then GitHub advisories) once for the CVE id
-- behind it. cve_id is NULL when the advisory names no CVE ("none published"), which is an answer
-- too. A failed or unreachable lookup stores no row, so the id is asked again on a later scan.
-- The table holds public advisory ids only. A resolved pair is also recorded in
-- vulnerability_aliases, which the scan reads (#337).
CREATE TABLE IF NOT EXISTS advisory_lookups (
    advisory_id TEXT PRIMARY KEY,   -- the GHSA or GO id
    cve_id TEXT,                    -- the CVE id, or NULL when none is published
    looked_up_at INTEGER NOT NULL,  -- Unix seconds
    source TEXT NOT NULL CHECK (source IN ('osv', 'github'))
);
