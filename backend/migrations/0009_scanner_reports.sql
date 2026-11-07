-- Scanner reports and scan launch (#224, part 1, migration 0009). Decided 2026-11-07, user, #224.
-- The tables below match the "Schema" section of specs/database.md. Nothing else changes.
-- Existing rows: one report per (mapping, digest) with scanner 'unknown', then its open findings.
-- Decided (2026-11-07, delegated, #224): no Harbor call is possible in a migration, so no existing row
-- gets a real scanner UUID. The first normal sync of a digest with a readable scanner replaces it.

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

-- Migration rule, step 1: one 'unknown' report per (mapping, digest) that has a successful sync report.
-- The newest successful sync report of the digest (by synced_at, then rowid) supplies the push time and
-- the retention clock. A NULL synced_at falls back to the migration time, so the row is not pruned at once.
WITH latest AS (
    SELECT mapping_id, image_digest, image_push_time,
           COALESCE(synced_at, unixepoch()) AS stored_at,
           ROW_NUMBER() OVER (
               PARTITION BY mapping_id, image_digest
               ORDER BY COALESCE(synced_at, 0) DESC, rowid DESC
           ) AS rn
    FROM sync_reports
    WHERE sarif_status = 'success'
)
INSERT INTO scanner_reports
    (id, mapping_id, image_digest, scanner_uuid, scanner_name, scanner_vendor, scanner_version,
     image_push_time, stored_at)
SELECT lower(hex(randomblob(16))), l.mapping_id, l.image_digest, 'unknown', NULL, NULL, NULL,
       l.image_push_time, l.stored_at
FROM latest AS l
WHERE l.rn = 1;

-- Migration rule, step 2: the open findings of the digest's newest successful tag become the findings of
-- its 'unknown' report. Fixed rows are not copied. version and cvss_v3 are NULL, as no source has them.
-- A clean image has no open rows, so its report gets no findings (step 3).
WITH latest AS (
    SELECT mapping_id, image_digest, harbor_repository, image_tag,
           ROW_NUMBER() OVER (
               PARTITION BY mapping_id, image_digest
               ORDER BY COALESCE(synced_at, 0) DESC, rowid DESC
           ) AS rn
    FROM sync_reports
    WHERE sarif_status = 'success'
)
INSERT INTO scanner_findings
    (report_id, cve_id, package, version, fixed_in_version, severity, cvss_v3, description)
SELECT sr.id, cf.cve_id, COALESCE(cf.package, ''), NULL, cf.fixed_in_version, cf.severity, NULL,
       cf.description
FROM scanner_reports AS sr
JOIN latest AS l
    ON l.mapping_id = sr.mapping_id
   AND l.image_digest = sr.image_digest
   AND l.rn = 1
JOIN cve_findings AS cf
    ON cf.mapping_id = l.mapping_id
   AND cf.harbor_repository = l.harbor_repository
   AND cf.image_tag = l.image_tag
   AND cf.status = 'open'
WHERE sr.scanner_uuid = 'unknown';

-- Step 4: harbor_scanners and project_scanner_locks start empty. Nothing else is written.
