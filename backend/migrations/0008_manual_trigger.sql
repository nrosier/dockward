-- no-transaction
-- The `manual` scan trigger (#335): a forced scan of one image from the source page. SQLite
-- cannot change a CHECK constraint, so `scan_runs` is rebuilt with the new list, following the
-- SQLite "generalized ALTER TABLE" procedure.
--
-- `-- no-transaction` is required: `PRAGMA foreign_keys` is a no-op inside a transaction, and
-- foreign keys must be OFF while the old table is dropped, or the drop cascades into
-- `scanner_findings`. The rebuild itself runs in its own transaction below.
--
-- The two views and the index that read `scan_runs` are dropped first and recreated exactly as
-- in 0001_init.sql, so the rename does not fail on a view that names a missing table.

PRAGMA foreign_keys = OFF;

BEGIN;

DROP VIEW IF EXISTS newest_digest_tags;
DROP VIEW IF EXISTS tag_scan_times;
DROP INDEX IF EXISTS idx_scan_runs_current;

-- One scan of one platform image by one scanner. Append-only history.
CREATE TABLE scan_runs_new (
    id TEXT PRIMARY KEY,
    image_platform_id TEXT NOT NULL REFERENCES image_platforms(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL CHECK (scanner IN ('grype', 'trivy')),
    scanner_version TEXT,
    db_built_at INTEGER,
    trigger TEXT NOT NULL CHECK (trigger IN ('first_pull', 'tag_moved', 'db_update', 'manual')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT                            -- one fixed string from section 6
);

-- rowid is copied too: tag_scan_times reads MAX(r.rowid) and the scan tests order by it.
INSERT INTO scan_runs_new (rowid, id, image_platform_id, scanner, scanner_version, db_built_at,
                           trigger, status, job_id, started_at, finished_at, error)
SELECT rowid, id, image_platform_id, scanner, scanner_version, db_built_at,
       trigger, status, job_id, started_at, finished_at, error
FROM scan_runs;

DROP TABLE scan_runs;
ALTER TABLE scan_runs_new RENAME TO scan_runs;

CREATE INDEX IF NOT EXISTS idx_scan_runs_current ON scan_runs (image_platform_id, scanner, status, finished_at);

-- The tags of a source's newest scanned image (decision 49). The newest image is the tag
-- observation with the latest first_seen_at among images that have a done scan run. A tag that
-- has since moved to another digest does not belong to it. Read by the CVE list and the dashboard.
CREATE VIEW IF NOT EXISTS newest_digest_tags AS
SELECT o.source_id AS source_id, o.tag AS image_tag
FROM tag_observations o
WHERE o.image_id = (
        SELECT o2.image_id FROM tag_observations o2
        WHERE o2.source_id = o.source_id
          AND EXISTS (
              SELECT 1 FROM image_platforms p
              JOIN scan_runs r ON r.image_platform_id = p.id AND r.status = 'done'
              WHERE p.image_id = o2.image_id)
        ORDER BY o2.first_seen_at DESC, o2.rowid DESC
        LIMIT 1)
  AND NOT EXISTS (
        SELECT 1 FROM tag_observations n
        WHERE n.source_id = o.source_id AND n.tag = o.tag
          AND (n.first_seen_at > o.first_seen_at
               OR (n.first_seen_at = o.first_seen_at AND n.rowid > o.rowid)));

-- When each tag of a source was last scanned: the latest finished done scan run of any image the
-- tag was observed on. A tag with no done scan is absent (it is not tracked). Tags that share an
-- image share its scan time, so seen_at (when discovery first saw the tag on the image) breaks the
-- tie, newest first. Read by the CVE list.
CREATE VIEW IF NOT EXISTS tag_scan_times AS
SELECT o.source_id AS source_id, o.tag AS image_tag,
       MAX(COALESCE(r.finished_at, 0)) AS scan_at, MAX(o.first_seen_at) AS seen_at,
       MAX(r.rowid) AS last_row
FROM tag_observations o
JOIN image_platforms p ON p.image_id = o.image_id
JOIN scan_runs r ON r.image_platform_id = p.id AND r.status = 'done'
GROUP BY o.source_id, o.tag;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
