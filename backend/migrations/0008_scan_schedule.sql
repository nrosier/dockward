-- Scheduled Harbor scan per mapping (#191, decided 2026-11-06). Off by default.
-- scan_schedule: 'off', 'daily' or 'weekly'. Times are UTC.
-- scan_minute: minute of the UTC day the run is due, 0 (00:00) to 1439 (23:59).
-- scan_weekday: ISO weekday of a weekly run, 1 (Monday) to 7 (Sunday). Ignored unless weekly.
-- scan_last_slot: Unix seconds of the last slot the scheduler handled. Set to the save time
-- when the schedule changes, so a slot already in the past never fires. NULL until then.
ALTER TABLE repo_mappings ADD COLUMN scan_schedule TEXT NOT NULL DEFAULT 'off'
    CHECK (scan_schedule IN ('off', 'daily', 'weekly'));
ALTER TABLE repo_mappings ADD COLUMN scan_minute INTEGER NOT NULL DEFAULT 0
    CHECK (scan_minute BETWEEN 0 AND 1439);
ALTER TABLE repo_mappings ADD COLUMN scan_weekday INTEGER NOT NULL DEFAULT 1
    CHECK (scan_weekday BETWEEN 1 AND 7);
ALTER TABLE repo_mappings ADD COLUMN scan_last_slot INTEGER;
-- sync_reports.cve_ids: JSON array of the distinct CVE ids in the scan, sorted. Written when the
-- report succeeds. NULL for reports stored before this migration. It is the stored result a
-- later scan of the same digest is compared with.
ALTER TABLE sync_reports ADD COLUMN cve_ids TEXT;
-- sync_reports.new_cve_ids: JSON array of the ids not in the last stored result for the same
-- digest. Set only for a sync started by a scheduled scan; NULL otherwise.
ALTER TABLE sync_reports ADD COLUMN new_cve_ids TEXT;
