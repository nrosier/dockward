-- Newest-digest close rule and manual close (#196). Decided 2026-11-06.
-- sync_reports.image_push_time: Harbor's push time of the scanned tag on that digest, in Unix
-- milliseconds. NULL for reports stored before this migration. The issue lifecycle picks the
-- newest scanned digest of a repository by this value.
ALTER TABLE sync_reports ADD COLUMN image_push_time INTEGER;
-- github_issues.closed_manually: 1 when HarborGate saw on GitHub that the issue was closed by
-- hand while the CVE was still reported. HarborGate does not reopen such an issue. Cleared
-- when HarborGate sets the status itself.
ALTER TABLE github_issues ADD COLUMN closed_manually INTEGER NOT NULL DEFAULT 0
    CHECK (closed_manually IN (0, 1));
