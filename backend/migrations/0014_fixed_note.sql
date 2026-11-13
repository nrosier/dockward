-- "Note only" (2026-11-13): Dockward no longer closes an issue when its CVE is fixed. It posts one
-- note and leaves the issue open. fixed_noted_at is the Unix-seconds time of that note, NULL when
-- no note stands. It is cleared when the CVE is reported again or the row status is set.
ALTER TABLE github_issues ADD COLUMN fixed_noted_at INTEGER;
