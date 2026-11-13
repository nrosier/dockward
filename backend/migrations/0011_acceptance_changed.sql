-- Re-review flag for an accepted CVE (#196). When the severity or the fixed-in version of the
-- CVE changes, or a fix becomes available, the active acceptance is marked changed. Both
-- columns are empty until then. Older rows stay empty.
ALTER TABLE cve_acceptances ADD COLUMN changed_at INTEGER;
ALTER TABLE cve_acceptances ADD COLUMN change_reason TEXT;
