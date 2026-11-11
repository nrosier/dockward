-- The scanner a db_update run refreshed (#308). NULL for every other run kind, and for runs
-- recorded before this migration. Trivy and Grype are the only scanner keys.
ALTER TABLE job_runs ADD COLUMN scanner TEXT CHECK (scanner IS NULL OR scanner IN ('trivy', 'grype'));
