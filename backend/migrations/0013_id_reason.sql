-- #367: why a record is shown under a GHSA or GO id instead of a CVE id. NULL for a CVE id and
-- for a record whose id is linked to a CVE. Backfilled for the rows that exist.
ALTER TABLE cve_findings ADD COLUMN id_reason TEXT;

UPDATE cve_findings
SET id_reason = 'no CVE id published'
WHERE (cve_id LIKE 'GHSA-%' OR cve_id LIKE 'GO-%')
  AND alias IS NULL
  AND cve_id NOT IN (SELECT alias FROM vulnerability_aliases);
