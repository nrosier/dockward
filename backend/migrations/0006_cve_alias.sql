-- The CVE alias of a GHSA finding (#323). Grype's related vulnerabilities can name the CVE id
-- of a GHSA id; the first `CVE-` id is stored here and shown beside the primary id. NULL when
-- the scanner names none. Set by the scan parser on each scanner finding and copied to the
-- cve_findings row of each tag.
ALTER TABLE scanner_findings ADD COLUMN alias TEXT;
ALTER TABLE cve_findings ADD COLUMN alias TEXT;
