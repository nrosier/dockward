-- #366: which scanners reported each CVE, per image tag. A comma list of scanner keys
-- (`grype`, `trivy`) in the merged-view order, or NULL when unknown (rows stored before this
-- migration, or rows written by the Harbor sync).
ALTER TABLE cve_findings ADD COLUMN scanners TEXT;
