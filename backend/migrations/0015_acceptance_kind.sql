-- False positive (2026-11-13, user, "Record and comment"): a verdict on a CVE is either an
-- accepted risk or a false positive. Both live in cve_acceptances and share the partial unique
-- index idx_cve_acceptances_active, so a source has at most one active verdict per CVE. Rows
-- written before this migration are accepted risks.
ALTER TABLE cve_acceptances ADD COLUMN kind TEXT NOT NULL DEFAULT 'accepted'
    CHECK (kind IN ('accepted', 'false_positive'));
