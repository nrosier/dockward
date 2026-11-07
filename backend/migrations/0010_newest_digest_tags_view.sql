-- Newest-digest view (#196, decisions 21 to 23). One row per (mapping, image tag) for the tags of
-- the mapping's newest scanned digest: the digest of the successful sync_reports row with the
-- latest image_push_time (a report without a push time ranks last, then synced_at, then insert
-- order). This is the same choice as db::github_issues::newest_digest, which the issue close
-- rule uses. A tag of the newest digest is listed when any successful report of the mapping
-- names that digest and tag, so a clean newest digest still has its tags. A mapping with no
-- successful report has no row. The CVE list, the dashboard counts and the per-CVE tag table
-- read this view.
CREATE VIEW IF NOT EXISTS newest_digest_tags AS
WITH ranked AS (
    SELECT sr.mapping_id AS mapping_id, sr.image_digest AS image_digest,
           ROW_NUMBER() OVER (
               PARTITION BY sr.mapping_id
               ORDER BY sr.image_push_time IS NULL, sr.image_push_time DESC,
                        sr.synced_at DESC, sr.rowid DESC
           ) AS rn
    FROM sync_reports sr
    JOIN repo_mappings m ON m.id = sr.mapping_id AND m.harbor_repository = sr.harbor_repository
    WHERE sr.sarif_status = 'success'
)
SELECT DISTINCT sr.mapping_id AS mapping_id, sr.image_tag AS image_tag
FROM ranked r
JOIN sync_reports sr ON sr.mapping_id = r.mapping_id AND sr.image_digest = r.image_digest
JOIN repo_mappings m ON m.id = sr.mapping_id AND m.harbor_repository = sr.harbor_repository
WHERE r.rn = 1 AND sr.sarif_status = 'success';
