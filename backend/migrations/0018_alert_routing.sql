-- #458: alert routing. Each alert channel receives only the events ticked for it.
--
-- alert_channels.events is a JSON array of event names: job_failed, new_high_or_critical,
-- cve_fixed. Every channel that exists before this migration gets ["job_failed"], the one event
-- that was sent before, so its behaviour does not change. No secret is held in the column.
ALTER TABLE alert_channels ADD COLUMN events TEXT NOT NULL DEFAULT '["job_failed"]'
    CHECK (json_valid(events) AND json_type(events) = 'array');

-- CVE changes found by the convert step and not yet alerted. One scan of an image is several
-- scan runs (one per scanner and platform), each its own job, so a change is recorded here in the
-- transaction that stores its run, and the alert is sent once every run of the image has ended:
-- one summary of the new CVEs per source, and one alert per fixed CVE. A row is deleted when it
-- is read for sending. Ids, tags and CVE ids only; never a secret or an upstream body.
CREATE TABLE IF NOT EXISTS alert_pending (
    id INTEGER PRIMARY KEY,
    event TEXT NOT NULL CHECK (event IN ('new_high_or_critical', 'cve_fixed')),
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES image_sources(id) ON DELETE CASCADE,
    image_tag TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (event, image_id, source_id, image_tag, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_pending_image ON alert_pending (image_id);
