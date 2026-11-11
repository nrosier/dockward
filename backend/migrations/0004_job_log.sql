-- Per-step log of a scanner job (#308). One row per scanner step (a database download, or a
-- scan). `attempt` is the job attempt the step ran in; the log route serves the latest attempt.
-- Lines hold the redacted stderr tail of the step, and stdout only for an update step. A scan's
-- stdout is the report and is never stored here. Rows are removed with their job (ON DELETE
-- CASCADE), so the logs follow jobs retention.
CREATE TABLE IF NOT EXISTS job_log_steps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  attempt INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  command TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  timeout_secs INTEGER NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('running','ok','failed','timed_out','output_too_large','spawn_failed')),
  exit_code INTEGER,
  truncated INTEGER NOT NULL DEFAULT 0,
  UNIQUE (job_id, attempt, seq));
CREATE TABLE IF NOT EXISTS job_log_lines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  step_id TEXT NOT NULL REFERENCES job_log_steps(id) ON DELETE CASCADE,
  at INTEGER NOT NULL,
  stream TEXT NOT NULL CHECK (stream IN ('stderr','stdout')),
  text TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS job_log_lines_step ON job_log_lines(step_id, id);
-- The job a run was recorded for (#308). NULL for a run recorded before this migration, and for
-- a run with no job.
ALTER TABLE job_runs ADD COLUMN job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL;
