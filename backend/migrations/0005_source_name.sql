-- The display name of a source (#323). Optional: null until one is set, and the UI falls back to
-- the repository. Set by the source form; the value is trimmed, at most 80 characters.
ALTER TABLE image_sources ADD COLUMN name TEXT;
