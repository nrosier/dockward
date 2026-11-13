-- Whether a finished job produced nothing new (#360): an unchanged pull, or a discovery that
-- recorded no new tag. The Jobs dashboard can hide these. Older rows are not empty (0).
ALTER TABLE jobs ADD COLUMN empty INTEGER NOT NULL DEFAULT 0 CHECK (empty IN (0, 1));
