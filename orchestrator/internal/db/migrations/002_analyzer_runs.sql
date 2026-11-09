-- One row per analyzer per job: whether it answered, its non-fatal notes, and how long it took.
-- An analyzer that fails never fails the job; this is where that shows.

CREATE TABLE analyzer_runs (
    job_id      TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    analyzer    TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('ok', 'unimplemented', 'failed')),
    error       TEXT NOT NULL DEFAULT '',
    -- JSON array of strings.
    notes       TEXT NOT NULL DEFAULT '[]',
    findings    INTEGER NOT NULL DEFAULT 0 CHECK (findings >= 0),
    duration_ms INTEGER NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
    PRIMARY KEY (job_id, analyzer)
) STRICT;
