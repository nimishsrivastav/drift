-- Enums are stored by their proto names, so that the database reads on its own.
-- Full messages are stored as protojson, with only the columns we filter on broken out.

CREATE TABLE jobs (
    id             TEXT PRIMARY KEY,
    -- Set for dependency sub-jobs, which go away with their parent.
    parent_job_id  TEXT REFERENCES jobs (id) ON DELETE CASCADE,
    depth          INTEGER NOT NULL DEFAULT 0,
    ecosystem      TEXT NOT NULL,
    package        TEXT NOT NULL,
    -- What was asked for, before version resolution. Empty means "work it out".
    requested_from TEXT NOT NULL DEFAULT '',
    requested_to   TEXT NOT NULL DEFAULT '',
    -- What resolution found. old_version stays NULL in new-package mode.
    old_version    TEXT,
    new_version    TEXT,
    status         TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'ingesting', 'ingested', 'analyzing', 'done', 'failed')),
    artifact_pair  TEXT,
    error          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    CHECK (depth >= 0),
    -- Depth 0 is the package being updated. Every sub-job has a parent.
    CHECK ((parent_job_id IS NULL) = (depth = 0))
) STRICT;

CREATE INDEX jobs_parent ON jobs (parent_job_id);
CREATE INDEX jobs_status ON jobs (status);
-- Dependency expansion caches verdicts by (ecosystem, name, version).
CREATE INDEX jobs_package_version ON jobs (ecosystem, package, new_version);

CREATE TABLE findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id         TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    analyzer       TEXT NOT NULL,
    kind           TEXT NOT NULL,
    capability     TEXT NOT NULL,
    context        TEXT NOT NULL,
    confidence     REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    via_dependency TEXT NOT NULL DEFAULT '',
    finding        TEXT NOT NULL
) STRICT;

CREATE INDEX findings_job ON findings (job_id);

CREATE TABLE reports (
    job_id      TEXT PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    score       REAL NOT NULL,
    verdict     TEXT NOT NULL
        CHECK (verdict IN ('VERDICT_BENIGN', 'VERDICT_REVIEW', 'VERDICT_SUSPICIOUS')),
    explanation TEXT NOT NULL,
    report      TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE INDEX reports_verdict ON reports (verdict);
