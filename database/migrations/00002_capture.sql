CREATE TABLE captures (
    capture_id TEXT NOT NULL PRIMARY KEY,
    authority_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    source_view_id TEXT NOT NULL,
    consistency TEXT NOT NULL,
    source_selection_digest TEXT NOT NULL,
    manifest_digest TEXT,
    manifest_entry_count TEXT,
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (authority_id, job_id, occurrence_id),
    CHECK ((manifest_digest IS NULL) = (manifest_entry_count IS NULL))
) STRICT;

CREATE INDEX captures_pending ON captures (capture_id) WHERE manifest_digest IS NULL;

PRAGMA user_version = 2;
