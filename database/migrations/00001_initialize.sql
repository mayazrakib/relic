CREATE TABLE jobs (
    job_id TEXT NOT NULL PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 2147483647),
    definition TEXT NOT NULL CHECK (json_valid(definition)),
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE publication_intents (
    commit_key TEXT NOT NULL PRIMARY KEY CHECK (json_valid(commit_key)),
    payload_hash TEXT NOT NULL,
    binding TEXT NOT NULL CHECK (json_valid(binding)),
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'admitted', 'published', 'unknown', 'verified')),
    native_result_id TEXT,
    receipt TEXT CHECK (receipt IS NULL OR json_valid(receipt)),
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE node_metadata (
    key TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL,
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE job_requests (
    request_key TEXT NOT NULL PRIMARY KEY,
    binding TEXT NOT NULL CHECK (json_valid(binding)),
    result TEXT NOT NULL CHECK (json_valid(result)),
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX publication_recovery ON publication_intents (effect_state, commit_key);

PRAGMA user_version = 1;
