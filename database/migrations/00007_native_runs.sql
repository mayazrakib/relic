CREATE TABLE native_runs (
    run_id TEXT NOT NULL PRIMARY KEY,
    stage_id TEXT NOT NULL REFERENCES archive_stages(stage_id),
    storage_endpoint_id TEXT NOT NULL,
    storage_identity TEXT NOT NULL,
    relative_name TEXT NOT NULL,
    repository_key_ref TEXT NOT NULL,
    capture_id TEXT NOT NULL REFERENCES captures(capture_id),
    manifest_digest TEXT NOT NULL,
    manifest_entry_count TEXT NOT NULL,
    file_count TEXT NOT NULL,
    payload_bytes TEXT NOT NULL,
    source_catalog_digest TEXT NOT NULL,
    source_key_ref TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'staging', 'ready', 'running', 'unknown', 'verified', 'abandoned')),
    container_identity TEXT,
    repository_identity TEXT,
    owner_lock_identity TEXT,
    scratch_identity TEXT,
    native_snapshot_id TEXT,
    active_operation TEXT CHECK (active_operation IS NULL OR active_operation IN ('create', 'verify')),
    creation_attempts INTEGER NOT NULL DEFAULT 0 CHECK (creation_attempts BETWEEN 0 AND 1),
    verification_attempts TEXT NOT NULL DEFAULT '0',
    verification_failures INTEGER NOT NULL DEFAULT 0 CHECK (verification_failures BETWEEN 0 AND 3),
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (effect_state NOT IN ('staging', 'ready', 'running', 'unknown', 'verified') OR container_identity IS NOT NULL),
    CHECK (effect_state NOT IN ('ready', 'running', 'unknown', 'verified') OR (repository_identity IS NOT NULL AND owner_lock_identity IS NOT NULL AND scratch_identity IS NOT NULL)),
    CHECK ((effect_state = 'running') = (active_operation IS NOT NULL)),
    CHECK (effect_state != 'verified' OR native_snapshot_id IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX native_run_endpoint_reservation ON native_runs (storage_endpoint_id, relative_name) WHERE effect_state != 'abandoned';
CREATE UNIQUE INDEX native_run_physical_reservation ON native_runs (storage_identity, relative_name) WHERE effect_state != 'abandoned';
CREATE INDEX native_run_pending ON native_runs (run_id) WHERE effect_state NOT IN ('verified', 'abandoned');

PRAGMA user_version = 7;
