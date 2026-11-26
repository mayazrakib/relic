CREATE TABLE restore_intents (
    restore_id TEXT NOT NULL PRIMARY KEY,
    capture_id TEXT NOT NULL REFERENCES captures(capture_id),
    payload_artifact_id TEXT NOT NULL REFERENCES payload_artifacts(artifact_id),
    target_endpoint_id TEXT NOT NULL,
    target_identity TEXT NOT NULL,
    relative_name TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'staging', 'verified', 'published', 'abandoned')),
    manifest_digest TEXT NOT NULL,
    payload_ciphertext_digest TEXT NOT NULL,
    manifest_entry_count TEXT NOT NULL,
    file_count TEXT NOT NULL,
    payload_bytes TEXT NOT NULL,
    staging_identity TEXT,
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (effect_state NOT IN ('staging', 'verified', 'published') OR staging_identity IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX restore_target_reservation ON restore_intents (target_endpoint_id, relative_name) WHERE effect_state IN ('prepared', 'staging', 'verified', 'published');
CREATE UNIQUE INDEX restore_physical_target_reservation ON restore_intents (target_identity, relative_name) WHERE effect_state IN ('prepared', 'staging', 'verified', 'published');
CREATE INDEX restore_pending ON restore_intents (restore_id) WHERE effect_state IN ('prepared', 'staging', 'verified');

PRAGMA user_version = 5;
