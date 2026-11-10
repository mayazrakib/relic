CREATE TABLE manifest_artifacts (
    artifact_id TEXT NOT NULL PRIMARY KEY,
    capture_id TEXT NOT NULL UNIQUE REFERENCES captures(capture_id),
    storage_endpoint_id TEXT NOT NULL,
    storage_identity TEXT NOT NULL,
    relative_name TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'sealed', 'abandoned')),
    ciphertext_digest TEXT,
    ciphertext_bytes TEXT,
    manifest_digest TEXT,
    manifest_entry_count TEXT,
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((effect_state = 'sealed') = (ciphertext_digest IS NOT NULL AND ciphertext_bytes IS NOT NULL AND manifest_digest IS NOT NULL AND manifest_entry_count IS NOT NULL)),
    CHECK (effect_state = 'sealed' OR (ciphertext_digest IS NULL AND ciphertext_bytes IS NULL AND manifest_digest IS NULL AND manifest_entry_count IS NULL))
) STRICT;

ALTER TABLE captures ADD COLUMN manifest_artifact_id TEXT REFERENCES manifest_artifacts(artifact_id);

CREATE INDEX manifest_artifacts_pending ON manifest_artifacts (artifact_id) WHERE effect_state = 'prepared';

PRAGMA user_version = 3;
