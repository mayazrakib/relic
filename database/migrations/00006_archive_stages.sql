CREATE TABLE archive_stages (
    stage_id TEXT NOT NULL PRIMARY KEY,
    capture_id TEXT NOT NULL REFERENCES captures(capture_id),
    payload_artifact_id TEXT NOT NULL REFERENCES payload_artifacts(artifact_id),
    storage_endpoint_id TEXT NOT NULL,
    storage_identity TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'sealed', 'abandoned')),
    manifest_digest TEXT NOT NULL,
    manifest_entry_count TEXT NOT NULL,
    payload_ciphertext_digest TEXT NOT NULL,
    file_count TEXT NOT NULL,
    payload_bytes TEXT NOT NULL,
    prepared_count TEXT NOT NULL DEFAULT '0',
    prepared_bytes TEXT NOT NULL DEFAULT '0',
    sealed_count TEXT NOT NULL DEFAULT '0',
    sealed_bytes TEXT NOT NULL DEFAULT '0',
    catalog_ciphertext_digest TEXT,
    catalog_ciphertext_bytes TEXT,
    catalog_identity TEXT,
    system_created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    system_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (effect_state != 'sealed' OR (catalog_ciphertext_digest IS NOT NULL AND catalog_ciphertext_bytes IS NOT NULL AND catalog_identity IS NOT NULL))
) STRICT;

CREATE TABLE archive_files (
    stage_id TEXT NOT NULL REFERENCES archive_stages(stage_id),
    file_id TEXT NOT NULL,
    header_digest TEXT NOT NULL,
    plaintext_bytes TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'sealed')),
    ciphertext_digest TEXT,
    ciphertext_bytes TEXT,
    identity TEXT,
    PRIMARY KEY (stage_id, file_id),
    CHECK (effect_state != 'sealed' OR (ciphertext_digest IS NOT NULL AND ciphertext_bytes IS NOT NULL AND identity IS NOT NULL))
) STRICT;

PRAGMA user_version = 6;
