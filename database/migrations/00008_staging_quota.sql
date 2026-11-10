CREATE TABLE staging_quota_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    inventory_complete INTEGER NOT NULL CHECK (inventory_complete IN (0, 1))
) STRICT;

INSERT INTO staging_quota_metadata (singleton, inventory_complete)
SELECT 1, CASE WHEN EXISTS (SELECT 1 FROM manifest_artifacts)
    OR EXISTS (SELECT 1 FROM payload_artifacts)
    OR EXISTS (SELECT 1 FROM archive_stages)
    OR EXISTS (SELECT 1 FROM native_runs)
    THEN 0 ELSE 1 END;

CREATE TABLE staging_quota (
    object_kind TEXT NOT NULL CHECK (object_kind IN ('manifest', 'payload', 'archive_stage', 'native_run')),
    object_id TEXT NOT NULL,
    storage_endpoint_id TEXT NOT NULL,
    storage_identity TEXT NOT NULL,
    volume_identity TEXT NOT NULL,
    max_bytes INTEGER NOT NULL CHECK (max_bytes > 0),
    PRIMARY KEY (object_kind, object_id)
) STRICT;

CREATE INDEX staging_quota_volume ON staging_quota (volume_identity);
PRAGMA user_version = 8;
