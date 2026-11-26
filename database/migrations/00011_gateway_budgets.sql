ALTER TABLE gateway_executions ADD COLUMN verify_attempts INTEGER NOT NULL DEFAULT 0 CHECK (verify_attempts BETWEEN 0 AND 3);
ALTER TABLE gateway_executions ADD COLUMN verification_worker_identity TEXT;

ALTER TABLE staging_quota RENAME TO staging_quota_v10;
CREATE TABLE staging_quota (
    object_kind TEXT NOT NULL CHECK (object_kind IN ('manifest', 'payload', 'archive_stage', 'native_run', 'gateway_scratch')),
    object_id TEXT NOT NULL,
    storage_endpoint_id TEXT NOT NULL,
    storage_identity TEXT NOT NULL,
    volume_identity TEXT NOT NULL,
    max_bytes INTEGER NOT NULL CHECK (max_bytes > 0),
    PRIMARY KEY (object_kind, object_id)
) STRICT;
INSERT INTO staging_quota (object_kind, object_id, storage_endpoint_id, storage_identity, volume_identity, max_bytes)
SELECT object_kind, object_id, storage_endpoint_id, storage_identity, volume_identity, max_bytes FROM staging_quota_v10;
DROP TABLE staging_quota_v10;
CREATE INDEX staging_quota_volume ON staging_quota (volume_identity);
UPDATE staging_quota_metadata SET inventory_complete = 0
WHERE EXISTS (SELECT 1 FROM gateway_layouts WHERE scratch_identity IS NOT NULL);
PRAGMA user_version = 11;
