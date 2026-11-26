-- Destination growth is separate from retained repository bytes and staging quota.
CREATE TABLE destination_growth_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    inventory_complete INTEGER NOT NULL CHECK (inventory_complete IN (0, 1))
) STRICT;

INSERT INTO destination_growth_metadata (singleton, inventory_complete)
SELECT 1, CASE WHEN EXISTS (
    SELECT 1 FROM gateway_layouts WHERE effect_state IN ('initializing', 'unknown')
) OR EXISTS (
    SELECT 1 FROM gateway_executions
    WHERE effect_state IN ('active', 'unknown', 'published_unverified')
) THEN 0 ELSE 1 END;

CREATE TABLE destination_growth (
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('initialization', 'copy')),
    operation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 3),
    resource_id TEXT NOT NULL REFERENCES gateway_resources(resource_id),
    storage_identity TEXT NOT NULL,
    volume_identity TEXT NOT NULL,
    receiver_epoch TEXT NOT NULL,
    fence_generation TEXT NOT NULL,
    max_bytes INTEGER NOT NULL CHECK (max_bytes BETWEEN 1 AND 536870912),
    effect_state TEXT NOT NULL CHECK (effect_state IN ('held', 'released')),
    PRIMARY KEY (operation_kind, operation_id, ordinal),
    CHECK ((operation_kind = 'initialization' AND ordinal = 0 AND operation_id = resource_id)
        OR (operation_kind = 'copy' AND ordinal BETWEEN 1 AND 3))
) STRICT;
CREATE INDEX destination_growth_volume ON destination_growth (volume_identity, effect_state);
PRAGMA user_version = 14;
