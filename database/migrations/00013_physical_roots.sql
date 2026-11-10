CREATE TABLE physical_registry_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    inventory_complete INTEGER NOT NULL CHECK (inventory_complete IN (0, 1)),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    coordinator_identity TEXT
) STRICT;
INSERT INTO physical_registry_meta (singleton, inventory_complete)
SELECT 1, CASE WHEN EXISTS (SELECT 1 FROM manifest_artifacts)
    OR EXISTS (SELECT 1 FROM payload_artifacts)
    OR EXISTS (SELECT 1 FROM archive_stages)
    OR EXISTS (SELECT 1 FROM native_runs)
    OR EXISTS (SELECT 1 FROM restore_intents)
    OR EXISTS (SELECT 1 FROM gateway_resources)
    THEN 0 ELSE 1 END;
CREATE TABLE physical_roots (
    root_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('state', 'executable', 'staging', 'source', 'gateway', 'restore')),
    owner_id TEXT NOT NULL,
    physical_identity TEXT NOT NULL,
    observation TEXT NOT NULL CHECK (json_valid(observation)),
    UNIQUE (kind, owner_id, physical_identity)
) STRICT;
CREATE INDEX physical_roots_owner ON physical_roots (kind, owner_id);
PRAGMA user_version = 13;
