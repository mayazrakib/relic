CREATE TABLE gateway_layouts (
    resource_id TEXT PRIMARY KEY REFERENCES gateway_resources(resource_id),
    owner_identity TEXT,
    scratch_identity TEXT,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'ready', 'initializing', 'unknown', 'initialized')),
    initialization_attempts INTEGER NOT NULL DEFAULT 0 CHECK (initialization_attempts BETWEEN 0 AND 1),
    initialization_epoch TEXT,
    initialization_fence TEXT,
    launch_protocol INTEGER NOT NULL DEFAULT 0 CHECK (launch_protocol BETWEEN 0 AND 1),
    containment TEXT,
    CHECK ((initialization_attempts = 0 AND launch_protocol = 0 AND containment IS NULL) OR (initialization_attempts = 1 AND launch_protocol = 1)),
    CHECK (scratch_identity IS NULL OR owner_identity IS NOT NULL),
    CHECK (effect_state = 'prepared' OR (owner_identity IS NOT NULL AND scratch_identity IS NOT NULL)),
    CHECK ((initialization_attempts = 0 AND initialization_epoch IS NULL AND initialization_fence IS NULL)
        OR (initialization_attempts = 1 AND initialization_epoch IS NOT NULL AND initialization_fence IS NOT NULL)),
    CHECK ((effect_state IN ('prepared', 'ready')) = (initialization_attempts = 0))
) STRICT;

ALTER TABLE gateway_executions ADD COLUMN worker_identity TEXT;

PRAGMA user_version = 10;
