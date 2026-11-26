CREATE TABLE gateway_resources (
    resource_id TEXT PRIMARY KEY,
    storage_identity TEXT NOT NULL UNIQUE,
    binding TEXT NOT NULL,
    receiver_epoch TEXT NOT NULL,
    fence_generation TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'ready', 'blocked')),
    repository_id TEXT
) STRICT;

CREATE TABLE gateway_admissions (
    admission_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES gateway_resources(resource_id),
    commit_key TEXT NOT NULL UNIQUE REFERENCES publication_intents(commit_key),
    binding TEXT NOT NULL,
    receiver_epoch TEXT NOT NULL,
    fence_generation TEXT NOT NULL,
    request_type TEXT NOT NULL CHECK (request_type = 'publication'),
    admission_decision TEXT NOT NULL CHECK (admission_decision = 'accepted'),
    UNIQUE (resource_id, commit_key)
) STRICT;

CREATE TABLE gateway_executions (
    admission_id TEXT NOT NULL REFERENCES gateway_admissions(admission_id),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
    resource_id TEXT NOT NULL REFERENCES gateway_resources(resource_id),
    receiver_epoch TEXT NOT NULL,
    fence_generation TEXT NOT NULL,
    effect_state TEXT NOT NULL CHECK (effect_state IN ('active', 'unknown', 'published_unverified', 'verified', 'proven_unpublished')),
    native_result_id TEXT,
    PRIMARY KEY (admission_id, ordinal)
) STRICT;

CREATE UNIQUE INDEX gateway_one_unresolved ON gateway_executions(resource_id)
    WHERE effect_state IN ('active', 'unknown', 'published_unverified');
CREATE INDEX gateway_pending ON gateway_admissions(resource_id, admission_id);

PRAGMA user_version = 9;
