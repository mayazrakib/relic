ALTER TABLE native_runs ADD COLUMN scope_protocol INTEGER NOT NULL DEFAULT 0 CHECK (scope_protocol BETWEEN 0 AND 1);
ALTER TABLE native_runs ADD COLUMN operation_token TEXT;
ALTER TABLE native_runs ADD COLUMN worker_identity TEXT;
PRAGMA user_version = 12;
