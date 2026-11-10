use relic::gateway_state::GatewayResourceBinding;
use relic::staging_quota::StagingQuotaBinding;
use relic::state::{CaptureBinding, ManifestArtifactBinding, StateError, StateStore};
use relic::worker_identity::WorkerIdentity;
use std::path::Path;

const SCRATCH: u64 = 8 * 1024 * 1024;
fn get_resource() -> GatewayResourceBinding {
    GatewayResourceBinding {
        resource_id: "resource".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: "unix:1:10".into(),
        repository_key_ref: "key".into(),
    }
}
fn get_identity(inode: u64) -> WorkerIdentity {
    WorkerIdentity {
        host_id: format!("sha256:{}", "a".repeat(64)),
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        cgroup_namespace_inode: 1,
        group_path: format!("/scope/worker_{}", "a".repeat(32)),
        group_inode: inode,
        parent_path: "/scope".into(),
        parent_inode: 2,
    }
}
fn create_execution(path: &Path) -> StateStore {
    let mut store = StateStore::open(path).unwrap();
    store.prepare_gateway_resource(&get_resource()).unwrap();
    drop(store);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch("UPDATE gateway_resources SET effect_state='ready',repository_id='repository' WHERE resource_id='resource'; INSERT INTO publication_intents(commit_key,payload_hash,binding,effect_state) VALUES('{}','payload','{}','unknown'); INSERT INTO gateway_admissions(admission_id,resource_id,commit_key,binding,receiver_epoch,fence_generation,request_type,admission_decision) VALUES('admission','resource','{}','{}','1','1','publication','accepted'); INSERT INTO gateway_executions(admission_id,ordinal,resource_id,receiver_epoch,fence_generation,effect_state) VALUES('admission',1,'resource','1','1','unknown');").unwrap();
    drop(db);
    StateStore::open(path).unwrap()
}
fn get_scratch() -> StagingQuotaBinding {
    StagingQuotaBinding {
        object_kind: "gateway_scratch".into(),
        object_id: "resource".into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: "unix:1:12".into(),
        volume_identity: "unix:1".into(),
        max_bytes: SCRATCH,
    }
}
fn create_bound_scratch(store: &mut StateStore) {
    store.prepare_gateway_resource(&get_resource()).unwrap();
    store.prepare_gateway_layout("resource").unwrap();
    store.bind_gateway_owner("resource", "unix:1:11").unwrap();
    store.bind_gateway_scratch("resource", "unix:1:12").unwrap();
    store.seal_gateway_layout("resource").unwrap();
}

#[test]
fn verification_attempts_and_worker_scope_are_durable_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = create_execution(&path);
    assert!(
        store
            .start_gateway_verification("admission", 1, 1, 2)
            .is_err()
    );
    let first = store
        .start_gateway_verification("admission", 1, 1, 1)
        .unwrap();
    assert_eq!(first.verify_attempts, 1);
    let identity = get_identity(3);
    let bound = store
        .bind_gateway_verification_worker("admission", 1, 1, 1, 1, &identity)
        .unwrap();
    assert_eq!(bound.verification_worker_identity.as_ref(), Some(&identity));
    assert_eq!(
        store
            .bind_gateway_verification_worker("admission", 1, 1, 1, 1, &identity)
            .unwrap(),
        bound
    );
    assert!(matches!(
        store.bind_gateway_verification_worker("admission", 1, 1, 1, 1, &get_identity(4)),
        Err(StateError::IdempotencyConflict)
    ));
    drop(store);
    let mut store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.list_gateway_executions("admission").unwrap()[0]
            .verification_worker_identity
            .as_ref(),
        Some(&identity)
    );
    store.block_gateway_resource("resource", 1, 1).unwrap();
    // Trusted caller must establish prior scope quiescence before incrementing.
    let second = store
        .start_gateway_verification("admission", 1, 1, 1)
        .unwrap();
    assert_eq!(second.verify_attempts, 2);
    assert!(second.verification_worker_identity.is_none());
    assert!(
        store
            .bind_gateway_verification_worker("admission", 1, 1, 1, 1, &identity)
            .is_err()
    );
    store
        .bind_gateway_verification_worker("admission", 1, 1, 1, 2, &get_identity(5))
        .unwrap();
    assert_eq!(
        store
            .start_gateway_verification("admission", 1, 1, 1)
            .unwrap()
            .verify_attempts,
        3
    );
    assert!(
        store
            .start_gateway_verification("admission", 1, 1, 1)
            .is_err()
    );
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.list_gateway_executions("admission").unwrap()[0].verify_attempts,
        3
    );
}

#[test]
fn scratch_reservation_is_fixed_bound_and_retained() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_bound_scratch(&mut store);
    let binding = get_scratch();
    let mut invalid = binding.clone();
    invalid.max_bytes = SCRATCH - 1;
    assert!(matches!(
        store.reserve_staging_quota(&invalid, 4_000_000_000, 4_000_000_000),
        Err(StateError::InvalidInput)
    ));
    let mut invalid = binding.clone();
    invalid.storage_identity = "unix:1:13".into();
    assert!(matches!(
        store.reserve_staging_quota(&invalid, 4_000_000_000, 4_000_000_000),
        Err(StateError::IdempotencyConflict)
    ));
    store
        .reserve_staging_quota(&binding, 4_000_000_000, 4_000_000_000)
        .unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.get_staging_quota_usage().unwrap(), SCRATCH);
    assert_eq!(
        store
            .get_staging_quota("gateway_scratch", "resource")
            .unwrap()
            .unwrap()
            .binding,
        binding
    );
}

#[test]
fn schema_ten_bound_scratch_closes_inventory_until_trusted_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_bound_scratch(&mut store);
    store
        .bind_capture(&CaptureBinding {
            authority_id: "authority".into(),
            job_id: "job".into(),
            occurrence_id: "occurrence".into(),
            capture_id: "capture".into(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: format!("sha256:{}", "a".repeat(64)),
        })
        .unwrap();
    store
        .prepare_manifest_artifact(&ManifestArtifactBinding {
            artifact_id: "manifest".into(),
            capture_id: "capture".into(),
            storage_endpoint_id: "endpoint".into(),
            storage_identity: "unix:1:20".into(),
            relative_name: "artifact_manifest.sealed".into(),
            key_ref: "key".into(),
        })
        .unwrap();
    let legacy = StagingQuotaBinding {
        object_kind: "manifest".into(),
        object_id: "manifest".into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: "unix:1:20".into(),
        volume_identity: "unix:1".into(),
        max_bytes: 99,
    };
    store
        .reserve_staging_quota(&legacy, 4_000_000_000, 4_000_000_000)
        .unwrap();
    drop(store);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch(
        "ALTER TABLE gateway_executions DROP COLUMN verification_worker_identity;
         ALTER TABLE gateway_executions DROP COLUMN verify_attempts;
         DROP INDEX staging_quota_volume;
         ALTER TABLE staging_quota RENAME TO staging_quota_future;
         CREATE TABLE staging_quota (
           object_kind TEXT NOT NULL CHECK (object_kind IN ('manifest','payload','archive_stage','native_run')),
           object_id TEXT NOT NULL, storage_endpoint_id TEXT NOT NULL, storage_identity TEXT NOT NULL,
           volume_identity TEXT NOT NULL, max_bytes INTEGER NOT NULL CHECK(max_bytes>0),
           PRIMARY KEY(object_kind,object_id)
         ) STRICT;
         INSERT INTO staging_quota SELECT * FROM staging_quota_future;
         DROP TABLE staging_quota_future;
         CREATE INDEX staging_quota_volume ON staging_quota(volume_identity);
         DROP TABLE physical_roots; DROP TABLE physical_registry_meta; ALTER TABLE native_runs DROP COLUMN worker_identity; ALTER TABLE native_runs DROP COLUMN operation_token; ALTER TABLE native_runs DROP COLUMN scope_protocol; PRAGMA user_version=10;",
    ).unwrap();
    drop(db);
    let mut store = StateStore::open(&path).unwrap();
    assert!(!store.is_staging_quota_inventory_complete().unwrap());
    assert_eq!(
        store
            .get_staging_quota("manifest", "manifest")
            .unwrap()
            .unwrap()
            .binding,
        legacy
    );
    assert!(matches!(
        store.reserve_staging_quota(&get_scratch(), 4_000_000_000, 4_000_000_000),
        Err(StateError::InventoryRequired)
    ));
    assert!(matches!(
        store.mark_staging_quota_inventory_complete(),
        Err(StateError::InventoryRequired)
    ));
    // Physical scratch inspection is the trusted caller's responsibility.
    store
        .record_staging_quota_inventory(&get_scratch(), 4_000_000_000, 4_000_000_000)
        .unwrap();
    store.mark_staging_quota_inventory_complete().unwrap();
    assert_eq!(store.get_staging_quota_usage().unwrap(), SCRATCH + 99);
}
