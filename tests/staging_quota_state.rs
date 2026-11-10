use std::sync::{Arc, Barrier};

use relic::staging_quota::{MAX_STAGING_BYTES, MIN_FREE_BYTES, StagingQuotaBinding};
use relic::state::{CaptureBinding, ManifestArtifactBinding, StateError, StateStore};

fn get_digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn create_manifest(store: &mut StateStore, suffix: &str, endpoint: &str, inode: u64) {
    let capture_id = format!("capture_{suffix}");
    store
        .bind_capture(&CaptureBinding {
            authority_id: "authority".into(),
            job_id: "job".into(),
            occurrence_id: format!("occurrence_{suffix}"),
            capture_id: capture_id.clone(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: get_digest(),
        })
        .unwrap();
    store
        .prepare_manifest_artifact(&ManifestArtifactBinding {
            artifact_id: format!("manifest_{suffix}"),
            capture_id,
            storage_endpoint_id: endpoint.into(),
            storage_identity: format!("unix:1:{inode}"),
            relative_name: format!("artifact_manifest_{suffix}.sealed"),
            key_ref: "key".into(),
        })
        .unwrap();
}

fn get_binding(suffix: &str, endpoint: &str, inode: u64, bytes: u64) -> StagingQuotaBinding {
    StagingQuotaBinding {
        object_kind: "manifest".into(),
        object_id: format!("manifest_{suffix}"),
        storage_endpoint_id: endpoint.into(),
        storage_identity: format!("unix:1:{inode}"),
        volume_identity: "unix:1".into(),
        max_bytes: bytes,
    }
}

#[test]
fn reserves_once_and_preserves_abandoned_charge_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    assert!(store.is_staging_quota_inventory_complete().unwrap());
    create_manifest(&mut store, "a", "alias_a", 11);
    let binding = get_binding("a", "alias_a", 11, 100);
    let record = store
        .reserve_staging_quota(&binding, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES)
        .unwrap();
    assert_eq!(
        store
            .reserve_staging_quota(&binding, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES)
            .unwrap(),
        record
    );
    assert!(matches!(
        store.reserve_staging_quota(&binding, 4 * MAX_STAGING_BYTES, MIN_FREE_BYTES),
        Err(StateError::QuotaExceeded)
    ));
    assert_eq!(store.get_staging_quota_usage().unwrap(), 100);
    let mut changed = binding.clone();
    changed.max_bytes = 101;
    assert!(matches!(
        store.reserve_staging_quota(&changed, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES),
        Err(StateError::IdempotencyConflict)
    ));
    store.abandon_manifest_artifact("manifest_a").unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.get_staging_quota("manifest", "manifest_a").unwrap(),
        Some(record)
    );
    assert_eq!(store.get_staging_quota_usage().unwrap(), 100);
}

#[test]
fn aliases_share_volume_free_space_reserve_and_failed_admission_does_not_charge() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_manifest(&mut store, "a", "alias_a", 11);
    create_manifest(&mut store, "b", "alias_b", 22);
    let capacity = 4 * MAX_STAGING_BYTES;
    let available = MIN_FREE_BYTES + 500 * 1024 * 1024;
    store
        .reserve_staging_quota(
            &get_binding("a", "alias_a", 11, 300 * 1024 * 1024),
            capacity,
            available,
        )
        .unwrap();
    let second = get_binding("b", "alias_b", 22, 250 * 1024 * 1024);
    assert!(matches!(
        store.reserve_staging_quota(&second, capacity, available),
        Err(StateError::QuotaExceeded)
    ));
    assert_eq!(store.get_staging_quota_usage().unwrap(), 300 * 1024 * 1024);
    assert!(
        store
            .get_staging_quota("manifest", "manifest_b")
            .unwrap()
            .is_none()
    );
    let mut forged = second;
    forged.volume_identity = "unix:2".into();
    assert!(matches!(
        store.reserve_staging_quota(&forged, capacity, capacity),
        Err(StateError::InvalidInput)
    ));
}

#[test]
fn separate_connections_cannot_admit_more_than_global_cap() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_manifest(&mut store, "a", "alias_a", 11);
    create_manifest(&mut store, "b", "alias_b", 22);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (suffix, alias, inode) in [("a", "alias_a", 11), ("b", "alias_b", 22)] {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut connection = StateStore::open(&path).unwrap();
            barrier.wait();
            connection
                .reserve_staging_quota(
                    &get_binding(suffix, alias, inode, 700 * 1024 * 1024),
                    8 * MAX_STAGING_BYTES,
                    8 * MAX_STAGING_BYTES,
                )
                .is_ok()
        }));
    }
    barrier.wait();
    let successes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|value| *value)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(store.get_staging_quota_usage().unwrap(), 700 * 1024 * 1024);
}

#[test]
fn migration_blocks_until_trusted_inventory_is_complete() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_manifest(&mut store, "a", "alias_a", 11);
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    connection
        .execute_batch(
            "DROP TABLE gateway_layouts; DROP TABLE gateway_executions; DROP TABLE gateway_admissions; DROP TABLE gateway_resources; DROP TABLE staging_quota; DROP TABLE staging_quota_metadata; ALTER TABLE native_runs DROP COLUMN worker_identity; ALTER TABLE native_runs DROP COLUMN operation_token; ALTER TABLE native_runs DROP COLUMN scope_protocol; PRAGMA user_version = 7;",
        )
        .unwrap();
    drop(connection);
    let mut store = StateStore::open(&path).unwrap();
    assert!(!store.is_staging_quota_inventory_complete().unwrap());
    let legacy = get_binding("a", "alias_a", 11, MAX_STAGING_BYTES + 1);
    assert!(matches!(
        store.reserve_staging_quota(&legacy, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES),
        Err(StateError::InventoryRequired)
    ));
    assert!(matches!(
        store.mark_staging_quota_inventory_complete(),
        Err(StateError::InventoryRequired)
    ));
    store
        .record_staging_quota_inventory(&legacy, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES)
        .unwrap();
    assert!(matches!(
        store.reserve_staging_quota(&legacy, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES),
        Err(StateError::InventoryRequired)
    ));
    store.mark_staging_quota_inventory_complete().unwrap();
    assert!(matches!(
        store.reserve_staging_quota(&legacy, 4 * MAX_STAGING_BYTES, 4 * MAX_STAGING_BYTES),
        Err(StateError::QuotaExceeded)
    ));
    assert_eq!(
        store.get_staging_quota_usage().unwrap(),
        MAX_STAGING_BYTES + 1
    );
    create_manifest(&mut store, "b", "alias_b", 22);
    assert!(matches!(
        store.reserve_staging_quota(
            &get_binding("b", "alias_b", 22, 1),
            4 * MAX_STAGING_BYTES,
            4 * MAX_STAGING_BYTES
        ),
        Err(StateError::QuotaExceeded)
    ));
}

#[test]
fn validates_owner_and_pages_without_unbounded_results() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_manifest(&mut store, "a", "alias_a", 11);
    create_manifest(&mut store, "b", "alias_b", 22);
    let mut invalid = get_binding("a", "alias_b", 11, 1);
    assert!(matches!(
        store.reserve_staging_quota(&invalid, MAX_STAGING_BYTES * 2, MAX_STAGING_BYTES * 2),
        Err(StateError::IdempotencyConflict)
    ));
    invalid = get_binding("a", "alias_a", 11, 0);
    assert!(matches!(
        store.reserve_staging_quota(&invalid, MAX_STAGING_BYTES * 2, MAX_STAGING_BYTES * 2),
        Err(StateError::InvalidInput)
    ));
    for binding in [
        get_binding("a", "alias_a", 11, 1),
        get_binding("b", "alias_b", 22, 2),
    ] {
        store
            .reserve_staging_quota(&binding, MAX_STAGING_BYTES * 2, MAX_STAGING_BYTES * 2)
            .unwrap();
    }
    let first = store.list_staging_quota("", "", 1).unwrap();
    assert_eq!(first[0].binding.object_id, "manifest_a");
    assert_eq!(
        store
            .list_staging_quota("manifest", "manifest_a", 1)
            .unwrap()[0]
            .binding
            .object_id,
        "manifest_b"
    );
    assert!(store.list_staging_quota("", "", 0).is_err());
}
