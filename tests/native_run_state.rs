use relic::state::{
    ArchiveStageBinding, CaptureBinding, ManifestArtifactBinding, NativeRunBinding,
    PayloadArtifactBinding, PayloadArtifactSeal, StateError, StateStore,
};

fn get_digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn get_stage(id: &str) -> ArchiveStageBinding {
    ArchiveStageBinding {
        stage_id: id.into(),
        capture_id: "capture".into(),
        payload_artifact_id: "payload".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity: "unix:1:2".into(),
        key_ref: "key".into(),
    }
}

fn create_capture(store: &mut StateStore) {
    store
        .bind_capture(&CaptureBinding {
            authority_id: "authority".into(),
            job_id: "job".into(),
            occurrence_id: "occurrence".into(),
            capture_id: "capture".into(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: get_digest('a'),
        })
        .unwrap();
}

fn create_sealed_capture(store: &mut StateStore) {
    create_capture(store);
    let manifest = ManifestArtifactBinding {
        artifact_id: "manifest".into(),
        capture_id: "capture".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity: "unix:1:2".into(),
        relative_name: "artifact_manifest.sealed".into(),
        key_ref: "key".into(),
    };
    store.prepare_manifest_artifact(&manifest).unwrap();
    store
        .seal_manifest_artifact("manifest", &get_digest('b'), 100, &get_digest('c'), 5)
        .unwrap();
    let payload = PayloadArtifactBinding {
        artifact_id: "payload".into(),
        capture_id: "capture".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity: "unix:1:2".into(),
        relative_name: "payload_payload.sealed".into(),
        key_ref: "key".into(),
    };
    store.prepare_payload_artifact(&payload).unwrap();
    store
        .seal_payload_artifact(
            "payload",
            &PayloadArtifactSeal {
                ciphertext_digest: get_digest('d'),
                ciphertext_bytes: 100,
                manifest_digest: get_digest('c'),
                manifest_entry_count: 5,
                file_count: 2,
                payload_bytes: 42,
            },
        )
        .unwrap();
}

fn create_sealed_stage(store: &mut StateStore) {
    create_sealed_capture(store);
    store.prepare_archive_stage(&get_stage("stage_1")).unwrap();
    store
        .prepare_archive_file("stage_1", "file_1", &get_digest('e'), 40)
        .unwrap();
    store
        .prepare_archive_file("stage_1", "file_2", &get_digest('f'), 2)
        .unwrap();
    store
        .seal_archive_file("stage_1", "file_1", &get_digest('1'), 100, "inode_1")
        .unwrap();
    store
        .seal_archive_file("stage_1", "file_2", &get_digest('2'), 100, "inode_2")
        .unwrap();
    store
        .seal_archive_stage("stage_1", &get_digest('3'), 100, "catalog_inode")
        .unwrap();
}

fn get_run(id: &str) -> NativeRunBinding {
    NativeRunBinding {
        run_id: id.into(),
        stage_id: "stage_1".into(),
        storage_endpoint_id: "native_endpoint".into(),
        storage_identity: "unix:1:3".into(),
        relative_name: format!("native_{id}"),
        repository_key_ref: "repository_key".into(),
    }
}

fn make_ready(store: &mut StateStore, id: &str) {
    store.prepare_native_run(&get_run(id)).unwrap();
    store.mark_native_staging(id, "container_inode").unwrap();
    store
        .mark_native_ready(id, "repository_inode", "lock_inode", "scratch_inode")
        .unwrap();
}

#[test]
fn requires_sealed_stage_and_binds_snapshot_immutably() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_capture(&mut store);
    store.prepare_archive_stage(&get_stage("stage_1")).unwrap();
    assert!(matches!(
        store.prepare_native_run(&get_run("run_1")),
        Err(StateError::EffectConflict)
    ));
    store
        .prepare_archive_file("stage_1", "file_1", &get_digest('e'), 40)
        .unwrap();
    store
        .prepare_archive_file("stage_1", "file_2", &get_digest('f'), 2)
        .unwrap();
    store
        .seal_archive_file("stage_1", "file_1", &get_digest('1'), 100, "inode_1")
        .unwrap();
    store
        .seal_archive_file("stage_1", "file_2", &get_digest('2'), 100, "inode_2")
        .unwrap();
    store
        .seal_archive_stage("stage_1", &get_digest('3'), 100, "catalog_inode")
        .unwrap();
    let binding = get_run("run_1");
    let record = store.prepare_native_run(&binding).unwrap();
    assert_eq!(record.manifest_digest, get_digest('c'));
    assert_eq!(record.source_catalog_digest, get_digest('3'));
    assert_eq!(record.file_count, "2");
    assert_eq!(store.prepare_native_run(&binding).unwrap(), record);
    let mut changed = binding.clone();
    changed.storage_identity = "unix:1:4".into();
    assert!(matches!(
        store.prepare_native_run(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    changed = binding;
    changed.run_id = "other".into();
    assert!(matches!(
        store.prepare_native_run(&changed),
        Err(StateError::InvalidInput)
    ));
}

#[test]
fn permits_one_creation_and_preserves_snapshot_through_unknown_verification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_sealed_stage(&mut store);
    make_ready(&mut store, "run_1");
    assert!(store.start_native_run("run_1", "verify").is_err());
    assert_eq!(
        store
            .start_native_run("run_1", "create")
            .unwrap()
            .creation_attempts,
        1
    );
    assert!(store.abandon_native_run("run_1").is_err());
    assert!(
        store
            .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 41)
            .is_err()
    );
    let sealed = store
        .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 42)
        .unwrap();
    assert_eq!(sealed.effect_state, "verified");
    assert_eq!(
        store
            .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 42)
            .unwrap(),
        sealed
    );
    assert!(store.start_native_run("run_1", "create").is_err());
    assert_eq!(
        store
            .start_native_run("run_1", "verify")
            .unwrap()
            .verification_attempts,
        1
    );
    let unknown = store.mark_native_unknown("run_1").unwrap();
    assert_eq!(unknown.verification_failures, 1);
    assert_eq!(
        unknown.native_snapshot_id.as_deref(),
        Some("a".repeat(64).as_str())
    );
    assert_eq!(store.mark_native_unknown("run_1").unwrap(), unknown);
    assert_eq!(
        store
            .mark_native_ready("run_1", "repository_inode", "lock_inode", "scratch_inode")
            .unwrap(),
        unknown
    );
    assert!(matches!(
        store.mark_native_ready("run_1", "other", "lock_inode", "scratch_inode"),
        Err(StateError::IdempotencyConflict)
    ));
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(reopened.get_native_run("run_1").unwrap(), Some(unknown));
}

#[test]
fn caps_failed_reverification_and_does_not_repeat_creation() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_stage(&mut store);
    make_ready(&mut store, "run_1");
    store.start_native_run("run_1", "create").unwrap();
    store.mark_native_unknown("run_1").unwrap();
    assert!(store.start_native_run("run_1", "create").is_err());
    for attempt in 1..=3 {
        let running = store.start_native_run("run_1", "verify").unwrap();
        assert_eq!(running.verification_attempts, attempt);
        let unknown = store.mark_native_unknown("run_1").unwrap();
        assert_eq!(unknown.verification_failures, attempt as u32);
        assert_eq!(store.mark_native_unknown("run_1").unwrap(), unknown);
    }
    assert!(store.start_native_run("run_1", "verify").is_err());
    assert_eq!(
        store.abandon_native_run("run_1").unwrap().effect_state,
        "abandoned"
    );
}

#[test]
fn paginates_pending_and_migrates_schema_six() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_sealed_stage(&mut store);
    store.prepare_native_run(&get_run("run_a")).unwrap();
    store.prepare_native_run(&get_run("run_b")).unwrap();
    assert_eq!(
        store.list_pending_native_runs("", 1).unwrap()[0]
            .binding
            .run_id,
        "run_a"
    );
    assert_eq!(
        store.list_pending_native_runs("run_a", 1).unwrap()[0]
            .binding
            .run_id,
        "run_b"
    );
    assert!(store.list_pending_native_runs("", 0).is_err());
    assert!(store.list_pending_native_runs("", 1001).is_err());
    store.abandon_native_run("run_a").unwrap();
    assert_eq!(store.list_pending_native_runs("", 10).unwrap().len(), 1);
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    connection
        .execute_batch("DROP TABLE gateway_layouts; DROP TABLE gateway_executions; DROP TABLE gateway_admissions; DROP TABLE gateway_resources; DROP TABLE staging_quota; DROP TABLE staging_quota_metadata; DROP TABLE native_runs; PRAGMA user_version = 6;")
        .unwrap();
    drop(connection);
    let store = StateStore::open(&path).unwrap();
    assert!(store.get_native_run("run_b").unwrap().is_none());
    assert!(store.get_archive_stage("stage_1").unwrap().is_some());
}

fn get_worker_identity(inode: u64) -> relic::worker_identity::WorkerIdentity {
    relic::worker_identity::WorkerIdentity {
        host_id: format!("sha256:{}", "a".repeat(64)),
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        cgroup_namespace_inode: 10,
        group_path: format!("/scope/worker_{}", "a".repeat(32)),
        group_inode: inode,
        parent_path: "/scope".into(),
        parent_inode: 11,
    }
}

#[test]
fn native_operation_scope_revokes_old_callbacks_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_sealed_stage(&mut store);
    make_ready(&mut store, "run_1");
    let first = store.start_native_run("run_1", "create").unwrap();
    assert_eq!(first.scope_protocol, 1);
    assert_eq!(first.operation_token.as_deref(), Some("create:1"));
    let identity = get_worker_identity(12);
    let bound = store
        .bind_native_run_worker("run_1", "create", "create:1", &identity)
        .unwrap();
    assert_eq!(bound.worker_identity.as_ref(), Some(&identity));
    assert_eq!(
        store
            .bind_native_run_worker("run_1", "create", "create:1", &identity)
            .unwrap(),
        bound
    );
    assert!(matches!(
        store.bind_native_run_worker("run_1", "create", "create:1", &get_worker_identity(13)),
        Err(StateError::IdempotencyConflict)
    ));
    store
        .mark_native_unknown_for_operation("run_1", "create", "create:1")
        .unwrap();
    assert!(
        store
            .bind_native_run_worker("run_1", "create", "create:1", &identity)
            .is_err()
    );
    drop(store);
    let mut store = StateStore::open(&path).unwrap();
    assert_eq!(
        store
            .get_native_run("run_1")
            .unwrap()
            .unwrap()
            .worker_identity
            .as_ref(),
        Some(&identity)
    );
    // The trusted controller must first quiesce the retained CREATE scope.
    let verify = store.start_native_run("run_1", "verify").unwrap();
    assert_eq!(verify.operation_token.as_deref(), Some("verify:1"));
    assert!(verify.worker_identity.is_none());
    assert!(
        store
            .bind_native_run_worker("run_1", "create", "create:1", &identity)
            .is_err()
    );
    assert!(
        store
            .mark_native_unknown_for_operation("run_1", "create", "create:1")
            .is_err()
    );
    store
        .bind_native_run_worker("run_1", "verify", "verify:1", &get_worker_identity(14))
        .unwrap();
    store
        .mark_native_unknown_for_operation("run_1", "verify", "verify:1")
        .unwrap();
    let verify = store.start_native_run("run_1", "verify").unwrap();
    assert_eq!(verify.operation_token.as_deref(), Some("verify:2"));
    assert!(
        store
            .bind_native_run_worker("run_1", "verify", "verify:1", &identity)
            .is_err()
    );
    assert!(
        store
            .seal_native_run_for_operation(
                "run_1",
                "verify",
                "verify:1",
                &"a".repeat(64),
                &get_digest('c'),
                5,
                2,
                42
            )
            .is_err()
    );
}

#[test]
fn migration_keeps_legacy_running_scope_explicitly_unrecorded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_sealed_stage(&mut store);
    make_ready(&mut store, "run_1");
    store.start_native_run("run_1", "create").unwrap();
    make_ready(&mut store, "run_2");
    store.start_native_run("run_2", "create").unwrap();
    store.mark_native_unknown("run_2").unwrap();
    drop(store);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch("ALTER TABLE native_runs DROP COLUMN worker_identity; ALTER TABLE native_runs DROP COLUMN operation_token; ALTER TABLE native_runs DROP COLUMN scope_protocol; PRAGMA user_version=11;").unwrap();
    drop(db);
    let mut store = StateStore::open(&path).unwrap();
    let legacy = store.get_native_run("run_1").unwrap().unwrap();
    assert_eq!(legacy.effect_state, "running");
    assert_eq!(legacy.scope_protocol, 0);
    assert!(legacy.operation_token.is_none());
    assert!(legacy.worker_identity.is_none());
    assert!(
        store
            .bind_native_run_worker("run_1", "create", "create:1", &get_worker_identity(12))
            .is_err()
    );
    assert!(
        store
            .mark_native_unknown_for_operation("run_1", "create", "create:1")
            .is_err()
    );
    let legacy_unknown = store.get_native_run("run_2").unwrap().unwrap();
    assert_eq!(legacy_unknown.effect_state, "unknown");
    assert_eq!(legacy_unknown.scope_protocol, 0);
    assert!(legacy_unknown.worker_identity.is_none());
}

#[test]
fn unknown_transition_revokes_an_unbound_prefork_callback() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_stage(&mut store);
    make_ready(&mut store, "run_1");
    store.start_native_run("run_1", "create").unwrap();
    let unknown = store
        .mark_native_unknown_for_operation("run_1", "create", "create:1")
        .unwrap();
    assert!(unknown.worker_identity.is_none());
    assert!(
        store
            .bind_native_run_worker("run_1", "create", "create:1", &get_worker_identity(12))
            .is_err()
    );
    assert_eq!(store.get_native_run("run_1").unwrap().unwrap(), unknown);
}
