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
        .execute_batch("DROP TABLE staging_quota; DROP TABLE staging_quota_metadata; DROP TABLE native_runs; PRAGMA user_version = 6;")
        .unwrap();
    drop(connection);
    let store = StateStore::open(&path).unwrap();
    assert!(store.get_native_run("run_b").unwrap().is_none());
    assert!(store.get_archive_stage("stage_1").unwrap().is_some());
}
