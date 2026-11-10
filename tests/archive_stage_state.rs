use relic::state::{
    ArchiveStageBinding, CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding,
    PayloadArtifactSeal, StateError, StateStore,
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

#[test]
fn requires_sealed_linked_artifacts_and_immutable_stage() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_capture(&mut store);
    let binding = get_stage("stage_1");
    assert!(matches!(
        store.prepare_archive_stage(&binding),
        Err(StateError::EffectConflict)
    ));
    drop(store);

    let other = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&other.path().join("state")).unwrap();
    create_sealed_capture(&mut store);
    let stage = store.prepare_archive_stage(&binding).unwrap();
    assert_eq!(stage.file_count, "2");
    assert_eq!(stage.payload_bytes, "42");
    assert_eq!(stage.payload_ciphertext_digest, get_digest('d'));
    assert_eq!(store.prepare_archive_stage(&binding).unwrap(), stage);
    let mut changed = binding.clone();
    changed.key_ref = "other".into();
    assert!(matches!(
        store.prepare_archive_stage(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    changed.stage_id = "bad.id".into();
    assert!(matches!(
        store.prepare_archive_stage(&changed),
        Err(StateError::InvalidInput)
    ));
}

#[test]
fn checks_file_bounds_replay_seal_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_sealed_capture(&mut store);
    store.prepare_archive_stage(&get_stage("stage_1")).unwrap();
    let first = store
        .prepare_archive_file("stage_1", "file_1", &get_digest('e'), 40)
        .unwrap();
    assert_eq!(
        store
            .prepare_archive_file("stage_1", "file_1", &get_digest('e'), 40)
            .unwrap(),
        first
    );
    assert!(matches!(
        store.prepare_archive_file("stage_1", "file_1", &get_digest('e'), 41),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(
        store
            .prepare_archive_file("stage_1", "file_2", &get_digest('e'), 3)
            .is_err()
    );
    store
        .prepare_archive_file("stage_1", "file_2", &get_digest('f'), 2)
        .unwrap();
    assert!(
        store
            .prepare_archive_file("stage_1", "file_3", &get_digest('f'), 0)
            .is_err()
    );
    assert!(matches!(
        store.seal_archive_stage("stage_1", &get_digest('1'), 100, "catalog"),
        Err(StateError::EffectConflict)
    ));
    let sealed = store
        .seal_archive_file("stage_1", "file_1", &get_digest('2'), 100, "inode_1")
        .unwrap();
    assert_eq!(
        store
            .seal_archive_file("stage_1", "file_1", &get_digest('2'), 100, "inode_1")
            .unwrap(),
        sealed
    );
    assert!(matches!(
        store.seal_archive_file("stage_1", "file_1", &get_digest('3'), 100, "inode_1"),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(
        store
            .seal_archive_stage("stage_1", &get_digest('1'), 100, "catalog")
            .is_err()
    );
    store
        .seal_archive_file("stage_1", "file_2", &get_digest('4'), 100, "inode_2")
        .unwrap();
    let stage = store
        .seal_archive_stage("stage_1", &get_digest('1'), 100, "catalog")
        .unwrap();
    assert_eq!(stage.effect_state, "sealed");
    assert_eq!(
        store
            .seal_archive_stage("stage_1", &get_digest('1'), 100, "catalog")
            .unwrap(),
        stage
    );
    assert!(matches!(
        store.seal_archive_stage("stage_1", &get_digest('5'), 100, "catalog"),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(store.abandon_archive_stage("stage_1").is_err());
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(reopened.get_archive_stage("stage_1").unwrap(), Some(stage));
    assert_eq!(
        reopened.get_archive_file("stage_1", "file_1").unwrap(),
        Some(sealed)
    );
}

#[test]
fn pages_files_and_preserves_abandoned_records() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_capture(&mut store);
    store.prepare_archive_stage(&get_stage("stage_1")).unwrap();
    store
        .prepare_archive_file("stage_1", "b", &get_digest('b'), 2)
        .unwrap();
    store
        .prepare_archive_file("stage_1", "a", &get_digest('a'), 40)
        .unwrap();
    assert_eq!(
        store.list_archive_files("stage_1", "", 1).unwrap()[0].file_id,
        "a"
    );
    assert_eq!(
        store.list_archive_files("stage_1", "a", 1).unwrap()[0].file_id,
        "b"
    );
    assert!(store.list_archive_files("stage_1", "", 0).is_err());
    assert!(store.list_archive_files("stage_1", "", 1001).is_err());
    assert_eq!(
        store.abandon_archive_stage("stage_1").unwrap().effect_state,
        "abandoned"
    );
    assert!(
        store
            .prepare_archive_file("stage_1", "a", &get_digest('a'), 40)
            .is_err()
    );
    assert!(
        store
            .seal_archive_file("stage_1", "a", &get_digest('c'), 100, "identity")
            .is_err()
    );
    assert_eq!(
        store.list_archive_files("stage_1", "", 10).unwrap().len(),
        2
    );
}

#[test]
fn migrates_existing_schema_five_to_current() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let store = StateStore::open(&path).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    connection
        .execute_batch(
            "DROP TABLE gateway_layouts; DROP TABLE gateway_executions; DROP TABLE gateway_admissions; DROP TABLE gateway_resources; DROP TABLE staging_quota; DROP TABLE staging_quota_metadata; DROP TABLE native_runs; DROP TABLE archive_files; DROP TABLE archive_stages; PRAGMA user_version = 5;",
        )
        .unwrap();
    drop(connection);
    let store = StateStore::open(&path).unwrap();
    assert!(store.get_archive_stage("stage_1").unwrap().is_none());
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 12);
}
