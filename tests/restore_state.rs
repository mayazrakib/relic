use relic::state::{
    CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding, PayloadArtifactSeal,
    RestoreBinding, StateError, StateStore,
};

fn get_digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn bind() -> RestoreBinding {
    RestoreBinding {
        restore_id: "restore1".into(),
        capture_id: "capture".into(),
        payload_artifact_id: "payload".into(),
        target_endpoint_id: "endpoint".into(),
        target_identity: "unix:1:2".into(),
        relative_name: "recovered".into(),
    }
}

fn prepare_source(store: &mut StateStore) {
    store
        .bind_capture(&CaptureBinding {
            authority_id: "local".into(),
            job_id: "job".into(),
            occurrence_id: "occurrence".into(),
            capture_id: "capture".into(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: get_digest('a'),
        })
        .unwrap();
    store
        .prepare_manifest_artifact(&ManifestArtifactBinding {
            artifact_id: "manifest".into(),
            capture_id: "capture".into(),
            storage_endpoint_id: "archive".into(),
            storage_identity: "storage".into(),
            relative_name: "artifact_manifest.sealed".into(),
            key_ref: "key".into(),
        })
        .unwrap();
    store
        .seal_manifest_artifact("manifest", &get_digest('b'), 100, &get_digest('c'), 5)
        .unwrap();
    store
        .prepare_payload_artifact(&PayloadArtifactBinding {
            artifact_id: "payload".into(),
            capture_id: "capture".into(),
            storage_endpoint_id: "archive".into(),
            storage_identity: "storage".into(),
            relative_name: "payload_payload.sealed".into(),
            key_ref: "key".into(),
        })
        .unwrap();
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
fn persists_reservations_and_guarded_transitions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    assert!(matches!(
        store.prepare_restore(&bind()),
        Err(StateError::EffectConflict)
    ));
    prepare_source(&mut store);
    let intent = store.prepare_restore(&bind()).unwrap();
    assert_eq!(intent.effect_state, "prepared");
    assert_eq!(store.prepare_restore(&bind()).unwrap(), intent);
    let mut changed = bind();
    changed.target_identity = "unix:3:4".into();
    assert!(matches!(
        store.prepare_restore(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    let mut other = bind();
    other.restore_id = "restore2".into();
    assert!(matches!(
        store.prepare_restore(&other),
        Err(StateError::EffectConflict)
    ));
    other.target_endpoint_id = "another_alias".into();
    assert!(matches!(
        store.prepare_restore(&other),
        Err(StateError::EffectConflict)
    ));
    assert_eq!(store.list_pending_restores("", 1).unwrap().len(), 1);
    store.mark_restore_staging("restore1", "unix:1:3").unwrap();
    store.mark_restore_staging("restore1", "unix:1:3").unwrap();
    assert!(matches!(
        store.mark_restore_staging("restore1", "unix:1:4"),
        Err(StateError::IdempotencyConflict)
    ));
    store.mark_restore_verified("restore1").unwrap();
    store.mark_restore_verified("restore1").unwrap();
    assert!(matches!(
        store.abandon_restore("restore1"),
        Err(StateError::EffectConflict)
    ));
    assert!(matches!(
        store.mark_restore_published("restore1", "unix:1:4"),
        Err(StateError::IdempotencyConflict)
    ));
    store
        .mark_restore_published("restore1", "unix:1:3")
        .unwrap();
    store
        .mark_restore_published("restore1", "unix:1:3")
        .unwrap();
    assert!(matches!(
        store.prepare_restore(&other),
        Err(StateError::EffectConflict)
    ));
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    let record = reopened.get_restore("restore1").unwrap().unwrap();
    assert_eq!(record.effect_state, "published");
    assert_eq!(record.staging_identity.as_deref(), Some("unix:1:3"));
    assert_eq!(record.payload_bytes, "42");
    assert!(reopened.list_pending_restores("", 10).unwrap().is_empty());
}

#[test]
fn validates_names_and_releases_abandoned_reservations() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    prepare_source(&mut store);
    for name in [".", "..", "a/b", "a\\b", ".restore_reserved", "bad\0name"] {
        let mut value = bind();
        value.relative_name = name.into();
        assert!(matches!(
            store.prepare_restore(&value),
            Err(StateError::InvalidInput)
        ));
    }
    let mut too_long = bind();
    too_long.relative_name = "a".repeat(256);
    assert!(matches!(
        store.prepare_restore(&too_long),
        Err(StateError::InvalidInput)
    ));
    store.prepare_restore(&bind()).unwrap();
    store.mark_restore_staging("restore1", "unix:1:3").unwrap();
    let abandoned = store.abandon_restore("restore1").unwrap();
    assert_eq!(abandoned.staging_identity.as_deref(), Some("unix:1:3"));
    assert!(matches!(
        store.prepare_restore(&bind()),
        Err(StateError::EffectConflict)
    ));
    let mut replacement = bind();
    replacement.restore_id = "restore2".into();
    store.prepare_restore(&replacement).unwrap();
    assert!(store.list_pending_restores("", 0).is_err());
}

#[test]
fn migrates_version_four_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let db = path.join("state.sqlite3");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(include_str!("../database/migrations/00001_initialize.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!("../database/migrations/00002_capture.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../database/migrations/00003_manifest_artifacts.sql"
        ))
        .unwrap();
    connection
        .execute_batch(include_str!(
            "../database/migrations/00004_payload_artifacts.sql"
        ))
        .unwrap();
    connection
        .execute(
            "INSERT INTO jobs(job_id,revision,definition) VALUES ('legacy',1,'{}')",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = StateStore::open(&path).unwrap();
    assert!(store.get_job("legacy").unwrap().is_some());
    assert!(store.list_pending_restores("", 1).unwrap().is_empty());
}
