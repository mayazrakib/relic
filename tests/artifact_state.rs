use relic::state::{CaptureBinding, ManifestArtifactBinding, StateError, StateStore};

fn capture(id: &str) -> CaptureBinding {
    CaptureBinding {
        authority_id: "local".into(),
        job_id: "job".into(),
        occurrence_id: format!("occurrence_{id}"),
        capture_id: id.into(),
        source_view_id: "view".into(),
        consistency: "best_effort".into(),
        source_selection_digest: digest('a'),
    }
}

fn artifact(id: &str, capture_id: &str) -> ManifestArtifactBinding {
    ManifestArtifactBinding {
        artifact_id: id.into(),
        capture_id: capture_id.into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: "storage".into(),
        relative_name: format!("artifact_{id}.sealed"),
        key_ref: "key_ref".into(),
    }
}

fn digest(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

#[test]
fn preparation_seal_and_reopen_are_immutable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    store.bind_capture(&capture("capture_1")).unwrap();
    let binding = artifact("one", "capture_1");
    assert_eq!(
        store
            .prepare_manifest_artifact(&binding)
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert_eq!(
        store.prepare_manifest_artifact(&binding).unwrap().binding,
        binding
    );
    assert_eq!(store.list_pending_artifacts("", 1).unwrap().len(), 1);
    let mut changed = binding.clone();
    changed.key_ref = "other".into();
    assert!(matches!(
        store.prepare_manifest_artifact(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    let sealed = store
        .seal_manifest_artifact("one", &digest('b'), 100, &digest('c'), 5)
        .unwrap();
    assert_eq!(sealed.effect_state, "sealed");
    assert_eq!(
        store
            .seal_manifest_artifact("one", &digest('b'), 100, &digest('c'), 5)
            .unwrap(),
        sealed
    );
    assert!(matches!(
        store.seal_manifest_artifact("one", &digest('b'), 101, &digest('c'), 5),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.abandon_manifest_artifact("one"),
        Err(StateError::EffectConflict)
    ));
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(
        reopened.get_capture_artifact("capture_1").unwrap(),
        Some(sealed)
    );
    let record = reopened.get_capture("capture_1").unwrap().unwrap();
    assert_eq!(record.manifest_artifact_id.as_deref(), Some("one"));
    assert_eq!(
        record.manifest_digest.as_deref(),
        Some(digest('c').as_str())
    );
    assert_eq!(record.manifest_entry_count.as_deref(), Some("5"));
    assert!(reopened.list_pending_artifacts("", 10).unwrap().is_empty());
}

#[test]
fn conflicting_freeze_and_abandoned_capture_remain_blocked() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    store.bind_capture(&capture("first")).unwrap();
    let first = artifact("first", "first");
    store.prepare_manifest_artifact(&first).unwrap();
    store
        .freeze_capture_manifest("first", &digest('a'), 1)
        .unwrap();
    assert!(matches!(
        store.seal_manifest_artifact("first", &digest('b'), 10, &digest('c'), 1),
        Err(StateError::IdempotencyConflict)
    ));
    assert_eq!(
        store
            .get_manifest_artifact("first")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert!(
        store
            .get_capture("first")
            .unwrap()
            .unwrap()
            .manifest_artifact_id
            .is_none()
    );
    store.abandon_manifest_artifact("first").unwrap();
    assert!(matches!(
        store.prepare_manifest_artifact(&first),
        Err(StateError::EffectConflict)
    ));
    assert!(matches!(
        store.prepare_manifest_artifact(&artifact("replacement", "first")),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.seal_manifest_artifact("first", &digest('b'), 10, &digest('a'), 1),
        Err(StateError::EffectConflict)
    ));
}

#[test]
fn validates_filename_and_pages_pending() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    for id in ["one", "two"] {
        store.bind_capture(&capture(id)).unwrap();
        store.prepare_manifest_artifact(&artifact(id, id)).unwrap();
    }
    let page = store.list_pending_artifacts("", 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(
        store
            .list_pending_artifacts(&page[0].binding.artifact_id, 1)
            .unwrap()
            .len(),
        1
    );
    let mut invalid = artifact("three", "one");
    invalid.relative_name = "../secret".into();
    assert!(matches!(
        store.prepare_manifest_artifact(&invalid),
        Err(StateError::InvalidInput)
    ));
}

#[test]
fn migrates_existing_version_two_capture() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = path.join("state.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(include_str!("../database/migrations/00001_initialize.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!("../database/migrations/00002_capture.sql"))
        .unwrap();
    connection.execute("INSERT INTO captures (capture_id, authority_id, job_id, occurrence_id, source_view_id, consistency, source_selection_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", rusqlite::params!["legacy", "local", "job", "occurrence", "view", "best_effort", digest('a')]).unwrap();
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = StateStore::open(&path).unwrap();
    assert!(
        store
            .get_capture("legacy")
            .unwrap()
            .unwrap()
            .manifest_artifact_id
            .is_none()
    );
    assert!(store.get_capture_artifact("legacy").unwrap().is_none());
}
