use relic::state::{CaptureBinding, StateError, StateStore};

fn capture() -> CaptureBinding {
    CaptureBinding {
        authority_id: "local_1".into(),
        job_id: "job_1".into(),
        occurrence_id: "occurrence_1".into(),
        capture_id: "capture_1".into(),
        source_view_id: "view_1".into(),
        consistency: "best_effort".into(),
        source_selection_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

#[test]
fn capture_binding_and_manifest_are_immutable_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    let binding = capture();
    store.bind_capture(&binding).unwrap();
    assert_eq!(store.list_pending_captures("", 1).unwrap().len(), 1);
    let mut changed = binding.clone();
    changed.source_view_id = "another_view".into();
    assert!(matches!(
        store.bind_capture(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    let digest = format!("sha256:{}", "b".repeat(64));
    store
        .freeze_capture_manifest(&binding.capture_id, &digest, 8)
        .unwrap();
    assert!(store.list_pending_captures("", 1).unwrap().is_empty());
    assert!(matches!(
        store.freeze_capture_manifest(&binding.capture_id, &digest, 9),
        Err(StateError::IdempotencyConflict)
    ));
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    let record = reopened.get_capture(&binding.capture_id).unwrap().unwrap();
    assert_eq!(record.binding, binding);
    assert_eq!(record.manifest_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(record.manifest_entry_count.as_deref(), Some("8"));
}

#[test]
fn publication_requires_matching_frozen_capture() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    let publication: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/publication.json")).unwrap();
    assert!(matches!(
        store.bind_publication(&publication),
        Err(StateError::EffectConflict)
    ));
    let mut binding = capture();
    binding.occurrence_id = publication["commit_key"]["occurrence_id"]
        .as_str()
        .unwrap()
        .into();
    binding.consistency = "crash_consistent".into();
    store.bind_capture(&binding).unwrap();
    assert!(matches!(
        store.bind_publication(&publication),
        Err(StateError::IdempotencyConflict)
    ));
    let wrong = format!("sha256:{}", "b".repeat(64));
    store
        .freeze_capture_manifest(&binding.capture_id, &wrong, 1)
        .unwrap();
    assert!(matches!(
        store.bind_publication(&publication),
        Err(StateError::IdempotencyConflict)
    ));
}

#[test]
fn migrates_version_one_database_without_losing_jobs() {
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
    connection.execute("INSERT INTO jobs(job_id, revision, definition) VALUES ('legacy', 1, '{\"job_id\":\"legacy\",\"revision\":1}')", []).unwrap();
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.get_job("legacy").unwrap().unwrap().revision, 1);
    assert!(store.list_pending_captures("", 10).unwrap().is_empty());
}
