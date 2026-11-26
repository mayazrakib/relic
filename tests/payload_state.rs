use relic::state::{
    CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding, PayloadArtifactSeal,
    StateError, StateStore,
};

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

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

fn payload(id: &str, capture_id: &str) -> PayloadArtifactBinding {
    PayloadArtifactBinding {
        artifact_id: id.into(),
        capture_id: capture_id.into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: "storage".into(),
        relative_name: format!("payload_{id}.sealed"),
        key_ref: "key_ref".into(),
    }
}

fn seal() -> PayloadArtifactSeal {
    PayloadArtifactSeal {
        ciphertext_digest: digest('b'),
        ciphertext_bytes: 100,
        manifest_digest: digest('c'),
        manifest_entry_count: 5,
        file_count: 2,
        payload_bytes: 42,
    }
}

fn seal_manifest(store: &mut StateStore, capture_id: &str) {
    let binding = ManifestArtifactBinding {
        artifact_id: "same".into(),
        capture_id: capture_id.into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: "storage".into(),
        relative_name: "artifact_same.sealed".into(),
        key_ref: "key_ref".into(),
    };
    store.prepare_manifest_artifact(&binding).unwrap();
    store
        .seal_manifest_artifact("same", &digest('d'), 100, &digest('c'), 5)
        .unwrap();
}

#[test]
fn seals_only_with_linked_manifest_and_persists_immutable_record() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    store.bind_capture(&capture("capture")).unwrap();
    store
        .freeze_capture_manifest("capture", &digest('c'), 5)
        .unwrap();
    let binding = payload("same", "capture");
    store.prepare_payload_artifact(&binding).unwrap();
    assert!(matches!(
        store.seal_payload_artifact("same", &seal()),
        Err(StateError::EffectConflict)
    ));
    seal_manifest(&mut store, "capture");
    let mut wrong = seal();
    wrong.manifest_digest = digest('e');
    assert!(matches!(
        store.seal_payload_artifact("same", &wrong),
        Err(StateError::IdempotencyConflict)
    ));
    let result = store.seal_payload_artifact("same", &seal()).unwrap();
    assert_eq!(
        store.seal_payload_artifact("same", &seal()).unwrap(),
        result
    );
    wrong = seal();
    wrong.payload_bytes += 1;
    assert!(matches!(
        store.seal_payload_artifact("same", &wrong),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.abandon_payload_artifact("same"),
        Err(StateError::EffectConflict)
    ));
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(
        reopened.get_capture_payload("capture").unwrap(),
        Some(result)
    );
    let capture = reopened.get_capture("capture").unwrap().unwrap();
    assert_eq!(capture.manifest_artifact_id.as_deref(), Some("same"));
    assert_eq!(capture.payload_artifact_id.as_deref(), Some("same"));
}

#[test]
fn validates_inputs_and_abandonment() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    for id in ["one", "two"] {
        store.bind_capture(&capture(id)).unwrap();
        store.prepare_payload_artifact(&payload(id, id)).unwrap();
    }
    let page = store.list_pending_payloads("", 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(
        store
            .list_pending_payloads(&page[0].binding.artifact_id, 1)
            .unwrap()
            .len(),
        1
    );
    assert!(store.list_pending_payloads("", 0).is_err());
    let mut invalid = seal();
    invalid.ciphertext_bytes = 59;
    assert!(matches!(
        store.seal_payload_artifact("one", &invalid),
        Err(StateError::InvalidInput)
    ));
    invalid = seal();
    invalid.file_count = 6;
    assert!(matches!(
        store.seal_payload_artifact("one", &invalid),
        Err(StateError::InvalidInput)
    ));
    invalid = seal();
    invalid.file_count = 0;
    invalid.payload_bytes = 1;
    assert!(matches!(
        store.seal_payload_artifact("one", &invalid),
        Err(StateError::InvalidInput)
    ));
    let mut bad = payload("bad:id", "one");
    bad.relative_name = "payload_bad:id.sealed".into();
    assert!(matches!(
        store.prepare_payload_artifact(&bad),
        Err(StateError::InvalidInput)
    ));
    store.abandon_payload_artifact("one").unwrap();
    assert!(matches!(
        store.prepare_payload_artifact(&payload("one", "one")),
        Err(StateError::EffectConflict)
    ));
    assert!(matches!(
        store.prepare_payload_artifact(&payload("replacement", "one")),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.seal_payload_artifact("one", &seal()),
        Err(StateError::EffectConflict)
    ));
}

#[test]
fn migrates_version_three_capture() {
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
    connection
        .execute_batch(include_str!(
            "../database/migrations/00003_manifest_artifacts.sql"
        ))
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
            .payload_artifact_id
            .is_none()
    );
    assert!(store.get_capture_payload("legacy").unwrap().is_none());
}
