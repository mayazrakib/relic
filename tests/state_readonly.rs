use relic::state::{
    ArchiveStageBinding, CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding,
    PayloadArtifactSeal, StateError, StateStore,
};

fn get_digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn get_capture() -> CaptureBinding {
    CaptureBinding {
        authority_id: "authority".into(),
        job_id: "job".into(),
        occurrence_id: "occurrence".into(),
        capture_id: "capture".into(),
        source_view_id: "view".into(),
        consistency: "best_effort".into(),
        source_selection_digest: get_digest('a'),
    }
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

fn create_sealed_capture(store: &mut StateStore) {
    store.bind_capture(&get_capture()).unwrap();
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
        .seal_manifest_artifact("manifest", &get_digest('b'), 100, &get_digest('c'), 2)
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
                manifest_entry_count: 2,
                file_count: 1,
                payload_bytes: 4,
            },
        )
        .unwrap();
}

#[test]
fn reads_live_wal_and_rejects_mutations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut writer = StateStore::open(&path).unwrap();
    create_sealed_capture(&mut writer);
    writer
        .prepare_archive_stage(&get_stage("prepared"))
        .unwrap();
    writer.prepare_archive_stage(&get_stage("sealed")).unwrap();
    writer
        .prepare_archive_file("sealed", "file_1", &get_digest('e'), 4)
        .unwrap();
    writer
        .seal_archive_file("sealed", "file_1", &get_digest('f'), 100, "inode_1")
        .unwrap();
    writer
        .seal_archive_stage("sealed", &get_digest('1'), 100, "catalog")
        .unwrap();
    let mut reader = StateStore::open_readonly(&path).unwrap();
    assert_eq!(
        reader
            .get_capture("capture")
            .unwrap()
            .unwrap()
            .payload_artifact_id
            .as_deref(),
        Some("payload")
    );
    assert_eq!(
        reader
            .get_archive_stage("prepared")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert_eq!(
        reader
            .get_archive_stage("sealed")
            .unwrap()
            .unwrap()
            .effect_state,
        "sealed"
    );
    assert_eq!(
        reader.list_archive_files("sealed", "", 10).unwrap()[0].plaintext_bytes,
        "4"
    );
    assert!(reader.abandon_archive_stage("prepared").is_err());
    assert!(
        reader
            .prepare_archive_file("prepared", "file_2", &get_digest('e'), 4)
            .is_err()
    );
    assert_eq!(
        writer
            .get_archive_stage("prepared")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert!(
        writer
            .list_archive_files("prepared", "", 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn refuses_missing_database_or_sidecars_without_creating_files() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    assert!(StateStore::open_readonly(&missing).is_err());
    assert!(!missing.exists());
    let state = directory.path().join("empty");
    std::fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(StateStore::open_readonly(&state).is_err());
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    let closed = directory.path().join("closed");
    drop(StateStore::open(&closed).unwrap());
    let wal = closed.join("state.sqlite3-wal");
    let shm = closed.join("state.sqlite3-shm");
    assert!(!wal.exists() && !shm.exists());
    assert!(StateStore::open_readonly(&closed).is_err());
    assert!(!wal.exists() && !shm.exists());
}

#[test]
fn refuses_old_schema_without_migration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let writer = StateStore::open(&path).unwrap();
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    connection.pragma_update(None, "user_version", 5).unwrap();
    assert!(matches!(
        StateStore::open_readonly(&path),
        Err(StateError::UnsupportedVersion)
    ));
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5);
    drop(writer);
}

#[cfg(unix)]
#[test]
fn refuses_shared_directory_and_symlinked_database() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let writer = StateStore::open(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        StateStore::open_readonly(&path),
        Err(StateError::InsecureDirectory)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(writer);
    let database = path.join("state.sqlite3");
    let original = path.join("original.sqlite3");
    std::fs::rename(&database, &original).unwrap();
    symlink(&original, &database).unwrap();
    assert!(matches!(
        StateStore::open_readonly(&path),
        Err(StateError::InsecureDirectory)
    ));
}
