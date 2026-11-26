#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use relic::artifact_store::{ArtifactStore, ArtifactStoreError};
use relic::encrypted_spool::SpoolLimits;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::resources::StageGuard;
use relic::restore_store::{RestoreLimits, RestoreStore, RestoreStoreError};
use relic::state::{ManifestArtifactBinding, RestoreBinding, StateError, StateStore};

fn endpoint(path: &Path) -> LocalEndpoint {
    let path = fs::canonicalize(path).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    LocalEndpoint::resolve(
        &path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap()
}

#[test]
fn constructors_accept_opaque_colon_and_reject_invalid_endpoint_ids() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ArtifactStore::new(endpoint(directory.path()), "files:primary").is_ok());
    assert!(RestoreStore::new(endpoint(directory.path()), "files:primary").is_ok());
    for invalid in ["", ":leading", "bad/name", "bad space"] {
        assert!(matches!(
            ArtifactStore::new(endpoint(directory.path()), invalid),
            Err(ArtifactStoreError::INVALID)
        ));
        assert!(matches!(
            RestoreStore::new(endpoint(directory.path()), invalid),
            Err(RestoreStoreError::INVALID)
        ));
    }
    let long = "a".repeat(129);
    assert!(matches!(
        ArtifactStore::new(endpoint(directory.path()), &long),
        Err(ArtifactStoreError::INVALID)
    ));
    assert!(matches!(
        RestoreStore::new(endpoint(directory.path()), &long),
        Err(RestoreStoreError::INVALID)
    ));
}

#[test]
fn bindings_use_colon_endpoints_and_keep_generated_ids_strict() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let artifacts = ArtifactStore::new(endpoint(directory.path()), "files:primary").unwrap();
    let restores = RestoreStore::new(endpoint(directory.path()), "files:primary").unwrap();
    let state_root = tempfile::tempdir().unwrap();
    let mut state = StateStore::open(&state_root.path().join("state")).unwrap();
    let mut artifact = ManifestArtifactBinding {
        artifact_id: "one".into(),
        capture_id: "missing".into(),
        storage_endpoint_id: "files:primary".into(),
        storage_identity: artifacts.storage_identity().into(),
        relative_name: "artifact_one.sealed".into(),
        key_ref: "key".into(),
    };
    let spool_limits = SpoolLimits {
        plaintext_bytes: 1024,
        ciphertext_bytes: 2048,
    };
    assert!(matches!(
        artifacts.begin(&mut state, &artifact, spool_limits, &StageGuard::default()),
        Err(ArtifactStoreError::INVALID)
    ));
    artifact.storage_endpoint_id = "other".into();
    assert!(matches!(
        artifacts.begin(&mut state, &artifact, spool_limits, &StageGuard::default()),
        Err(ArtifactStoreError::WRONG_STORAGE)
    ));
    artifact.storage_endpoint_id = "files:primary".into();
    artifact.artifact_id = "bad:id".into();
    artifact.relative_name = "artifact_bad:id.sealed".into();
    assert!(matches!(
        state.prepare_manifest_artifact(&artifact),
        Err(StateError::InvalidInput)
    ));
    assert!(matches!(
        artifacts.begin(&mut state, &artifact, spool_limits, &StageGuard::default()),
        Err(ArtifactStoreError::INVALID)
    ));
    let mut restore = RestoreBinding {
        restore_id: "one".into(),
        capture_id: "missing".into(),
        payload_artifact_id: "payload".into(),
        target_endpoint_id: "files:primary".into(),
        target_identity: restores.get_storage_identity().into(),
        relative_name: "recovered".into(),
    };
    let restore_limits = RestoreLimits {
        max_entries: 10,
        max_payload_bytes: 1024,
        max_depth: 4,
        max_open_files: 12,
    };
    assert!(matches!(
        restores.begin(&mut state, &restore, restore_limits, &StageGuard::default()),
        Err(RestoreStoreError::STATE(StateError::EffectConflict))
    ));
    restore.restore_id = "bad:id".into();
    assert!(matches!(
        state.prepare_restore(&restore),
        Err(StateError::InvalidInput)
    ));
    assert!(matches!(
        restores.begin(&mut state, &restore, restore_limits, &StageGuard::default()),
        Err(RestoreStoreError::CHANGED)
    ));
}
