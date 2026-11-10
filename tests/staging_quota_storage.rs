#![cfg(unix)]
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::staging_quota::{StagingQuotaBinding, reserve_owned_staging_quota};
use relic::state::{CaptureBinding, ManifestArtifactBinding, StateError, StateStore};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn create_endpoint(path: &std::path::Path) -> LocalEndpoint {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = fs::metadata(path).unwrap();
    LocalEndpoint::resolve(
        path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap()
}
fn create_binding(state: &mut StateStore, endpoint: &LocalEndpoint) -> StagingQuotaBinding {
    let identity = endpoint.identity();
    let storage_identity = format!("unix:{}:{}", identity.device, identity.inode);
    state
        .bind_capture(&CaptureBinding {
            authority_id: "authority".into(),
            job_id: "job".into(),
            occurrence_id: "occurrence".into(),
            capture_id: "capture".into(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: format!("sha256:{}", "a".repeat(64)),
        })
        .unwrap();
    state
        .prepare_manifest_artifact(&ManifestArtifactBinding {
            artifact_id: "manifest".into(),
            capture_id: "capture".into(),
            storage_endpoint_id: "storage".into(),
            storage_identity: storage_identity.clone(),
            relative_name: "artifact_manifest.sealed".into(),
            key_ref: "key".into(),
        })
        .unwrap();
    StagingQuotaBinding {
        object_kind: "manifest".into(),
        object_id: "manifest".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity,
        volume_identity: format!("unix:{}", identity.device),
        max_bytes: 1024,
    }
}
#[test]
fn rejects_unregistered_nonempty_root_and_preserves_orphan() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = create_endpoint(&temp.path().join("storage"));
    let mut state = StateStore::open(&temp.path().join("state")).unwrap();
    let binding = create_binding(&mut state, &endpoint);
    let orphan = temp.path().join("storage/orphan");
    fs::write(&orphan, b"retained").unwrap();
    assert!(matches!(
        reserve_owned_staging_quota(&mut state, &endpoint, &binding),
        Err(StateError::EffectConflict)
    ));
    assert_eq!(fs::read(orphan).unwrap(), b"retained");
    assert_eq!(state.get_staging_quota_usage().unwrap(), 0);
    assert!(!state.is_staging_quota_inventory_complete().unwrap());
    drop(state);
    let mut state = StateStore::open(&temp.path().join("state")).unwrap();
    assert!(!state.is_staging_quota_inventory_complete().unwrap());
    let other = create_endpoint(&temp.path().join("other"));
    let identity = other.identity();
    let storage_identity = format!("unix:{}:{}", identity.device, identity.inode);
    state
        .prepare_payload_artifact(&relic::state::PayloadArtifactBinding {
            artifact_id: "payload_other".into(),
            capture_id: "capture".into(),
            storage_endpoint_id: "other".into(),
            storage_identity: storage_identity.clone(),
            relative_name: "payload_payload_other.sealed".into(),
            key_ref: "key".into(),
        })
        .unwrap();
    let binding = StagingQuotaBinding {
        object_kind: "payload".into(),
        object_id: "payload_other".into(),
        storage_endpoint_id: "other".into(),
        storage_identity,
        volume_identity: format!("unix:{}", identity.device),
        max_bytes: 1024,
    };
    assert!(matches!(
        reserve_owned_staging_quota(&mut state, &other, &binding),
        Err(StateError::InventoryRequired)
    ));
}
#[test]
fn empty_root_admits_and_reopened_registered_storage_keeps_charge() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = create_endpoint(&temp.path().join("storage"));
    let path = temp.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let binding = create_binding(&mut state, &endpoint);
    let mut wrong = binding.clone();
    wrong.volume_identity = "unix:999999999".into();
    assert!(matches!(
        reserve_owned_staging_quota(&mut state, &endpoint, &wrong),
        Err(StateError::InvalidInput)
    ));
    let record = reserve_owned_staging_quota(&mut state, &endpoint, &binding).unwrap();
    fs::write(temp.path().join("storage/retained"), b"retained").unwrap();
    drop(state);
    let mut state = StateStore::open(&path).unwrap();
    assert!(
        state
            .has_staging_quota_storage(&binding.storage_identity)
            .unwrap()
    );
    assert_eq!(
        reserve_owned_staging_quota(&mut state, &endpoint, &binding).unwrap(),
        record
    );
    assert_eq!(state.get_staging_quota_usage().unwrap(), 1024);
}
