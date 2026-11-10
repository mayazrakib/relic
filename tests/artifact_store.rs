#![cfg(unix)]

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use relic::artifact_store::{ArtifactStore, ArtifactStoreError};
use relic::encrypted_spool::SpoolLimits;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::manifest::ManifestEntry;
use relic::manifest_artifact::{ManifestArtifact, ManifestArtifactWriter};
use relic::resources::StageGuard;
use relic::state::{CaptureBinding, ManifestArtifactBinding, StateStore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn create_directory() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();

    root
}

fn open_store(path: &Path) -> ArtifactStore {
    let path = fs::canonicalize(path).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let endpoint = LocalEndpoint::resolve(
        &path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();

    ArtifactStore::new(endpoint, "local_artifacts").unwrap()
}

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

fn build_binding(store: &ArtifactStore) -> ManifestArtifactBinding {
    ManifestArtifactBinding {
        artifact_id: "one".into(),
        capture_id: "capture_1".into(),
        storage_endpoint_id: "local_artifacts".into(),
        storage_identity: store.storage_identity().into(),
        relative_name: "artifact_one.sealed".into(),
        key_ref: "manifest_key".into(),
    }
}

fn limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 1024 * 1024,
        ciphertext_bytes: 2 * 1024 * 1024,
    }
}

fn write_manifest(
    destination: &mut impl Write,
    key: &Zeroizing<[u8; 32]>,
    guard: &StageGuard,
) -> ManifestArtifact {
    let mut writer =
        ManifestArtifactWriter::new(&capture(), 1, destination, key, limits(), guard).unwrap();
    let entry: ManifestEntry =
        serde_json::from_str(include_str!("../fixtures/contracts/manifest_entry.json")).unwrap();
    writer.add_entry(&entry).unwrap();

    writer.finish().unwrap()
}

#[test]
fn commits_verified_artifact_and_reconciles_after_reopen() {
    let directory = create_directory();
    let store = open_store(directory.path());
    let state_root = create_directory();
    let mut state = StateStore::open(state_root.path()).unwrap();
    state.bind_capture(&capture()).unwrap();
    let binding = build_binding(&store);
    let key = Zeroizing::new([29; 32]);
    let guard = StageGuard::default();
    let mut stage = store.begin(&mut state, &binding, limits(), &guard).unwrap();
    let manifest = write_manifest(&mut stage, &key, &guard);
    let record = store
        .commit(stage, &mut state, "manifest_key", &key, &manifest)
        .unwrap();
    assert_eq!(record.effect_state, "sealed");
    assert_eq!(record.binding.key_ref, "manifest_key");
    let ciphertext = fs::read(directory.path().join("artifact_one.sealed")).unwrap();
    let expected_checksum = format!(
        "sha256:{}",
        Sha256::digest(&ciphertext)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(
        record.ciphertext_digest.as_deref(),
        Some(expected_checksum.as_str())
    );
    assert_eq!(
        record.ciphertext_bytes.as_deref(),
        Some(ciphertext.len().to_string().as_str())
    );
    assert_eq!(
        record.manifest_digest.as_deref(),
        Some(manifest.digest.as_str())
    );
    assert_eq!(
        state
            .get_capture("capture_1")
            .unwrap()
            .unwrap()
            .manifest_artifact_id
            .as_deref(),
        Some("one")
    );
    assert!(!directory.path().join(".artifact_one.pending").exists());
    assert_eq!(
        fs::metadata(directory.path().join("artifact_one.sealed"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(state);
    drop(store);
    let store = open_store(directory.path());
    let mut state = StateStore::open(state_root.path()).unwrap();
    assert_eq!(
        store
            .reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard)
            .unwrap(),
        record
    );
}

#[test]
fn recovers_completed_ciphertext_across_native_publication_boundaries() {
    for point in ["pending", "linked", "final"] {
        let directory = create_directory();
        let store = open_store(directory.path());
        let state_root = create_directory();
        let mut state = StateStore::open(state_root.path()).unwrap();
        state.bind_capture(&capture()).unwrap();
        let binding = build_binding(&store);
        let key = Zeroizing::new([30; 32]);
        let guard = StageGuard::default();
        let mut stage = store.begin(&mut state, &binding, limits(), &guard).unwrap();
        let manifest = write_manifest(&mut stage, &key, &guard);
        drop(stage);
        let pending = directory.path().join(".artifact_one.pending");
        let final_path = directory.path().join("artifact_one.sealed");

        match point {
            "linked" => fs::hard_link(&pending, &final_path).unwrap(),
            "final" => fs::rename(&pending, &final_path).unwrap(),
            _ => {}
        }

        assert!(
            state
                .get_capture("capture_1")
                .unwrap()
                .unwrap()
                .manifest_digest
                .is_none()
        );
        drop(state);
        drop(store);
        let store = open_store(directory.path());
        let mut state = StateStore::open(state_root.path()).unwrap();
        let record = store
            .reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard)
            .unwrap();
        assert_eq!(record.effect_state, "sealed", "failed at {point}");
        assert_eq!(
            record.manifest_digest.as_deref(),
            Some(manifest.digest.as_str())
        );
        assert!(!pending.exists());
        assert!(final_path.exists());
    }
}

#[test]
fn live_ownership_corruption_and_wrong_key_do_not_freeze_capture() {
    let directory = create_directory();
    let store = open_store(directory.path());
    let state_root = create_directory();
    let mut state = StateStore::open(state_root.path()).unwrap();
    state.bind_capture(&capture()).unwrap();
    let binding = build_binding(&store);
    let key = Zeroizing::new([31; 32]);
    let guard = StageGuard::default();
    let mut stage = store.begin(&mut state, &binding, limits(), &guard).unwrap();
    assert!(matches!(
        store.reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard),
        Err(ArtifactStoreError::BUSY)
    ));
    write_manifest(&mut stage, &key, &guard);
    drop(stage);
    assert!(matches!(
        store.begin(&mut state, &binding, limits(), &guard),
        Err(ArtifactStoreError::RECONCILIATION_REQUIRED)
    ));
    assert!(matches!(
        store.reconcile(&mut state, "one", "wrong_ref", &key, limits(), &guard),
        Err(ArtifactStoreError::WRONG_KEY_REFERENCE)
    ));
    assert!(
        store
            .reconcile(
                &mut state,
                "one",
                "manifest_key",
                &Zeroizing::new([32; 32]),
                limits(),
                &guard
            )
            .is_err()
    );
    let pending = directory.path().join(".artifact_one.pending");
    let file = File::options().write(true).open(&pending).unwrap();
    file.set_len(32).unwrap();
    drop(file);
    assert!(
        store
            .reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard)
            .is_err()
    );
    assert!(pending.exists());
    assert_eq!(
        state
            .get_manifest_artifact("one")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert!(
        state
            .get_capture("capture_1")
            .unwrap()
            .unwrap()
            .manifest_digest
            .is_none()
    );
}

#[test]
fn never_removes_a_different_pending_inode() {
    let directory = create_directory();
    let store = open_store(directory.path());
    let state_root = create_directory();
    let mut state = StateStore::open(state_root.path()).unwrap();
    state.bind_capture(&capture()).unwrap();
    let binding = build_binding(&store);
    let key = Zeroizing::new([33; 32]);
    let guard = StageGuard::default();
    let mut stage = store.begin(&mut state, &binding, limits(), &guard).unwrap();
    write_manifest(&mut stage, &key, &guard);
    drop(stage);
    let pending = directory.path().join(".artifact_one.pending");
    let final_path = directory.path().join("artifact_one.sealed");
    fs::copy(&pending, &final_path).unwrap();
    assert!(matches!(
        store.reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard),
        Err(ArtifactStoreError::OUTCOME_UNKNOWN)
    ));
    assert!(pending.exists());
    assert!(final_path.exists());
    assert!(
        state
            .get_capture("capture_1")
            .unwrap()
            .unwrap()
            .manifest_digest
            .is_none()
    );
}

#[test]
fn sealed_ciphertext_identity_is_checked_before_republication() {
    let directory = create_directory();
    let store = open_store(directory.path());
    let state_root = create_directory();
    let mut state = StateStore::open(state_root.path()).unwrap();
    state.bind_capture(&capture()).unwrap();
    let binding = build_binding(&store);
    let key = Zeroizing::new([35; 32]);
    let guard = StageGuard::default();
    let mut stage = store.begin(&mut state, &binding, limits(), &guard).unwrap();
    let manifest = write_manifest(&mut stage, &key, &guard);
    let original = store
        .commit(stage, &mut state, "manifest_key", &key, &manifest)
        .unwrap();
    let final_path = directory.path().join("artifact_one.sealed");
    fs::remove_file(&final_path).unwrap();
    let pending = directory.path().join(".artifact_one.pending");
    let mut replacement = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    write_manifest(&mut replacement, &key, &guard);
    drop(replacement);

    assert!(matches!(
        store.reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard),
        Err(ArtifactStoreError::RECONCILIATION_REQUIRED)
    ));
    assert!(!final_path.exists());
    assert!(pending.exists());
    assert_eq!(
        state.get_manifest_artifact("one").unwrap().unwrap(),
        original
    );
}

#[test]
fn missing_effect_is_terminal_and_quota_failure_is_not_committed() {
    let directory = create_directory();
    let store = open_store(directory.path());
    let state_root = create_directory();
    let mut state = StateStore::open(state_root.path()).unwrap();
    state.bind_capture(&capture()).unwrap();
    let binding = build_binding(&store);
    state.prepare_manifest_artifact(&binding).unwrap();
    let key = Zeroizing::new([34; 32]);
    let guard = StageGuard::default();
    let record = store
        .reconcile(&mut state, "one", "manifest_key", &key, limits(), &guard)
        .unwrap();
    assert_eq!(record.effect_state, "abandoned");
    assert!(store.begin(&mut state, &binding, limits(), &guard).is_err());

    let other_root = create_directory();
    let other_artifacts = create_directory();
    let other_store = open_store(other_artifacts.path());
    let other_binding = build_binding(&other_store);
    let mut other_state = StateStore::open(other_root.path()).unwrap();
    other_state.bind_capture(&capture()).unwrap();
    let mut stage = other_store
        .begin(
            &mut other_state,
            &other_binding,
            SpoolLimits {
                plaintext_bytes: 100,
                ciphertext_bytes: 60,
            },
            &guard,
        )
        .unwrap();
    assert!(stage.write_all(&[0; 61]).is_err());
    drop(stage);
    assert!(
        other_state
            .get_capture("capture_1")
            .unwrap()
            .unwrap()
            .manifest_digest
            .is_none()
    );
}
