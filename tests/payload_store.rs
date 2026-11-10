#![cfg(unix)]

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use relic::artifact_store::{ArtifactStore, ArtifactStoreError, PayloadStage, PayloadVerification};
use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
use relic::encrypted_spool::SpoolLimits;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::manifest::ManifestEntry;
use relic::manifest_artifact::seal_sorted_manifest;
use relic::payload_capture::{CapturedPayload, PayloadCapture, PayloadLimits};
use relic::resources::StageGuard;
use relic::source_scan::{ManifestSink, ScanError};
use relic::state::{
    CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding, PayloadArtifactRecord,
    StateStore,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const CONTENT: &[u8] = b"source payload retained for recovery";

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    artifacts: PathBuf,
    runs: PathBuf,
    store: ArtifactStore,
    key: Zeroizing<[u8; 32]>,
    guard: StageGuard,
    capture: CaptureBinding,
}

fn open_store(path: &Path) -> ArtifactStore {
    let metadata = fs::metadata(path).unwrap();
    let endpoint = LocalEndpoint::resolve(
        path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();

    ArtifactStore::new(endpoint, "storage_1").unwrap()
}

fn spool_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 2 * 1024 * 1024,
        ciphertext_bytes: 3 * 1024 * 1024,
    }
}

fn payload_limits() -> PayloadLimits {
    PayloadLimits {
        max_entries: 16,
        max_file_bytes: 1024 * 1024,
        max_total_bytes: 1024 * 1024,
        max_depth: 8,
        spool: spool_limits(),
    }
}

fn entry() -> ManifestEntry {
    ManifestEntry {
        source_id: "source_1".into(),
        path_encoding: "unix_bytes".into(),
        path: vec!["ZGF0YQ".into()],
        kind: "file".into(),
        size_bytes: Some(CONTENT.len().to_string()),
        content_digest: Some(format!(
            "sha256:{}",
            Sha256::digest(CONTENT)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )),
        link_target_base64url: None,
        metadata: Vec::new(),
    }
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let artifacts = root.join("artifacts");
        let runs = root.join("runs");

        for directory in [&root, &artifacts, &runs] {
            fs::create_dir_all(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let store = open_store(&artifacts);

        Self {
            _temporary: temporary,
            root,
            artifacts,
            runs,
            store,
            key: Zeroizing::new([7; 32]),
            guard: StageGuard::default(),
            capture: CaptureBinding {
                authority_id: "local_1".into(),
                job_id: "job_1".into(),
                occurrence_id: "occurrence_1".into(),
                capture_id: "capture_1".into(),
                source_view_id: "view_1".into(),
                consistency: "best_effort".into(),
                source_selection_digest: format!("sha256:{}", "a".repeat(64)),
            },
        }
    }

    fn open_state(&self) -> StateStore {
        StateStore::open(&self.root.join("state")).unwrap()
    }

    fn get_payload_binding(&self) -> PayloadArtifactBinding {
        PayloadArtifactBinding {
            artifact_id: "one".into(),
            capture_id: self.capture.capture_id.clone(),
            storage_endpoint_id: "storage_1".into(),
            storage_identity: self.store.storage_identity().to_owned(),
            relative_name: "payload_one.sealed".into(),
            key_ref: "key_1".into(),
        }
    }

    fn create_sorter(&self) -> EncryptedManifestSort {
        EncryptedManifestSort::create(
            &self.runs,
            &self.key,
            SortLimits {
                max_entries: 16,
                max_frame_bytes: 256 * 1024,
                max_chunk_bytes: 512 * 1024,
                max_chunk_entries: 16,
                max_runs: 4,
                max_fan_in: 4,
                max_cipher_bytes: 4 * 1024 * 1024,
                max_memory_bytes: 8 * 1024 * 1024,
            },
            &self.guard,
        )
        .unwrap()
    }

    fn write_payload<'a>(
        &'a self,
        state: &mut StateStore,
    ) -> CapturedPayload<EncryptedManifestSort, PayloadStage<'a>> {
        state.bind_capture(&self.capture).unwrap();
        let stage = self
            .store
            .begin_payload(
                state,
                &self.get_payload_binding(),
                spool_limits(),
                &self.guard,
            )
            .unwrap();
        let mut capture = PayloadCapture::new(
            self.create_sorter(),
            stage,
            &self.capture,
            &self.key,
            payload_limits(),
            &self.guard,
        )
        .unwrap();
        let entry = entry();
        capture
            .begin_file("source_1", &entry.path, CONTENT.len() as u64)
            .unwrap();
        capture.write_file_chunk(CONTENT).unwrap();
        capture.append_entry(&entry).unwrap();

        capture.finish().unwrap()
    }

    fn publish_manifest(&self, state: &mut StateStore, sorter: &mut EncryptedManifestSort) {
        let binding = ManifestArtifactBinding {
            artifact_id: "one".into(),
            capture_id: self.capture.capture_id.clone(),
            storage_endpoint_id: "storage_1".into(),
            storage_identity: self.store.storage_identity().to_owned(),
            relative_name: "artifact_one.sealed".into(),
            key_ref: "key_1".into(),
        };
        let mut stage = self
            .store
            .begin(state, &binding, spool_limits(), &self.guard)
            .unwrap();
        let manifest = seal_sorted_manifest(
            sorter,
            1,
            &self.capture,
            &mut stage,
            &self.key,
            spool_limits(),
            &self.guard,
        )
        .unwrap();
        self.store
            .commit(stage, state, "key_1", &self.key, &manifest)
            .unwrap();
    }

    fn write_pair<'a>(&'a self, state: &mut StateStore) -> PayloadStage<'a> {
        let mut result = self.write_payload(state);
        self.publish_manifest(state, &mut result.metadata);

        result.destination
    }

    fn commit(
        &self,
        stage: PayloadStage<'_>,
        state: &mut StateStore,
    ) -> Result<PayloadArtifactRecord, ArtifactStoreError> {
        self.store.commit_payload(
            stage,
            state,
            &mut PayloadVerification {
                key_ref: "key_1",
                key: &self.key,
                limits: payload_limits(),
                sorter: &mut self.create_sorter(),
            },
        )
    }

    fn reconcile(
        &self,
        state: &mut StateStore,
    ) -> Result<PayloadArtifactRecord, ArtifactStoreError> {
        self.store.reconcile_payload(
            state,
            "one",
            &mut PayloadVerification {
                key_ref: "key_1",
                key: &self.key,
                limits: payload_limits(),
                sorter: &mut self.create_sorter(),
            },
            &self.guard,
        )
    }
}

#[test]
fn commits_and_reopens_payload_bound_to_sealed_manifest() {
    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    let stage = fixture.write_pair(&mut state);
    assert_eq!(
        state
            .get_payload_artifact("one")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    let sealed = fixture.commit(stage, &mut state).unwrap();
    assert_eq!(sealed.effect_state, "sealed");
    assert_eq!(
        sealed.payload_bytes.as_deref(),
        Some(CONTENT.len().to_string().as_str())
    );
    assert_eq!(sealed.file_count.as_deref(), Some("1"));
    let ciphertext = fs::read(fixture.artifacts.join("payload_one.sealed")).unwrap();
    let digest = format!(
        "sha256:{}",
        Sha256::digest(&ciphertext)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(sealed.ciphertext_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(
        sealed.ciphertext_bytes.as_deref(),
        Some(ciphertext.len().to_string().as_str())
    );
    assert!(
        !ciphertext
            .windows(CONTENT.len())
            .any(|bytes| bytes == CONTENT)
    );
    assert!(!fixture.artifacts.join(".payload_one.pending").exists());
    assert!(fixture.artifacts.join("artifact_one.sealed").exists());
    drop(state);
    let mut reopened = fixture.open_state();
    let capture = reopened.get_capture("capture_1").unwrap().unwrap();
    assert_eq!(capture.manifest_artifact_id.as_deref(), Some("one"));
    assert_eq!(capture.payload_artifact_id.as_deref(), Some("one"));
    assert_eq!(fixture.reconcile(&mut reopened).unwrap(), sealed);
}

#[test]
fn reconciles_pending_linked_and_final_process_boundaries() {
    for boundary in ["pending", "linked", "final"] {
        let fixture = Fixture::new();
        let mut state = fixture.open_state();
        drop(fixture.write_pair(&mut state));
        let pending = fixture.artifacts.join(".payload_one.pending");
        let final_path = fixture.artifacts.join("payload_one.sealed");

        if boundary != "pending" {
            fs::hard_link(&pending, &final_path).unwrap();
        }

        if boundary == "final" {
            fs::remove_file(&pending).unwrap();
        }

        drop(state);
        let mut state = fixture.open_state();
        let record = fixture.reconcile(&mut state).unwrap();
        assert_eq!(record.effect_state, "sealed");
        assert!(final_path.exists());
        assert!(!pending.exists());
        assert_eq!(fixture.reconcile(&mut state).unwrap(), record);
    }
}

#[test]
fn withholds_payload_until_manifest_is_sealed_and_then_recovers() {
    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    let mut result = fixture.write_payload(&mut state);
    assert!(matches!(
        fixture.commit(result.destination, &mut state),
        Err(ArtifactStoreError::RECONCILIATION_REQUIRED)
    ));
    assert!(!fixture.artifacts.join("payload_one.sealed").exists());
    assert!(fixture.artifacts.join(".payload_one.pending").exists());
    fixture.publish_manifest(&mut state, &mut result.metadata);
    assert_eq!(
        fixture.reconcile(&mut state).unwrap().effect_state,
        "sealed"
    );
}

#[test]
fn live_owner_blocks_payload_recovery_but_not_manifest_operations() {
    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    let stage = fixture.write_pair(&mut state);
    assert!(matches!(
        fixture.reconcile(&mut state),
        Err(ArtifactStoreError::BUSY)
    ));
    assert!(matches!(
        fixture.store.begin_payload(
            &mut state,
            &fixture.get_payload_binding(),
            spool_limits(),
            &fixture.guard
        ),
        Err(ArtifactStoreError::BUSY)
    ));
    let manifest = fixture
        .store
        .reconcile(
            &mut state,
            "one",
            "key_1",
            &fixture.key,
            spool_limits(),
            &fixture.guard,
        )
        .unwrap();
    assert_eq!(manifest.effect_state, "sealed");
    drop(stage);
    assert_eq!(
        fixture.reconcile(&mut state).unwrap().effect_state,
        "sealed"
    );
}

#[test]
fn refuses_wrong_key_reference_key_and_storage_identity_without_mutation() {
    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    drop(fixture.write_pair(&mut state));
    let path = fixture.artifacts.join(".payload_one.pending");
    let bytes = fs::read(&path).unwrap();

    for (key_ref, key) in [
        ("wrong", Zeroizing::new([7; 32])),
        ("key_1", Zeroizing::new([8; 32])),
    ] {
        assert!(
            fixture
                .store
                .reconcile_payload(
                    &mut state,
                    "one",
                    &mut PayloadVerification {
                        key_ref,
                        key: &key,
                        limits: payload_limits(),
                        sorter: &mut fixture.create_sorter(),
                    },
                    &fixture.guard
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            state
                .get_payload_artifact("one")
                .unwrap()
                .unwrap()
                .effect_state,
            "prepared"
        );
    }

    let other_root = fixture.root.join("different");
    fs::create_dir(&other_root).unwrap();
    fs::set_permissions(&other_root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        open_store(&other_root).reconcile_payload(
            &mut state,
            "one",
            &mut PayloadVerification {
                key_ref: "key_1",
                key: &fixture.key,
                limits: payload_limits(),
                sorter: &mut fixture.create_sorter(),
            },
            &fixture.guard
        ),
        Err(ArtifactStoreError::WRONG_STORAGE)
    ));
    assert!(
        state
            .get_capture("capture_1")
            .unwrap()
            .unwrap()
            .payload_artifact_id
            .is_none()
    );
}

#[test]
fn preserves_incomplete_or_corrupt_payload_and_conflicting_native_files() {
    for fault in ["truncate", "corrupt", "different_inode"] {
        let fixture = Fixture::new();
        let mut state = fixture.open_state();
        drop(fixture.write_pair(&mut state));
        let pending = fixture.artifacts.join(".payload_one.pending");
        let final_path = fixture.artifacts.join("payload_one.sealed");
        let mut bytes = fs::read(&pending).unwrap();

        match fault {
            "truncate" => {
                bytes.pop();
                fs::write(&pending, &bytes).unwrap();
            }
            "corrupt" => {
                bytes[35] ^= 1;
                fs::write(&pending, &bytes).unwrap();
            }
            "different_inode" => {
                fs::copy(&pending, &final_path).unwrap();
            }
            _ => unreachable!(),
        }

        assert!(fixture.reconcile(&mut state).is_err());
        assert_eq!(fs::read(&pending).unwrap(), bytes);
        assert_eq!(
            state
                .get_payload_artifact("one")
                .unwrap()
                .unwrap()
                .effect_state,
            "prepared"
        );

        if fault == "different_inode" {
            assert_eq!(fs::read(&final_path).unwrap(), bytes);
        } else {
            assert!(!final_path.exists());
        }
    }
}

#[test]
fn refuses_changed_sealed_ciphertext_before_republication() {
    struct Discard;

    impl ManifestSink for Discard {
        fn append_entry(&mut self, _entry: &ManifestEntry) -> Result<(), ScanError> {
            Ok(())
        }
    }

    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    let stage = fixture.write_pair(&mut state);
    let sealed = fixture.commit(stage, &mut state).unwrap();
    let pending = fixture.artifacts.join(".payload_one.pending");
    let final_path = fixture.artifacts.join("payload_one.sealed");
    fs::rename(&final_path, &pending).unwrap();
    let mut replacement = PayloadCapture::new(
        Discard,
        Vec::new(),
        &fixture.capture,
        &fixture.key,
        payload_limits(),
        &fixture.guard,
    )
    .unwrap();
    let entry = entry();
    replacement
        .begin_file("source_1", &entry.path, CONTENT.len() as u64)
        .unwrap();
    replacement.write_file_chunk(CONTENT).unwrap();
    replacement.append_entry(&entry).unwrap();
    let ciphertext = replacement.finish().unwrap().destination;
    fs::write(&pending, &ciphertext).unwrap();
    assert!(matches!(
        fixture.reconcile(&mut state),
        Err(ArtifactStoreError::RECONCILIATION_REQUIRED)
    ));
    assert!(!final_path.exists());
    assert_eq!(fs::read(&pending).unwrap(), ciphertext);
    assert_eq!(state.get_payload_artifact("one").unwrap().unwrap(), sealed);
}

#[test]
fn abandons_missing_prepared_payload_and_enforces_stage_quota_and_cancellation() {
    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    drop(fixture.write_pair(&mut state));
    fs::remove_file(fixture.artifacts.join(".payload_one.pending")).unwrap();
    assert_eq!(
        fixture.reconcile(&mut state).unwrap().effect_state,
        "abandoned"
    );
    assert!(
        fixture
            .store
            .begin_payload(
                &mut state,
                &fixture.get_payload_binding(),
                spool_limits(),
                &fixture.guard
            )
            .is_err()
    );
    assert!(
        state
            .get_capture("capture_1")
            .unwrap()
            .unwrap()
            .payload_artifact_id
            .is_none()
    );
    let fixture = Fixture::new();
    let mut state = fixture.open_state();
    state.bind_capture(&fixture.capture).unwrap();
    let mut stage = fixture
        .store
        .begin_payload(
            &mut state,
            &fixture.get_payload_binding(),
            SpoolLimits {
                plaintext_bytes: 1,
                ciphertext_bytes: 60,
            },
            &fixture.guard,
        )
        .unwrap();
    assert!(stage.write_all(&[42; 61]).is_err());
    assert!(stage.flush().is_err());
    drop(stage);
    let mut sorter = fixture.create_sorter();
    fixture.guard.cancellation.cancel();
    assert!(matches!(
        fixture.store.reconcile_payload(
            &mut state,
            "one",
            &mut PayloadVerification {
                key_ref: "key_1",
                key: &fixture.key,
                limits: payload_limits(),
                sorter: &mut sorter,
            },
            &fixture.guard,
        ),
        Err(ArtifactStoreError::RESOURCE(_))
    ));
    assert_eq!(
        state
            .get_payload_artifact("one")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert_eq!(
        File::open(fixture.artifacts.join(".payload_one.pending"))
            .unwrap()
            .metadata()
            .unwrap()
            .len(),
        0
    );
}
