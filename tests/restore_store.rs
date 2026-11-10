#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use relic::artifact_store::{ArtifactStore, PayloadVerification};
use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
use relic::encrypted_spool::SpoolLimits;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::manifest_artifact::seal_sorted_manifest;
use relic::payload_capture::{PayloadCapture, PayloadLimits};
use relic::resources::{
    ActiveJob, Demand, ResourceClass, ResourcePool, StageGuard, StageReservation,
};
use relic::restore_store::{RestoreLimits, RestoreStore, RestoreStoreError};
use relic::source_scan::{ScanLimits, scan_source_pinned};
use relic::state::{
    CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding, RestoreBinding, StateStore,
};
use zeroize::Zeroizing;

fn get_spool_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 512 * 1024,
        ciphertext_bytes: 1024 * 1024,
    }
}

fn get_sort_limits() -> SortLimits {
    SortLimits {
        max_entries: 20,
        max_frame_bytes: 256 * 1024,
        max_chunk_bytes: 512 * 1024,
        max_chunk_entries: 1,
        max_runs: 4,
        max_fan_in: 4,
        max_cipher_bytes: 2 * 1024 * 1024,
        max_memory_bytes: 8 * 1024 * 1024,
    }
}

fn get_payload_limits() -> PayloadLimits {
    PayloadLimits {
        max_entries: 20,
        max_file_bytes: 256 * 1024,
        max_total_bytes: 512 * 1024,
        max_depth: 4,
        spool: get_spool_limits(),
    }
}

fn get_restore_limits() -> RestoreLimits {
    RestoreLimits {
        max_entries: 20,
        max_payload_bytes: 512 * 1024,
        max_depth: 4,
        max_open_files: 12,
    }
}

fn resolve_endpoint(path: &Path) -> LocalEndpoint {
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

fn create_private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn run_with_verifier<T>(
    runs: &Path,
    key: &Zeroizing<[u8; 32]>,
    guard: &StageGuard,
    operation: impl FnOnce(&mut PayloadVerification<'_>) -> T,
) -> T {
    let mut sorter = EncryptedManifestSort::create(runs, key, get_sort_limits(), guard).unwrap();
    let mut verification = PayloadVerification {
        key_ref: "key_1",
        key,
        limits: get_payload_limits(),
        sorter: &mut sorter,
    };
    operation(&mut verification)
}

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    runs: PathBuf,
    state: StateStore,
    artifacts: ArtifactStore,
    restore: RestoreStore,
    key: Zeroizing<[u8; 32]>,
    guard: StageGuard,
    _job: ActiveJob,
    _permit: StageReservation,
}

impl Fixture {
    fn new() -> Self {
        Self::create_with_content(b"known bytes")
    }

    fn create_with_content(content: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let runs = root.join("runs");
        let source = root.join("source");
        let storage = root.join("storage");
        let target = root.join("target");
        for path in [&runs, &source, &storage, &target] {
            create_private_directory(path);
        }
        create_private_directory(&source.join("nested"));
        fs::write(source.join("nested/data"), content).unwrap();
        fs::write(source.join("empty"), b"").unwrap();
        let guard = StageGuard::default();
        let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
        let job = pool.admit_job("job_1", &guard).unwrap();
        let permit = job
            .reserve_stage(
                Some("restore"),
                Demand {
                    data_bytes: 16 * 1024 * 1024,
                    spool_bytes: 16 * 1024 * 1024,
                    open_files: 32,
                    cpu_workers: 1,
                    streams: 1,
                    ..Demand::default()
                },
                &guard,
            )
            .unwrap();
        let key = Zeroizing::new([7; 32]);
        let mut state = StateStore::open(&root.join("state")).unwrap();
        let artifacts = ArtifactStore::new(resolve_endpoint(&storage), "storage").unwrap();
        let restore = RestoreStore::new(resolve_endpoint(&target), "target").unwrap();
        let binding = CaptureBinding {
            authority_id: "local_1".into(),
            job_id: "job_1".into(),
            occurrence_id: "occurrence_1".into(),
            capture_id: "capture_1".into(),
            source_view_id: "view_1".into(),
            consistency: "best_effort".into(),
            source_selection_digest: format!("sha256:{}", "a".repeat(64)),
        };
        state.bind_capture(&binding).unwrap();
        let manifest = ManifestArtifactBinding {
            artifact_id: "manifest_1".into(),
            capture_id: binding.capture_id.clone(),
            storage_endpoint_id: "storage".into(),
            storage_identity: artifacts.storage_identity().into(),
            relative_name: "artifact_manifest_1.sealed".into(),
            key_ref: "key_1".into(),
        };
        let payload = PayloadArtifactBinding {
            artifact_id: "payload_1".into(),
            capture_id: binding.capture_id.clone(),
            storage_endpoint_id: "storage".into(),
            storage_identity: artifacts.storage_identity().into(),
            relative_name: "payload_payload_1.sealed".into(),
            key_ref: "key_1".into(),
        };
        let mut manifest_stage = artifacts
            .begin(&mut state, &manifest, get_spool_limits(), &guard)
            .unwrap();
        let payload_stage = artifacts
            .begin_payload(&mut state, &payload, get_spool_limits(), &guard)
            .unwrap();
        let sorter = EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
        let sink = PayloadCapture::new(
            sorter,
            payload_stage,
            &binding,
            &key,
            get_payload_limits(),
            &guard,
        )
        .unwrap();
        let source_endpoint = resolve_endpoint(&source);
        let (sink, count) = scan_source_pinned(
            &source_endpoint,
            "source_1",
            sink,
            ScanLimits {
                max_depth: 4,
                max_open_files: 7,
                max_entries: 20,
                max_file_bytes: 256 * 1024,
                max_total_bytes: 512 * 1024,
            },
            &guard,
        )
        .unwrap();
        assert_eq!(count, 4);
        let captured = sink.finish().unwrap();
        let mut sorter = captured.metadata;
        let sealed = seal_sorted_manifest(
            &mut sorter,
            count,
            &binding,
            &mut manifest_stage,
            &key,
            get_spool_limits(),
            &guard,
        )
        .unwrap();
        artifacts
            .commit(manifest_stage, &mut state, "key_1", &key, &sealed)
            .unwrap();
        drop(sorter);
        run_with_verifier(&runs, &key, &guard, |verification| {
            artifacts.commit_payload(captured.destination, &mut state, verification)
        })
        .unwrap();
        drop(source_endpoint);
        fs::remove_dir_all(&source).unwrap();
        Self {
            _directory: directory,
            root,
            runs,
            state,
            artifacts,
            restore,
            key,
            guard,
            _job: job,
            _permit: permit,
        }
    }

    fn get_binding(&self, id: &str) -> RestoreBinding {
        RestoreBinding {
            restore_id: id.into(),
            capture_id: "capture_1".into(),
            payload_artifact_id: "payload_1".into(),
            target_endpoint_id: "target".into(),
            target_identity: self.restore.get_storage_identity().into(),
            relative_name: format!("result_{id}"),
        }
    }

    fn get_pending_tree(&self, id: &str) -> PathBuf {
        self.root
            .join("target")
            .join(format!(".restore_{id}.pending/tree"))
    }
    fn get_output_path(&self, id: &str) -> PathBuf {
        self.root.join("target").join(format!("result_{id}"))
    }
}

#[test]
fn restores_real_payload_and_recovers_verified_and_renamed_staging() {
    for scenario in ["publish", "verified", "renamed"] {
        let mut fixture = Fixture::new();
        let binding = fixture.get_binding("restore_1");
        let mut stage = fixture
            .restore
            .begin(
                &mut fixture.state,
                &binding,
                get_restore_limits(),
                &fixture.guard,
            )
            .unwrap();
        let verified = run_with_verifier(
            &fixture.runs,
            &fixture.key,
            &fixture.guard,
            |verification| {
                fixture.restore.build(
                    &mut stage,
                    &mut fixture.state,
                    &fixture.artifacts,
                    verification,
                )
            },
        )
        .unwrap();
        assert_eq!(verified.effect_state, "verified");
        let inode = fs::metadata(fixture.get_pending_tree("restore_1"))
            .unwrap()
            .ino();
        let published = if scenario == "publish" {
            run_with_verifier(
                &fixture.runs,
                &fixture.key,
                &fixture.guard,
                |verification| {
                    fixture.restore.publish(
                        stage,
                        &mut fixture.state,
                        &fixture.artifacts,
                        verification,
                    )
                },
            )
            .unwrap()
        } else {
            drop(stage);
            if scenario == "renamed" {
                fs::rename(
                    fixture.get_pending_tree("restore_1"),
                    fixture.get_output_path("restore_1"),
                )
                .unwrap();
            }
            run_with_verifier(
                &fixture.runs,
                &fixture.key,
                &fixture.guard,
                |verification| {
                    fixture.restore.reconcile(
                        &mut fixture.state,
                        "restore_1",
                        &fixture.artifacts,
                        verification,
                        get_restore_limits(),
                        &fixture.guard,
                    )
                },
            )
            .unwrap()
        };
        assert_eq!(published.effect_state, "published");
        assert_eq!(
            fs::metadata(fixture.get_output_path("restore_1"))
                .unwrap()
                .ino(),
            inode
        );
        assert_eq!(
            fs::read(
                fixture
                    .get_output_path("restore_1")
                    .join("source_1/nested/data")
            )
            .unwrap(),
            b"known bytes"
        );
        assert_eq!(
            fs::read(fixture.get_output_path("restore_1").join("source_1/empty")).unwrap(),
            b""
        );
        drop(fixture.state);
        let state = StateStore::open(&fixture.root.join("state")).unwrap();
        assert_eq!(state.get_restore("restore_1").unwrap().unwrap(), published);
    }
}

#[test]
fn restores_multirecord_payload_without_whole_file_buffers() {
    let expected: Vec<u8> = (0..131_089).map(|index| (index % 251) as u8).collect();
    let mut fixture = Fixture::create_with_content(&expected);
    let binding = fixture.get_binding("large_restore");
    let mut stage = fixture
        .restore
        .begin(
            &mut fixture.state,
            &binding,
            get_restore_limits(),
            &fixture.guard,
        )
        .unwrap();
    run_with_verifier(
        &fixture.runs,
        &fixture.key,
        &fixture.guard,
        |verification| {
            fixture.restore.build(
                &mut stage,
                &mut fixture.state,
                &fixture.artifacts,
                verification,
            )
        },
    )
    .unwrap();
    let result = run_with_verifier(
        &fixture.runs,
        &fixture.key,
        &fixture.guard,
        |verification| {
            fixture
                .restore
                .publish(stage, &mut fixture.state, &fixture.artifacts, verification)
        },
    )
    .unwrap();
    assert_eq!(result.effect_state, "published");
    assert_eq!(result.payload_bytes, expected.len().to_string());
    assert_eq!(
        fs::read(
            fixture
                .get_output_path("large_restore")
                .join("source_1/nested/data")
        )
        .unwrap(),
        expected
    );
}

#[test]
fn refuses_existing_targets_and_live_owner() {
    for kind in ["file", "directory", "symlink"] {
        let mut fixture = Fixture::new();
        let output = fixture.get_output_path("restore_1");
        match kind {
            "file" => fs::write(&output, b"preserve").unwrap(),
            "directory" => fs::create_dir(&output).unwrap(),
            "symlink" => symlink(fixture.root.join("storage"), &output).unwrap(),
            _ => unreachable!(),
        }
        let binding = fixture.get_binding("restore_1");
        assert!(matches!(
            fixture.restore.begin(
                &mut fixture.state,
                &binding,
                get_restore_limits(),
                &fixture.guard
            ),
            Err(RestoreStoreError::CONFLICT)
        ));
        assert!(fs::symlink_metadata(&output).is_ok());
        if kind == "file" {
            assert_eq!(fs::read(output).unwrap(), b"preserve");
        }
    }
    let mut fixture = Fixture::new();
    let binding = fixture.get_binding("restore_1");
    let stage = fixture
        .restore
        .begin(
            &mut fixture.state,
            &binding,
            get_restore_limits(),
            &fixture.guard,
        )
        .unwrap();
    assert!(matches!(
        fixture.restore.begin(
            &mut fixture.state,
            &binding,
            get_restore_limits(),
            &fixture.guard
        ),
        Err(RestoreStoreError::BUSY)
    ));
    drop(stage);
}

#[test]
fn refuses_mutated_or_extra_staged_content() {
    for mutation in ["file", "extra", "tree", "container"] {
        let mut fixture = Fixture::new();
        let binding = fixture.get_binding("restore_1");
        let mut stage = fixture
            .restore
            .begin(
                &mut fixture.state,
                &binding,
                get_restore_limits(),
                &fixture.guard,
            )
            .unwrap();
        run_with_verifier(
            &fixture.runs,
            &fixture.key,
            &fixture.guard,
            |verification| {
                fixture.restore.build(
                    &mut stage,
                    &mut fixture.state,
                    &fixture.artifacts,
                    verification,
                )
            },
        )
        .unwrap();
        let tree = fixture.get_pending_tree("restore_1");
        match mutation {
            "file" => fs::write(tree.join("source_1/nested/data"), b"changed").unwrap(),
            "extra" => fs::write(tree.join("source_1/unexpected"), b"extra").unwrap(),
            "container" => {
                let container = tree.parent().unwrap();
                fs::rename(container, container.with_file_name("moved_container")).unwrap();
                create_private_directory(container);
                create_private_directory(&tree);
            }
            "tree" => {
                drop(stage);
                fs::rename(&tree, tree.with_file_name("old_tree")).unwrap();
                fs::create_dir(&tree).unwrap();
                assert!(
                    run_with_verifier(
                        &fixture.runs,
                        &fixture.key,
                        &fixture.guard,
                        |verification| fixture.restore.reconcile(
                            &mut fixture.state,
                            "restore_1",
                            &fixture.artifacts,
                            verification,
                            get_restore_limits(),
                            &fixture.guard
                        )
                    )
                    .is_err()
                );
                assert!(!fixture.get_output_path("restore_1").exists());
                continue;
            }
            _ => unreachable!(),
        }
        assert!(
            run_with_verifier(
                &fixture.runs,
                &fixture.key,
                &fixture.guard,
                |verification| fixture.restore.publish(
                    stage,
                    &mut fixture.state,
                    &fixture.artifacts,
                    verification
                )
            )
            .is_err()
        );
        assert!(!fixture.get_output_path("restore_1").exists());
        assert!(tree.exists());
    }
}

#[test]
fn refuses_wrong_key_corrupt_payload_cancellation_and_limits() {
    for scenario in ["wrong_key", "corrupt", "cancel", "limits"] {
        let mut fixture = Fixture::new();
        let binding = fixture.get_binding("restore_1");
        if scenario == "limits" {
            let limits = RestoreLimits {
                max_payload_bytes: 1,
                ..get_restore_limits()
            };
            assert!(
                fixture
                    .restore
                    .begin(&mut fixture.state, &binding, limits, &fixture.guard)
                    .is_err()
            );
            assert!(!fixture.get_output_path("restore_1").exists());
            continue;
        }
        let mut stage = fixture
            .restore
            .begin(
                &mut fixture.state,
                &binding,
                get_restore_limits(),
                &fixture.guard,
            )
            .unwrap();
        let other_guard = StageGuard::default();
        let wrong_key = Zeroizing::new([8; 32]);
        if scenario == "corrupt" {
            fs::write(
                fixture.root.join("storage/payload_payload_1.sealed"),
                b"corrupt",
            )
            .unwrap();
        }
        if scenario == "cancel" {
            fixture.guard.cancellation.cancel();
        }
        let key = if scenario == "wrong_key" {
            &wrong_key
        } else {
            &fixture.key
        };
        let result = run_with_verifier(&fixture.runs, key, &other_guard, |verification| {
            fixture.restore.build(
                &mut stage,
                &mut fixture.state,
                &fixture.artifacts,
                verification,
            )
        });
        assert!(result.is_err());
        drop(stage);
        assert!(!fixture.get_output_path("restore_1").exists());
        assert!(fixture.get_pending_tree("restore_1").exists());
    }
}

#[test]
fn reconciles_absent_prepared_intent_and_rejects_replaced_final_tree() {
    let mut fixture = Fixture::new();
    let binding = fixture.get_binding("restore_1");
    assert_eq!(
        fixture
            .state
            .prepare_restore(&binding)
            .unwrap()
            .effect_state,
        "prepared"
    );
    let result = run_with_verifier(
        &fixture.runs,
        &fixture.key,
        &fixture.guard,
        |verification| {
            fixture.restore.reconcile(
                &mut fixture.state,
                "restore_1",
                &fixture.artifacts,
                verification,
                get_restore_limits(),
                &fixture.guard,
            )
        },
    )
    .unwrap();
    assert_eq!(result.effect_state, "abandoned");
    let binding = fixture.get_binding("restore_2");
    let mut stage = fixture
        .restore
        .begin(
            &mut fixture.state,
            &binding,
            get_restore_limits(),
            &fixture.guard,
        )
        .unwrap();
    run_with_verifier(
        &fixture.runs,
        &fixture.key,
        &fixture.guard,
        |verification| {
            fixture.restore.build(
                &mut stage,
                &mut fixture.state,
                &fixture.artifacts,
                verification,
            )
        },
    )
    .unwrap();
    run_with_verifier(
        &fixture.runs,
        &fixture.key,
        &fixture.guard,
        |verification| {
            fixture
                .restore
                .publish(stage, &mut fixture.state, &fixture.artifacts, verification)
        },
    )
    .unwrap();
    let output = fixture.get_output_path("restore_2");
    fs::rename(&output, output.with_file_name("old_output")).unwrap();
    fs::create_dir(&output).unwrap();
    assert!(
        run_with_verifier(
            &fixture.runs,
            &fixture.key,
            &fixture.guard,
            |verification| fixture.restore.reconcile(
                &mut fixture.state,
                "restore_2",
                &fixture.artifacts,
                verification,
                get_restore_limits(),
                &fixture.guard
            )
        )
        .is_err()
    );
}
