#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use relic::artifact_store::{ArtifactStore, PayloadVerification};
use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
use relic::encrypted_spool::SpoolLimits;
use relic::identity::hash_domain;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::manifest_artifact::seal_sorted_manifest;
use relic::payload_capture::{PayloadCapture, PayloadLimits};
use relic::resources::{Demand, ResourceClass, ResourcePool, StageGuard};
use relic::source_scan::{ScanLimits, scan_source_pinned};
use relic::state::{CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding, StateStore};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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

fn get_spool_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 512 * 1024,
        ciphertext_bytes: 1024 * 1024,
    }
}

fn get_payload_limits() -> PayloadLimits {
    PayloadLimits {
        max_entries: 20,
        max_file_bytes: 1024,
        max_total_bytes: 2048,
        max_depth: 4,
        spool: get_spool_limits(),
    }
}

fn get_binding(endpoint: &LocalEndpoint) -> CaptureBinding {
    CaptureBinding {
        authority_id: "local_1".into(),
        job_id: "job_1".into(),
        occurrence_id: "occurrence_1".into(),
        capture_id: "capture_1".into(),
        source_view_id: "view_1".into(),
        consistency: "best_effort".into(),
        source_selection_digest: hash_domain(
            "relic/source-selection/v1",
            &json!({
                "source_id": "private_source_id",
                "endpoint_device": endpoint.identity().device.to_string(),
                "endpoint_inode": endpoint.identity().inode.to_string(),
                "selector": "."
            }),
        )
        .unwrap(),
    }
}

#[test]
fn captures_pinned_source_into_verified_encrypted_artifact_and_freezes() {
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let source = root.join("source");
    let runs = root.join("runs");
    let state = root.join("state");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&runs).unwrap();
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(source.join("confidential_name"), b"data").unwrap();
    let artifact_directory = root.join("artifacts");
    fs::create_dir(&artifact_directory).unwrap();
    fs::set_permissions(&artifact_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let key = Zeroizing::new([7; 32]);
    let guard = StageGuard::default();
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let job = pool.admit_job("job_1", &guard).unwrap();
    let stage_reservation = job
        .reserve_stage(
            Some("capture_endpoint"),
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
    let metadata = fs::metadata(&source).unwrap();
    let endpoint = LocalEndpoint::resolve(
        &source,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();
    let metadata = fs::metadata(&artifact_directory).unwrap();
    let artifact_endpoint = LocalEndpoint::resolve(
        &artifact_directory,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();
    let artifacts = ArtifactStore::new(artifact_endpoint, "local_artifacts").unwrap();
    let binding = get_binding(&endpoint);
    let artifact_binding = ManifestArtifactBinding {
        artifact_id: "artifact_1".into(),
        capture_id: binding.capture_id.clone(),
        storage_endpoint_id: "local_artifacts".into(),
        storage_identity: artifacts.storage_identity().to_owned(),
        relative_name: "artifact_artifact_1.sealed".into(),
        key_ref: "key_1".into(),
    };
    let payload_binding = PayloadArtifactBinding {
        artifact_id: "payload_1".into(),
        capture_id: binding.capture_id.clone(),
        storage_endpoint_id: "local_artifacts".into(),
        storage_identity: artifacts.storage_identity().to_owned(),
        relative_name: "payload_payload_1.sealed".into(),
        key_ref: "key_1".into(),
    };
    let mut store = StateStore::open(&state).unwrap();
    store.bind_capture(&binding).unwrap();
    let mut stage = artifacts
        .begin(&mut store, &artifact_binding, get_spool_limits(), &guard)
        .unwrap();
    let payload_stage = artifacts
        .begin_payload(&mut store, &payload_binding, get_spool_limits(), &guard)
        .unwrap();
    let pending = root.join("artifacts/.artifact_artifact_1.pending");
    let pending_payload = root.join("artifacts/.payload_payload_1.pending");
    assert_eq!(
        store
            .get_payload_artifact("payload_1")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    assert_eq!(
        store
            .get_manifest_artifact("artifact_1")
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
    let sorter = EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
    let capture = PayloadCapture::new(
        sorter,
        payload_stage,
        &binding,
        &key,
        get_payload_limits(),
        &guard,
    )
    .unwrap();
    let (capture, count) = scan_source_pinned(
        &endpoint,
        "private_source_id",
        capture,
        ScanLimits {
            max_depth: 4,
            max_open_files: 7,
            max_entries: 20,
            max_file_bytes: 1024,
            max_total_bytes: 2048,
        },
        &guard,
    )
    .unwrap();
    assert_eq!(count, 2);
    let captured = capture.finish().unwrap();
    assert_eq!(captured.summary.entry_count, 2);
    assert_eq!(captured.summary.file_count, 1);
    assert_eq!(captured.summary.payload_bytes, 4);
    let mut sorter = captured.metadata;
    let payload_stage = captured.destination;
    let expected_checksum = format!(
        "sha256:{}",
        Sha256::digest(b"data")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut saw_file = false;
    sorter
        .visit_sorted(&binding.capture_id, |entry| {
            if entry.kind == "file" {
                assert_eq!(entry.size_bytes.as_deref(), Some("4"));
                assert_eq!(
                    entry.content_digest.as_deref(),
                    Some(expected_checksum.as_str())
                );
                saw_file = true;
            }
            Ok(())
        })
        .unwrap();
    assert!(saw_file);
    let artifact = seal_sorted_manifest(
        &mut sorter,
        count,
        &binding,
        &mut stage,
        &key,
        get_spool_limits(),
        &guard,
    )
    .unwrap();
    for path in fs::read_dir(&runs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .chain([pending, pending_payload])
    {
        let bytes = fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(b"private_source_id".len())
                .any(|value| value == b"private_source_id")
        );
        assert!(
            !bytes
                .windows(b"confidential_name".len())
                .any(|value| value == b"confidential_name")
        );
        assert!(
            !bytes
                .windows(b"Y29uZmlkZW50aWFsX25hbWU".len())
                .any(|value| value == b"Y29uZmlkZW50aWFsX25hbWU")
        );
    }
    let committed = artifacts
        .commit(stage, &mut store, "key_1", &key, &artifact)
        .unwrap();
    assert_eq!(committed.effect_state, "sealed");
    drop(sorter);
    let mut verifier =
        EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
    let mut verification = PayloadVerification {
        key_ref: "key_1",
        key: &key,
        limits: get_payload_limits(),
        sorter: &mut verifier,
    };
    let committed_payload = artifacts
        .commit_payload(payload_stage, &mut store, &mut verification)
        .unwrap();
    assert_eq!(committed_payload.effect_state, "sealed");
    assert_eq!(committed_payload.file_count.as_deref(), Some("1"));
    assert_eq!(committed_payload.payload_bytes.as_deref(), Some("4"));
    drop(verifier);
    let capture = store.get_capture(&binding.capture_id).unwrap().unwrap();
    assert_eq!(
        capture.manifest_digest.as_deref(),
        Some(artifact.digest.as_str())
    );
    assert_eq!(capture.manifest_entry_count.as_deref(), Some("2"));
    assert_eq!(capture.manifest_artifact_id.as_deref(), Some("artifact_1"));
    assert_eq!(capture.payload_artifact_id.as_deref(), Some("payload_1"));
    drop(artifacts);
    drop(store);
    let metadata = fs::metadata(&artifact_directory).unwrap();
    let reopened_endpoint = LocalEndpoint::resolve(
        &artifact_directory,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();
    let reopened_artifacts = ArtifactStore::new(reopened_endpoint, "local_artifacts").unwrap();
    let mut reopened_state = StateStore::open(&state).unwrap();
    let reconciled = reopened_artifacts
        .reconcile(
            &mut reopened_state,
            "artifact_1",
            "key_1",
            &key,
            get_spool_limits(),
            &guard,
        )
        .unwrap();
    assert_eq!(reconciled, committed);
    let mut verifier =
        EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
    let mut verification = PayloadVerification {
        key_ref: "key_1",
        key: &key,
        limits: get_payload_limits(),
        sorter: &mut verifier,
    };
    let reconciled_payload = reopened_artifacts
        .reconcile_payload(&mut reopened_state, "payload_1", &mut verification, &guard)
        .unwrap();
    assert_eq!(reconciled_payload, committed_payload);
    drop(verifier);
    let capture = reopened_state
        .get_capture(&binding.capture_id)
        .unwrap()
        .unwrap();
    assert_eq!(capture.manifest_artifact_id.as_deref(), Some("artifact_1"));
    assert_eq!(capture.payload_artifact_id.as_deref(), Some("payload_1"));
    drop(reopened_state);
    drop(reopened_artifacts);
    drop(endpoint);
    drop(job);
    assert_eq!(pool.usage().unwrap().0.jobs, 1);
    drop(stage_reservation);
    assert_eq!(pool.usage().unwrap().0, Demand::default());
}
