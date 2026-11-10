#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
use relic::encrypted_spool::SpoolLimits;
use relic::identity::hash_domain;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::manifest_artifact::{seal_sorted_manifest, verify_sealed_manifest};
use relic::resources::StageGuard;
use relic::source_scan::{ScanLimits, scan_source_pinned};
use relic::state::{CaptureBinding, StateStore};
use serde_json::json;
use zeroize::Zeroizing;

fn get_sort_limits() -> SortLimits {
    SortLimits {
        max_entries: 20,
        max_frame_bytes: 256 * 1024,
        max_chunk_bytes: 512 * 1024,
        max_chunk_entries: 1,
        max_runs: 4,
        max_fan_in: 4,
        max_cipher_bytes: 4 * 1024 * 1024,
        max_memory_bytes: 8 * 1024 * 1024,
    }
}

fn get_spool_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 2 * 1024 * 1024,
        ciphertext_bytes: 3 * 1024 * 1024,
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
    let metadata = fs::metadata(&source).unwrap();
    let endpoint = LocalEndpoint::resolve(
        &source,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();
    let key = Zeroizing::new([7; 32]);
    let guard = StageGuard::default();
    let binding = get_binding(&endpoint);
    let mut store = StateStore::open(&state).unwrap();
    store.bind_capture(&binding).unwrap();
    let sorter = EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
    let (mut sorter, count) = scan_source_pinned(
        &endpoint,
        "private_source_id",
        sorter,
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
    let artifact_path = root.join("artifact.enc");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&artifact_path)
        .unwrap();
    let artifact = seal_sorted_manifest(
        &mut sorter,
        count,
        &binding,
        &mut file,
        &key,
        get_spool_limits(),
        &guard,
    )
    .unwrap();
    file.sync_all().unwrap();
    File::open(&root).unwrap().sync_all().unwrap();
    for entry in fs::read_dir(&runs).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(b"private_source_id".len())
                .any(|value| value == b"private_source_id")
        );
    }
    let bytes = fs::read(&artifact_path).unwrap();
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
    let verified = verify_sealed_manifest(
        &mut File::open(&artifact_path).unwrap(),
        &binding,
        &key,
        get_spool_limits(),
        &guard,
        &artifact.digest,
    )
    .unwrap();
    assert_eq!(verified, artifact);
    store
        .freeze_capture_manifest(&binding.capture_id, &verified.digest, verified.entry_count)
        .unwrap();
    drop(store);
    let store = StateStore::open(&state).unwrap();
    let capture = store.get_capture(&binding.capture_id).unwrap().unwrap();
    assert_eq!(
        capture.manifest_digest.as_deref(),
        Some(verified.digest.as_str())
    );
    assert_eq!(capture.manifest_entry_count.as_deref(), Some("2"));
}
