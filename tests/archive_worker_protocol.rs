#![cfg(all(feature = "embedded-archive", unix))]

use std::io::Cursor;

use relic::archive_disk::ArchiveDiskLimits;
use relic::archive_worker::{
    ArchiveWorkerOperation, ArchiveWorkerReport, ArchiveWorkerRequest, WorkerDirectoryIdentity,
    read_request, write_report,
};
use relic::state::ArchiveStageBinding;

fn get_request() -> ArchiveWorkerRequest {
    ArchiveWorkerRequest {
        protocol_version: 1,
        run_id: "run_1".into(),
        operation: ArchiveWorkerOperation::CREATE,
        scratch_dir: "/scratch".into(),
        scratch_identity: WorkerDirectoryIdentity {
            device: 1,
            inode: 3,
        },
        owner_lock: "/owner.lock".into(),
        owner_lock_identity: WorkerDirectoryIdentity {
            device: 1,
            inode: 4,
        },
        repository_max_bytes: 16 * 1024 * 1024,
        state_dir: "/state".into(),
        archive_dir: "/archive".into(),
        repository_dir: "/repository".into(),
        stage_binding: ArchiveStageBinding {
            stage_id: "stage_1".into(),
            capture_id: "capture_1".into(),
            payload_artifact_id: "payload_1".into(),
            storage_endpoint_id: "disk".into(),
            storage_identity: "unix:1:2".into(),
            key_ref: "key_1".into(),
        },
        archive_key: [7; 32],
        source_limits: ArchiveDiskLimits {
            max_entries: 20,
            max_file_bytes: 1024,
            max_ciphertext_bytes: 4096,
            max_catalog_bytes: 4096,
        },
        repository_identity: WorkerDirectoryIdentity {
            device: 1,
            inode: 2,
        },
        repository_password: "test-only-password".into(),
        memory_max_bytes: 1024 * 1024 * 1024,
        timeout_seconds: 30,
    }
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(bytes);
    result
}

#[test]
fn reads_exact_bounded_request_and_rejects_trailing_or_unknown_data() {
    let bytes = serde_json::to_vec(&get_request()).unwrap();
    let parsed = read_request(Cursor::new(frame(&bytes))).unwrap();
    assert_eq!(parsed.stage_binding.stage_id, "stage_1");
    assert_eq!(parsed.archive_key, [7; 32]);
    let mut trailing = frame(&bytes);
    trailing.push(b'x');
    assert!(read_request(Cursor::new(trailing)).is_err());
    assert!(read_request(Cursor::new([0, 1, 0, 1])).is_err());
    assert!(read_request(Cursor::new([0, 0, 0, 10, b'{'])).is_err());
    assert!(read_request(Cursor::new(frame(b"{}"))).is_err());
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["unknown"] = true.into();
    assert!(read_request(Cursor::new(frame(&serde_json::to_vec(&extra).unwrap()))).is_err());
    extra.as_object_mut().unwrap().remove("unknown");
    extra["source_limits"]["unknown"] = true.into();
    assert!(read_request(Cursor::new(frame(&serde_json::to_vec(&extra).unwrap()))).is_err());
}

#[test]
fn writes_length_framed_bounded_report() {
    let report = ArchiveWorkerReport {
        protocol_version: 1,
        run_id: "run_1".into(),
        repository_bytes: 1024,
        stage_id: "stage_1".into(),
        native_snapshot_id: "snapshot_1".into(),
        manifest_digest: "sha256:example".into(),
        entry_count: 2,
        file_count: 1,
        payload_bytes: 4,
    };
    let mut bytes = Vec::new();
    write_report(&mut bytes, &report).unwrap();
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(length, bytes.len() - 4);
    let decoded: ArchiveWorkerReport = serde_json::from_slice(&bytes[4..]).unwrap();
    assert_eq!(decoded.entry_count, 2);
    let oversized = ArchiveWorkerReport {
        stage_id: "x".repeat(17_000),
        ..report
    };
    assert!(write_report(Vec::new(), &oversized).is_err());
}
