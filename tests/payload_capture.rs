use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use relic::encrypted_spool::{SpoolLimits, encrypt_spool};
use relic::manifest::ManifestEntry;
use relic::payload_capture::{
    PayloadCapture, PayloadError, PayloadFile, PayloadLimits, PayloadVisitor, visit_payload,
};
use relic::resources::StageGuard;
use relic::source_scan::{ManifestSink, ScanError};
use relic::state::CaptureBinding;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Default)]
struct Entries(Vec<ManifestEntry>);

impl ManifestSink for Entries {
    fn append_entry(&mut self, entry: &ManifestEntry) -> Result<(), ScanError> {
        self.0.push(entry.clone());

        Ok(())
    }
}

#[derive(Default)]
struct Recovery {
    entries: Vec<ManifestEntry>,
    files: Vec<Vec<u8>>,
    max_chunk_bytes: usize,
}

impl PayloadVisitor for Recovery {
    fn begin_file(&mut self, _file: &PayloadFile) -> Result<(), PayloadError> {
        self.files.push(Vec::new());

        Ok(())
    }

    fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
        self.max_chunk_bytes = self.max_chunk_bytes.max(bytes.len());
        self.files.last_mut().unwrap().extend_from_slice(bytes);

        Ok(())
    }

    fn finish_entry(&mut self, entry: &ManifestEntry) -> Result<(), PayloadError> {
        self.entries.push(entry.clone());

        Ok(())
    }
}

fn binding() -> CaptureBinding {
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

fn limits() -> PayloadLimits {
    PayloadLimits {
        max_entries: 16,
        max_file_bytes: 2 * 1024 * 1024,
        max_total_bytes: 4 * 1024 * 1024,
        max_depth: 8,
        spool: SpoolLimits {
            plaintext_bytes: 5 * 1024 * 1024,
            ciphertext_bytes: 6 * 1024 * 1024,
        },
    }
}

fn file_entry(name: &str, bytes: &[u8]) -> ManifestEntry {
    ManifestEntry {
        source_id: "documents".into(),
        path_encoding: "unix_bytes".into(),
        path: vec![URL_SAFE_NO_PAD.encode(name)],
        kind: "file".into(),
        size_bytes: Some(bytes.len().to_string()),
        content_digest: Some(format!(
            "sha256:{}",
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )),
        link_target_base64url: None,
        metadata: Vec::new(),
    }
}

fn capture(bytes: &[u8]) -> Vec<u8> {
    let key = Zeroizing::new([7; 32]);
    let mut capture = PayloadCapture::new(
        Entries::default(),
        Vec::new(),
        &binding(),
        &key,
        limits(),
        &StageGuard::default(),
    )
    .unwrap();
    let entry = file_entry("private_file", bytes);
    capture
        .begin_file("documents", &entry.path, bytes.len() as u64)
        .unwrap();

    for chunk in bytes.chunks(19_999) {
        capture.write_file_chunk(chunk).unwrap();
    }

    capture.append_entry(&entry).unwrap();
    capture.finish().unwrap().destination
}

fn frame(output: &mut Vec<u8>, tag: u8, value: &impl serde::Serialize) {
    let bytes = serde_jcs::to_vec(value).unwrap();
    output.push(tag);
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(&bytes);
}

fn raw_file(bytes: &[u8], entry: &ManifestEntry) -> Vec<u8> {
    let mut output = b"relic/source-payload/v1\0".to_vec();
    frame(
        &mut output,
        2,
        &json!({
            "source_id": entry.source_id,
            "path_encoding": entry.path_encoding,
            "path": entry.path,
            "size_bytes": entry.size_bytes,
        }),
    );
    output.extend_from_slice(bytes);
    frame(&mut output, 3, entry);
    frame(
        &mut output,
        0,
        &json!({
            "entry_count": "1",
            "file_count": "1",
            "payload_bytes": entry.size_bytes,
        }),
    );

    output
}

fn encrypt_raw(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"relic/source-payload/v1\0");
    hasher.update(serde_jcs::to_vec(&binding()).unwrap());
    let mut output = Vec::new();
    encrypt_spool(
        &mut &bytes[..],
        &mut output,
        &Zeroizing::new([7; 32]),
        &hasher.finalize(),
        limits().spool,
        &StageGuard::default(),
    )
    .unwrap();

    output
}

#[test]
fn recovers_empty_small_and_multirecord_payloads_with_bounded_chunks() {
    for length in [0, 1, 65_535, 65_536, 65_537, 1_048_593] {
        let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        let ciphertext = capture(&bytes);
        let mut recovery = Recovery::default();
        let summary = visit_payload(
            ciphertext.as_slice(),
            &binding(),
            &Zeroizing::new([7; 32]),
            limits(),
            &StageGuard::default(),
            &mut recovery,
        )
        .unwrap();
        assert_eq!(summary.payload_bytes, length as u64);
        assert_eq!(summary.entry_count, 1);
        assert_eq!(summary.file_count, 1);
        assert_eq!(recovery.files, vec![bytes]);
        assert_eq!(recovery.entries.len(), 1);
        assert!(recovery.max_chunk_bytes <= 65_536);
        assert!(!ciphertext.windows(12).any(|bytes| bytes == b"private_file"));
    }
}

#[test]
fn rejects_wrong_binding_key_corruption_truncation_and_trailing_bytes() {
    let ciphertext = capture(b"private contents");
    let mut wrong_binding = binding();
    wrong_binding.source_view_id = "another_view".into();
    let mut corrupted = ciphertext.clone();
    corrupted[35] ^= 1;
    let mut trailing = ciphertext.clone();
    trailing.push(0);

    for (bytes, binding, key) in [
        (&ciphertext[..], wrong_binding, Zeroizing::new([7; 32])),
        (&ciphertext[..], binding(), Zeroizing::new([8; 32])),
        (&corrupted[..], binding(), Zeroizing::new([7; 32])),
        (
            &ciphertext[..ciphertext.len() - 1],
            binding(),
            Zeroizing::new([7; 32]),
        ),
        (&trailing[..], binding(), Zeroizing::new([7; 32])),
    ] {
        assert!(
            visit_payload(
                bytes,
                &binding,
                &key,
                limits(),
                &StageGuard::default(),
                &mut Recovery::default(),
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_authenticated_semantic_corruption_and_invalid_counts() {
    let entry = file_entry("private_file", b"good");
    let mismatched_digest = raw_file(b"evil", &entry);
    let mut wrong_trailer = b"relic/source-payload/v1\0".to_vec();
    frame(
        &mut wrong_trailer,
        2,
        &json!({
            "source_id": entry.source_id,
            "path_encoding": entry.path_encoding,
            "path": entry.path,
            "size_bytes": entry.size_bytes,
        }),
    );
    wrong_trailer.extend_from_slice(b"good");
    let mut other_entry = entry.clone();
    other_entry.path = vec![URL_SAFE_NO_PAD.encode("other_file")];
    frame(&mut wrong_trailer, 3, &other_entry);
    let mut wrong_summary = raw_file(b"good", &entry);
    let position = wrong_summary
        .windows(17)
        .position(|bytes| bytes == b"\"entry_count\":\"1\"")
        .unwrap();
    wrong_summary[position + 15] = b'2';
    let mut extra_plaintext = raw_file(b"good", &entry);
    extra_plaintext.push(1);

    for bytes in [
        mismatched_digest,
        wrong_trailer,
        wrong_summary,
        extra_plaintext,
    ] {
        assert!(
            visit_payload(
                encrypt_raw(&bytes).as_slice(),
                &binding(),
                &Zeroizing::new([7; 32]),
                limits(),
                &StageGuard::default(),
                &mut Recovery::default(),
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_unbounded_lengths_and_traversal_before_consumer_effects() {
    let mut malicious = Vec::new();

    for (path, size_bytes) in [
        (vec!["Li4"], "0"),
        (vec!["YQ"], "18446744073709551615"),
        (vec!["YQ"], "00"),
    ] {
        let mut bytes = b"relic/source-payload/v1\0".to_vec();
        frame(
            &mut bytes,
            2,
            &json!({
                "source_id": "documents",
                "path_encoding": "unix_bytes",
                "path": path,
                "size_bytes": size_bytes,
            }),
        );
        malicious.push(bytes);
    }

    let mut oversized_frame = b"relic/source-payload/v1\0".to_vec();
    oversized_frame.push(2);
    oversized_frame.extend_from_slice(&262_145_u32.to_be_bytes());
    malicious.push(oversized_frame);

    for bytes in malicious {
        let mut recovery = Recovery::default();
        assert!(
            visit_payload(
                encrypt_raw(&bytes).as_slice(),
                &binding(),
                &Zeroizing::new([7; 32]),
                limits(),
                &StageGuard::default(),
                &mut recovery,
            )
            .is_err()
        );
        assert!(recovery.files.is_empty());
        assert!(recovery.entries.is_empty());
    }
}

#[test]
fn refuses_finalization_after_incomplete_file_or_any_capture_failure() {
    let entry = file_entry("private_file", b"data");

    for failure in ["short", "long", "digest", "metadata", "limit"] {
        let key = Zeroizing::new([7; 32]);
        let mut capture = PayloadCapture::new(
            Entries::default(),
            Vec::new(),
            &binding(),
            &key,
            limits(),
            &StageGuard::default(),
        )
        .unwrap();
        capture.begin_file("documents", &entry.path, 4).unwrap();

        match failure {
            "short" => {
                capture.write_file_chunk(b"dat").unwrap();
            }
            "long" => {
                assert!(capture.write_file_chunk(b"extra").is_err());
            }
            "digest" => {
                capture.write_file_chunk(b"evil").unwrap();
                assert!(capture.append_entry(&entry).is_err());
            }
            "metadata" => {
                capture.write_file_chunk(b"data").unwrap();
                let mut changed = entry.clone();
                changed.path = vec![URL_SAFE_NO_PAD.encode("other")];
                assert!(capture.append_entry(&changed).is_err());
            }
            "limit" => {
                assert!(
                    capture
                        .begin_file("documents", &entry.path, u64::MAX)
                        .is_err()
                );
            }
            _ => unreachable!(),
        }

        assert!(capture.finish().is_err());
    }
}

#[test]
fn cancels_within_streaming_reads_and_propagates_consumer_errors() {
    struct CancelVisitor(StageGuard);

    impl PayloadVisitor for CancelVisitor {
        fn begin_file(&mut self, _file: &PayloadFile) -> Result<(), PayloadError> {
            Ok(())
        }

        fn write_file_chunk(&mut self, _bytes: &[u8]) -> Result<(), PayloadError> {
            self.0.cancellation.cancel();

            Ok(())
        }

        fn finish_entry(&mut self, _entry: &ManifestEntry) -> Result<(), PayloadError> {
            Err(PayloadError::SINK)
        }
    }

    let bytes = capture(&vec![42; 128 * 1024]);
    let guard = StageGuard::default();
    let mut visitor = CancelVisitor(guard.clone());
    assert!(
        visit_payload(
            bytes.as_slice(),
            &binding(),
            &Zeroizing::new([7; 32]),
            limits(),
            &guard,
            &mut visitor
        )
        .is_err()
    );
    assert!(guard.cancellation.is_canceled());
    let guard = StageGuard::default();
    assert!(
        visit_payload(
            capture(b"").as_slice(),
            &binding(),
            &Zeroizing::new([7; 32]),
            limits(),
            &guard,
            &mut CancelVisitor(guard.clone())
        )
        .is_err()
    );
}

#[test]
fn does_not_finalize_a_failed_destination_or_metadata_sink() {
    struct FailedWriter;

    impl Write for FailedWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailedSink;

    impl ManifestSink for FailedSink {
        fn append_entry(&mut self, _entry: &ManifestEntry) -> Result<(), ScanError> {
            Err(ScanError::LIMIT_EXCEEDED)
        }
    }

    let key = Zeroizing::new([7; 32]);
    let guard = StageGuard::default();
    assert!(
        PayloadCapture::new(
            Entries::default(),
            FailedWriter,
            &binding(),
            &key,
            limits(),
            &guard
        )
        .is_err()
    );
    let mut capture =
        PayloadCapture::new(FailedSink, Vec::new(), &binding(), &key, limits(), &guard).unwrap();
    let entry = file_entry("empty", b"");
    capture.begin_file("documents", &entry.path, 0).unwrap();
    assert!(capture.append_entry(&entry).is_err());
    assert!(capture.finish().is_err());
}

#[test]
fn does_not_accept_provisional_payload_without_final_authentication() {
    let complete = capture(b"provisional bytes");
    let incomplete = &complete[..complete.len() - 36];
    let mut recovery = Recovery::default();
    assert!(
        visit_payload(
            incomplete,
            &binding(),
            &Zeroizing::new([7; 32]),
            limits(),
            &StageGuard::default(),
            &mut recovery,
        )
        .is_err()
    );
    assert_eq!(recovery.files, vec![b"provisional bytes".to_vec()]);
}

#[test]
fn enforces_aggregate_byte_entry_and_ciphertext_limits() {
    let key = Zeroizing::new([7; 32]);
    let guard = StageGuard::default();
    let entry = file_entry("first", b"ab");

    for constrained in [
        PayloadLimits {
            max_file_bytes: 3,
            max_total_bytes: 3,
            ..limits()
        },
        PayloadLimits {
            max_entries: 1,
            ..limits()
        },
    ] {
        let mut capture = PayloadCapture::new(
            Entries::default(),
            Vec::new(),
            &binding(),
            &key,
            constrained,
            &guard,
        )
        .unwrap();
        capture.begin_file("documents", &entry.path, 2).unwrap();
        capture.write_file_chunk(b"ab").unwrap();
        capture.append_entry(&entry).unwrap();
        assert!(
            capture
                .begin_file("documents", &[URL_SAFE_NO_PAD.encode("second")], 2)
                .is_err()
        );
        assert!(capture.finish().is_err());
    }

    let ciphertext = capture(b"four");
    let mut recovery = Recovery::default();
    assert!(
        visit_payload(
            ciphertext.as_slice(),
            &binding(),
            &key,
            PayloadLimits {
                max_file_bytes: 3,
                max_total_bytes: 3,
                ..limits()
            },
            &guard,
            &mut recovery,
        )
        .is_err()
    );
    assert!(recovery.files.is_empty());
    let mut constrained = limits();
    constrained.spool.ciphertext_bytes = 60;
    let mut capture = PayloadCapture::new(
        Entries::default(),
        Vec::new(),
        &binding(),
        &key,
        constrained,
        &guard,
    )
    .unwrap();
    let entry = file_entry("private_file", b"");
    capture.begin_file("documents", &entry.path, 0).unwrap();
    capture.append_entry(&entry).unwrap();
    assert!(capture.finish().is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
    use relic::local_endpoint::{FileIdentity, LocalEndpoint};
    use relic::manifest_artifact::ManifestArtifact;
    use relic::payload_capture::verify_payload;
    use relic::resources::{Demand, ResourceClass, ResourcePool};
    use relic::restore::{RestoreName, open_restore_directory, restore_file};
    use relic::source_scan::{ScanLimits, scan_source_pinned};
    use relic::state::StateStore;

    use super::*;

    fn create_sorter(path: &std::path::Path, guard: &StageGuard) -> EncryptedManifestSort {
        EncryptedManifestSort::create(
            path,
            &Zeroizing::new([7; 32]),
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
            guard,
        )
        .unwrap()
    }

    #[test]
    fn restores_pinned_capture_after_source_removal_and_binds_exact_manifest() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let source = root.join("source");
        let runs = root.join("runs");
        let restored = root.join("restored");

        for path in [&root, &source, &runs, &restored] {
            fs::create_dir_all(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }

        fs::create_dir(source.join("docs")).unwrap();
        let original: Vec<u8> = (0..131_089).map(|index| (index % 251) as u8).collect();
        fs::write(source.join("docs/private_data"), &original).unwrap();
        fs::write(source.join("empty"), b"").unwrap();
        let guard = StageGuard::default();
        let pool = ResourcePool::new(ResourceClass::BALANCED, 2);
        let job = pool.admit_job("job_1", &guard).unwrap();
        let reservation = job
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
        let binding = binding();
        let mut state = StateStore::open(&root.join("state")).unwrap();
        state.bind_capture(&binding).unwrap();
        let artifact_path = root.join("payload.sealed");
        let destination = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&artifact_path)
            .unwrap();
        let capture = PayloadCapture::new(
            create_sorter(&runs, &guard),
            destination,
            &binding,
            &Zeroizing::new([7; 32]),
            limits(),
            &guard,
        )
        .unwrap();
        let (capture, count) = scan_source_pinned(
            &endpoint,
            "documents",
            capture,
            ScanLimits {
                max_depth: 8,
                max_open_files: 12,
                max_entries: 16,
                max_file_bytes: 2 * 1024 * 1024,
                max_total_bytes: 4 * 1024 * 1024,
            },
            &guard,
        )
        .unwrap();
        let mut result = capture.finish().unwrap();
        result.destination.sync_all().unwrap();
        File::open(&root).unwrap().sync_all().unwrap();
        let expected = ManifestArtifact {
            digest: result
                .metadata
                .visit_sorted(&binding.capture_id, |_| Ok(()))
                .unwrap(),
            entry_count: count,
        };
        assert_eq!(count, 4);
        assert_eq!(result.summary.file_count, 2);
        assert_eq!(result.summary.payload_bytes, original.len() as u64);
        drop(result);
        drop(endpoint);
        fs::remove_dir_all(&source).unwrap();
        assert!(!source.exists());
        let mut verified_sorter = create_sorter(&runs, &guard);
        let verified = verify_payload(
            File::open(&artifact_path).unwrap(),
            &binding,
            &Zeroizing::new([7; 32]),
            limits(),
            &guard,
            &mut verified_sorter,
            &expected,
        )
        .unwrap();
        assert_eq!(verified.payload_bytes, original.len() as u64);
        let mut recovery = Recovery::default();
        visit_payload(
            File::open(&artifact_path).unwrap(),
            &binding,
            &Zeroizing::new([7; 32]),
            limits(),
            &guard,
            &mut recovery,
        )
        .unwrap();
        let root_handle = File::open(&restored).unwrap();
        let mut payloads = recovery.files.iter();

        for entry in recovery.entries {
            let path: Vec<RestoreName> = entry
                .path
                .iter()
                .map(|component| {
                    RestoreName::new(&URL_SAFE_NO_PAD.decode(component).unwrap()).unwrap()
                })
                .collect();

            if entry.kind == "directory" {
                open_restore_directory(&root_handle, &path, true, || false).unwrap();
            } else {
                let parent =
                    open_restore_directory(&root_handle, &path[..path.len() - 1], true, || false)
                        .unwrap();
                let bytes = payloads.next().unwrap();
                restore_file(
                    &parent,
                    path.last().unwrap(),
                    &mut bytes.as_slice(),
                    bytes.len() as u64,
                    Sha256::digest(bytes).into(),
                    limits().max_file_bytes,
                    || false,
                )
                .unwrap();
            }
        }

        assert_eq!(
            fs::read(restored.join("docs/private_data")).unwrap(),
            original
        );
        assert_eq!(fs::metadata(restored.join("empty")).unwrap().len(), 0);
        assert_eq!(
            state
                .get_capture(&binding.capture_id)
                .unwrap()
                .unwrap()
                .binding,
            binding
        );
        let ciphertext = fs::read(artifact_path).unwrap();
        assert!(!ciphertext.windows(12).any(|bytes| bytes == b"private_data"));
        drop(verified_sorter);
        drop(reservation);
        drop(job);
        assert_eq!(pool.usage().unwrap(), (Demand::default(), 0));
    }

    #[test]
    fn rejects_duplicate_entries_and_wrong_expected_manifest() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let guard = StageGuard::default();
        let key = Zeroizing::new([7; 32]);
        let entry = file_entry("private_file", b"");
        let mut capture = PayloadCapture::new(
            Entries::default(),
            Vec::new(),
            &binding(),
            &key,
            limits(),
            &guard,
        )
        .unwrap();

        for _ in 0..2 {
            capture.begin_file("documents", &entry.path, 0).unwrap();
            capture.append_entry(&entry).unwrap();
        }

        let duplicate = capture.finish().unwrap();
        assert!(matches!(
            verify_payload(
                duplicate.destination.as_slice(),
                &binding(),
                &key,
                limits(),
                &guard,
                &mut create_sorter(directory.path(), &guard),
                &ManifestArtifact {
                    digest: format!("sha256:{}", "a".repeat(64)),
                    entry_count: 2
                },
            ),
            Err(PayloadError::SINK)
        ));
        assert!(matches!(
            verify_payload(
                super::capture(b"").as_slice(),
                &binding(),
                &key,
                limits(),
                &guard,
                &mut create_sorter(directory.path(), &guard),
                &ManifestArtifact {
                    digest: format!("sha256:{}", "a".repeat(64)),
                    entry_count: 1
                },
            ),
            Err(PayloadError::INVALID)
        ));
    }

    #[test]
    fn source_change_aborts_capture_without_finalizing_payload() {
        struct MutatingSink<S> {
            sink: S,
            source: std::path::PathBuf,
            has_changed: bool,
        }

        impl<S: ManifestSink> ManifestSink for MutatingSink<S> {
            fn begin_file(
                &mut self,
                source_id: &str,
                path: &[String],
                size_bytes: u64,
            ) -> Result<(), ScanError> {
                self.sink.begin_file(source_id, path, size_bytes)
            }

            fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), ScanError> {
                self.sink.write_file_chunk(bytes)?;

                if !self.has_changed {
                    OpenOptions::new()
                        .append(true)
                        .open(&self.source)
                        .unwrap()
                        .write_all(b"x")
                        .unwrap();
                    self.has_changed = true;
                }

                Ok(())
            }

            fn append_entry(&mut self, entry: &ManifestEntry) -> Result<(), ScanError> {
                self.sink.append_entry(entry)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(directory.path()).unwrap();
        let file_path = source.join("data");
        fs::write(&file_path, vec![42; 128 * 1024]).unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let endpoint = LocalEndpoint::resolve(
            &source,
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )
        .unwrap();
        let mut ciphertext = Vec::new();
        let guard = StageGuard::default();
        let key = Zeroizing::new([7; 32]);
        let capture = PayloadCapture::new(
            Entries::default(),
            &mut ciphertext,
            &binding(),
            &key,
            limits(),
            &guard,
        )
        .unwrap();
        let result = scan_source_pinned(
            &endpoint,
            "documents",
            MutatingSink {
                sink: capture,
                source: file_path,
                has_changed: false,
            },
            ScanLimits {
                max_depth: 8,
                max_open_files: 12,
                max_entries: 16,
                max_file_bytes: 2 * 1024 * 1024,
                max_total_bytes: 4 * 1024 * 1024,
            },
            &guard,
        );
        assert!(matches!(result, Err(ScanError::CHANGED)));
        assert!(
            visit_payload(
                ciphertext.as_slice(),
                &binding(),
                &key,
                limits(),
                &guard,
                &mut Recovery::default()
            )
            .is_err()
        );
    }
}
