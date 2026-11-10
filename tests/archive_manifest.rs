#![cfg(all(feature = "embedded-archive", unix))]

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use relic::archive::Archive;
use relic::archive_manifest::{
    ArchiveManifestError, ArchiveManifestLimits, ArchiveManifestProjection, verify_snapshot,
};
use relic::archive_source::{
    ArchiveSourceLimits, FrozenArchiveEntry, FrozenArchiveSource, encrypt_archive_file,
};
use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
use relic::encrypted_spool::SpoolLimits;
use relic::manifest::{ManifestEntry, ManifestHeader, ManifestValidator, MetadataValue};
use relic::manifest_artifact::ManifestArtifact;
use relic::resources::StageGuard;
use relic::state::CaptureBinding;
use rustic_backend::BackendOptions;
use rustic_core::repofile::SnapshotFile;
use rustic_core::{
    BackupOptions, CheckOptions, ConfigOptions, Credentials, IndexedFullStatus, KeyOptions,
    ParentOptions, Repository, RepositoryOptions, SnapshotOptions,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Input {
    entry: ManifestEntry,
    content: Option<Vec<u8>>,
}

fn get_binding() -> CaptureBinding {
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

fn get_limits() -> ArchiveManifestLimits {
    ArchiveManifestLimits {
        max_entries: 32,
        max_file_bytes: 256 * 1024,
        max_total_bytes: 512 * 1024,
        max_depth: 8,
    }
}

fn create_input(path: &[&str], content: Option<&[u8]>) -> Input {
    Input {
        entry: ManifestEntry {
            source_id: "documents".into(),
            path_encoding: "unix_bytes".into(),
            path: path
                .iter()
                .map(|part| URL_SAFE_NO_PAD.encode(part))
                .collect(),
            kind: if content.is_some() {
                "file"
            } else {
                "directory"
            }
            .into(),
            size_bytes: content.map(|bytes| bytes.len().to_string()),
            content_digest: content.map(|bytes| {
                format!(
                    "sha256:{}",
                    Sha256::digest(bytes)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                )
            }),
            link_target_base64url: None,
            metadata: Vec::new(),
        },
        content: content.map(<[u8]>::to_vec),
    }
}

fn get_inputs() -> Vec<Input> {
    vec![
        create_input(&[], None),
        create_input(&["folder"], None),
        create_input(
            &["folder", "data.txt"],
            Some(b"expected archive contents\n"),
        ),
        create_input(&["empty"], Some(b"")),
    ]
}

fn get_expected(inputs: &[Input]) -> ManifestArtifact {
    let mut entries: Vec<ManifestEntry> = inputs.iter().map(|input| input.entry.clone()).collect();
    entries.sort_by_key(|entry| {
        (
            entry.source_id.clone(),
            entry
                .path
                .iter()
                .map(|component| URL_SAFE_NO_PAD.decode(component).unwrap())
                .collect::<Vec<_>>(),
        )
    });
    let mut validator = ManifestValidator::new(&ManifestHeader {
        schema_version: 1,
        capture_id: get_binding().capture_id,
        entry_count: entries.len().to_string(),
    })
    .unwrap();

    for entry in &entries {
        validator.add_entry(entry).unwrap();
    }

    ManifestArtifact {
        digest: validator.finish().unwrap(),
        entry_count: entries.len() as u64,
    }
}

fn create_sorter(root: &Path, guard: &StageGuard) -> EncryptedManifestSort {
    let runs = root.join("runs");
    fs::create_dir_all(&runs).unwrap();
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).unwrap();

    EncryptedManifestSort::create(
        &runs,
        &Zeroizing::new([7; 32]),
        SortLimits {
            max_entries: 64,
            max_frame_bytes: 256 * 1024,
            max_chunk_bytes: 512 * 1024,
            max_chunk_entries: 1,
            max_runs: 64,
            max_fan_in: 4,
            max_cipher_bytes: 4 * 1024 * 1024,
            max_memory_bytes: 8 * 1024 * 1024,
        },
        guard,
    )
    .unwrap()
}

fn create_snapshot(
    root: &Path,
    inputs: Vec<Input>,
    is_corrupt: bool,
) -> (Repository<IndexedFullStatus>, SnapshotFile) {
    let key = Zeroizing::new([7; 32]);
    let binding = get_binding();
    let guard = StageGuard::default();
    let mut frozen = Vec::new();

    for input in inputs {
        let ciphertext = input.content.map(|bytes| {
            let ciphertext = encrypt_archive_file(
                &input.entry,
                &binding,
                &mut Cursor::new(bytes),
                &key,
                SpoolLimits {
                    plaintext_bytes: 256 * 1024,
                    ciphertext_bytes: 512 * 1024,
                },
                &guard,
            )
            .unwrap();

            if is_corrupt && input.entry.path.last().map(String::as_str) == Some("ZGF0YS50eHQ") {
                let mut bytes = ciphertext.to_vec();
                bytes[35] ^= 1;

                Arc::from(bytes)
            } else {
                ciphertext
            }
        });
        frozen.push(FrozenArchiveEntry {
            entry: input.entry,
            ciphertext,
        });
    }

    let source = FrozenArchiveSource::new(
        frozen,
        &binding,
        &key,
        ArchiveSourceLimits {
            max_entries: 64,
            max_file_bytes: 256 * 1024,
            max_ciphertext_bytes: 1024 * 1024,
            max_metadata_bytes: 1024 * 1024,
        },
        &guard,
    )
    .unwrap();
    let path = root.join("repository");
    let backends = BackendOptions::default()
        .repository(path.to_str().unwrap())
        .to_backends()
        .unwrap();
    let options = RepositoryOptions::default().no_cache(true);
    let credentials = Credentials::password("test-only-password");
    let repository = Repository::new(&options, &backends)
        .unwrap()
        .init(
            &credentials,
            &KeyOptions::default(),
            &ConfigOptions::default().set_version(2),
        )
        .unwrap()
        .to_indexed_ids()
        .unwrap();
    let mut backup = BackupOptions::default();
    backup.parent_opts = ParentOptions::default().force(true);
    let snapshot = repository
        .archive(
            &backup,
            &source,
            SnapshotOptions::default().to_snapshot().unwrap(),
            &[PathBuf::from("sources")],
        )
        .unwrap();
    drop(source);
    drop(repository);
    let repository = Repository::new(&options, &backends)
        .unwrap()
        .open(&credentials)
        .unwrap()
        .to_indexed()
        .unwrap();

    (repository, snapshot)
}

fn verify_capture(
    root: &Path,
    repository: &Repository<IndexedFullStatus>,
    snapshot: &SnapshotFile,
    expected: &ManifestArtifact,
) -> Result<relic::archive_manifest::ArchiveManifestReport, ArchiveManifestError> {
    let binding = get_binding();
    let sources = BTreeMap::from([("documents".to_owned(), "unix_bytes".to_owned())]);
    let guard = StageGuard::default();
    verify_snapshot(
        repository,
        snapshot,
        ArchiveManifestProjection {
            binding: &binding,
            expected,
            virtual_prefix: Path::new("sources"),
            source_encodings: &sources,
        },
        &mut create_sorter(root, &guard),
        get_limits(),
        &guard,
    )
}

#[test]
fn verifies_complete_frozen_archive_and_multirecord_file_content() {
    let directory = tempfile::tempdir().unwrap();
    let mut inputs = get_inputs();
    let medium: Vec<u8> = (0..131_089).map(|index| (index % 251) as u8).collect();
    inputs.push(create_input(&["medium"], Some(&medium)));
    let expected = get_expected(&inputs);
    let (repository, snapshot) = create_snapshot(directory.path(), inputs, false);
    let report = verify_capture(directory.path(), &repository, &snapshot, &expected).unwrap();
    assert_eq!(report.manifest, expected);
    assert_eq!(report.file_count, 3);
    assert_eq!(
        report.payload_bytes,
        medium.len() as u64 + b"expected archive contents\n".len() as u64
    );
}

#[test]
fn rejects_sdk_success_after_corrupt_source_file_is_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let inputs = get_inputs();
    let expected = get_expected(&inputs);
    let (repository, snapshot) = create_snapshot(directory.path(), inputs, true);
    repository
        .check(CheckOptions::default().read_data(true))
        .unwrap()
        .is_ok()
        .unwrap();
    assert!(verify_capture(directory.path(), &repository, &snapshot, &expected).is_err());
}

#[test]
fn rejects_missing_extra_renamed_and_changed_archive_entries() {
    let original = get_inputs();
    let expected = get_expected(&original);

    for fault in ["missing", "extra", "renamed", "changed"] {
        let directory = tempfile::tempdir().unwrap();
        let mut inputs = original.clone();

        match fault {
            "missing" => {
                inputs.remove(2);
            }
            "extra" => {
                inputs.push(create_input(&["unexpected"], Some(b"extra")));
            }
            "renamed" => {
                inputs[2] =
                    create_input(&["folder", "renamed"], Some(b"expected archive contents\n"));
            }
            "changed" => {
                inputs[2] =
                    create_input(&["folder", "data.txt"], Some(b"different archive content"));
            }
            _ => unreachable!(),
        }

        let (repository, snapshot) = create_snapshot(directory.path(), inputs, false);
        assert!(
            verify_capture(directory.path(), &repository, &snapshot, &expected).is_err(),
            "{fault}"
        );
    }
}

#[test]
fn rejects_wrong_mapping_metadata_expectation_limits_and_cancellation() {
    let directory = tempfile::tempdir().unwrap();
    let inputs = get_inputs();
    let expected = get_expected(&inputs);
    let (repository, snapshot) = create_snapshot(directory.path(), inputs.clone(), false);
    let binding = get_binding();
    let guard = StageGuard::default();
    for wrong_sources in [
        BTreeMap::from([("other_source".to_owned(), "unix_bytes".to_owned())]),
        BTreeMap::from([
            ("documents".to_owned(), "unix_bytes".to_owned()),
            ("missing".to_owned(), "unix_bytes".to_owned()),
        ]),
    ] {
        assert!(
            verify_snapshot(
                &repository,
                &snapshot,
                ArchiveManifestProjection {
                    binding: &binding,
                    expected: &expected,
                    virtual_prefix: Path::new("sources"),
                    source_encodings: &wrong_sources,
                },
                &mut create_sorter(directory.path(), &guard),
                get_limits(),
                &guard
            )
            .is_err()
        );
    }

    let mut metadata_inputs = inputs;
    metadata_inputs[2].entry.metadata.push(MetadataValue {
        namespace: "unix".into(),
        name: "mode".into(),
        value_base64url: "NjQ0".into(),
    });
    assert!(
        verify_capture(
            directory.path(),
            &repository,
            &snapshot,
            &get_expected(&metadata_inputs)
        )
        .is_err()
    );
    let sources = BTreeMap::from([("documents".to_owned(), "unix_bytes".to_owned())]);
    assert!(
        verify_snapshot(
            &repository,
            &snapshot,
            ArchiveManifestProjection {
                binding: &binding,
                expected: &expected,
                virtual_prefix: Path::new("sources"),
                source_encodings: &sources,
            },
            &mut create_sorter(directory.path(), &guard),
            ArchiveManifestLimits {
                max_file_bytes: 1,
                ..get_limits()
            },
            &guard
        )
        .is_err()
    );
    let mut sorter = create_sorter(directory.path(), &guard);
    guard.cancellation.cancel();
    assert!(matches!(
        verify_snapshot(
            &repository,
            &snapshot,
            ArchiveManifestProjection {
                binding: &binding,
                expected: &expected,
                virtual_prefix: Path::new("sources"),
                source_encodings: &sources,
            },
            &mut sorter,
            get_limits(),
            &guard
        ),
        Err(ArchiveManifestError::RESOURCE)
    ));
}

#[test]
#[ignore = "requires verified independent restic executable"]
fn independently_recovers_standard_archive_from_encrypted_frozen_source() {
    let executable = std::env::var_os("RELIC_TEST_RESTIC").expect("verified restic is required");
    let directory = tempfile::tempdir().unwrap();
    let inputs = get_inputs();
    let expected = get_expected(&inputs);
    let (repository, snapshot) = create_snapshot(directory.path(), inputs, false);
    verify_capture(directory.path(), &repository, &snapshot, &expected).unwrap();
    drop(repository);
    let password = directory.path().join("password");
    fs::write(&password, b"test-only-password\n").unwrap();
    fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
    let archive = Archive {
        executable: executable.into(),
        repository: directory.path().join("repository"),
        password_file: password,
        timeout: Duration::from_secs(30),
    };
    archive.check().unwrap();
    let restored = directory.path().join("independent_restore");
    archive
        .restore(snapshot.id.to_hex().as_str(), &restored)
        .unwrap();
    assert_eq!(
        fs::read(restored.join("sources/documents/folder/data.txt")).unwrap(),
        b"expected archive contents\n"
    );
    assert_eq!(
        fs::read(restored.join("sources/documents/empty")).unwrap(),
        b""
    );
}

#[derive(Clone)]
struct MalformedNativeSource {
    declared_bytes: u64,
    content: Vec<u8>,
    has_extra_source: bool,
}

impl rustic_core::ReadSource for MalformedNativeSource {
    type Open = Cursor<Vec<u8>>;
    type Iter =
        std::vec::IntoIter<rustic_core::RusticResult<rustic_core::ReadSourceEntry<Self::Open>>>;

    fn size(&self) -> rustic_core::RusticResult<Option<u64>> {
        Ok(Some(self.content.len() as u64))
    }

    fn entries(&self) -> Self::Iter {
        let mut entries = Vec::new();
        for (path, name, kind, size, content) in [
            ("sources", "sources", "dir", 0, None),
            ("sources/documents", "documents", "dir", 0, None),
            (
                "sources/documents/data.txt",
                "data.txt",
                "file",
                self.declared_bytes,
                Some(self.content.clone()),
            ),
        ] {
            let node = serde_json::from_value(serde_json::json!({"name": name, "type": kind, "size": size, "mode": if kind == "dir" { 0o700 } else { 0o600 }})).unwrap();
            entries.push(Ok(rustic_core::ReadSourceEntry {
                path: PathBuf::from(path),
                node,
                open: content.map(Cursor::new),
            }));
        }

        if self.has_extra_source {
            let node = serde_json::from_value(
                serde_json::json!({"name": "intruder", "type": "dir", "size": 0, "mode": 0o700}),
            )
            .unwrap();
            entries.push(Ok(rustic_core::ReadSourceEntry {
                path: PathBuf::from("sources/intruder"),
                node,
                open: None,
            }));
        }

        entries.into_iter()
    }
}

fn create_malformed_snapshot(
    root: &Path,
    source: &MalformedNativeSource,
) -> (Repository<IndexedFullStatus>, SnapshotFile) {
    let path = root.join("repository");
    let backends = BackendOptions::default()
        .repository(path.to_str().unwrap())
        .to_backends()
        .unwrap();
    let options = RepositoryOptions::default().no_cache(true);
    let credentials = Credentials::password("test-only-password");
    let repository = Repository::new(&options, &backends)
        .unwrap()
        .init(
            &credentials,
            &KeyOptions::default(),
            &ConfigOptions::default().set_version(2),
        )
        .unwrap()
        .to_indexed_ids()
        .unwrap();
    let mut backup = BackupOptions::default();
    backup.parent_opts = ParentOptions::default().force(true);
    let snapshot = repository
        .archive(
            &backup,
            source,
            SnapshotOptions::default().to_snapshot().unwrap(),
            &[PathBuf::from("sources")],
        )
        .unwrap();
    drop(repository);
    let repository = Repository::new(&options, &backends)
        .unwrap()
        .open(&credentials)
        .unwrap()
        .to_indexed()
        .unwrap();
    (repository, snapshot)
}

#[test]
fn rejects_native_nodes_with_inconsistent_declared_and_stored_sizes() {
    let content = b"native bytes";
    for declared_bytes in [0, 4, 20] {
        let directory = tempfile::tempdir().unwrap();
        let source = MalformedNativeSource {
            declared_bytes,
            content: content.to_vec(),
            has_extra_source: false,
        };
        let (repository, snapshot) = create_malformed_snapshot(directory.path(), &source);
        let node = repository
            .node_from_snapshot_and_path(&snapshot, "sources/documents/data.txt")
            .unwrap();
        assert_eq!(node.meta.size, declared_bytes);
        let file = repository.open_file(&node).unwrap();
        assert_eq!(
            repository.read_file_at(&file, 0, 100).unwrap().as_ref(),
            content
        );
        let mut expected_bytes = content.to_vec();
        expected_bytes.resize(declared_bytes as usize, b'_');
        let expected = get_expected(&[
            create_input(&[], None),
            create_input(&["data.txt"], Some(&expected_bytes)),
        ]);
        assert!(
            verify_capture(directory.path(), &repository, &snapshot, &expected).is_err(),
            "declared size {declared_bytes}"
        );
    }
}

#[test]
fn rejects_unexpected_native_source_namespace() {
    let directory = tempfile::tempdir().unwrap();
    let content = b"native bytes";
    let source = MalformedNativeSource {
        declared_bytes: content.len() as u64,
        content: content.to_vec(),
        has_extra_source: true,
    };
    let (repository, snapshot) = create_malformed_snapshot(directory.path(), &source);
    assert!(
        repository
            .node_from_snapshot_and_path(&snapshot, "sources/intruder")
            .unwrap()
            .is_dir()
    );
    let expected = get_expected(&[
        create_input(&[], None),
        create_input(&["data.txt"], Some(content)),
    ]);
    assert!(verify_capture(directory.path(), &repository, &snapshot, &expected).is_err());
}
