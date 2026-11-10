#![cfg(all(
    feature = "embedded-archive",
    any(target_os = "linux", target_os = "macos")
))]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use relic::archive_disk::{
    ArchiveDiskError, ArchiveDiskLimits, ArchiveDiskRequest, ArchiveDiskStore, DiskArchiveSource,
};
use relic::archive_manifest::{ArchiveManifestLimits, ArchiveManifestProjection, verify_snapshot};
use relic::artifact_store::{ArtifactStore, PayloadVerification};
use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
use relic::encrypted_spool::SpoolLimits;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::manifest_artifact::{ManifestArtifact, seal_sorted_manifest};
use relic::payload_capture::{PayloadCapture, PayloadLimits};
use relic::resources::{ActiveJob, Demand, ResourceClass, ResourcePool, StageGuard};
use relic::source_scan::{ScanLimits, scan_source_pinned};
use relic::state::{
    ArchiveStageBinding, CaptureBinding, ManifestArtifactBinding, PayloadArtifactBinding,
    StateStore,
};
use rustic_backend::BackendOptions;
use rustic_core::{
    BackupOptions, ConfigOptions, Credentials, KeyOptions, ParentOptions, ReadSource,
    ReadSourceOpen, Repository, RepositoryOptions, SnapshotOptions,
};
use zeroize::Zeroizing;

const CHUNK_BYTES: usize = 64 * 1024;

fn create_private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn get_endpoint(path: &Path) -> LocalEndpoint {
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

fn get_spool_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 32 * 1024 * 1024,
        ciphertext_bytes: 64 * 1024 * 1024,
    }
}

fn get_payload_limits() -> PayloadLimits {
    PayloadLimits {
        max_entries: 20,
        max_file_bytes: 16 * 1024 * 1024,
        max_total_bytes: 32 * 1024 * 1024,
        max_depth: 4,
        spool: get_spool_limits(),
    }
}

fn get_sort_limits() -> SortLimits {
    SortLimits {
        max_entries: 20,
        max_frame_bytes: 256 * 1024,
        max_chunk_bytes: 512 * 1024,
        max_chunk_entries: 2,
        max_runs: 8,
        max_fan_in: 4,
        max_cipher_bytes: 4 * 1024 * 1024,
        max_memory_bytes: 8 * 1024 * 1024,
    }
}

fn get_disk_limits() -> ArchiveDiskLimits {
    ArchiveDiskLimits {
        max_entries: 20,
        max_file_bytes: 16 * 1024 * 1024,
        max_ciphertext_bytes: 32 * 1024 * 1024,
        max_catalog_bytes: 64 * 1024,
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    root: PathBuf,
    state: StateStore,
    artifacts: ArtifactStore,
    disk: ArchiveDiskStore,
    key: Zeroizing<[u8; 32]>,
    pool: ResourcePool,
    job: ActiveJob,
    capture: CaptureBinding,
    expected: ManifestArtifact,
    data_bytes: u64,
}

impl Fixture {
    fn create(data_bytes: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source");
        let artifacts_path = root.join("artifacts");
        let disk_path = root.join("disk");
        let runs = root.join("capture_runs");
        for path in [&source, &artifacts_path, &disk_path, &runs] {
            create_private_directory(path);
        }
        create_private_directory(&source.join("folder"));
        fs::write(source.join("empty"), b"").unwrap();
        fs::write(source.join("folder/nested"), b"nested content").unwrap();
        let mut file = File::create(source.join("data.bin")).unwrap();
        let buffer = [0x5a; CHUNK_BYTES];
        let mut remaining_bytes = data_bytes;
        while remaining_bytes > 0 {
            let count = remaining_bytes.min(CHUNK_BYTES as u64) as usize;
            file.write_all(&buffer[..count]).unwrap();
            remaining_bytes -= count as u64;
        }
        drop(file);
        let endpoint = get_endpoint(&source);
        let artifacts =
            ArtifactStore::new(get_endpoint(&artifacts_path), "capture_storage").unwrap();
        let disk = ArchiveDiskStore::new(get_endpoint(&disk_path), "archive_storage").unwrap();
        let key = Zeroizing::new([7; 32]);
        let guard = StageGuard::default();
        let pool = ResourcePool::new(ResourceClass::LOW, 2);
        let job = pool.admit_job("job_1", &guard).unwrap();
        let reservation = job
            .reserve_stage(
                None,
                Demand {
                    data_bytes: 16 * 1024 * 1024,
                    spool_bytes: 128 * 1024 * 1024,
                    open_files: 24,
                    cpu_workers: 1,
                    streams: 1,
                    ..Demand::default()
                },
                &guard,
            )
            .unwrap();
        let capture = CaptureBinding {
            authority_id: "local_1".into(),
            job_id: "job_1".into(),
            occurrence_id: "occurrence_1".into(),
            capture_id: "capture_1".into(),
            source_view_id: "view_1".into(),
            consistency: "best_effort".into(),
            source_selection_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let mut state = StateStore::open(&root.join("state")).unwrap();
        state.bind_capture(&capture).unwrap();
        let manifest_binding = ManifestArtifactBinding {
            artifact_id: "manifest_1".into(),
            capture_id: capture.capture_id.clone(),
            storage_endpoint_id: "capture_storage".into(),
            storage_identity: artifacts.storage_identity().into(),
            relative_name: "artifact_manifest_1.sealed".into(),
            key_ref: "capture_key".into(),
        };
        let payload_binding = PayloadArtifactBinding {
            artifact_id: "payload_1".into(),
            capture_id: capture.capture_id.clone(),
            storage_endpoint_id: "capture_storage".into(),
            storage_identity: artifacts.storage_identity().into(),
            relative_name: "payload_payload_1.sealed".into(),
            key_ref: "capture_key".into(),
        };
        let mut manifest = artifacts
            .begin(&mut state, &manifest_binding, get_spool_limits(), &guard)
            .unwrap();
        let payload = artifacts
            .begin_payload(&mut state, &payload_binding, get_spool_limits(), &guard)
            .unwrap();
        let sorter = EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
        let capture_writer = PayloadCapture::new(
            sorter,
            payload,
            &capture,
            &key,
            get_payload_limits(),
            &guard,
        )
        .unwrap();
        let (capture_writer, count) = scan_source_pinned(
            &endpoint,
            "documents",
            capture_writer,
            ScanLimits {
                max_depth: 4,
                max_open_files: 8,
                max_entries: 20,
                max_file_bytes: 16 * 1024 * 1024,
                max_total_bytes: 32 * 1024 * 1024,
            },
            &guard,
        )
        .unwrap();
        let captured = capture_writer.finish().unwrap();
        let mut sorter = captured.metadata;
        let expected = seal_sorted_manifest(
            &mut sorter,
            count,
            &capture,
            &mut manifest,
            &key,
            get_spool_limits(),
            &guard,
        )
        .unwrap();
        artifacts
            .commit(manifest, &mut state, "capture_key", &key, &expected)
            .unwrap();
        drop(sorter);
        let mut sorter =
            EncryptedManifestSort::create(&runs, &key, get_sort_limits(), &guard).unwrap();
        artifacts
            .commit_payload(
                captured.destination,
                &mut state,
                &mut PayloadVerification {
                    key_ref: "capture_key",
                    key: &key,
                    limits: get_payload_limits(),
                    sorter: &mut sorter,
                },
            )
            .unwrap();
        drop(sorter);
        drop(endpoint);
        fs::remove_dir_all(source).unwrap();
        drop(reservation);
        Self {
            directory,
            root,
            state,
            artifacts,
            disk,
            key,
            pool,
            job,
            capture,
            expected,
            data_bytes,
        }
    }

    fn get_binding(&self, stage_id: &str) -> ArchiveStageBinding {
        ArchiveStageBinding {
            stage_id: stage_id.into(),
            capture_id: "capture_1".into(),
            payload_artifact_id: "payload_1".into(),
            storage_endpoint_id: "archive_storage".into(),
            storage_identity: self.disk.storage_identity().into(),
            key_ref: "archive_key".into(),
        }
    }

    fn create_source(
        &mut self,
        stage_id: &str,
        guard: &StageGuard,
    ) -> Result<DiskArchiveSource, ArchiveDiskError> {
        let runs = self
            .root
            .join(format!("verify_{}", uuid::Uuid::now_v7().simple()));
        create_private_directory(&runs);
        let mut sorter =
            EncryptedManifestSort::create(&runs, &self.key, get_sort_limits(), guard).unwrap();
        let binding = self.get_binding(stage_id);
        self.disk.create_source(
            &mut self.state,
            &self.artifacts,
            &mut PayloadVerification {
                key_ref: "capture_key",
                key: &self.key,
                limits: get_payload_limits(),
                sorter: &mut sorter,
            },
            ArchiveDiskRequest {
                binding: &binding,
                key: &self.key,
                limits: get_disk_limits(),
                guard,
            },
            &self.job,
        )
    }

    fn get_spool_path(&self, stage_id: &str) -> PathBuf {
        let row = self
            .state
            .list_archive_files(stage_id, "", 1)
            .unwrap()
            .remove(0);
        self.root
            .join("disk")
            .join(format!("archive_{}_{}.spool", stage_id, row.file_id))
    }

    fn reopen_source(
        &self,
        stage_id: &str,
        guard: &StageGuard,
    ) -> Result<DiskArchiveSource, ArchiveDiskError> {
        self.disk.reopen_source(
            &self.state,
            ArchiveDiskRequest {
                binding: &self.get_binding(stage_id),
                key: &self.key,
                limits: get_disk_limits(),
                guard,
            },
            &self.job,
        )
    }

    fn simulate_catalog_commit_crash(&self, stage_id: &str) {
        let connection = rusqlite::Connection::open(self.root.join("state/state.sqlite3")).unwrap();
        connection.execute("UPDATE archive_stages SET effect_state = 'prepared', catalog_ciphertext_digest = NULL, catalog_ciphertext_bytes = NULL, catalog_identity = NULL WHERE stage_id = ?1", [stage_id]).unwrap();
    }

    fn reconcile_source(
        &mut self,
        stage_id: &str,
        guard: &StageGuard,
    ) -> Result<DiskArchiveSource, ArchiveDiskError> {
        let binding = self.get_binding(stage_id);
        self.disk.reconcile_source(
            &mut self.state,
            ArchiveDiskRequest {
                binding: &binding,
                key: &self.key,
                limits: get_disk_limits(),
                guard,
            },
            &self.job,
        )
    }
}

fn assert_ciphertext_markers_absent(path: &Path) {
    let mut file = File::open(path).unwrap();
    let mut buffer = [0; CHUNK_BYTES];
    let mut window = Vec::with_capacity(CHUNK_BYTES + 32);
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        window.extend_from_slice(&buffer[..count]);
        for marker in [
            b"nested content".as_slice(),
            b"documents".as_slice(),
            b"data.bin".as_slice(),
        ] {
            assert!(!window.windows(marker.len()).any(|bytes| bytes == marker));
        }
        let keep_bytes = window.len().min(32);
        window.drain(..window.len() - keep_bytes);
    }
}

fn corrupt_final_byte(path: &Path) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&byte).unwrap();
}

fn read_data_file(source: &DiskArchiveSource) -> Vec<u8> {
    let open = source
        .entries()
        .map(Result::unwrap)
        .find(|entry| entry.path == Path::new("sources/documents/data.bin"))
        .unwrap()
        .open
        .unwrap();
    let mut reader = open.open().unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn stages_files_larger_than_ram_profile_and_reopens_without_original_payload() {
    let mut fixture = Fixture::create(9 * 1024 * 1024 + 17);
    let guard = StageGuard::default();
    let source = fixture.create_source("stage_1", &guard).unwrap();
    assert_eq!(source.size().unwrap(), Some(fixture.data_bytes + 14));
    assert_eq!(fixture.pool.usage().unwrap().0.data_bytes, 16 * 1024 * 1024);
    for path in fs::read_dir(fixture.root.join("disk"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
    {
        assert_ciphertext_markers_absent(&path);
    }
    let mut total_bytes = 0;
    let mut buffer = [0; CHUNK_BYTES];
    let open = source
        .entries()
        .map(Result::unwrap)
        .find(|entry| entry.path == Path::new("sources/documents/data.bin"))
        .unwrap()
        .open
        .unwrap();
    let mut reader = open.open().unwrap();
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        assert!(buffer[..count].iter().all(|byte| *byte == 0x5a));
        total_bytes += count as u64;
    }
    assert_eq!(total_bytes, fixture.data_bytes);
    drop(reader);
    assert!(matches!(
        fixture.reopen_source("stage_1", &guard),
        Err(ArchiveDiskError::BUSY)
    ));
    drop(source);
    assert_eq!(fixture.pool.usage().unwrap().0.data_bytes, 0);
    fs::remove_file(fixture.root.join("artifacts/payload_payload_1.sealed")).unwrap();
    let reopened = fixture.reopen_source("stage_1", &guard).unwrap();
    assert_eq!(reopened.size().unwrap(), Some(fixture.data_bytes + 14));
    drop(reopened);
    assert_eq!(fixture.pool.usage().unwrap().0.data_bytes, 0);
    assert!(fixture.directory.path().exists());
}

#[test]
fn bounds_simultaneous_readers_and_retains_job_lease_until_the_last_reader() {
    let mut fixture = Fixture::create(131_089);
    let guard = StageGuard::default();
    let source = fixture.create_source("stage_1", &guard).unwrap();
    let mut readers = Vec::new();
    for _ in 0..4 {
        let open = source
            .entries()
            .map(Result::unwrap)
            .find(|entry| entry.path == Path::new("sources/documents/data.bin"))
            .unwrap()
            .open
            .unwrap();
        readers.push(open.open().unwrap());
    }
    let open = source
        .entries()
        .map(Result::unwrap)
        .find(|entry| entry.path == Path::new("sources/documents/data.bin"))
        .unwrap()
        .open
        .unwrap();
    assert!(open.open().is_err());
    for (index, reader) in readers.iter_mut().enumerate() {
        let mut bytes = vec![0; 31 + index];
        reader.read_exact(&mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
    }
    drop(source);
    drop(fixture.job);
    assert_eq!(fixture.pool.usage().unwrap().0.jobs, 1);
    assert_eq!(fixture.pool.usage().unwrap().0.data_bytes, 16 * 1024 * 1024);
    drop(readers);
    assert_eq!(fixture.pool.usage().unwrap().0.jobs, 0);
    assert_eq!(fixture.pool.usage().unwrap().0.data_bytes, 0);
}

#[test]
fn rejects_wrong_keys_replaced_files_catalog_corruption_and_cancellation() {
    for fault in [
        "wrong_key",
        "file_symlink",
        "file_hardlink",
        "file_fifo",
        "moved_container",
        "replaced_lock",
        "file_tamper",
        "catalog_tamper",
        "cancel",
    ] {
        let mut fixture = Fixture::create(131_089);
        let guard = StageGuard::default();
        let source = fixture.create_source("stage_1", &guard).unwrap();
        drop(source);
        match fault {
            "wrong_key" => {
                let key = Zeroizing::new([8; 32]);
                assert!(
                    fixture
                        .disk
                        .reopen_source(
                            &fixture.state,
                            ArchiveDiskRequest {
                                binding: &fixture.get_binding("stage_1"),
                                key: &key,
                                limits: get_disk_limits(),
                                guard: &guard
                            },
                            &fixture.job
                        )
                        .is_err()
                );
            }
            "file_symlink" => {
                let path = fixture.get_spool_path("stage_1");
                fs::remove_file(&path).unwrap();
                symlink(
                    fixture.root.join("artifacts/payload_payload_1.sealed"),
                    path,
                )
                .unwrap();
                assert!(fixture.reopen_source("stage_1", &guard).is_err());
            }
            "file_hardlink" => {
                let path = fixture.get_spool_path("stage_1");
                fs::hard_link(&path, fixture.root.join("linked_spool")).unwrap();
                assert!(fixture.reopen_source("stage_1", &guard).is_err());
            }
            "file_fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let path = fixture.get_spool_path("stage_1");
                fs::remove_file(&path).unwrap();
                let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                // SAFETY: name is a valid NUL-terminated fixture path; mode is private.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                assert!(fixture.reopen_source("stage_1", &guard).is_err());
            }
            "moved_container" => {
                let source = fixture.reopen_source("stage_1", &guard).unwrap();
                fs::rename(fixture.root.join("disk"), fixture.root.join("moved_disk")).unwrap();
                assert!(source.entries().next().unwrap().is_err());
            }
            "replaced_lock" => {
                let source = fixture.reopen_source("stage_1", &guard).unwrap();
                let lock = fixture.root.join("disk/.archive_stage_1.lock");
                fs::rename(&lock, fixture.root.join("old_lock")).unwrap();
                File::create(&lock).unwrap();
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                assert!(source.entries().next().unwrap().is_err());
            }
            "file_tamper" => {
                let source = fixture.reopen_source("stage_1", &guard).unwrap();
                for row in fixture.state.list_archive_files("stage_1", "", 20).unwrap() {
                    let path = fixture
                        .root
                        .join("disk")
                        .join(format!("archive_stage_1_{}.spool", row.file_id));
                    corrupt_final_byte(&path);
                }
                let mut saw_failure = false;
                for entry in source.entries().map(Result::unwrap) {
                    if let Some(open) = entry.open {
                        let mut reader = open.open().unwrap();
                        saw_failure |= reader.read_to_end(&mut Vec::new()).is_err();
                    }
                }
                assert!(saw_failure);
            }
            "catalog_tamper" => {
                let path = fixture.root.join("disk/archive_stage_1.catalog");
                corrupt_final_byte(&path);
                assert!(fixture.reopen_source("stage_1", &guard).is_err());
            }
            "cancel" => {
                let source = fixture.reopen_source("stage_1", &guard).unwrap();
                let mut reader = source
                    .entries()
                    .map(Result::unwrap)
                    .find_map(|entry| entry.open)
                    .unwrap()
                    .open()
                    .unwrap();
                guard.cancellation.cancel();
                assert!(reader.read(&mut [0; 1]).is_err());
                assert!(source.entries().next().unwrap().is_err());
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn reconciles_complete_process_effects_and_preserves_corrupt_partial_stages() {
    for is_corrupt in [false, true] {
        let mut fixture = Fixture::create(131_089);
        let guard = StageGuard::default();
        let source = fixture.create_source("stage_1", &guard).unwrap();
        drop(source);
        fixture.simulate_catalog_commit_crash("stage_1");
        assert!(fixture.reopen_source("stage_1", &guard).is_err());
        if is_corrupt {
            let path = fixture.get_spool_path("stage_1");
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(25)
                .unwrap();
            assert!(fixture.reconcile_source("stage_1", &guard).is_err());
            assert_eq!(
                fixture
                    .state
                    .get_archive_stage("stage_1")
                    .unwrap()
                    .unwrap()
                    .effect_state,
                "prepared"
            );
            fixture.state.abandon_archive_stage("stage_1").unwrap();
            assert!(fixture.reconcile_source("stage_1", &guard).is_err());
        } else {
            let source = fixture.reconcile_source("stage_1", &guard).unwrap();
            assert_eq!(
                read_data_file(&source),
                vec![0x5a; fixture.data_bytes as usize]
            );
            assert_eq!(
                fixture
                    .state
                    .get_archive_stage("stage_1")
                    .unwrap()
                    .unwrap()
                    .effect_state,
                "sealed"
            );
        }
        assert!(fixture.root.join("disk/archive_stage_1.catalog").exists());
    }
}

#[test]
fn prevents_catalog_admission_after_source_corruption_and_quota_failure() {
    for fault in ["payload", "catalog_quota"] {
        let mut fixture = Fixture::create(131_089);
        let guard = StageGuard::default();
        if fault == "payload" {
            let path = fixture.root.join("artifacts/payload_payload_1.sealed");
            corrupt_final_byte(&path);
            assert!(fixture.create_source("stage_1", &guard).is_err());
        } else {
            let binding = fixture.get_binding("stage_1");
            let runs = fixture.root.join("limited_verifier");
            create_private_directory(&runs);
            let mut sorter =
                EncryptedManifestSort::create(&runs, &fixture.key, get_sort_limits(), &guard)
                    .unwrap();
            assert!(
                fixture
                    .disk
                    .create_source(
                        &mut fixture.state,
                        &fixture.artifacts,
                        &mut PayloadVerification {
                            key_ref: "capture_key",
                            key: &fixture.key,
                            limits: get_payload_limits(),
                            sorter: &mut sorter
                        },
                        ArchiveDiskRequest {
                            binding: &binding,
                            key: &fixture.key,
                            limits: ArchiveDiskLimits {
                                max_catalog_bytes: 1,
                                ..get_disk_limits()
                            },
                            guard: &guard
                        },
                        &fixture.job
                    )
                    .is_err()
            );
        }
        assert_eq!(
            fixture
                .state
                .get_archive_stage("stage_1")
                .unwrap()
                .unwrap()
                .effect_state,
            "prepared"
        );
        assert!(!fixture.root.join("disk/archive_stage_1.catalog").exists());
        assert!(fixture.reconcile_source("stage_1", &guard).is_err());
        assert_eq!(fixture.pool.usage().unwrap().0.data_bytes, 0);
    }
}

#[test]
fn native_archive_consumes_owned_files_and_matches_frozen_manifest() {
    let mut fixture = Fixture::create(131_089);
    let guard = StageGuard::default();
    let source = fixture.create_source("stage_1", &guard).unwrap();
    fs::remove_file(fixture.root.join("artifacts/payload_payload_1.sealed")).unwrap();
    let repository_path = fixture.root.join("repository");
    let backends = BackendOptions::default()
        .repository(repository_path.to_str().unwrap())
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
    drop(repository);
    drop(source);
    let repository = Repository::new(&options, &backends)
        .unwrap()
        .open(&credentials)
        .unwrap()
        .to_indexed()
        .unwrap();
    let runs = fixture.root.join("native_verifier");
    create_private_directory(&runs);
    let mut sorter =
        EncryptedManifestSort::create(&runs, &fixture.key, get_sort_limits(), &guard).unwrap();
    let sources = BTreeMap::from([("documents".to_owned(), "unix_bytes".to_owned())]);
    let report = verify_snapshot(
        &repository,
        &snapshot,
        ArchiveManifestProjection {
            binding: &fixture.capture,
            expected: &fixture.expected,
            virtual_prefix: Path::new("sources"),
            source_encodings: &sources,
        },
        &mut sorter,
        ArchiveManifestLimits {
            max_entries: 20,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
            max_depth: 4,
        },
        &guard,
    )
    .unwrap();
    assert_eq!(report.file_count, 3);
    assert_eq!(report.payload_bytes, fixture.data_bytes + 14);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires delegated Linux cgroup guard and verified independent restic"]
fn contained_worker_verifies_native_snapshot_and_independent_recovery() {
    use relic::archive::Archive;
    use relic::native_run_store::{NativeRunExecution, NativeRunStore};
    use relic::state::NativeRunBinding;
    use relic::worker_runtime::WorkerLimits;
    use std::time::Duration;

    let mut fixture = Fixture::create(131_089);
    let guard = StageGuard::default();
    drop(fixture.create_source("stage_1", &guard).unwrap());
    fs::remove_file(fixture.root.join("artifacts/payload_payload_1.sealed")).unwrap();
    let native_root = fixture.root.join("native_runs");
    create_private_directory(&native_root);
    let store =
        NativeRunStore::new(get_endpoint(&native_root), &native_root, "native_storage").unwrap();
    let binding = NativeRunBinding {
        run_id: "run_1".into(),
        stage_id: "stage_1".into(),
        storage_endpoint_id: "native_storage".into(),
        storage_identity: store.storage_identity().into(),
        relative_name: "native_run_1".into(),
        repository_key_ref: "native_key".into(),
    };
    assert_eq!(
        store
            .prepare(&mut fixture.state, &binding, &guard)
            .unwrap()
            .effect_state,
        "ready"
    );
    let limits = WorkerLimits {
        memory_max_bytes: 192 * 1024 * 1024,
        memory_high_bytes: 144 * 1024 * 1024,
        max_tasks: 64,
        max_open_files: 64,
        max_runtime: Duration::from_secs(120),
        max_output_bytes: 16 * 1024 + 4,
    };
    let pool = ResourcePool::new(ResourceClass::BALANCED, 2);
    let job = pool.admit_job("job_1", &guard).unwrap();
    let state_dir = fixture.root.join("state");
    let archive_dir = fixture.root.join("disk");
    let execution = NativeRunExecution {
        executable: Path::new(env!("CARGO_BIN_EXE_relic-worker")),
        state_dir: &state_dir,
        archive_dir: &archive_dir,
        source_key_ref: "archive_key",
        source_key: &fixture.key,
        repository_key_ref: "native_key",
        repository_password: "test-only-password",
        source_limits: get_disk_limits(),
        worker_limits: limits,
        job: &job,
        guard: &guard,
    };
    let wrong_key_execution = NativeRunExecution {
        repository_key_ref: "changed_key",
        ..execution
    };
    assert!(matches!(
        store.execute(&mut fixture.state, "run_1", &wrong_key_execution),
        Err(relic::native_run_store::NativeRunError::WRONG_KEY_REFERENCE)
    ));
    assert_eq!(
        fixture
            .state
            .get_native_run("run_1")
            .unwrap()
            .unwrap()
            .creation_attempts,
        0
    );
    let report = store
        .execute(&mut fixture.state, "run_1", &execution)
        .unwrap();
    assert_eq!(report.effect_state, "verified");
    assert_eq!(report.manifest_digest, fixture.expected.digest);
    assert_eq!(
        report.manifest_entry_count,
        fixture.expected.entry_count.to_string()
    );
    assert_eq!(report.file_count, "3");
    assert_eq!(report.payload_bytes, (fixture.data_bytes + 14).to_string());
    let snapshot_id = report.native_snapshot_id.unwrap();
    assert_eq!(snapshot_id.len(), 64);
    assert!(
        store
            .execute(&mut fixture.state, "run_1", &execution)
            .is_err()
    );
    // Simulate a parent crash after native publication, before recording its response.
    let database = rusqlite::Connection::open(state_dir.join("state.sqlite3")).unwrap();
    database.execute("UPDATE native_runs SET effect_state='running', active_operation='create', native_snapshot_id=NULL WHERE run_id='run_1'", []).unwrap();
    drop(database);
    fs::remove_dir_all(&archive_dir).unwrap();
    drop(store);
    let store =
        NativeRunStore::new(get_endpoint(&native_root), &native_root, "native_storage").unwrap();
    let reconciled = store
        .reconcile(&mut fixture.state, "run_1", &execution)
        .unwrap();
    assert_eq!(reconciled.effect_state, "verified");
    assert_eq!(
        reconciled.native_snapshot_id.as_deref(),
        Some(snapshot_id.as_str())
    );
    assert_eq!(reconciled.creation_attempts, 1);
    assert_eq!(reconciled.verification_attempts, 1);
    let repository = native_root.join("native_run_1/repository");
    let executable = std::env::var_os("RELIC_TEST_RESTIC").expect("verified restic is required");
    let password_file = fixture.root.join("password");
    fs::write(&password_file, b"test-only-password").unwrap();
    fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600)).unwrap();
    let archive = Archive {
        executable: executable.into(),
        repository,
        password_file,
        timeout: Duration::from_secs(60),
    };
    archive.check().unwrap();
    let restored = fixture.root.join("independent_restore");
    archive.restore(&snapshot_id, &restored).unwrap();
    assert_eq!(
        fs::read(restored.join("sources/documents/data.bin")).unwrap(),
        vec![0x5a; fixture.data_bytes as usize]
    );
    assert_eq!(
        fs::read(restored.join("sources/documents/empty")).unwrap(),
        b""
    );
    assert_eq!(
        fs::read(restored.join("sources/documents/folder/nested")).unwrap(),
        b"nested content"
    );
}
