use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::archive_disk::ArchiveDiskLimits;
use crate::state::ArchiveStageBinding;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveWorkerRequest {
    pub state_dir: PathBuf,
    pub archive_dir: PathBuf,
    pub stage_binding: ArchiveStageBinding,
    pub archive_key: [u8; 32],
    pub source_limits: ArchiveDiskLimits,
    pub repository_dir: PathBuf,
    pub repository_identity: WorkerDirectoryIdentity,
    pub repository_password: String,
    pub memory_max_bytes: u64,
    pub timeout_seconds: u64,
}

impl Drop for ArchiveWorkerRequest {
    fn drop(&mut self) {
        self.archive_key.zeroize();
        self.repository_password.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveWorkerReport {
    pub stage_id: String,
    pub native_snapshot_id: String,
    pub manifest_digest: String,
    pub entry_count: u64,
    pub file_count: u64,
    pub payload_bytes: u64,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum WorkerProtocolError {
    INVALID,
    ENVELOPE,
    IO,
    STATE,
    RESOURCE,
    ENGINE,
    VERIFICATION,
}

impl fmt::Display for WorkerProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid archive worker request",
            Self::ENVELOPE => "worker resource envelope is unavailable",
            Self::IO => "archive worker I/O failed",
            Self::STATE => "archive worker state verification failed",
            Self::RESOURCE => "archive worker resource limit reached",
            Self::ENGINE => "archive worker engine failed",
            Self::VERIFICATION => "archive worker verification failed",
        })
    }
}

impl std::error::Error for WorkerProtocolError {}

pub fn read_request(mut reader: impl Read) -> Result<ArchiveWorkerRequest, WorkerProtocolError> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| WorkerProtocolError::IO)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(WorkerProtocolError::INVALID);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader
        .read_exact(&mut bytes)
        .map_err(|_| WorkerProtocolError::IO)?;
    let mut trailing = [0u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| WorkerProtocolError::IO)?
        != 0
    {
        return Err(WorkerProtocolError::INVALID);
    }
    serde_json::from_slice(&bytes).map_err(|_| WorkerProtocolError::INVALID)
}

pub fn write_report(
    mut writer: impl Write,
    report: &ArchiveWorkerReport,
) -> Result<(), WorkerProtocolError> {
    let bytes = serde_json::to_vec(report).map_err(|_| WorkerProtocolError::INVALID)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(WorkerProtocolError::INVALID);
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| WorkerProtocolError::IO)?;
    writer
        .write_all(&bytes)
        .map_err(|_| WorkerProtocolError::IO)?;
    writer.flush().map_err(|_| WorkerProtocolError::IO)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, Instant};

    use rustic_backend::BackendOptions;
    use rustic_core::{
        BackupOptions, ConfigOptions, Credentials, KeyOptions, ParentOptions, ReadSource,
        Repository, RepositoryOptions, SnapshotOptions,
    };
    use zeroize::Zeroizing;

    use super::{ArchiveWorkerReport, ArchiveWorkerRequest, WorkerProtocolError};
    use crate::archive_disk::{ArchiveDiskRequest, ArchiveDiskStore};
    use crate::archive_manifest::{
        ArchiveManifestLimits, ArchiveManifestProjection, verify_snapshot,
    };
    use crate::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
    use crate::local_endpoint::{FileIdentity, LocalEndpoint, get_disjoint_scope_evidence};
    use crate::manifest_artifact::ManifestArtifact;
    use crate::resources::{Demand, ResourceClass, ResourcePool, StageGuard};
    use crate::state::StateStore;

    fn check_path(path: &Path) -> Result<(), WorkerProtocolError> {
        if !path.is_absolute()
            || path.as_os_str().len() > 4096
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(WorkerProtocolError::INVALID);
        }
        Ok(())
    }

    fn get_endpoint(path: &Path) -> Result<LocalEndpoint, WorkerProtocolError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| WorkerProtocolError::IO)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(WorkerProtocolError::INVALID);
        }
        LocalEndpoint::resolve(
            path,
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )
        .map_err(|_| WorkerProtocolError::IO)
    }

    struct ScratchDirectory {
        path: PathBuf,
    }

    fn create_scratch(
        endpoint: &LocalEndpoint,
        base: &Path,
    ) -> Result<ScratchDirectory, WorkerProtocolError> {
        endpoint.revalidate().map_err(|_| WorkerProtocolError::IO)?;
        let name = format!(".relic-sort-{}", uuid::Uuid::now_v7().simple());
        let component =
            std::ffi::CString::new(name.as_str()).map_err(|_| WorkerProtocolError::INVALID)?;
        // SAFETY: the pinned directory descriptor and NUL-terminated component remain live.
        if unsafe { libc::mkdirat(endpoint.directory().as_raw_fd(), component.as_ptr(), 0o700) }
            != 0
        {
            return Err(WorkerProtocolError::IO);
        }
        let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the parent descriptor, component, and output storage remain valid.
        if unsafe {
            libc::fstatat(
                endpoint.directory().as_raw_fd(),
                component.as_ptr(),
                value.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(WorkerProtocolError::IO);
        }
        // SAFETY: successful fstatat initialized value.
        let value = unsafe { value.assume_init() };
        if value.st_mode & libc::S_IFMT != libc::S_IFDIR || value.st_mode & 0o7777 != 0o700 {
            return Err(WorkerProtocolError::IO);
        }
        let scratch = ScratchDirectory {
            path: base.join(name),
        };
        endpoint.revalidate().map_err(|_| WorkerProtocolError::IO)?;
        Ok(scratch)
    }

    pub fn execute_archive(
        request: &ArchiveWorkerRequest,
    ) -> Result<ArchiveWorkerReport, WorkerProtocolError> {
        crate::worker_runtime::verify_worker_envelope(request.memory_max_bytes)
            .map_err(|_| WorkerProtocolError::ENVELOPE)?;
        if request.timeout_seconds == 0
            || request.timeout_seconds > 900
            || request.repository_password.is_empty()
            || request.repository_password.len() > 4096
        {
            return Err(WorkerProtocolError::INVALID);
        }
        for path in [
            &request.state_dir,
            &request.archive_dir,
            &request.repository_dir,
        ] {
            check_path(path)?;
        }
        let state_endpoint = get_endpoint(&request.state_dir)?;
        let archive_endpoint = get_endpoint(&request.archive_dir)?;
        let repo_endpoint = get_endpoint(&request.repository_dir)?;
        if repo_endpoint.identity()
            != (FileIdentity {
                device: request.repository_identity.device,
                inode: request.repository_identity.inode,
            })
        {
            return Err(WorkerProtocolError::INVALID);
        }
        get_disjoint_scope_evidence(&[&state_endpoint, &archive_endpoint, &repo_endpoint])
            .map_err(|_| WorkerProtocolError::INVALID)?;
        let meta = repo_endpoint
            .directory()
            .metadata()
            .map_err(|_| WorkerProtocolError::IO)?;
        // SAFETY: geteuid has no arguments and reads the process identity.
        if meta.uid() != unsafe { libc::geteuid() } || meta.permissions().mode() & 0o7777 != 0o700 {
            return Err(WorkerProtocolError::INVALID);
        }
        let proc_path = format!("/proc/self/fd/{}", repo_endpoint.directory().as_raw_fd());
        if fs::read_dir(&proc_path)
            .map_err(|_| WorkerProtocolError::IO)?
            .next()
            .is_some()
        {
            return Err(WorkerProtocolError::INVALID);
        }
        let state = StateStore::open_readonly(&request.state_dir)
            .map_err(|_| WorkerProtocolError::STATE)?;
        let stage = state
            .get_archive_stage(&request.stage_binding.stage_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .ok_or(WorkerProtocolError::STATE)?;
        if stage.effect_state != "sealed" || stage.binding != request.stage_binding {
            return Err(WorkerProtocolError::STATE);
        }
        let capture = state
            .get_capture(&stage.binding.capture_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .ok_or(WorkerProtocolError::STATE)?;
        let count: u64 = stage
            .manifest_entry_count
            .parse()
            .map_err(|_| WorkerProtocolError::STATE)?;
        if count == 0
            || count > 10_000
            || capture.manifest_digest.as_deref() != Some(stage.manifest_digest.as_str())
            || capture.manifest_entry_count.as_deref() != Some(stage.manifest_entry_count.as_str())
            || capture.payload_artifact_id.as_deref()
                != Some(stage.binding.payload_artifact_id.as_str())
        {
            return Err(WorkerProtocolError::STATE);
        }
        let guard = StageGuard {
            deadline: Instant::now().checked_add(Duration::from_secs(request.timeout_seconds)),
            ..StageGuard::default()
        };
        if guard.deadline.is_none() {
            return Err(WorkerProtocolError::INVALID);
        }
        let pool = ResourcePool::new(
            ResourceClass::BALANCED,
            std::thread::available_parallelism().map_or(1, usize::from),
        );
        let job = pool
            .admit_job(&capture.binding.job_id, &guard)
            .map_err(|_| WorkerProtocolError::RESOURCE)?;
        let disk = ArchiveDiskStore::new(archive_endpoint, &stage.binding.storage_endpoint_id)
            .map_err(|_| WorkerProtocolError::STATE)?;
        let key = Zeroizing::new(request.archive_key);
        let source = disk
            .reopen_source(
                &state,
                ArchiveDiskRequest {
                    binding: &request.stage_binding,
                    key: &key,
                    limits: request.source_limits,
                    guard: &guard,
                },
                &job,
            )
            .map_err(|_| WorkerProtocolError::STATE)?;
        let mut source_encodings = BTreeMap::new();
        for item in source.entries() {
            guard.check().map_err(|_| WorkerProtocolError::RESOURCE)?;
            let item = item.map_err(|_| WorkerProtocolError::STATE)?;
            if item.path.parent() == Some(Path::new("sources")) {
                if !item.node.is_dir() {
                    return Err(WorkerProtocolError::STATE);
                }
                let id = item
                    .path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or(WorkerProtocolError::STATE)?;
                if source_encodings
                    .insert(id.to_owned(), "unix_bytes".to_owned())
                    .is_some()
                    || source_encodings.len() > 1024
                {
                    return Err(WorkerProtocolError::STATE);
                }
            }
        }
        if source_encodings.is_empty() {
            return Err(WorkerProtocolError::STATE);
        }
        repo_endpoint
            .revalidate()
            .map_err(|_| WorkerProtocolError::IO)?;
        let repository_path = request
            .repository_dir
            .to_str()
            .ok_or(WorkerProtocolError::INVALID)?;
        let backends = BackendOptions::default()
            .repository(repository_path)
            .to_backends()
            .map_err(|_| WorkerProtocolError::ENGINE)?;
        let options = RepositoryOptions::default().no_cache(true);
        let credentials = Credentials::password(request.repository_password.as_str());
        let repository = Repository::new(&options, &backends)
            .map_err(|_| WorkerProtocolError::ENGINE)?
            .init(
                &credentials,
                &KeyOptions::default(),
                &ConfigOptions::default().set_version(2),
            )
            .map_err(|_| WorkerProtocolError::ENGINE)?
            .to_indexed_ids()
            .map_err(|_| WorkerProtocolError::ENGINE)?;
        let mut backup = BackupOptions::default();
        backup.parent_opts = ParentOptions::default().force(true);
        let snapshot = repository
            .archive(
                &backup,
                &source,
                SnapshotOptions::default()
                    .to_snapshot()
                    .map_err(|_| WorkerProtocolError::ENGINE)?,
                &[PathBuf::from("sources")],
            )
            .map_err(|_| WorkerProtocolError::ENGINE)?;
        drop(repository);
        drop(source);
        guard.check().map_err(|_| WorkerProtocolError::RESOURCE)?;
        repo_endpoint
            .revalidate()
            .map_err(|_| WorkerProtocolError::IO)?;
        let repository = Repository::new(&options, &backends)
            .map_err(|_| WorkerProtocolError::ENGINE)?
            .open(&credentials)
            .map_err(|_| WorkerProtocolError::ENGINE)?
            .to_indexed()
            .map_err(|_| WorkerProtocolError::ENGINE)?;
        let verification_reservation = job
            .reserve_stage(
                None,
                Demand {
                    data_bytes: 8 * 1024 * 1024,
                    spool_bytes: 8 * 1024 * 1024,
                    open_files: 8,
                    cpu_workers: 1,
                    ..Demand::default()
                },
                &guard,
            )
            .map_err(|_| WorkerProtocolError::RESOURCE)?;
        let scratch = create_scratch(&repo_endpoint, &request.repository_dir)?;
        let mut sorter = EncryptedManifestSort::create(
            &scratch.path,
            &key,
            SortLimits {
                max_entries: count,
                max_frame_bytes: 256 * 1024,
                max_chunk_bytes: 512 * 1024,
                max_chunk_entries: 64,
                max_runs: 64,
                max_fan_in: 4,
                max_cipher_bytes: 8 * 1024 * 1024,
                max_memory_bytes: 8 * 1024 * 1024,
            },
            &guard,
        )
        .map_err(|_| WorkerProtocolError::RESOURCE)?;
        let expected = ManifestArtifact {
            digest: stage.manifest_digest.clone(),
            entry_count: count,
        };
        let total_bytes: u64 = stage
            .payload_bytes
            .parse()
            .map_err(|_| WorkerProtocolError::STATE)?;
        let report = verify_snapshot(
            &repository,
            &snapshot,
            ArchiveManifestProjection {
                binding: &capture.binding,
                expected: &expected,
                virtual_prefix: Path::new("sources"),
                source_encodings: &source_encodings,
            },
            &mut sorter,
            ArchiveManifestLimits {
                max_entries: request.source_limits.max_entries,
                max_file_bytes: request
                    .source_limits
                    .max_file_bytes
                    .min(total_bytes.max(1))
                    .max(1),
                max_total_bytes: total_bytes.max(1),
                max_depth: 32,
            },
            &guard,
        )
        .map_err(|_| WorkerProtocolError::VERIFICATION)?;
        drop(sorter);
        drop(scratch);
        drop(verification_reservation);
        repo_endpoint
            .revalidate()
            .map_err(|_| WorkerProtocolError::IO)?;
        Ok(ArchiveWorkerReport {
            stage_id: stage.binding.stage_id,
            native_snapshot_id: snapshot.id.to_hex().to_string(),
            manifest_digest: report.manifest.digest,
            entry_count: report.manifest.entry_count,
            file_count: report.file_count,
            payload_bytes: report.payload_bytes,
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::execute_archive;

#[cfg(not(target_os = "linux"))]
pub fn execute_archive(
    _request: &ArchiveWorkerRequest,
) -> Result<ArchiveWorkerReport, WorkerProtocolError> {
    Err(WorkerProtocolError::ENVELOPE)
}
