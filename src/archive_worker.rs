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
    pub protocol_version: u32,
    pub run_id: String,
    pub operation: ArchiveWorkerOperation,
    pub operation_token: String,
    pub state_dir: PathBuf,
    pub archive_dir: PathBuf,
    pub stage_binding: ArchiveStageBinding,
    pub archive_key: [u8; 32],
    pub source_limits: ArchiveDiskLimits,
    pub repository_dir: PathBuf,
    pub repository_identity: WorkerDirectoryIdentity,
    pub scratch_dir: PathBuf,
    pub scratch_identity: WorkerDirectoryIdentity,
    pub owner_lock: PathBuf,
    pub owner_lock_identity: WorkerDirectoryIdentity,
    pub repository_password: String,
    pub repository_max_bytes: u64,
    pub memory_max_bytes: u64,
    pub timeout_seconds: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum ArchiveWorkerOperation {
    CREATE,
    VERIFY,
}

impl ArchiveWorkerOperation {
    pub fn get_name(self) -> &'static str {
        match self {
            Self::CREATE => "create",
            Self::VERIFY => "verify",
        }
    }
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
    pub protocol_version: u32,
    pub operation_token: String,
    pub run_id: String,
    pub stage_id: String,
    pub native_snapshot_id: String,
    pub manifest_digest: String,
    pub entry_count: u64,
    pub file_count: u64,
    pub payload_bytes: u64,
    pub repository_bytes: u64,
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
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, Instant};

    use rustic_backend::BackendOptions;
    use rustic_core::{
        BackupOptions, ConfigOptions, Credentials, KeyOptions, ParentOptions, Repository,
        RepositoryOptions, SnapshotOptions,
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

    struct OwnerLease {
        file: fs::File,
        parent: LocalEndpoint,
        name: std::ffi::CString,
        identity: FileIdentity,
    }

    impl OwnerLease {
        fn check(&self) -> Result<(), WorkerProtocolError> {
            self.parent
                .revalidate()
                .map_err(|_| WorkerProtocolError::IO)?;
            let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: the pinned directory, single component, and output storage are live.
            if unsafe {
                libc::fstatat(
                    self.parent.directory().as_raw_fd(),
                    self.name.as_ptr(),
                    value.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(WorkerProtocolError::IO);
            }
            // SAFETY: successful fstatat initialized value.
            let value = unsafe { value.assume_init() };
            if value.st_dev != self.identity.device
                || value.st_ino != self.identity.inode
                || value.st_mode & libc::S_IFMT != libc::S_IFREG
            {
                return Err(WorkerProtocolError::IO);
            }
            let metadata = self.file.metadata().map_err(|_| WorkerProtocolError::IO)?;
            if metadata.dev() != self.identity.device
                || metadata.ino() != self.identity.inode
                || metadata.len() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
            {
                return Err(WorkerProtocolError::IO);
            }
            Ok(())
        }
    }

    fn open_regular(
        parent: &fs::File,
        name: &std::ffi::CStr,
    ) -> Result<fs::File, WorkerProtocolError> {
        use std::os::fd::FromRawFd;
        // SAFETY: O_PATH pins this component without opening a potential device driver.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(WorkerProtocolError::IO);
        }
        // SAFETY: the fresh descriptor is transferred exactly once to File.
        let pinned = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = pinned.metadata().map_err(|_| WorkerProtocolError::IO)?;
        // SAFETY: geteuid has no arguments or retained memory.
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(WorkerProtocolError::IO);
        }
        let file = fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
            .map_err(|_| WorkerProtocolError::IO)?;
        let actual = file.metadata().map_err(|_| WorkerProtocolError::IO)?;
        if actual.dev() != metadata.dev() || actual.ino() != metadata.ino() {
            return Err(WorkerProtocolError::IO);
        }
        Ok(file)
    }

    fn acquire_owner(
        request: &ArchiveWorkerRequest,
        container_identity: &str,
    ) -> Result<OwnerLease, WorkerProtocolError> {
        use std::os::unix::ffi::OsStrExt;
        let parent_path = request
            .owner_lock
            .parent()
            .ok_or(WorkerProtocolError::INVALID)?;
        if request.repository_dir.parent() != Some(parent_path)
            || request.scratch_dir.parent() != Some(parent_path)
        {
            return Err(WorkerProtocolError::INVALID);
        }
        let parent = get_endpoint(parent_path)?;
        if get_identity_text(parent.identity()) != container_identity {
            return Err(WorkerProtocolError::STATE);
        }
        let name = std::ffi::CString::new(
            request
                .owner_lock
                .file_name()
                .ok_or(WorkerProtocolError::INVALID)?
                .as_bytes(),
        )
        .map_err(|_| WorkerProtocolError::INVALID)?;
        let file = open_regular(parent.directory(), &name)?;
        let identity = FileIdentity {
            device: request.owner_lock_identity.device,
            inode: request.owner_lock_identity.inode,
        };
        let lease = OwnerLease {
            file,
            parent,
            name,
            identity,
        };
        lease.check()?;
        lease
            .file
            .try_lock()
            .map_err(|_| WorkerProtocolError::STATE)?;
        lease.check()?;
        Ok(lease)
    }

    fn get_identity_text(identity: FileIdentity) -> String {
        format!("unix:{}:{}", identity.device, identity.inode)
    }

    fn sync_repository(
        endpoint: &LocalEndpoint,
        maximum_bytes: u64,
        guard: &StageGuard,
    ) -> Result<u64, WorkerProtocolError> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        fn check_generation(
            before: &fs::Metadata,
            after: &fs::Metadata,
        ) -> Result<(), WorkerProtocolError> {
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(WorkerProtocolError::IO);
            }
            Ok(())
        }
        fn check_entry(
            parent: &fs::File,
            name: &std::ffi::CStr,
            expected: &fs::Metadata,
        ) -> Result<(), WorkerProtocolError> {
            let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: the pinned parent, single component, and output storage remain live.
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    value.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(WorkerProtocolError::IO);
            }
            // SAFETY: successful fstatat initialized the output.
            let value = unsafe { value.assume_init() };
            if value.st_dev != expected.dev()
                || value.st_ino != expected.ino()
                || value.st_mode & libc::S_IFMT != expected.mode() & libc::S_IFMT
            {
                return Err(WorkerProtocolError::IO);
            }
            Ok(())
        }
        fn visit(
            directory: &fs::File,
            device: u64,
            depth: usize,
            count: &mut u64,
            total_bytes: &mut u64,
            maximum_bytes: u64,
            guard: &StageGuard,
        ) -> Result<(), WorkerProtocolError> {
            if depth > 4 {
                return Err(WorkerProtocolError::RESOURCE);
            }
            let directory_before = directory.metadata().map_err(|_| WorkerProtocolError::IO)?;
            let entries = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .map_err(|_| WorkerProtocolError::IO)?;
            for entry in entries {
                guard.check().map_err(|_| WorkerProtocolError::RESOURCE)?;
                let entry = entry.map_err(|_| WorkerProtocolError::IO)?;
                *count = count.checked_add(1).ok_or(WorkerProtocolError::RESOURCE)?;
                if *count > 10_000 {
                    return Err(WorkerProtocolError::RESOURCE);
                }
                let name = entry.file_name();
                let name =
                    std::ffi::CString::new(name.as_bytes()).map_err(|_| WorkerProtocolError::IO)?;
                let kind = entry.file_type().map_err(|_| WorkerProtocolError::IO)?;
                if kind.is_dir() {
                    // SAFETY: the directory descriptor and component are valid and no-follow.
                    let fd = unsafe {
                        libc::openat(
                            directory.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(WorkerProtocolError::IO);
                    }
                    // SAFETY: the fresh descriptor is transferred exactly once to File.
                    let child = unsafe { fs::File::from_raw_fd(fd) };
                    let metadata = child.metadata().map_err(|_| WorkerProtocolError::IO)?;
                    check_entry(directory, &name, &metadata)?;
                    if metadata.dev() != device {
                        return Err(WorkerProtocolError::IO);
                    }
                    visit(
                        &child,
                        device,
                        depth + 1,
                        count,
                        total_bytes,
                        maximum_bytes,
                        guard,
                    )?;
                    check_entry(directory, &name, &metadata)?;
                } else if kind.is_file() {
                    let file = open_regular(directory, &name)?;
                    let before = file.metadata().map_err(|_| WorkerProtocolError::IO)?;
                    check_entry(directory, &name, &before)?;
                    if before.dev() != device {
                        return Err(WorkerProtocolError::IO);
                    }
                    *total_bytes = total_bytes
                        .checked_add(before.len())
                        .ok_or(WorkerProtocolError::RESOURCE)?;
                    if *total_bytes > maximum_bytes {
                        return Err(WorkerProtocolError::RESOURCE);
                    }
                    file.sync_all().map_err(|_| WorkerProtocolError::IO)?;
                    let after = file.metadata().map_err(|_| WorkerProtocolError::IO)?;
                    check_generation(&before, &after)?;
                    check_entry(directory, &name, &after)?;
                } else {
                    return Err(WorkerProtocolError::IO);
                }
            }
            directory.sync_all().map_err(|_| WorkerProtocolError::IO)?;
            check_generation(
                &directory_before,
                &directory.metadata().map_err(|_| WorkerProtocolError::IO)?,
            )
        }
        endpoint.revalidate().map_err(|_| WorkerProtocolError::IO)?;
        let mut count = 0;
        let mut total_bytes = 0;
        visit(
            endpoint.directory(),
            endpoint.identity().device,
            0,
            &mut count,
            &mut total_bytes,
            maximum_bytes,
            guard,
        )?;
        endpoint.revalidate().map_err(|_| WorkerProtocolError::IO)?;
        Ok(total_bytes)
    }

    pub fn execute_archive(
        request: &ArchiveWorkerRequest,
    ) -> Result<ArchiveWorkerReport, WorkerProtocolError> {
        use super::ArchiveWorkerOperation;
        use crate::archive_backend::ArchiveBudgetBackend;
        use rustic_core::{LsOptions, RepositoryBackends};
        use std::sync::Arc;
        crate::worker_runtime::verify_worker_envelope(request.memory_max_bytes)
            .map_err(|_| WorkerProtocolError::ENVELOPE)?;
        if request.protocol_version != 1
            || request.timeout_seconds == 0
            || request.timeout_seconds > 900
            || request.repository_password.is_empty()
            || request.repository_password.len() > 4096
            || request.repository_max_bytes == 0
            || request.repository_max_bytes > 512 * 1024 * 1024
        {
            return Err(WorkerProtocolError::INVALID);
        }
        for path in [
            &request.state_dir,
            &request.repository_dir,
            &request.scratch_dir,
            &request.owner_lock,
        ] {
            check_path(path)?;
        }
        let state_metadata =
            fs::symlink_metadata(&request.state_dir).map_err(|_| WorkerProtocolError::IO)?;
        let state_endpoint = LocalEndpoint::resolve_metadata(
            &request.state_dir,
            FileIdentity {
                device: state_metadata.dev(),
                inode: state_metadata.ino(),
            },
        )
        .map_err(|_| WorkerProtocolError::STATE)?;
        let repo_endpoint = get_endpoint(&request.repository_dir)?;
        let scratch_endpoint = get_endpoint(&request.scratch_dir)?;
        if repo_endpoint.identity()
            != (FileIdentity {
                device: request.repository_identity.device,
                inode: request.repository_identity.inode,
            })
            || scratch_endpoint.identity()
                != (FileIdentity {
                    device: request.scratch_identity.device,
                    inode: request.scratch_identity.inode,
                })
        {
            return Err(WorkerProtocolError::STATE);
        }
        get_disjoint_scope_evidence(&[&state_endpoint, &repo_endpoint, &scratch_endpoint])
            .map_err(|_| WorkerProtocolError::INVALID)?;
        let state = StateStore::open_readonly(&request.state_dir)
            .map_err(|_| WorkerProtocolError::STATE)?;
        if !state
            .is_staging_quota_inventory_complete()
            .map_err(|_| WorkerProtocolError::STATE)?
            || !state
                .is_destination_growth_inventory_complete()
                .map_err(|_| WorkerProtocolError::STATE)?
        {
            return Err(WorkerProtocolError::STATE);
        }

        let run = state
            .get_native_run(&request.run_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .ok_or(WorkerProtocolError::STATE)?;
        let stage = state
            .get_archive_stage(&request.stage_binding.stage_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .ok_or(WorkerProtocolError::STATE)?;
        if run.scope_protocol != 1
            || run.operation_token.as_deref() != Some(request.operation_token.as_str())
            || run.effect_state != "running"
            || run.active_operation.as_deref() != Some(request.operation.get_name())
            || run.binding.stage_id != stage.binding.stage_id
            || run.source_catalog_digest
                != stage
                    .catalog_ciphertext_digest
                    .clone()
                    .ok_or(WorkerProtocolError::STATE)?
            || run.repository_identity.as_deref()
                != Some(get_identity_text(repo_endpoint.identity()).as_str())
            || run.scratch_identity.as_deref()
                != Some(get_identity_text(scratch_endpoint.identity()).as_str())
            || run.owner_lock_identity.as_deref()
                != Some(
                    get_identity_text(FileIdentity {
                        device: request.owner_lock_identity.device,
                        inode: request.owner_lock_identity.inode,
                    })
                    .as_str(),
                )
            || stage.effect_state != "sealed"
            || stage.binding != request.stage_binding
        {
            return Err(WorkerProtocolError::STATE);
        }
        crate::worker_runtime::verify_current_worker_identity(
            run.worker_identity
                .as_ref()
                .ok_or(WorkerProtocolError::STATE)?,
        )
        .map_err(|_| WorkerProtocolError::ENVELOPE)?;
        let owner = acquire_owner(
            request,
            run.container_identity
                .as_deref()
                .ok_or(WorkerProtocolError::STATE)?,
        )?;
        if state
            .get_native_run(&request.run_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .as_ref()
            != Some(&run)
        {
            return Err(WorkerProtocolError::STATE);
        }
        let capture = state
            .get_capture(&stage.binding.capture_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .ok_or(WorkerProtocolError::STATE)?;
        let count = run
            .manifest_entry_count
            .parse::<u64>()
            .map_err(|_| WorkerProtocolError::STATE)?;
        let total_bytes = run
            .payload_bytes
            .parse::<u64>()
            .map_err(|_| WorkerProtocolError::STATE)?;
        if count == 0
            || count > 10_000
            || capture.manifest_digest.as_deref() != Some(run.manifest_digest.as_str())
            || capture.manifest_entry_count.as_deref() != Some(run.manifest_entry_count.as_str())
        {
            return Err(WorkerProtocolError::STATE);
        }
        let guard = StageGuard {
            deadline: Instant::now().checked_add(Duration::from_secs(request.timeout_seconds)),
            ..StageGuard::default()
        };
        for endpoint in [&repo_endpoint, &scratch_endpoint] {
            crate::physical_registry::check_registered_access(
                &state,
                crate::physical_registry::PhysicalRootKind::STAGING,
                &run.binding.storage_endpoint_id,
                endpoint,
                &guard,
            )
            .map_err(|_| WorkerProtocolError::STATE)?;
        }
        let pool = ResourcePool::new(
            ResourceClass::BALANCED,
            std::thread::available_parallelism().map_or(1, usize::from),
        );
        let job = pool
            .admit_job(&capture.binding.job_id, &guard)
            .map_err(|_| WorkerProtocolError::RESOURCE)?;
        let key = Zeroizing::new(request.archive_key);
        let can_create = request.operation == ArchiveWorkerOperation::CREATE;
        let repository_path = request
            .repository_dir
            .to_str()
            .ok_or(WorkerProtocolError::INVALID)?;
        let native = BackendOptions::default()
            .repository(repository_path)
            .to_backends()
            .map_err(|_| WorkerProtocolError::ENGINE)?;
        let budget = ArchiveBudgetBackend::new(
            native.repository(),
            request.repository_max_bytes,
            can_create,
            guard.clone(),
        )
        .map_err(|_| WorkerProtocolError::RESOURCE)?;
        let backends = RepositoryBackends::new(Arc::new(budget), None);
        let options = RepositoryOptions::default().no_cache(true);
        let credentials = Credentials::password(request.repository_password.as_str());
        let run_tag = format!("relic-run-{}", request.run_id);
        let stage_tag = format!("relic-stage-{}", stage.binding.stage_id);
        if can_create {
            let mut entries = fs::read_dir(format!(
                "/proc/self/fd/{}",
                repo_endpoint.directory().as_raw_fd()
            ))
            .map_err(|_| WorkerProtocolError::IO)?;
            if entries.next().is_some() {
                return Err(WorkerProtocolError::STATE);
            }
            check_path(&request.archive_dir)?;
            let archive_endpoint = get_endpoint(&request.archive_dir)?;
            crate::physical_registry::check_registered_access(
                &state,
                crate::physical_registry::PhysicalRootKind::STAGING,
                &stage.binding.storage_endpoint_id,
                &archive_endpoint,
                &guard,
            )
            .map_err(|_| WorkerProtocolError::STATE)?;
            get_disjoint_scope_evidence(&[
                &state_endpoint,
                &archive_endpoint,
                &repo_endpoint,
                &scratch_endpoint,
            ])
            .map_err(|_| WorkerProtocolError::INVALID)?;
            let disk = ArchiveDiskStore::new(archive_endpoint, &stage.binding.storage_endpoint_id)
                .map_err(|_| WorkerProtocolError::STATE)?;
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
            let snapshot_options = SnapshotOptions::default()
                .add_tags(&run_tag)
                .map_err(|_| WorkerProtocolError::INVALID)?
                .add_tags(&stage_tag)
                .map_err(|_| WorkerProtocolError::INVALID)?;
            repository
                .archive(
                    &backup,
                    &source,
                    snapshot_options
                        .to_snapshot()
                        .map_err(|_| WorkerProtocolError::ENGINE)?,
                    &[PathBuf::from("sources")],
                )
                .map_err(|_| WorkerProtocolError::ENGINE)?;
            drop(repository);
            drop(source);
        }
        owner.check()?;
        guard.check().map_err(|_| WorkerProtocolError::RESOURCE)?;
        let repository = Repository::new(&options, &backends)
            .map_err(|_| WorkerProtocolError::ENGINE)?
            .open(&credentials)
            .map_err(|_| WorkerProtocolError::ENGINE)?
            .to_indexed()
            .map_err(|_| WorkerProtocolError::ENGINE)?;
        let mut snapshots = crate::archive_snapshot::get_snapshots_checked(
            &repository,
            &repo_endpoint,
            crate::archive_snapshot::SnapshotLimits {
                max_snapshots: 1024,
                max_ciphertext_bytes: 1024 * 1024,
                max_metadata_bytes: 8 * 1024 * 1024,
            },
            &guard,
        )
        .map_err(|_| WorkerProtocolError::VERIFICATION)?;
        if snapshots.len() != 1 {
            return Err(WorkerProtocolError::VERIFICATION);
        }
        let snapshot = snapshots.pop().ok_or(WorkerProtocolError::VERIFICATION)?;
        if !snapshot.tags.contains(&run_tag)
            || !snapshot.tags.contains(&stage_tag)
            || run
                .native_snapshot_id
                .as_deref()
                .is_some_and(|id| id != snapshot.id.to_hex().as_str())
        {
            return Err(WorkerProtocolError::VERIFICATION);
        }
        let root = repository
            .node_from_snapshot_and_path(&snapshot, "sources")
            .map_err(|_| WorkerProtocolError::VERIFICATION)?;
        let mut source_encodings = BTreeMap::new();
        let mut list_options = LsOptions::default();
        list_options.recursive = false;
        for entry in repository
            .ls(&root, &list_options)
            .map_err(|_| WorkerProtocolError::VERIFICATION)?
        {
            let (path, node) = entry.map_err(|_| WorkerProtocolError::VERIFICATION)?;
            if path.as_os_str().is_empty() {
                continue;
            }
            if !node.is_dir() || path.components().count() != 1 || source_encodings.len() >= 1024 {
                return Err(WorkerProtocolError::VERIFICATION);
            }
            let id = path
                .to_str()
                .ok_or(WorkerProtocolError::VERIFICATION)?
                .to_owned();
            if source_encodings
                .insert(id, "unix_bytes".to_owned())
                .is_some()
            {
                return Err(WorkerProtocolError::VERIFICATION);
            }
        }
        let _verification_reservation = job
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
        let retained_scratch_bytes = sync_repository(&scratch_endpoint, 8 * 1024 * 1024, &guard)?;
        let available_scratch_bytes = (8 * 1024 * 1024u64)
            .checked_sub(retained_scratch_bytes)
            .filter(|bytes| *bytes > 0)
            .ok_or(WorkerProtocolError::RESOURCE)?;
        let scratch = create_scratch(&scratch_endpoint, &request.scratch_dir)?;
        let mut sorter_key = Zeroizing::new([0; 32]);
        getrandom::fill(sorter_key.as_mut()).map_err(|_| WorkerProtocolError::RESOURCE)?;
        let mut sorter = EncryptedManifestSort::create(
            &scratch.path,
            &sorter_key,
            SortLimits {
                max_entries: count,
                max_frame_bytes: 256 * 1024,
                max_chunk_bytes: 512 * 1024,
                max_chunk_entries: 64,
                max_runs: 64,
                max_fan_in: 4,
                max_cipher_bytes: available_scratch_bytes,
                max_memory_bytes: 8 * 1024 * 1024,
            },
            &guard,
        )
        .map_err(|_| WorkerProtocolError::RESOURCE)?;
        let expected = ManifestArtifact {
            digest: run.manifest_digest.clone(),
            entry_count: count,
        };
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
        let repository_bytes =
            sync_repository(&repo_endpoint, request.repository_max_bytes, &guard)?;
        owner.check()?;
        if state
            .get_native_run(&request.run_id)
            .map_err(|_| WorkerProtocolError::STATE)?
            .as_ref()
            != Some(&run)
        {
            return Err(WorkerProtocolError::STATE);
        }
        guard.check().map_err(|_| WorkerProtocolError::RESOURCE)?;
        Ok(ArchiveWorkerReport {
            protocol_version: 1,
            operation_token: request.operation_token.clone(),
            run_id: request.run_id.clone(),
            stage_id: stage.binding.stage_id,
            native_snapshot_id: snapshot.id.to_hex().to_string(),
            manifest_digest: report.manifest.digest,
            entry_count: report.manifest.entry_count,
            file_count: report.file_count,
            payload_bytes: report.payload_bytes,
            repository_bytes,
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
