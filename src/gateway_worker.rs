//! Bounded local gateway worker with journal-bound physical owner identities.
//! Public job admission remains gated on complete controller qualification.
use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::archive_worker::WorkerDirectoryIdentity;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum GatewayWorkerOperation {
    INITIALIZE,
    INSPECT_INITIALIZATION,
    COPY,
    VERIFY,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayWorkerRequest {
    pub protocol_version: u32,
    pub operation: GatewayWorkerOperation,
    pub state_dir: PathBuf,
    pub target_dir: PathBuf,
    pub target_identity: WorkerDirectoryIdentity,
    pub owner_identity: WorkerDirectoryIdentity,
    pub scratch_identity: WorkerDirectoryIdentity,
    pub resource_id: String,
    pub receiver_epoch: u64,
    pub fence_generation: u64,
    pub admission_id: Option<String>,
    pub execution_ordinal: Option<u32>,
    pub source_repository_dir: Option<PathBuf>,
    #[serde(default)]
    pub source_password: Option<String>,
    #[serde(default)]
    pub source_key_ref: Option<String>,
    pub target_password: String,
    pub target_key_ref: String,
    pub repository_max_bytes: u64,
    pub memory_max_bytes: u64,
    pub timeout_seconds: u64,
}

impl Drop for GatewayWorkerRequest {
    fn drop(&mut self) {
        self.source_password.zeroize();
        self.target_password.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayWorkerReport {
    pub protocol_version: u32,
    pub resource_id: String,
    pub admission_id: Option<String>,
    pub execution_ordinal: Option<u32>,
    pub receiver_epoch: u64,
    pub fence_generation: u64,
    pub repository_id: String,
    pub native_snapshot_id: Option<String>,
    pub manifest_digest: Option<String>,
    pub entry_count: u64,
    pub file_count: u64,
    pub payload_bytes: u64,
    pub repository_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GatewayWorkerError {
    INVALID,
    IO,
    ENVELOPE,
    STATE,
    RESOURCE,
    ENGINE,
    VERIFICATION,
    UNSUPPORTED,
}

impl fmt::Display for GatewayWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid gateway worker request",
            Self::IO => "gateway worker I/O failed",
            Self::ENVELOPE => "gateway worker resource envelope unavailable",
            Self::STATE => "gateway worker state verification failed",
            Self::RESOURCE => "gateway worker resource limit reached",
            Self::ENGINE => "gateway repository operation failed",
            Self::VERIFICATION => "gateway repository verification failed",
            Self::UNSUPPORTED => "gateway worker execution unavailable",
        })
    }
}
impl std::error::Error for GatewayWorkerError {}

pub fn read_request(mut reader: impl Read) -> Result<GatewayWorkerRequest, GatewayWorkerError> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| GatewayWorkerError::IO)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(GatewayWorkerError::INVALID);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader
        .read_exact(&mut bytes)
        .map_err(|_| GatewayWorkerError::IO)?;
    let mut trailing = [0u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| GatewayWorkerError::IO)?
        != 0
    {
        return Err(GatewayWorkerError::INVALID);
    }
    let mut value =
        crate::config::parse_json_bytes(&bytes).map_err(|_| GatewayWorkerError::INVALID)?;
    let result = serde_json::from_slice(&bytes).map_err(|_| GatewayWorkerError::INVALID);
    scrub_json(&mut value);
    result
}

fn scrub_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_json),
        serde_json::Value::Object(items) => items.values_mut().for_each(scrub_json),
        _ => {}
    }
}

pub fn write_report(
    mut writer: impl Write,
    report: &GatewayWorkerReport,
) -> Result<(), GatewayWorkerError> {
    let bytes = serde_json::to_vec(report).map_err(|_| GatewayWorkerError::INVALID)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(GatewayWorkerError::INVALID);
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| GatewayWorkerError::IO)?;
    writer
        .write_all(&bytes)
        .map_err(|_| GatewayWorkerError::IO)?;
    writer.flush().map_err(|_| GatewayWorkerError::IO)
}

/// Execute one journal-bound operation inside the verified worker envelope.
pub fn execute_gateway(
    request: &GatewayWorkerRequest,
) -> Result<GatewayWorkerReport, GatewayWorkerError> {
    #[cfg(target_os = "linux")]
    {
        linux::execute_gateway(request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        Err(GatewayWorkerError::UNSUPPORTED)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        GatewayWorkerError as Error, GatewayWorkerOperation as Operation, GatewayWorkerReport,
        GatewayWorkerRequest,
    };
    use crate::local_endpoint::{FileIdentity, LocalEndpoint};
    use crate::resources::StageGuard;
    use crate::state::StateStore;
    use std::fs::{self, File};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    fn get_endpoint(path: &Path) -> Result<LocalEndpoint, Error> {
        if !path.is_absolute()
            || path.as_os_str().len() > 4096
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::INVALID);
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::IO)?;
        // SAFETY: geteuid reads only the process identity.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(Error::STATE);
        }
        LocalEndpoint::resolve(
            path,
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )
        .map_err(|_| Error::STATE)
    }

    fn get_metadata_endpoint(path: &Path) -> Result<LocalEndpoint, Error> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::IO)?;
        LocalEndpoint::resolve_metadata(
            path,
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )
        .map_err(|_| Error::STATE)
    }

    fn acquire_owner(root: &LocalEndpoint, request: &GatewayWorkerRequest) -> Result<File, Error> {
        // SAFETY: root is pinned and the component is static, NUL-terminated.
        let fd = unsafe {
            libc::openat(
                root.directory().as_raw_fd(),
                c".relic-owner.lock".as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::IO);
        }
        // SAFETY: fd is newly owned by this function.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::IO)?;
        // SAFETY: geteuid reads only the process identity.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != 0
            || metadata.dev() != request.owner_identity.device
            || metadata.ino() != request.owner_identity.inode
        {
            return Err(Error::STATE);
        }
        let reopened =
            File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| Error::IO)?;
        let actual = reopened.metadata().map_err(|_| Error::IO)?;
        if actual.dev() != metadata.dev() || actual.ino() != metadata.ino() {
            return Err(Error::STATE);
        }
        reopened.try_lock().map_err(|_| Error::STATE)?;
        let file = reopened;
        let mut slot = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: descriptor, static name and output storage are valid.
        if unsafe {
            libc::fstatat(
                root.directory().as_raw_fd(),
                c".relic-owner.lock".as_ptr(),
                slot.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(Error::IO);
        }
        // SAFETY: successful fstatat initialized slot.
        let slot = unsafe { slot.assume_init() };
        if slot.st_dev != metadata.dev()
            || slot.st_ino != metadata.ino()
            || slot.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(Error::STATE);
        }
        Ok(file)
    }

    // Adapted from archive_worker: pin regular files before reopening via procfd.
    fn open_regular(parent: &fs::File, name: &std::ffi::CStr) -> Result<fs::File, Error> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::IO);
        }
        let pinned = unsafe { fs::File::from_raw_fd(fd) };
        let expected = pinned.metadata().map_err(|_| Error::IO)?;
        if !expected.is_file()
            || expected.nlink() != 1
            || expected.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::IO);
        }
        let file = fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
            .map_err(|_| Error::IO)?;
        let actual = file.metadata().map_err(|_| Error::IO)?;
        if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
            return Err(Error::IO);
        }
        Ok(file)
    }

    fn sync_repository(
        endpoint: &LocalEndpoint,
        maximum_bytes: u64,
        guard: &StageGuard,
    ) -> Result<u64, Error> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        fn check_generation(before: &fs::Metadata, after: &fs::Metadata) -> Result<(), Error> {
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(Error::IO);
            }
            Ok(())
        }
        fn check_entry(
            parent: &fs::File,
            name: &std::ffi::CStr,
            expected: &fs::Metadata,
        ) -> Result<(), Error> {
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
                return Err(Error::IO);
            }
            // SAFETY: successful fstatat initialized the output.
            let value = unsafe { value.assume_init() };
            if value.st_dev != expected.dev()
                || value.st_ino != expected.ino()
                || value.st_mode & libc::S_IFMT != expected.mode() & libc::S_IFMT
            {
                return Err(Error::IO);
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
        ) -> Result<(), Error> {
            if depth > 4 {
                return Err(Error::RESOURCE);
            }
            let directory_before = directory.metadata().map_err(|_| Error::IO)?;
            let entries = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .map_err(|_| Error::IO)?;
            for entry in entries {
                guard.check().map_err(|_| Error::RESOURCE)?;
                let entry = entry.map_err(|_| Error::IO)?;
                *count = count.checked_add(1).ok_or(Error::RESOURCE)?;
                if *count > 10_000 {
                    return Err(Error::RESOURCE);
                }
                let name = entry.file_name();
                let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| Error::IO)?;
                let kind = entry.file_type().map_err(|_| Error::IO)?;
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
                        return Err(Error::IO);
                    }
                    // SAFETY: the fresh descriptor is transferred exactly once to File.
                    let child = unsafe { fs::File::from_raw_fd(fd) };
                    let metadata = child.metadata().map_err(|_| Error::IO)?;
                    check_entry(directory, &name, &metadata)?;
                    if metadata.dev() != device {
                        return Err(Error::IO);
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
                    let before = file.metadata().map_err(|_| Error::IO)?;
                    check_entry(directory, &name, &before)?;
                    if before.dev() != device {
                        return Err(Error::IO);
                    }
                    *total_bytes = total_bytes
                        .checked_add(before.len())
                        .ok_or(Error::RESOURCE)?;
                    if *total_bytes > maximum_bytes {
                        return Err(Error::RESOURCE);
                    }
                    file.sync_all().map_err(|_| Error::IO)?;
                    let after = file.metadata().map_err(|_| Error::IO)?;
                    check_generation(&before, &after)?;
                    check_entry(directory, &name, &after)?;
                } else {
                    return Err(Error::IO);
                }
            }
            directory.sync_all().map_err(|_| Error::IO)?;
            check_generation(
                &directory_before,
                &directory.metadata().map_err(|_| Error::IO)?,
            )
        }
        endpoint.revalidate().map_err(|_| Error::IO)?;
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
        endpoint.revalidate().map_err(|_| Error::IO)?;
        Ok(total_bytes)
    }

    fn check_lock_slot(
        parent: &LocalEndpoint,
        name: &std::ffi::CStr,
        held: &File,
    ) -> Result<(), Error> {
        parent.revalidate().map_err(|_| Error::STATE)?;
        let expected = held.metadata().map_err(|_| Error::IO)?;
        let current = open_regular(parent.directory(), name)?
            .metadata()
            .map_err(|_| Error::IO)?;
        if expected.dev() != current.dev()
            || expected.ino() != current.ino()
            || current.len() != 0
            || current.mode() & 0o7777 != 0o600
        {
            return Err(Error::STATE);
        }
        Ok(())
    }

    fn verify_projection<S: rustic_core::IndexedFull>(
        repository: &rustic_core::Repository<S>,
        snapshot: &rustic_core::repofile::SnapshotFile,
        capture: &crate::state::CaptureBinding,
        run: &crate::state::NativeRunRecord,
        scratch: &LocalEndpoint,
        scratch_path: &Path,
        guard: &StageGuard,
    ) -> Result<crate::archive_manifest::ArchiveManifestReport, Error> {
        use crate::archive_manifest::{
            ArchiveManifestLimits, ArchiveManifestProjection, verify_snapshot,
        };
        use crate::encrypted_manifest_sort::{EncryptedManifestSort, SortLimits};
        use crate::manifest_artifact::ManifestArtifact;
        use std::collections::BTreeMap;
        let count = run
            .manifest_entry_count
            .parse::<u64>()
            .map_err(|_| Error::STATE)?;
        let bytes = run.payload_bytes.parse::<u64>().map_err(|_| Error::STATE)?;
        if count == 0 || count > 10_000 {
            return Err(Error::RESOURCE);
        }
        let node = repository
            .node_from_snapshot_and_path(snapshot, "sources")
            .map_err(|_| Error::VERIFICATION)?;
        let mut options = rustic_core::LsOptions::default();
        options.recursive = false;
        let mut encodings = BTreeMap::new();
        for item in repository
            .ls(&node, &options)
            .map_err(|_| Error::VERIFICATION)?
        {
            let (path, node) = item.map_err(|_| Error::VERIFICATION)?;
            if path.as_os_str().is_empty() {
                continue;
            }
            if !node.is_dir() || path.components().count() != 1 || encodings.len() >= 1024 {
                return Err(Error::VERIFICATION);
            }
            let id = path.to_str().ok_or(Error::VERIFICATION)?;
            if !crate::state::valid_identifier_text(id)
                || encodings
                    .insert(id.to_owned(), "unix_bytes".to_owned())
                    .is_some()
            {
                return Err(Error::VERIFICATION);
            }
        }
        let retained = sync_repository(scratch, 8 * 1024 * 1024, guard)?;
        let available = (8 * 1024 * 1024u64)
            .checked_sub(retained)
            .filter(|n| *n > 0)
            .ok_or(Error::RESOURCE)?;
        let name = format!(".relic-sort-{}", uuid::Uuid::now_v7().simple());
        let component = std::ffi::CString::new(name.as_str()).map_err(|_| Error::INVALID)?;
        // SAFETY: parent descriptor is pinned and component is a valid generated name.
        if unsafe { libc::mkdirat(scratch.directory().as_raw_fd(), component.as_ptr(), 0o700) } != 0
        {
            return Err(Error::IO);
        }
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| Error::RESOURCE)?;
        let mut sorter = EncryptedManifestSort::create(
            &scratch_path.join(name),
            &key,
            SortLimits {
                max_entries: count,
                max_frame_bytes: 256 * 1024,
                max_chunk_bytes: 512 * 1024,
                max_chunk_entries: 64,
                max_runs: 64,
                max_fan_in: 4,
                max_cipher_bytes: available,
                max_memory_bytes: 8 * 1024 * 1024,
            },
            guard,
        )
        .map_err(|_| Error::RESOURCE)?;
        let expected = ManifestArtifact {
            digest: run.manifest_digest.clone(),
            entry_count: count,
        };
        let result = verify_snapshot(
            repository,
            snapshot,
            ArchiveManifestProjection {
                binding: capture,
                expected: &expected,
                virtual_prefix: Path::new("sources"),
                source_encodings: &encodings,
            },
            &mut sorter,
            ArchiveManifestLimits {
                max_entries: count,
                max_file_bytes: bytes.max(1),
                max_total_bytes: bytes.max(1),
                max_depth: 32,
            },
            guard,
        )
        .map_err(|_| Error::VERIFICATION)?;
        if result.file_count.to_string() != run.file_count
            || result.payload_bytes.to_string() != run.payload_bytes
        {
            return Err(Error::VERIFICATION);
        }
        Ok(result)
    }

    fn get_snapshot_candidate(
        snapshots: &[rustic_core::repofile::SnapshotFile],
        admission: &crate::gateway_state::GatewayAdmissionRecord,
        execution: &crate::gateway_state::GatewayExecutionRecord,
    ) -> Result<Option<usize>, Error> {
        let tags = [
            format!("relic-admission-{}", admission.binding.admission_id),
            format!("relic-resource-{}", admission.binding.resource_id),
            format!("relic-payload-{}", admission.binding.payload_hash),
            format!("relic-execution-{}", execution.ordinal),
            format!("relic-epoch-{}", execution.receiver_epoch),
            format!("relic-fence-{}", execution.fence_generation),
        ];
        let mut result = None;
        for (index, snapshot) in snapshots.iter().enumerate() {
            if snapshot.tags.contains(&tags[0]) {
                if result.is_some() || tags.iter().any(|tag| !snapshot.tags.contains(tag)) {
                    return Err(Error::VERIFICATION);
                }
                for tag in snapshot.tags.iter() {
                    if [
                        "relic-admission-",
                        "relic-resource-",
                        "relic-payload-",
                        "relic-execution-",
                        "relic-epoch-",
                        "relic-fence-",
                    ]
                    .iter()
                    .any(|prefix| tag.starts_with(prefix))
                        && !tags.contains(tag)
                    {
                        return Err(Error::VERIFICATION);
                    }
                }
                result = Some(index);
            }
        }
        Ok(result)
    }

    fn execute_transfer(
        request: &GatewayWorkerRequest,
        state: &StateStore,
        resource: &crate::gateway_state::GatewayResourceRecord,
        root: &LocalEndpoint,
        scratch: &LocalEndpoint,
        owner: &File,
    ) -> Result<GatewayWorkerReport, Error> {
        use crate::archive_backend::ArchiveBudgetBackend;
        use crate::archive_snapshot::{SnapshotLimits, get_snapshots_checked};
        use crate::local_endpoint::get_disjoint_scope_evidence;
        use rustic_backend::BackendOptions;
        use rustic_core::{Credentials, Repository, RepositoryBackends, RepositoryOptions};
        use std::collections::BTreeSet;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let id = request.admission_id.as_deref().ok_or(Error::INVALID)?;
        let ordinal = request.execution_ordinal.ok_or(Error::INVALID)?;
        let admission = state
            .get_gateway_admission(id)
            .map_err(|_| Error::STATE)?
            .ok_or(Error::STATE)?;
        let execution = state
            .list_gateway_executions(id)
            .map_err(|_| Error::STATE)?
            .into_iter()
            .find(|item| item.ordinal == ordinal)
            .ok_or(Error::STATE)?;
        let run = state
            .get_native_run(&admission.binding.native_run_id)
            .map_err(|_| Error::STATE)?
            .ok_or(Error::STATE)?;
        let capture = state
            .get_capture(&run.capture_id)
            .map_err(|_| Error::STATE)?
            .ok_or(Error::STATE)?;
        if capture.manifest_digest.as_deref() != Some(run.manifest_digest.as_str())
            || capture.manifest_entry_count.as_deref() != Some(run.manifest_entry_count.as_str())
        {
            return Err(Error::STATE);
        }
        let guard = StageGuard {
            deadline: Instant::now().checked_add(Duration::from_secs(request.timeout_seconds)),
            ..StageGuard::default()
        };
        let state_endpoint = get_metadata_endpoint(&request.state_dir)?;
        get_disjoint_scope_evidence(&[&state_endpoint, root]).map_err(|_| Error::STATE)?;
        let retained = sync_repository(root, request.repository_max_bytes, &guard)?;
        let can_write = request.operation == Operation::COPY;
        let remaining = if can_write {
            request
                .repository_max_bytes
                .checked_sub(retained)
                .filter(|n| *n > 0)
                .ok_or(Error::RESOURCE)?
        } else {
            1
        };
        let target_path = request.target_dir.to_str().ok_or(Error::INVALID)?;
        let native = BackendOptions::default()
            .repository(target_path)
            .to_backends()
            .map_err(|_| Error::ENGINE)?;
        let target_budget =
            ArchiveBudgetBackend::new(native.repository(), remaining, can_write, guard.clone())
                .map_err(|_| Error::RESOURCE)?;
        let target_backends = RepositoryBackends::new(Arc::new(target_budget), None);
        let options = RepositoryOptions::default().no_cache(true);
        let credentials = Credentials::password(&request.target_password);
        let opened = Repository::new(&options, &target_backends)
            .map_err(|_| Error::ENGINE)?
            .open(&credentials)
            .map_err(|_| Error::ENGINE)?;
        let repository_id = opened.config().id.to_hex().to_string();
        if opened.config().version != 2
            || resource.repository_id.as_deref() != Some(repository_id.as_str())
        {
            return Err(Error::STATE);
        }
        let before = get_snapshots_checked(
            &opened,
            root,
            SnapshotLimits {
                max_snapshots: 1024,
                max_ciphertext_bytes: 16 * 1024 * 1024,
                max_metadata_bytes: 8 * 1024 * 1024,
            },
            &guard,
        )
        .map_err(|_| Error::VERIFICATION)?;
        let existing = get_snapshot_candidate(&before, &admission, &execution)?;
        if !can_write && existing.is_none() {
            if execution.native_result_id.is_some() {
                // A previously reported snapshot disappearing is corruption, not safe absence.
                return Err(Error::VERIFICATION);
            }
            let repository_bytes = sync_repository(root, request.repository_max_bytes, &guard)?;
            check_lock_slot(root, c".relic-owner.lock", owner)?;
            root.revalidate().map_err(|_| Error::STATE)?;
            scratch.revalidate().map_err(|_| Error::STATE)?;
            if state
                .get_gateway_resource(&request.resource_id)
                .map_err(|_| Error::STATE)?
                .as_ref()
                != Some(resource)
                || state
                    .get_gateway_admission(id)
                    .map_err(|_| Error::STATE)?
                    .as_ref()
                    != Some(&admission)
                || state
                    .list_gateway_executions(id)
                    .map_err(|_| Error::STATE)?
                    .into_iter()
                    .find(|row| row.ordinal == ordinal)
                    .as_ref()
                    != Some(&execution)
            {
                return Err(Error::STATE);
            }
            guard.check().map_err(|_| Error::RESOURCE)?;
            return Ok(GatewayWorkerReport {
                protocol_version: 1,
                resource_id: request.resource_id.clone(),
                admission_id: Some(id.into()),
                execution_ordinal: Some(ordinal),
                receiver_epoch: execution.receiver_epoch,
                fence_generation: execution.fence_generation,
                repository_id,
                native_snapshot_id: None,
                manifest_digest: None,
                entry_count: 0,
                file_count: 0,
                payload_bytes: 0,
                repository_bytes,
            });
        }
        let before_ids: BTreeSet<String> = before
            .iter()
            .map(|snapshot| snapshot.id.to_hex().to_string())
            .collect();
        if before_ids.len() != before.len() {
            return Err(Error::VERIFICATION);
        }
        let mut source_owner = None;
        let mut source_parent = None;
        let mut source_endpoint = None;
        if can_write {
            let source_path = request
                .source_repository_dir
                .as_deref()
                .ok_or(Error::INVALID)?;
            if source_path.file_name().and_then(|v| v.to_str()) != Some("repository")
                || request.source_key_ref.as_deref()
                    != Some(run.binding.repository_key_ref.as_str())
            {
                return Err(Error::STATE);
            }
            let password = request
                .source_password
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or(Error::INVALID)?;
            let parent = get_endpoint(source_path.parent().ok_or(Error::INVALID)?)?;
            let source = get_endpoint(source_path)?;
            if run.container_identity.as_deref()
                != Some(
                    format!(
                        "unix:{}:{}",
                        parent.identity().device,
                        parent.identity().inode
                    )
                    .as_str(),
                )
                || run.repository_identity.as_deref()
                    != Some(
                        format!(
                            "unix:{}:{}",
                            source.identity().device,
                            source.identity().inode
                        )
                        .as_str(),
                    )
            {
                return Err(Error::STATE);
            }
            get_disjoint_scope_evidence(&[&state_endpoint, root, &parent])
                .map_err(|_| Error::STATE)?;
            let source_lock = open_regular(parent.directory(), c"owner.lock")?;
            let lock_metadata = source_lock.metadata().map_err(|_| Error::IO)?;
            if lock_metadata.mode() & 0o7777 != 0o600
                || lock_metadata.len() != 0
                || run.owner_lock_identity.as_deref()
                    != Some(
                        format!("unix:{}:{}", lock_metadata.dev(), lock_metadata.ino()).as_str(),
                    )
            {
                return Err(Error::STATE);
            }
            source_lock.try_lock().map_err(|_| Error::STATE)?;
            crate::physical_registry::check_registered_access(
                state,
                crate::physical_registry::PhysicalRootKind::STAGING,
                &run.binding.storage_endpoint_id,
                &source,
                &guard,
            )
            .map_err(|_| Error::STATE)?;
            check_lock_slot(&parent, c"owner.lock", &source_lock)?;
            let backend = BackendOptions::default()
                .repository(source_path.to_str().ok_or(Error::INVALID)?)
                .to_backends()
                .map_err(|_| Error::ENGINE)?;
            let budget = ArchiveBudgetBackend::new(backend.repository(), 1, false, guard.clone())
                .map_err(|_| Error::RESOURCE)?;
            let source_backends = RepositoryBackends::new(Arc::new(budget), None);
            let source_creds = Credentials::password(password);
            let source_repo = Repository::new(&options, &source_backends)
                .map_err(|_| Error::ENGINE)?
                .open(&source_creds)
                .map_err(|_| Error::ENGINE)?
                .to_indexed()
                .map_err(|_| Error::ENGINE)?;
            let snapshot = source_repo
                .get_snapshot_from_str(&admission.binding.native_snapshot_id, |_| true)
                .map_err(|_| Error::VERIFICATION)?;
            if snapshot.id.to_hex().as_str() != admission.binding.native_snapshot_id
                || !snapshot
                    .tags
                    .contains(&format!("relic-run-{}", run.binding.run_id))
                || !snapshot
                    .tags
                    .contains(&format!("relic-stage-{}", run.binding.stage_id))
            {
                return Err(Error::VERIFICATION);
            }
            verify_projection(
                &source_repo,
                &snapshot,
                &capture.binding,
                &run,
                scratch,
                &request.target_dir.join(".relic-scratch"),
                &guard,
            )?;
            if existing.is_none() {
                let mut tagged = snapshot.clone();
                if tagged.tags.iter().any(|tag| {
                    [
                        "relic-admission-",
                        "relic-resource-",
                        "relic-payload-",
                        "relic-execution-",
                        "relic-epoch-",
                        "relic-fence-",
                    ]
                    .iter()
                    .any(|prefix| tag.starts_with(prefix))
                }) {
                    return Err(Error::VERIFICATION);
                }
                for tag in [
                    format!("relic-admission-{}", id),
                    format!("relic-resource-{}", request.resource_id),
                    format!("relic-payload-{}", admission.binding.payload_hash),
                    format!("relic-execution-{}", ordinal),
                    format!("relic-epoch-{}", execution.receiver_epoch),
                    format!("relic-fence-{}", execution.fence_generation),
                ] {
                    tagged.tags.add(tag);
                }
                check_lock_slot(root, c".relic-owner.lock", owner)?;
                check_lock_slot(&parent, c"owner.lock", &source_lock)?;
                if state
                    .get_gateway_resource(&request.resource_id)
                    .map_err(|_| Error::STATE)?
                    .as_ref()
                    != Some(resource)
                    || state
                        .get_gateway_admission(id)
                        .map_err(|_| Error::STATE)?
                        .as_ref()
                        != Some(&admission)
                    || state
                        .list_gateway_executions(id)
                        .map_err(|_| Error::STATE)?
                        .into_iter()
                        .find(|row| row.ordinal == ordinal)
                        .as_ref()
                        != Some(&execution)
                {
                    return Err(Error::STATE);
                }
                let target = opened.to_indexed_ids().map_err(|_| Error::ENGINE)?;
                source_repo
                    .copy(&target, [&tagged])
                    .map_err(|_| Error::ENGINE)?;
            }
            source_owner = Some(source_lock);
            source_parent = Some(parent);
            source_endpoint = Some(source);
        }
        // Reopen the destination and re-enumerate after any effect; SDK relevance
        // filtering compares snapshot times and is deliberately never used here.
        let target = Repository::new(&options, &target_backends)
            .map_err(|_| Error::ENGINE)?
            .open(&credentials)
            .map_err(|_| Error::ENGINE)?
            .to_indexed()
            .map_err(|_| Error::ENGINE)?;
        if target.config().id.to_hex().as_str() != repository_id {
            return Err(Error::STATE);
        }
        let after = get_snapshots_checked(
            &target,
            root,
            SnapshotLimits {
                max_snapshots: 1024,
                max_ciphertext_bytes: 16 * 1024 * 1024,
                max_metadata_bytes: 8 * 1024 * 1024,
            },
            &guard,
        )
        .map_err(|_| Error::VERIFICATION)?;
        let after_ids: BTreeSet<String> = after
            .iter()
            .map(|snapshot| snapshot.id.to_hex().to_string())
            .collect();
        if !before_ids.is_subset(&after_ids)
            || after_ids.len() != after.len()
            || (can_write && existing.is_none() && after_ids.len() != before_ids.len() + 1)
            || (existing.is_some() && after_ids != before_ids)
        {
            return Err(Error::VERIFICATION);
        }
        let candidate =
            get_snapshot_candidate(&after, &admission, &execution)?.ok_or(Error::VERIFICATION)?;
        let snapshot = &after[candidate];
        let snapshot_id = snapshot.id.to_hex().to_string();
        if execution
            .native_result_id
            .as_deref()
            .is_some_and(|v| v != snapshot_id)
        {
            return Err(Error::VERIFICATION);
        }
        let verified = verify_projection(
            &target,
            snapshot,
            &capture.binding,
            &run,
            scratch,
            &request.target_dir.join(".relic-scratch"),
            &guard,
        )?;
        drop(target);
        let repository_bytes = sync_repository(root, request.repository_max_bytes, &guard)?;
        root.revalidate().map_err(|_| Error::STATE)?;
        scratch.revalidate().map_err(|_| Error::STATE)?;
        let owner_metadata = owner.metadata().map_err(|_| Error::IO)?;
        let current_owner = open_regular(root.directory(), c".relic-owner.lock")?
            .metadata()
            .map_err(|_| Error::IO)?;
        if owner_metadata.dev() != current_owner.dev()
            || owner_metadata.ino() != current_owner.ino()
            || current_owner.dev() != request.owner_identity.device
            || current_owner.ino() != request.owner_identity.inode
            || current_owner.len() != 0
            || current_owner.mode() & 0o7777 != 0o600
        {
            return Err(Error::STATE);
        }
        if let (Some(lock), Some(parent), Some(source)) =
            (&source_owner, &source_parent, &source_endpoint)
        {
            parent.revalidate().map_err(|_| Error::STATE)?;
            source.revalidate().map_err(|_| Error::STATE)?;
            let held = lock.metadata().map_err(|_| Error::IO)?;
            let current = open_regular(parent.directory(), c"owner.lock")?
                .metadata()
                .map_err(|_| Error::IO)?;
            if held.dev() != current.dev()
                || held.ino() != current.ino()
                || current.len() != 0
                || current.mode() & 0o7777 != 0o600
            {
                return Err(Error::STATE);
            }
        }
        if state
            .get_gateway_resource(&request.resource_id)
            .map_err(|_| Error::STATE)?
            .as_ref()
            != Some(resource)
            || state
                .get_gateway_admission(id)
                .map_err(|_| Error::STATE)?
                .as_ref()
                != Some(&admission)
            || state
                .get_native_run(&run.binding.run_id)
                .map_err(|_| Error::STATE)?
                .as_ref()
                != Some(&run)
            || state
                .list_gateway_executions(id)
                .map_err(|_| Error::STATE)?
                .into_iter()
                .find(|row| row.ordinal == ordinal)
                .as_ref()
                != Some(&execution)
        {
            return Err(Error::STATE);
        }
        guard.check().map_err(|_| Error::RESOURCE)?;
        Ok(GatewayWorkerReport {
            protocol_version: 1,
            resource_id: request.resource_id.clone(),
            admission_id: Some(id.into()),
            execution_ordinal: Some(ordinal),
            receiver_epoch: execution.receiver_epoch,
            fence_generation: execution.fence_generation,
            repository_id,
            native_snapshot_id: Some(snapshot_id),
            manifest_digest: Some(verified.manifest.digest),
            entry_count: verified.manifest.entry_count,
            file_count: verified.file_count,
            payload_bytes: verified.payload_bytes,
            repository_bytes,
        })
    }

    pub(super) fn execute_gateway(
        request: &GatewayWorkerRequest,
    ) -> Result<GatewayWorkerReport, Error> {
        crate::worker_runtime::verify_worker_envelope(request.memory_max_bytes)
            .map_err(|_| Error::ENVELOPE)?;
        if request.protocol_version != 1
            || request.receiver_epoch == 0
            || request.fence_generation == 0
            || request.timeout_seconds == 0
            || request.timeout_seconds > 900
            || request.repository_max_bytes == 0
            || request.repository_max_bytes > 512 * 1024 * 1024
            || request.target_password.is_empty()
            || request.target_password.len() > 4096
            || request
                .source_password
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
        {
            return Err(Error::INVALID);
        }
        let root = get_endpoint(&request.target_dir)?;
        if root.identity()
            != (FileIdentity {
                device: request.target_identity.device,
                inode: request.target_identity.inode,
            })
        {
            return Err(Error::STATE);
        }
        let scratch = get_endpoint(&request.target_dir.join(".relic-scratch"))?;
        if scratch.identity()
            != (FileIdentity {
                device: request.scratch_identity.device,
                inode: request.scratch_identity.inode,
            })
        {
            return Err(Error::STATE);
        }
        let _owner = acquire_owner(&root, request)?;
        let state = StateStore::open_readonly(&request.state_dir).map_err(|_| Error::STATE)?;
        let resource = state
            .get_gateway_resource(&request.resource_id)
            .map_err(|_| Error::STATE)?
            .ok_or(Error::STATE)?;
        if resource.receiver_epoch != request.receiver_epoch
            || resource.fence_generation != request.fence_generation
            || resource.binding.repository_key_ref != request.target_key_ref
            || resource.binding.storage_identity
                != format!("unix:{}:{}", root.identity().device, root.identity().inode)
        {
            return Err(Error::STATE);
        }
        let (growth_kind, growth_id, growth_ordinal) = match request.operation {
            Operation::INITIALIZE | Operation::INSPECT_INITIALIZATION => {
                ("initialization", request.resource_id.as_str(), 0)
            }
            Operation::COPY | Operation::VERIFY => (
                "copy",
                request.admission_id.as_deref().ok_or(Error::STATE)?,
                request.execution_ordinal.ok_or(Error::STATE)?,
            ),
        };
        let growth = state
            .get_destination_growth(growth_kind, growth_id, growth_ordinal)
            .map_err(|_| Error::STATE)?
            .ok_or(Error::STATE)?;
        if !state
            .is_staging_quota_inventory_complete()
            .map_err(|_| Error::STATE)?
            || !state
                .is_destination_growth_inventory_complete()
                .map_err(|_| Error::STATE)?
            || growth.effect_state != "held"
            || growth.binding.resource_id != request.resource_id
            || growth.binding.storage_identity != resource.binding.storage_identity
            || growth.binding.volume_identity != format!("unix:{}", root.identity().device)
            || growth.binding.receiver_epoch != request.receiver_epoch
            || growth.binding.fence_generation != request.fence_generation
            || growth.binding.max_bytes != request.repository_max_bytes
        {
            return Err(Error::STATE);
        }
        let layout = state
            .get_gateway_layout(&request.resource_id)
            .map_err(|_| Error::STATE)?
            .ok_or(Error::STATE)?;
        crate::physical_registry::check_registered_access(
            &state,
            crate::physical_registry::PhysicalRootKind::GATEWAY,
            &request.resource_id,
            &root,
            &StageGuard::default(),
        )
        .map_err(|_| Error::STATE)?;
        if layout.owner_identity.as_deref()
            != Some(
                format!(
                    "unix:{}:{}",
                    request.owner_identity.device, request.owner_identity.inode
                )
                .as_str(),
            )
            || layout.scratch_identity.as_deref()
                != Some(
                    format!(
                        "unix:{}:{}",
                        request.scratch_identity.device, request.scratch_identity.inode
                    )
                    .as_str(),
                )
        {
            return Err(Error::STATE);
        }
        if matches!(
            request.operation,
            Operation::INITIALIZE | Operation::INSPECT_INITIALIZATION
        ) {
            if layout.initialization_attempts != 1
                || layout.launch_protocol != 1
                || layout.initialization_epoch != Some(request.receiver_epoch)
                || layout.initialization_fence != Some(request.fence_generation)
            {
                return Err(Error::STATE);
            }
            if request.operation == Operation::INITIALIZE {
                if layout.effect_state != "initializing" {
                    return Err(Error::STATE);
                }
                crate::worker_runtime::verify_current_worker_identity(
                    layout.containment.as_ref().ok_or(Error::STATE)?,
                )
                .map_err(|_| Error::ENVELOPE)?;
            } else if !matches!(layout.effect_state.as_str(), "initializing" | "unknown") {
                return Err(Error::STATE);
            }
        } else if layout.effect_state != "initialized" {
            return Err(Error::STATE);
        }
        match request.operation {
            Operation::INITIALIZE | Operation::INSPECT_INITIALIZATION => {
                if !matches!(resource.effect_state.as_str(), "prepared" | "blocked")
                    || resource.repository_id.is_some()
                    || request.admission_id.is_some()
                    || request.execution_ordinal.is_some()
                {
                    return Err(Error::STATE);
                }
            }
            Operation::COPY | Operation::VERIFY => {
                if !matches!(resource.effect_state.as_str(), "ready" | "blocked") {
                    return Err(Error::STATE);
                }
                let id = request.admission_id.as_deref().ok_or(Error::INVALID)?;
                let ordinal = request.execution_ordinal.ok_or(Error::INVALID)?;
                let admission = state
                    .get_gateway_admission(id)
                    .map_err(|_| Error::STATE)?
                    .ok_or(Error::STATE)?;
                let execution = state
                    .list_gateway_executions(id)
                    .map_err(|_| Error::STATE)?
                    .into_iter()
                    .find(|item| item.ordinal == ordinal)
                    .ok_or(Error::STATE)?;
                if admission.binding.resource_id != request.resource_id
                    || execution.resource_id != request.resource_id
                    || execution.receiver_epoch != request.receiver_epoch
                    || execution.fence_generation != request.fence_generation
                    || (request.operation == Operation::COPY && execution.effect_state != "active")
                    || (request.operation == Operation::VERIFY
                        && !matches!(
                            execution.effect_state.as_str(),
                            "active" | "unknown" | "published_unverified"
                        ))
                {
                    return Err(Error::STATE);
                }
                if request.operation == Operation::COPY {
                    crate::worker_runtime::verify_current_worker_identity(
                        execution.worker_identity.as_ref().ok_or(Error::STATE)?,
                    )
                    .map_err(|_| Error::ENVELOPE)?;
                } else {
                    crate::worker_runtime::verify_current_worker_identity(
                        execution
                            .verification_worker_identity
                            .as_ref()
                            .ok_or(Error::STATE)?,
                    )
                    .map_err(|_| Error::ENVELOPE)?;
                }
                let run = state
                    .get_native_run(&admission.binding.native_run_id)
                    .map_err(|_| Error::STATE)?
                    .ok_or(Error::STATE)?;
                if run.effect_state != "verified"
                    || run.capture_id != admission.binding.capture_id
                    || run.manifest_digest != admission.binding.manifest_digest
                    || run.native_snapshot_id.as_deref()
                        != Some(admission.binding.native_snapshot_id.as_str())
                {
                    return Err(Error::STATE);
                }
            }
        }
        if matches!(request.operation, Operation::COPY | Operation::VERIFY) {
            return execute_transfer(request, &state, &resource, &root, &scratch, &_owner);
        }
        use crate::archive_backend::ArchiveBudgetBackend;
        use crate::archive_snapshot::{SnapshotLimits, get_snapshots_checked};
        use crate::local_endpoint::get_disjoint_scope_evidence;
        use rustic_backend::BackendOptions;
        use rustic_core::{
            ConfigOptions, Credentials, KeyOptions, Repository, RepositoryBackends,
            RepositoryOptions,
        };
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let state_endpoint = get_metadata_endpoint(&request.state_dir)?;
        get_disjoint_scope_evidence(&[&state_endpoint, &root]).map_err(|_| Error::STATE)?;
        let guard = StageGuard {
            deadline: Instant::now().checked_add(Duration::from_secs(request.timeout_seconds)),
            ..StageGuard::default()
        };
        let is_initialize = request.operation == Operation::INITIALIZE;
        if is_initialize {
            let mut owner_seen = false;
            let mut scratch_seen = false;
            for entry in fs::read_dir(format!("/proc/self/fd/{}", root.directory().as_raw_fd()))
                .map_err(|_| Error::IO)?
            {
                guard.check().map_err(|_| Error::RESOURCE)?;
                let entry = entry.map_err(|_| Error::IO)?;
                match entry.file_name().to_str() {
                    Some(".relic-owner.lock") if !owner_seen => owner_seen = true,
                    Some(".relic-scratch") if !scratch_seen => scratch_seen = true,
                    Some(".relic-coordinator.lock") => {
                        let file = open_regular(root.directory(), c".relic-coordinator.lock")?;
                        let metadata = file.metadata().map_err(|_| Error::IO)?;
                        if metadata.len() != 0
                            || metadata.nlink() != 1
                            || metadata.mode() & 0o7777 != 0o600
                        {
                            return Err(Error::STATE);
                        }
                    }
                    _ => return Err(Error::STATE),
                }
            }
            if !owner_seen || !scratch_seen {
                return Err(Error::STATE);
            }
        }
        root.revalidate().map_err(|_| Error::STATE)?;
        scratch.revalidate().map_err(|_| Error::STATE)?;
        let repository_path = request.target_dir.to_str().ok_or(Error::INVALID)?;
        let native = BackendOptions::default()
            .repository(repository_path)
            .to_backends()
            .map_err(|_| Error::ENGINE)?;
        let bounded = ArchiveBudgetBackend::new(
            native.repository(),
            request.repository_max_bytes,
            is_initialize,
            guard.clone(),
        )
        .map_err(|_| Error::RESOURCE)?;
        let backends = RepositoryBackends::new(Arc::new(bounded), None);
        let options = RepositoryOptions::default().no_cache(true);
        let credentials = Credentials::password(request.target_password.as_str());
        if is_initialize {
            Repository::new(&options, &backends)
                .map_err(|_| Error::ENGINE)?
                .init(
                    &credentials,
                    &KeyOptions::default(),
                    &ConfigOptions::default().set_version(2),
                )
                .map_err(|_| Error::ENGINE)?;
        }
        let repository = Repository::new(&options, &backends)
            .map_err(|_| Error::ENGINE)?
            .open(&credentials)
            .map_err(|_| Error::ENGINE)?
            .to_indexed()
            .map_err(|_| Error::ENGINE)?;
        if repository.config().version != 2 {
            return Err(Error::VERIFICATION);
        }
        let repository_id = repository.config().id.to_hex().to_string();
        let snapshots = get_snapshots_checked(
            &repository,
            &root,
            SnapshotLimits {
                max_snapshots: 1024,
                max_ciphertext_bytes: 16 * 1024 * 1024,
                max_metadata_bytes: 8 * 1024 * 1024,
            },
            &guard,
        )
        .map_err(|_| Error::VERIFICATION)?;
        if !snapshots.is_empty() {
            return Err(Error::VERIFICATION);
        }
        drop(repository);
        let repository_bytes = sync_repository(&root, request.repository_max_bytes, &guard)?;
        root.revalidate().map_err(|_| Error::STATE)?;
        scratch.revalidate().map_err(|_| Error::STATE)?;
        let expected_owner = _owner.metadata().map_err(|_| Error::IO)?;
        let mut slot = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: root descriptor, static component and output storage remain valid.
        if unsafe {
            libc::fstatat(
                root.directory().as_raw_fd(),
                c".relic-owner.lock".as_ptr(),
                slot.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(Error::IO);
        }
        // SAFETY: successful fstatat initialized slot.
        let slot = unsafe { slot.assume_init() };
        if slot.st_dev != request.owner_identity.device
            || slot.st_ino != request.owner_identity.inode
            || slot.st_mode & libc::S_IFMT != libc::S_IFREG
            || expected_owner.dev() != request.owner_identity.device
            || expected_owner.ino() != request.owner_identity.inode
            || expected_owner.len() != 0
            || expected_owner.nlink() != 1
            || expected_owner.mode() & 0o7777 != 0o600
            // SAFETY: geteuid reads only the process identity.
            || expected_owner.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::STATE);
        }
        if state
            .get_gateway_resource(&request.resource_id)
            .map_err(|_| Error::STATE)?
            .as_ref()
            != Some(&resource)
        {
            return Err(Error::STATE);
        }
        guard.check().map_err(|_| Error::RESOURCE)?;
        Ok(GatewayWorkerReport {
            protocol_version: 1,
            resource_id: request.resource_id.clone(),
            admission_id: None,
            execution_ordinal: None,
            receiver_epoch: request.receiver_epoch,
            fence_generation: request.fence_generation,
            repository_id,
            native_snapshot_id: None,
            manifest_digest: None,
            entry_count: 0,
            file_count: 0,
            payload_bytes: 0,
            repository_bytes,
        })
    }
}
