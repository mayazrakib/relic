use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::archive_disk::ArchiveDiskLimits;
use crate::archive_worker::{
    ArchiveWorkerOperation, ArchiveWorkerReport, ArchiveWorkerRequest, WorkerDirectoryIdentity,
};
use crate::local_endpoint::LocalEndpoint;
use crate::resources::{ActiveJob, Demand, StageGuard, StageReservation};
use crate::state::{NativeRunBinding, NativeRunRecord, StateStore};
use crate::worker_runtime::{
    PendingWorker, WorkerError, WorkerLimits, execute_worker_recorded, quiesce_recorded_worker,
};

const RESERVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const SCRATCH_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum NativeRunError {
    INVALID,
    STORAGE,
    STATE,
    BUSY,
    CAPACITY,
    RESOURCE,
    WRONG_KEY_REFERENCE,
    RECONCILIATION_REQUIRED,
    OUTCOME_UNKNOWN,
}

impl fmt::Display for NativeRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid native run request",
            Self::STORAGE => "native run storage identity or I/O failed",
            Self::STATE => "native run journal rejected the operation",
            Self::BUSY => "native run has a live owner",
            Self::CAPACITY => "native run capacity unavailable",
            Self::RESOURCE => "native run resource guard stopped the operation",
            Self::WRONG_KEY_REFERENCE => "native run key reference changed",
            Self::RECONCILIATION_REQUIRED => "native run requires reconciliation",
            Self::OUTCOME_UNKNOWN => "native run effects require reconciliation",
        })
    }
}

impl std::error::Error for NativeRunError {}

pub struct NativeRunStore {
    endpoint: LocalEndpoint,
    root: PathBuf,
    endpoint_id: String,
    identity: String,
    pending: Mutex<BTreeMap<String, PendingNative>>,
}

struct PendingNative {
    worker: Box<PendingWorker>,
    reservation: Option<StageReservation>,
    parent_lock: Option<File>,
}

impl Drop for PendingNative {
    fn drop(&mut self) {
        if !self.worker.has_ended() {
            // An unproved termination must not release admission for a potentially live worker.
            if let Some(reservation) = self.reservation.take() {
                std::mem::forget(reservation);
            }
            if let Some(lock) = self.parent_lock.take() {
                std::mem::forget(lock);
            }
        }
    }
}

pub struct NativeRunExecution<'a> {
    pub executable: &'a Path,
    pub state_dir: &'a Path,
    pub archive_dir: &'a Path,
    pub source_key_ref: &'a str,
    pub source_key: &'a Zeroizing<[u8; 32]>,
    pub repository_key_ref: &'a str,
    pub repository_password: &'a str,
    pub source_limits: ArchiveDiskLimits,
    pub worker_limits: WorkerLimits,
    pub job: &'a ActiveJob,
    pub guard: &'a StageGuard,
}

fn get_repository_budget(record: &NativeRunRecord) -> Result<u64, NativeRunError> {
    record
        .payload_bytes
        .parse::<u64>()
        .map_err(|_| NativeRunError::STATE)?
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(16 * 1024 * 1024))
        .map(|bytes| bytes.min(MAX_REPOSITORY_BYTES))
        .ok_or(NativeRunError::CAPACITY)
}

fn get_identity(file: &File) -> Result<String, NativeRunError> {
    let metadata = file.metadata().map_err(|_| NativeRunError::STORAGE)?;
    Ok(format!("unix:{}:{}", metadata.dev(), metadata.ino()))
}

fn get_worker_identity(text: &str) -> Result<WorkerDirectoryIdentity, NativeRunError> {
    let mut parts = text.split(':');
    if parts.next() != Some("unix") {
        return Err(NativeRunError::STORAGE);
    }
    let device = parts
        .next()
        .ok_or(NativeRunError::STORAGE)?
        .parse()
        .map_err(|_| NativeRunError::STORAGE)?;
    let inode = parts
        .next()
        .ok_or(NativeRunError::STORAGE)?
        .parse()
        .map_err(|_| NativeRunError::STORAGE)?;
    if parts.next().is_some() {
        return Err(NativeRunError::STORAGE);
    }
    Ok(WorkerDirectoryIdentity { device, inode })
}

fn get_name(text: &str) -> Result<CString, NativeRunError> {
    if text.is_empty() || text.len() > 255 || text.contains('/') || text.contains('\\') {
        return Err(NativeRunError::INVALID);
    }
    CString::new(text).map_err(|_| NativeRunError::INVALID)
}

fn open_directory(parent: &File, name: &CStr) -> Result<File, NativeRunError> {
    // SAFETY: parent and component are live; directory and no-follow flags reject other types.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(NativeRunError::STORAGE);
    }
    // SAFETY: the fresh descriptor is transferred exactly once to File.
    let file = unsafe { File::from_raw_fd(fd) };
    check_private(&file, true)?;
    Ok(file)
}

fn check_private(file: &File, is_directory: bool) -> Result<(), NativeRunError> {
    let metadata = file.metadata().map_err(|_| NativeRunError::STORAGE)?;
    // SAFETY: geteuid has no arguments and reads only process identity.
    let owner = unsafe { libc::geteuid() };
    if metadata.uid() != owner
        || metadata.mode() & 0o7777 != if is_directory { 0o700 } else { 0o600 }
        || if is_directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0
        }
    {
        return Err(NativeRunError::STORAGE);
    }
    Ok(())
}

fn open_lock(parent: &File, name: &CStr, can_create: bool) -> Result<File, NativeRunError> {
    if can_create {
        // SAFETY: exclusive creation cannot open an existing device or symbolic link.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: the fresh descriptor is transferred exactly once to File.
            let file = unsafe { File::from_raw_fd(fd) };
            check_private(&file, false)?;
            file.sync_all().map_err(|_| NativeRunError::STORAGE)?;
            parent.sync_all().map_err(|_| NativeRunError::STORAGE)?;
            return Ok(file);
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(NativeRunError::STORAGE);
        }
    }
    // SAFETY: O_PATH pins without invoking the open implementation of a device node.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(NativeRunError::STORAGE);
    }
    // SAFETY: the new descriptor is transferred exactly once to File.
    let pinned = unsafe { File::from_raw_fd(fd) };
    check_private(&pinned, false)?;
    let file = File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| NativeRunError::STORAGE)?;
    if get_identity(&file)? != get_identity(&pinned)? {
        return Err(NativeRunError::STORAGE);
    }
    Ok(file)
}

fn acquire_file_lock(file: &File) -> Result<(), NativeRunError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(NativeRunError::BUSY),
        Err(_) => Err(NativeRunError::STORAGE),
    }
}

fn check_slot(
    parent: &File,
    name: &CStr,
    expected: &str,
    is_directory: bool,
) -> Result<(), NativeRunError> {
    let file = if is_directory {
        open_directory(parent, name)?
    } else {
        open_lock(parent, name, false)?
    };
    if get_identity(&file)? != expected {
        return Err(NativeRunError::STORAGE);
    }
    Ok(())
}

fn create_directory(parent: &File, name: &CStr) -> Result<File, NativeRunError> {
    // SAFETY: the pinned directory and single NUL-terminated component are live.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(NativeRunError::RECONCILIATION_REQUIRED);
    }
    let file = open_directory(parent, name)?;
    file.sync_all().map_err(|_| NativeRunError::STORAGE)?;
    parent.sync_all().map_err(|_| NativeRunError::STORAGE)?;
    Ok(file)
}

fn is_present(parent: &File, name: &CStr) -> Result<bool, NativeRunError> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: this no-follow existence check uses live descriptors and output storage.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(NativeRunError::STORAGE)
}

fn check_empty(directory: &File) -> Result<(), NativeRunError> {
    if fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| NativeRunError::STORAGE)?
        .next()
        .is_some()
    {
        return Err(NativeRunError::RECONCILIATION_REQUIRED);
    }
    Ok(())
}

struct Layout {
    _container: File,
    repository: File,
    _scratch: File,
    owner: File,
}

impl NativeRunStore {
    pub fn new(
        endpoint: LocalEndpoint,
        root: &Path,
        endpoint_id: &str,
    ) -> Result<Self, NativeRunError> {
        if !crate::state::valid_identifier_text(endpoint_id) || !root.is_absolute() {
            return Err(NativeRunError::INVALID);
        }
        let root = fs::canonicalize(root).map_err(|_| NativeRunError::STORAGE)?;
        check_private(endpoint.directory(), true)?;
        let identity = get_identity(endpoint.directory())?;
        let store = Self {
            endpoint,
            root,
            endpoint_id: endpoint_id.to_owned(),
            identity,
            pending: Mutex::new(BTreeMap::new()),
        };
        store.revalidate()?;
        Ok(store)
    }

    pub fn reap_pending(&self, run_id: &str, guard: &StageGuard) -> Result<bool, NativeRunError> {
        guard.check().map_err(|_| NativeRunError::RESOURCE)?;
        let mut pending = self.pending.lock().map_err(|_| NativeRunError::RESOURCE)?;
        if let Some(entry) = pending.get_mut(run_id) {
            if !entry.worker.try_reap() {
                return Ok(false);
            }
            pending.remove(run_id);
        }
        Ok(true)
    }

    pub fn storage_identity(&self) -> &str {
        &self.identity
    }

    fn revalidate(&self) -> Result<(), NativeRunError> {
        self.endpoint
            .revalidate()
            .map_err(|_| NativeRunError::STORAGE)?;
        check_private(self.endpoint.directory(), true)?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the directory is pinned and statfs output storage is writable.
        if unsafe {
            libc::fstatfs(
                self.endpoint.directory().as_raw_fd(),
                filesystem.as_mut_ptr(),
            )
        } != 0
        {
            return Err(NativeRunError::STORAGE);
        }
        // SAFETY: successful fstatfs initialized the output.
        if !matches!(
            unsafe { filesystem.assume_init() }.f_type,
            0xef53 | 0x9123683e | 0x58465342
        ) {
            // A local process stop cannot drain outstanding remote filesystem operations.
            return Err(NativeRunError::STORAGE);
        }
        let metadata = fs::symlink_metadata(&self.root).map_err(|_| NativeRunError::STORAGE)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || format!("unix:{}:{}", metadata.dev(), metadata.ino()) != self.identity
        {
            return Err(NativeRunError::STORAGE);
        }
        Ok(())
    }

    fn validate_record(&self, record: &NativeRunRecord) -> Result<(), NativeRunError> {
        self.revalidate()?;
        if record.binding.storage_endpoint_id != self.endpoint_id
            || record.binding.storage_identity != self.identity
            || record.binding.relative_name != format!("native_{}", record.binding.run_id)
        {
            return Err(NativeRunError::STORAGE);
        }
        Ok(())
    }

    fn acquire_parent_lock(&self, record: &NativeRunRecord) -> Result<File, NativeRunError> {
        self.validate_record(record)?;
        let name = get_name(&format!(".native_{}.lock", record.binding.run_id))?;
        let file = open_lock(self.endpoint.directory(), &name, true)?;
        acquire_file_lock(&file)?;
        check_slot(
            self.endpoint.directory(),
            &name,
            &get_identity(&file)?,
            false,
        )?;
        Ok(file)
    }

    fn check_parent_lock(
        &self,
        record: &NativeRunRecord,
        file: &File,
    ) -> Result<(), NativeRunError> {
        self.validate_record(record)?;
        check_slot(
            self.endpoint.directory(),
            &get_name(&format!(".native_{}.lock", record.binding.run_id))?,
            &get_identity(file)?,
            false,
        )
    }

    fn open_layout(&self, record: &NativeRunRecord) -> Result<Layout, NativeRunError> {
        self.validate_record(record)?;
        let container = open_directory(
            self.endpoint.directory(),
            &get_name(&record.binding.relative_name)?,
        )?;
        if record.container_identity.as_deref() != Some(get_identity(&container)?.as_str()) {
            return Err(NativeRunError::STORAGE);
        }
        let repository = open_directory(&container, c"repository")?;
        let scratch = open_directory(&container, c"scratch")?;
        let owner = open_lock(&container, c"owner.lock", false)?;
        if record.repository_identity.as_deref() != Some(get_identity(&repository)?.as_str())
            || record.scratch_identity.as_deref() != Some(get_identity(&scratch)?.as_str())
            || record.owner_lock_identity.as_deref() != Some(get_identity(&owner)?.as_str())
        {
            return Err(NativeRunError::STORAGE);
        }
        let mut names = fs::read_dir(format!("/proc/self/fd/{}", container.as_raw_fd()))
            .map_err(|_| NativeRunError::STORAGE)?;
        let mut count = 0;
        for item in &mut names {
            let name = item.map_err(|_| NativeRunError::STORAGE)?.file_name();
            if !matches!(name.to_str(), Some("owner.lock" | "repository" | "scratch")) {
                return Err(NativeRunError::STORAGE);
            }
            count += 1;
            if count > 3 {
                return Err(NativeRunError::STORAGE);
            }
        }
        if count != 3 {
            return Err(NativeRunError::STORAGE);
        }
        Ok(Layout {
            _container: container,
            repository,
            _scratch: scratch,
            owner,
        })
    }

    fn reserve_quota(
        &self,
        state: &mut StateStore,
        record: &NativeRunRecord,
        is_recovery: bool,
    ) -> Result<(), NativeRunError> {
        self.validate_record(record)?;
        if is_recovery {
            crate::physical_registry::check_registered_access(
                state,
                crate::physical_registry::PhysicalRootKind::STAGING,
                &record.binding.storage_endpoint_id,
                &self.endpoint,
                &StageGuard::default(),
            )
            .map_err(|_| NativeRunError::RECONCILIATION_REQUIRED)?;
            let saved = state
                .get_staging_quota("native_run", &record.binding.run_id)
                .map_err(|_| NativeRunError::STATE)?
                .ok_or(NativeRunError::RECONCILIATION_REQUIRED)?;
            if !state
                .is_staging_quota_inventory_complete()
                .map_err(|_| NativeRunError::STATE)?
                || saved.binding.storage_endpoint_id != record.binding.storage_endpoint_id
                || saved.binding.storage_identity != record.binding.storage_identity
                || saved.binding.volume_identity
                    != format!("unix:{}", self.endpoint.identity().device)
                || saved.binding.max_bytes
                    != get_repository_budget(record)?
                        .checked_add(SCRATCH_BYTES)
                        .ok_or(NativeRunError::CAPACITY)?
            {
                return Err(NativeRunError::RECONCILIATION_REQUIRED);
            }
            return Ok(());
        }
        crate::staging_quota::reserve_owned_staging_quota(
            state,
            &self.endpoint,
            &crate::staging_quota::StagingQuotaBinding {
                object_kind: "native_run".into(),
                object_id: record.binding.run_id.clone(),
                storage_endpoint_id: record.binding.storage_endpoint_id.clone(),
                storage_identity: record.binding.storage_identity.clone(),
                volume_identity: format!("unix:{}", self.endpoint.identity().device),
                max_bytes: get_repository_budget(record)?
                    .checked_add(SCRATCH_BYTES)
                    .ok_or(NativeRunError::CAPACITY)?,
            },
        )
        .map_err(|error| match error {
            crate::state::StateError::EffectConflict
            | crate::state::StateError::InventoryRequired => {
                NativeRunError::RECONCILIATION_REQUIRED
            }
            crate::state::StateError::QuotaExceeded => NativeRunError::CAPACITY,
            _ => NativeRunError::STATE,
        })?;
        Ok(())
    }

    pub fn prepare(
        &self,
        state: &mut StateStore,
        binding: &NativeRunBinding,
        guard: &StageGuard,
    ) -> Result<NativeRunRecord, NativeRunError> {
        guard.check().map_err(|_| NativeRunError::RESOURCE)?;
        self.revalidate()?;
        if binding.storage_endpoint_id != self.endpoint_id
            || binding.storage_identity != self.identity
            || binding.relative_name != format!("native_{}", binding.run_id)
        {
            return Err(NativeRunError::INVALID);
        }
        let record = state
            .prepare_native_run(binding)
            .map_err(|_| NativeRunError::STATE)?;
        self.validate_record(&record)?;
        self.reserve_quota(state, &record, false)?;
        let lock = self.acquire_parent_lock(&record)?;
        let record = state
            .get_native_run(&binding.run_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        self.validate_record(&record)?;
        if record.effect_state != "prepared" {
            self.open_layout(&record)?;
            return Ok(record);
        }
        let name = get_name(&binding.relative_name)?;
        if is_present(self.endpoint.directory(), &name)? {
            return Err(NativeRunError::RECONCILIATION_REQUIRED);
        }
        let container = create_directory(self.endpoint.directory(), &name)?;
        self.check_parent_lock(&record, &lock)?;
        let record = state
            .mark_native_staging(&binding.run_id, &get_identity(&container)?)
            .map_err(|_| NativeRunError::OUTCOME_UNKNOWN)?;
        self.finish_layout(state, &record, &container, guard)
    }

    fn finish_layout(
        &self,
        state: &mut StateStore,
        record: &NativeRunRecord,
        container: &File,
        guard: &StageGuard,
    ) -> Result<NativeRunRecord, NativeRunError> {
        guard.check().map_err(|_| NativeRunError::RESOURCE)?;
        let owner = open_lock(container, c"owner.lock", true)?;
        acquire_file_lock(&owner)?;
        let repository = if is_present(container, c"repository")? {
            open_directory(container, c"repository")?
        } else {
            create_directory(container, c"repository")?
        };
        let scratch = if is_present(container, c"scratch")? {
            open_directory(container, c"scratch")?
        } else {
            create_directory(container, c"scratch")?
        };
        check_empty(&repository)?;
        check_empty(&scratch)?;
        container.sync_all().map_err(|_| NativeRunError::STORAGE)?;
        self.revalidate()?;
        check_slot(
            self.endpoint.directory(),
            &get_name(&record.binding.relative_name)?,
            record
                .container_identity
                .as_deref()
                .ok_or(NativeRunError::STATE)?,
            true,
        )?;
        guard.check().map_err(|_| NativeRunError::RESOURCE)?;
        let result = state
            .mark_native_ready(
                &record.binding.run_id,
                &get_identity(&repository)?,
                &get_identity(&owner)?,
                &get_identity(&scratch)?,
            )
            .map_err(|_| NativeRunError::OUTCOME_UNKNOWN)?;
        self.open_layout(&result)?;
        Ok(result)
    }

    pub fn execute(
        &self,
        state: &mut StateStore,
        run_id: &str,
        execution: &NativeRunExecution<'_>,
    ) -> Result<NativeRunRecord, NativeRunError> {
        if !self.reap_pending(run_id, execution.guard)? {
            return Err(NativeRunError::BUSY);
        }
        let record = state
            .get_native_run(run_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        let lock = self.acquire_parent_lock(&record)?;
        let record = state
            .get_native_run(run_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        self.validate_record(&record)?;
        if record.effect_state != "ready" {
            return Err(NativeRunError::RECONCILIATION_REQUIRED);
        }
        let layout = self.open_layout(&record)?;
        acquire_file_lock(&layout.owner)?;
        check_empty(&layout.repository)?;
        drop(layout);
        self.run_worker(
            state,
            &record,
            ArchiveWorkerOperation::CREATE,
            execution,
            &lock,
        )
    }

    pub fn reconcile(
        &self,
        state: &mut StateStore,
        run_id: &str,
        execution: &NativeRunExecution<'_>,
    ) -> Result<NativeRunRecord, NativeRunError> {
        execution
            .guard
            .check()
            .map_err(|_| NativeRunError::RESOURCE)?;
        if !self.reap_pending(run_id, execution.guard)? {
            return Err(NativeRunError::BUSY);
        }
        let mut record = state
            .get_native_run(run_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        self.reserve_quota(state, &record, true)?;
        let lock = self.acquire_parent_lock(&record)?;
        record = state
            .get_native_run(run_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        self.validate_record(&record)?;
        if record.effect_state == "staging" {
            let container = open_directory(
                self.endpoint.directory(),
                &get_name(&record.binding.relative_name)?,
            )?;
            if record.container_identity.as_deref() != Some(get_identity(&container)?.as_str()) {
                return Err(NativeRunError::STORAGE);
            }
            return self.finish_layout(state, &record, &container, execution.guard);
        }
        if !matches!(
            record.effect_state.as_str(),
            "running" | "unknown" | "verified"
        ) {
            return Err(NativeRunError::RECONCILIATION_REQUIRED);
        }
        if matches!(record.effect_state.as_str(), "running" | "unknown")
            && (record.scope_protocol != 1 || record.operation_token.is_none())
        {
            return Err(NativeRunError::RECONCILIATION_REQUIRED);
        }
        if record.effect_state == "running" {
            let operation = record
                .active_operation
                .as_deref()
                .ok_or(NativeRunError::STATE)?;
            let token = record
                .operation_token
                .as_deref()
                .ok_or(NativeRunError::STATE)?;
            record = state
                .mark_native_unknown_for_operation(run_id, operation, token)
                .map_err(|_| NativeRunError::STATE)?;
        }
        if let Some(identity) = &record.worker_identity
            && !quiesce_recorded_worker(identity, execution.guard)
                .map_err(|_| NativeRunError::RECONCILIATION_REQUIRED)?
        {
            return Err(NativeRunError::BUSY);
        }
        let layout = self.open_layout(&record)?;
        acquire_file_lock(&layout.owner)?;
        drop(layout);
        self.run_worker(
            state,
            &record,
            ArchiveWorkerOperation::VERIFY,
            execution,
            &lock,
        )
    }

    fn run_worker(
        &self,
        state: &mut StateStore,
        record: &NativeRunRecord,
        operation: ArchiveWorkerOperation,
        execution: &NativeRunExecution<'_>,
        lock: &File,
    ) -> Result<NativeRunRecord, NativeRunError> {
        execution
            .guard
            .check()
            .map_err(|_| NativeRunError::RESOURCE)?;
        self.check_parent_lock(record, lock)?;
        let database = state.connection.path().ok_or(NativeRunError::STATE)?;
        let database = fs::canonicalize(database).map_err(|_| NativeRunError::STATE)?;
        let state_path =
            fs::canonicalize(execution.state_dir).map_err(|_| NativeRunError::STORAGE)?;
        if database.parent() != Some(state_path.as_path()) {
            return Err(NativeRunError::STATE);
        }
        if execution.repository_key_ref != record.binding.repository_key_ref
            || (operation == ArchiveWorkerOperation::CREATE
                && execution.source_key_ref != record.source_key_ref)
        {
            return Err(NativeRunError::WRONG_KEY_REFERENCE);
        }
        if execution.repository_password.is_empty()
            || execution.repository_password.len() > 4096
            || !execution.executable.is_file()
        {
            return Err(NativeRunError::INVALID);
        }
        let executable =
            fs::canonicalize(execution.executable).map_err(|_| NativeRunError::INVALID)?;
        let executable_parent = executable.parent().ok_or(NativeRunError::INVALID)?;
        let metadata = fs::metadata(executable_parent).map_err(|_| NativeRunError::STORAGE)?;
        let executable_endpoint = LocalEndpoint::resolve(
            executable_parent,
            crate::local_endpoint::FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )
        .map_err(|_| NativeRunError::STORAGE)?;
        if operation == ArchiveWorkerOperation::VERIFY {
            crate::physical_registry::check_registered_access(
                state,
                crate::physical_registry::PhysicalRootKind::EXECUTABLE,
                "archive_worker_binary",
                &executable_endpoint,
                execution.guard,
            )
            .map_err(|_| NativeRunError::RECONCILIATION_REQUIRED)?;
            let metadata = fs::metadata(&state_path).map_err(|_| NativeRunError::STORAGE)?;
            let state_endpoint = LocalEndpoint::resolve_metadata(
                &state_path,
                crate::local_endpoint::FileIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            )
            .map_err(|_| NativeRunError::STORAGE)?;
            crate::physical_registry::check_registered_access(
                state,
                crate::physical_registry::PhysicalRootKind::STATE,
                "node",
                &state_endpoint,
                execution.guard,
            )
            .map_err(|_| NativeRunError::RECONCILIATION_REQUIRED)?;
        } else {
            crate::physical_registry::register_roots(
                state,
                &[crate::physical_registry::PhysicalRootClaim {
                    kind: crate::physical_registry::PhysicalRootKind::EXECUTABLE,
                    owner_id: "archive_worker_binary",
                    endpoint: &executable_endpoint,
                }],
                execution.guard,
            )
            .map_err(|_| NativeRunError::RECONCILIATION_REQUIRED)?;
        }
        let capture = state
            .get_capture(&record.capture_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        if capture.binding.job_id != execution.job.get_job_id() {
            return Err(NativeRunError::RESOURCE);
        }
        let stage = state
            .get_archive_stage(&record.binding.stage_id)
            .map_err(|_| NativeRunError::STATE)?
            .ok_or(NativeRunError::STATE)?;
        if stage.effect_state != "sealed"
            || stage.catalog_ciphertext_digest.as_deref()
                != Some(record.source_catalog_digest.as_str())
        {
            return Err(NativeRunError::STATE);
        }
        let layout = self.open_layout(record)?;
        let repository_max_bytes = get_repository_budget(record)?;
        self.reserve_quota(state, record, operation == ArchiveWorkerOperation::VERIFY)?;
        let spool_bytes = repository_max_bytes
            .checked_add(SCRATCH_BYTES)
            .ok_or(NativeRunError::CAPACITY)?;
        let capacity = self
            .endpoint
            .capacity()
            .map_err(|_| NativeRunError::STORAGE)?;
        if operation == ArchiveWorkerOperation::CREATE
            && capacity.available_bytes
                < spool_bytes
                    .saturating_add(RESERVE_BYTES.max(capacity.capacity_bytes.div_ceil(20)))
        {
            return Err(NativeRunError::CAPACITY);
        }
        let mut reservation = Some(
            execution
                .job
                .reserve_stage(
                    None,
                    Demand {
                        data_bytes: execution.worker_limits.memory_max_bytes,
                        spool_bytes,
                        open_files: execution.worker_limits.max_open_files,
                        cpu_workers: 1,
                        streams: 4,
                        ..Demand::default()
                    },
                    execution.guard,
                )
                .map_err(|_| NativeRunError::RESOURCE)?,
        );
        let container_path = self.root.join(&record.binding.relative_name);
        let repository_dir = container_path.join("repository");
        let scratch_dir = container_path.join("scratch");
        self.check_parent_lock(record, lock)?;
        drop(layout);
        let mut pending_lock = Some(lock.try_clone().map_err(|_| NativeRunError::STORAGE)?);
        let started = state
            .start_native_run(&record.binding.run_id, operation.get_name())
            .map_err(|_| NativeRunError::STATE)?;
        let record = &started;
        let token = record
            .operation_token
            .as_deref()
            .ok_or(NativeRunError::STATE)?;
        let outcome = (|| {
            let request = ArchiveWorkerRequest {
                protocol_version: 1,
                run_id: record.binding.run_id.clone(),
                operation_token: token.to_owned(),
                operation,
                state_dir: execution.state_dir.to_path_buf(),
                archive_dir: execution.archive_dir.to_path_buf(),
                stage_binding: stage.binding,
                archive_key: if operation == ArchiveWorkerOperation::CREATE {
                    **execution.source_key
                } else {
                    [0; 32]
                },
                source_limits: execution.source_limits,
                repository_dir: repository_dir.clone(),
                repository_identity: get_worker_identity(
                    record
                        .repository_identity
                        .as_deref()
                        .ok_or(NativeRunError::STATE)?,
                )?,
                scratch_dir: scratch_dir.clone(),
                scratch_identity: get_worker_identity(
                    record
                        .scratch_identity
                        .as_deref()
                        .ok_or(NativeRunError::STATE)?,
                )?,
                owner_lock: container_path.join("owner.lock"),
                owner_lock_identity: get_worker_identity(
                    record
                        .owner_lock_identity
                        .as_deref()
                        .ok_or(NativeRunError::STATE)?,
                )?,
                repository_password: execution.repository_password.to_owned(),
                repository_max_bytes,
                memory_max_bytes: execution.worker_limits.memory_max_bytes,
                timeout_seconds: execution.worker_limits.max_runtime.as_secs().clamp(1, 900),
            };
            let body =
                Zeroizing::new(serde_json::to_vec(&request).map_err(|_| NativeRunError::INVALID)?);
            if body.len() > 65536 {
                return Err(NativeRunError::INVALID);
            }
            let mut input = Zeroizing::new((body.len() as u32).to_be_bytes().to_vec());
            input.extend_from_slice(&body);
            let mut read_paths =
                crate::worker_state::get_readonly_state_paths(state, execution.state_dir)
                    .map_err(|_| NativeRunError::STATE)?;
            read_paths.push(container_path);
            let mut write_paths = vec![scratch_dir];
            if operation == ArchiveWorkerOperation::CREATE {
                read_paths.push(execution.archive_dir.to_path_buf());
                write_paths.push(repository_dir);
            }
            self.check_parent_lock(record, lock)?;
            let output = execute_worker_recorded(
                execution.executable,
                &input,
                &read_paths,
                &write_paths,
                execution.worker_limits,
                execution.guard,
                |identity| {
                    state
                        .bind_native_run_worker(
                            &record.binding.run_id,
                            operation.get_name(),
                            token,
                            identity,
                        )
                        .map_err(|_| WorkerError::INVALID)?;
                    Ok(())
                },
            )
            .map_err(|error| {
                if let WorkerError::OUTCOME_UNKNOWN(mut stop) = error
                    && let Some(worker) = stop.recovery.take()
                {
                    let pending = PendingNative {
                        worker,
                        reservation: reservation.take(),
                        parent_lock: pending_lock.take(),
                    };
                    match self.pending.lock() {
                        Ok(mut entries) => {
                            entries.insert(record.binding.run_id.clone(), pending);
                        }
                        Err(_) => {
                            drop(pending);
                        }
                    }
                }
                NativeRunError::OUTCOME_UNKNOWN
            })?;
            if output.stdout.len() < 4 {
                return Err(NativeRunError::OUTCOME_UNKNOWN);
            }
            let length = u32::from_be_bytes(
                output.stdout[..4]
                    .try_into()
                    .map_err(|_| NativeRunError::OUTCOME_UNKNOWN)?,
            ) as usize;
            if length > 16384 || length != output.stdout.len() - 4 {
                return Err(NativeRunError::OUTCOME_UNKNOWN);
            }
            let report: ArchiveWorkerReport = serde_json::from_slice(&output.stdout[4..])
                .map_err(|_| NativeRunError::OUTCOME_UNKNOWN)?;
            if report.protocol_version != 1
                || report.run_id != record.binding.run_id
                || report.operation_token != token
                || report.stage_id != record.binding.stage_id
                || report.manifest_digest != record.manifest_digest
                || report.entry_count.to_string() != record.manifest_entry_count
                || report.file_count.to_string() != record.file_count
                || report.payload_bytes.to_string() != record.payload_bytes
                || report.repository_bytes > repository_max_bytes
            {
                return Err(NativeRunError::OUTCOME_UNKNOWN);
            }
            self.check_parent_lock(record, lock)?;
            let layout = self.open_layout(record)?;
            acquire_file_lock(&layout.owner)?;
            execution
                .guard
                .check()
                .map_err(|_| NativeRunError::RESOURCE)?;
            state
                .seal_native_run_for_operation(
                    &record.binding.run_id,
                    operation.get_name(),
                    token,
                    &report.native_snapshot_id,
                    &report.manifest_digest,
                    report.entry_count,
                    report.file_count,
                    report.payload_bytes,
                )
                .map_err(|_| NativeRunError::OUTCOME_UNKNOWN)
        })();
        if outcome.is_err() {
            state
                .mark_native_unknown_for_operation(
                    &record.binding.run_id,
                    operation.get_name(),
                    token,
                )
                .map_err(|_| NativeRunError::OUTCOME_UNKNOWN)?;
        }
        outcome
    }
}
