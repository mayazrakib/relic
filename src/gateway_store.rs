//! Linux local gateway initialization controller. The durable journal records
//! identities; callers remain responsible for excluding external repository writers.
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::archive_worker::WorkerDirectoryIdentity;
use crate::gateway_layout::GatewayLayoutRecord;
use crate::gateway_state::{GatewayResourceBinding, GatewayResourceRecord};
use crate::gateway_worker::{GatewayWorkerOperation, GatewayWorkerReport, GatewayWorkerRequest};
use crate::local_endpoint::{FileIdentity, LocalEndpoint, get_disjoint_scope_evidence};
use crate::resources::{ActiveJob, Demand, StageGuard, StageReservation};
use crate::state::StateStore;
use crate::worker_runtime::{
    PendingWorker, WorkerError, WorkerLimits, execute_worker_recorded, quiesce_recorded_worker,
};

const MEMORY_BYTES: u64 = 192 * 1024 * 1024;
const SCRATCH_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

#[path = "gateway_publication.rs"]
mod publication;
pub use publication::GatewayPublicationSource;

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum GatewayStoreError {
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
impl fmt::Display for GatewayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid gateway initialization request",
            Self::STORAGE => "gateway storage validation failed",
            Self::STATE => "gateway journal rejected the operation",
            Self::BUSY => "gateway has a live owner",
            Self::CAPACITY => "gateway capacity unavailable",
            Self::RESOURCE => "gateway resource admission failed",
            Self::WRONG_KEY_REFERENCE => "gateway key reference changed",
            Self::RECONCILIATION_REQUIRED => "gateway initialization requires reconciliation",
            Self::OUTCOME_UNKNOWN => "gateway initialization outcome is unknown",
        })
    }
}
impl std::error::Error for GatewayStoreError {}

pub struct GatewayExecutionContext<'a> {
    pub executable: &'a Path,
    pub state_dir: &'a Path,
    pub target_key_ref: &'a str,
    pub target_password: &'a str,
    pub repository_max_bytes: u64,
    pub worker_limits: WorkerLimits,
    pub job: &'a ActiveJob,
    pub guard: &'a StageGuard,
}
pub struct LocalGatewayStore {
    endpoint: LocalEndpoint,
    root: PathBuf,
    endpoint_id: String,
    identity: String,
    pending: Mutex<BTreeMap<String, PendingGateway>>,
}
struct PendingGateway {
    worker: Box<PendingWorker>,
    reservation: Option<StageReservation>,
    coordinator: Option<File>,
}
impl Drop for PendingGateway {
    fn drop(&mut self) {
        if !self.worker.has_ended() {
            if let Some(reservation) = self.reservation.take() {
                std::mem::forget(reservation);
            }
            if let Some(lock) = self.coordinator.take() {
                std::mem::forget(lock);
            }
        }
    }
}

fn get_identity(file: &File) -> Result<String, GatewayStoreError> {
    let metadata = file.metadata().map_err(|_| GatewayStoreError::STORAGE)?;
    Ok(format!("unix:{}:{}", metadata.dev(), metadata.ino()))
}

fn get_worker_identity(text: &str) -> Result<WorkerDirectoryIdentity, GatewayStoreError> {
    let mut parts = text.split(':');
    if parts.next() != Some("unix") {
        return Err(GatewayStoreError::STORAGE);
    }
    let device = parts
        .next()
        .ok_or(GatewayStoreError::STORAGE)?
        .parse()
        .map_err(|_| GatewayStoreError::STORAGE)?;
    let inode = parts
        .next()
        .ok_or(GatewayStoreError::STORAGE)?
        .parse()
        .map_err(|_| GatewayStoreError::STORAGE)?;
    if parts.next().is_some() {
        return Err(GatewayStoreError::STORAGE);
    }
    Ok(WorkerDirectoryIdentity { device, inode })
}

fn open_directory(parent: &File, name: &CStr) -> Result<File, GatewayStoreError> {
    // SAFETY: parent and component are live; directory and no-follow flags reject other types.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(GatewayStoreError::STORAGE);
    }
    // SAFETY: the fresh descriptor is transferred exactly once to File.
    let file = unsafe { File::from_raw_fd(fd) };
    check_private(&file, true)?;
    Ok(file)
}

fn check_private(file: &File, is_directory: bool) -> Result<(), GatewayStoreError> {
    let metadata = file.metadata().map_err(|_| GatewayStoreError::STORAGE)?;
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
        return Err(GatewayStoreError::STORAGE);
    }
    Ok(())
}

fn open_lock(parent: &File, name: &CStr, can_create: bool) -> Result<File, GatewayStoreError> {
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
            file.sync_all().map_err(|_| GatewayStoreError::STORAGE)?;
            parent.sync_all().map_err(|_| GatewayStoreError::STORAGE)?;
            return Ok(file);
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(GatewayStoreError::STORAGE);
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
        return Err(GatewayStoreError::STORAGE);
    }
    // SAFETY: the new descriptor is transferred exactly once to File.
    let pinned = unsafe { File::from_raw_fd(fd) };
    check_private(&pinned, false)?;
    let file = File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| GatewayStoreError::STORAGE)?;
    if get_identity(&file)? != get_identity(&pinned)? {
        return Err(GatewayStoreError::STORAGE);
    }
    Ok(file)
}

fn acquire_file_lock(file: &File) -> Result<(), GatewayStoreError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(GatewayStoreError::BUSY),
        Err(_) => Err(GatewayStoreError::STORAGE),
    }
}

fn check_slot(
    parent: &File,
    name: &CStr,
    expected: &str,
    is_directory: bool,
) -> Result<(), GatewayStoreError> {
    let file = if is_directory {
        open_directory(parent, name)?
    } else {
        open_lock(parent, name, false)?
    };
    if get_identity(&file)? != expected {
        return Err(GatewayStoreError::STORAGE);
    }
    Ok(())
}

fn create_directory(parent: &File, name: &CStr) -> Result<File, GatewayStoreError> {
    // SAFETY: the pinned directory and single NUL-terminated component are live.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
    }
    let file = open_directory(parent, name)?;
    file.sync_all().map_err(|_| GatewayStoreError::STORAGE)?;
    parent.sync_all().map_err(|_| GatewayStoreError::STORAGE)?;
    Ok(file)
}

fn is_present(parent: &File, name: &CStr) -> Result<bool, GatewayStoreError> {
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
    Err(GatewayStoreError::STORAGE)
}

fn check_empty(directory: &File) -> Result<(), GatewayStoreError> {
    if fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| GatewayStoreError::STORAGE)?
        .next()
        .is_some()
    {
        return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
    }
    Ok(())
}
impl LocalGatewayStore {
    pub fn new(
        endpoint: LocalEndpoint,
        root: &Path,
        endpoint_id: &str,
    ) -> Result<Self, GatewayStoreError> {
        if !crate::state::valid_identifier_text(endpoint_id) || !root.is_absolute() {
            return Err(GatewayStoreError::INVALID);
        }
        let root = fs::canonicalize(root).map_err(|_| GatewayStoreError::STORAGE)?;
        check_private(endpoint.directory(), true)?;
        let identity = get_identity(endpoint.directory())?;
        let result = Self {
            endpoint,
            root,
            endpoint_id: endpoint_id.into(),
            identity,
            pending: Mutex::new(BTreeMap::new()),
        };
        result.revalidate()?;
        Ok(result)
    }
    pub fn storage_identity(&self) -> &str {
        &self.identity
    }
    fn revalidate(&self) -> Result<(), GatewayStoreError> {
        self.endpoint
            .revalidate()
            .map_err(|_| GatewayStoreError::STORAGE)?;
        check_private(self.endpoint.directory(), true)?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: endpoint is pinned and the statfs output is writable.
        if unsafe {
            libc::fstatfs(
                self.endpoint.directory().as_raw_fd(),
                filesystem.as_mut_ptr(),
            )
        } != 0
        {
            return Err(GatewayStoreError::STORAGE);
        }
        // SAFETY: successful fstatfs initialized the output.
        let filesystem = unsafe { filesystem.assume_init() };
        if !matches!(filesystem.f_type, 0xef53 | 0x9123683e | 0x58465342) {
            // Recorded local process quiescence does not establish exclusion of remote filesystem requests.
            return Err(GatewayStoreError::STORAGE);
        }
        let metadata = fs::symlink_metadata(&self.root).map_err(|_| GatewayStoreError::STORAGE)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || format!("unix:{}:{}", metadata.dev(), metadata.ino()) != self.identity
        {
            return Err(GatewayStoreError::STORAGE);
        }
        Ok(())
    }
    fn check_resource(&self, resource: &GatewayResourceRecord) -> Result<(), GatewayStoreError> {
        self.revalidate()?;
        if resource.binding.storage_endpoint_id != self.endpoint_id
            || resource.binding.storage_identity != self.identity
        {
            return Err(GatewayStoreError::STORAGE);
        }
        Ok(())
    }
    fn acquire_coordinator(&self, create: bool) -> Result<File, GatewayStoreError> {
        self.revalidate()?;
        let file = open_lock(
            self.endpoint.directory(),
            c".relic-coordinator.lock",
            create,
        )?;
        acquire_file_lock(&file)?;
        check_slot(
            self.endpoint.directory(),
            c".relic-coordinator.lock",
            &get_identity(&file)?,
            false,
        )?;
        Ok(file)
    }
    fn check_coordinator(&self, file: &File) -> Result<(), GatewayStoreError> {
        self.revalidate()?;
        check_slot(
            self.endpoint.directory(),
            c".relic-coordinator.lock",
            &get_identity(file)?,
            false,
        )
    }
    fn check_initial_names(&self) -> Result<(), GatewayStoreError> {
        let mut count = 0;
        for entry in fs::read_dir(format!(
            "/proc/self/fd/{}",
            self.endpoint.directory().as_raw_fd()
        ))
        .map_err(|_| GatewayStoreError::STORAGE)?
        {
            let name = entry.map_err(|_| GatewayStoreError::STORAGE)?.file_name();
            if !matches!(
                name.to_str(),
                Some(".relic-coordinator.lock" | ".relic-owner.lock" | ".relic-scratch")
            ) {
                return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
            }
            count += 1;
            if count > 3 {
                return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
            }
        }
        Ok(())
    }
    fn open_bound_layout(
        &self,
        record: &GatewayLayoutRecord,
    ) -> Result<(File, File), GatewayStoreError> {
        self.revalidate()?;
        let owner = open_lock(self.endpoint.directory(), c".relic-owner.lock", false)?;
        let scratch = open_directory(self.endpoint.directory(), c".relic-scratch")?;
        if record.owner_identity.as_deref() != Some(get_identity(&owner)?.as_str())
            || record.scratch_identity.as_deref() != Some(get_identity(&scratch)?.as_str())
        {
            return Err(GatewayStoreError::STORAGE);
        }
        check_slot(
            self.endpoint.directory(),
            c".relic-owner.lock",
            &get_identity(&owner)?,
            false,
        )?;
        check_slot(
            self.endpoint.directory(),
            c".relic-scratch",
            &get_identity(&scratch)?,
            true,
        )?;
        Ok((owner, scratch))
    }
    pub fn prepare(
        &self,
        state: &mut StateStore,
        binding: &GatewayResourceBinding,
        guard: &StageGuard,
    ) -> Result<GatewayLayoutRecord, GatewayStoreError> {
        guard.check().map_err(|_| GatewayStoreError::RESOURCE)?;
        self.revalidate()?;
        if binding.storage_endpoint_id != self.endpoint_id
            || binding.storage_identity != self.identity
        {
            return Err(GatewayStoreError::STORAGE);
        }
        let resource = state
            .prepare_gateway_resource(binding)
            .map_err(|_| GatewayStoreError::STATE)?;
        let mut layout = state
            .prepare_gateway_layout(&binding.resource_id)
            .map_err(|_| GatewayStoreError::STATE)?;
        self.check_resource(&resource)?;
        if layout.owner_identity.is_none() || layout.scratch_identity.is_none() {
            self.check_initial_names()?;
        }
        let coordinator = self.acquire_coordinator(true)?;
        if layout.owner_identity.is_none() || layout.scratch_identity.is_none() {
            self.check_initial_names()?;
        }
        if layout.effect_state != "prepared" {
            let (owner, _scratch) = self.open_bound_layout(&layout)?;
            acquire_file_lock(&owner)?;
            self.check_coordinator(&coordinator)?;
            return Ok(layout);
        }
        let owner = open_lock(
            self.endpoint.directory(),
            c".relic-owner.lock",
            layout.owner_identity.is_none(),
        )?;
        acquire_file_lock(&owner)?;
        let owner_identity = get_identity(&owner)?;
        check_slot(
            self.endpoint.directory(),
            c".relic-owner.lock",
            &owner_identity,
            false,
        )?;
        if layout
            .owner_identity
            .as_deref()
            .is_some_and(|id| id != owner_identity)
        {
            return Err(GatewayStoreError::STORAGE);
        }
        if layout.owner_identity.is_none() {
            owner.sync_all().map_err(|_| GatewayStoreError::STORAGE)?;
            self.endpoint
                .directory()
                .sync_all()
                .map_err(|_| GatewayStoreError::STORAGE)?;
            layout = state
                .bind_gateway_owner(&binding.resource_id, &owner_identity)
                .map_err(|_| GatewayStoreError::STATE)?;
        }
        let scratch = if is_present(self.endpoint.directory(), c".relic-scratch")? {
            let dir = open_directory(self.endpoint.directory(), c".relic-scratch")?;
            if layout.scratch_identity.is_none() {
                check_empty(&dir)?;
            }
            dir
        } else {
            if layout.scratch_identity.is_some() {
                return Err(GatewayStoreError::STORAGE);
            }
            create_directory(self.endpoint.directory(), c".relic-scratch")?
        };
        let scratch_identity = get_identity(&scratch)?;
        check_slot(
            self.endpoint.directory(),
            c".relic-scratch",
            &scratch_identity,
            true,
        )?;
        if layout
            .scratch_identity
            .as_deref()
            .is_some_and(|id| id != scratch_identity)
        {
            return Err(GatewayStoreError::STORAGE);
        }
        if layout.scratch_identity.is_none() {
            scratch.sync_all().map_err(|_| GatewayStoreError::STORAGE)?;
            self.endpoint
                .directory()
                .sync_all()
                .map_err(|_| GatewayStoreError::STORAGE)?;
            state
                .bind_gateway_scratch(&binding.resource_id, &scratch_identity)
                .map_err(|_| GatewayStoreError::STATE)?;
        }
        self.check_coordinator(&coordinator)?;
        guard.check().map_err(|_| GatewayStoreError::RESOURCE)?;
        state
            .seal_gateway_layout(&binding.resource_id)
            .map_err(|_| GatewayStoreError::STATE)
    }
    pub fn reap_pending(&self, id: &str, guard: &StageGuard) -> Result<bool, GatewayStoreError> {
        guard.check().map_err(|_| GatewayStoreError::RESOURCE)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| GatewayStoreError::RESOURCE)?;
        if let Some(entry) = pending.get_mut(id) {
            if !entry.worker.try_reap() {
                return Ok(false);
            }
            pending.remove(id);
        }
        Ok(true)
    }
    fn validate_execution(
        &self,
        state: &StateStore,
        resource: &GatewayResourceRecord,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<(), GatewayStoreError> {
        context
            .guard
            .check()
            .map_err(|_| GatewayStoreError::RESOURCE)?;
        self.check_resource(resource)?;
        if context.target_key_ref != resource.binding.repository_key_ref {
            return Err(GatewayStoreError::WRONG_KEY_REFERENCE);
        }
        if context.target_password.is_empty()
            || context.target_password.len() > 4096
            || context.repository_max_bytes == 0
            || context.repository_max_bytes > MAX_REPOSITORY_BYTES
            || context.worker_limits.memory_max_bytes == 0
            || context.worker_limits.memory_max_bytes > MEMORY_BYTES
            || context.worker_limits.max_open_files > 64
            || context.worker_limits.max_output_bytes > 16388
            || context.worker_limits.max_output_bytes < 4
        {
            return Err(GatewayStoreError::INVALID);
        }
        let state_path =
            fs::canonicalize(context.state_dir).map_err(|_| GatewayStoreError::STORAGE)?;
        let database = state.connection.path().ok_or(GatewayStoreError::STATE)?;
        let database = fs::canonicalize(database).map_err(|_| GatewayStoreError::STATE)?;
        if database.parent() != Some(state_path.as_path()) {
            return Err(GatewayStoreError::STATE);
        }
        let executable =
            fs::canonicalize(context.executable).map_err(|_| GatewayStoreError::STORAGE)?;
        if !executable.is_file() {
            return Err(GatewayStoreError::INVALID);
        }
        let executable_parent = executable.parent().ok_or(GatewayStoreError::INVALID)?;
        let state_endpoint = resolve_endpoint(&state_path)?;
        let executable_endpoint = resolve_endpoint(executable_parent)?;
        get_disjoint_scope_evidence(&[&self.endpoint, &state_endpoint])
            .map_err(|_| GatewayStoreError::STORAGE)?;
        get_disjoint_scope_evidence(&[&self.endpoint, &executable_endpoint])
            .map_err(|_| GatewayStoreError::STORAGE)?;
        Ok(())
    }
    fn check_capacity(
        &self,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<(), GatewayStoreError> {
        let capacity = self
            .endpoint
            .capacity()
            .map_err(|_| GatewayStoreError::CAPACITY)?;
        let reserve = MIN_FREE_BYTES.max(capacity.capacity_bytes.div_ceil(20));
        let needed = context
            .repository_max_bytes
            .checked_add(SCRATCH_BYTES)
            .and_then(|v| v.checked_add(reserve))
            .ok_or(GatewayStoreError::CAPACITY)?;
        if capacity.available_bytes < needed {
            return Err(GatewayStoreError::CAPACITY);
        }
        Ok(())
    }
    pub fn initialize(
        &self,
        state: &mut StateStore,
        id: &str,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<GatewayResourceRecord, GatewayStoreError> {
        if !self.reap_pending(id, context.guard)? {
            return Err(GatewayStoreError::BUSY);
        }
        let resource = state
            .get_gateway_resource(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        self.validate_execution(state, &resource, context)?;
        let coordinator = self.acquire_coordinator(false)?;
        let layout = state
            .get_gateway_layout(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        let (owner, _scratch) = self.open_bound_layout(&layout)?;
        acquire_file_lock(&owner)?;
        self.check_coordinator(&coordinator)?;
        if state
            .get_gateway_resource(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .as_ref()
            != Some(&resource)
        {
            return Err(GatewayStoreError::STATE);
        }
        if layout.effect_state == "initialized" && resource.effect_state == "ready" {
            return Ok(resource);
        }
        self.check_capacity(context)?;
        if layout.effect_state != "ready" || resource.effect_state != "prepared" {
            return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
        }
        self.check_initial_names()?;
        drop(owner);
        self.run_initialization(state, &resource, &layout, context, &coordinator, false)
    }
    pub fn reconcile_initialization(
        &self,
        state: &mut StateStore,
        id: &str,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<GatewayResourceRecord, GatewayStoreError> {
        if !self.reap_pending(id, context.guard)? {
            return Err(GatewayStoreError::BUSY);
        }
        let resource = state
            .get_gateway_resource(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        self.validate_execution(state, &resource, context)?;
        let coordinator = self.acquire_coordinator(false)?;
        let mut layout = state
            .get_gateway_layout(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        let (_owner, _scratch) = self.open_bound_layout(&layout)?;
        self.check_coordinator(&coordinator)?;
        if state
            .get_gateway_resource(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .as_ref()
            != Some(&resource)
        {
            return Err(GatewayStoreError::STATE);
        }
        if layout.effect_state == "initialized" && resource.effect_state == "ready" {
            acquire_file_lock(&_owner)?;
            return Ok(resource);
        }
        if layout.effect_state == "initializing" {
            layout = state
                .mark_gateway_initialization_unknown(
                    id,
                    resource.receiver_epoch,
                    resource.fence_generation,
                )
                .map_err(|_| GatewayStoreError::STATE)?;
        }
        if layout.effect_state != "unknown"
            || layout.initialization_attempts != 1
            || !matches!(resource.effect_state.as_str(), "prepared" | "blocked")
        {
            return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
        }
        if layout.launch_protocol != 1 {
            return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
        }
        if let Some(identity) = &layout.containment {
            if !quiesce_recorded_worker(identity, context.guard)
                .map_err(|_| GatewayStoreError::RECONCILIATION_REQUIRED)?
            {
                return Err(GatewayStoreError::BUSY);
            }
        } else {
            // mark_unknown above serialized against the callback: an unbound initializer can no longer launch.
            state
                .revoke_unbound_gateway_initialization(
                    id,
                    resource.receiver_epoch,
                    resource.fence_generation,
                )
                .map_err(|_| GatewayStoreError::RECONCILIATION_REQUIRED)?;
        }
        let (owner, _scratch) = self.open_bound_layout(&layout)?;
        acquire_file_lock(&owner)?;
        self.check_coordinator(&coordinator)?;
        drop(owner);
        self.run_initialization(state, &resource, &layout, context, &coordinator, true)
    }
    fn run_initialization(
        &self,
        state: &mut StateStore,
        resource: &GatewayResourceRecord,
        layout: &GatewayLayoutRecord,
        context: &GatewayExecutionContext<'_>,
        coordinator: &File,
        is_inspection: bool,
    ) -> Result<GatewayResourceRecord, GatewayStoreError> {
        let mut reservation = Some(
            context
                .job
                .reserve_stage(
                    None,
                    Demand {
                        data_bytes: MEMORY_BYTES,
                        spool_bytes: SCRATCH_BYTES,
                        open_files: 64,
                        cpu_workers: 1,
                        streams: 4,
                        ..Demand::default()
                    },
                    context.guard,
                )
                .map_err(|_| GatewayStoreError::RESOURCE)?,
        );
        let request = GatewayWorkerRequest {
            protocol_version: 1,
            operation: if is_inspection {
                GatewayWorkerOperation::INSPECT_INITIALIZATION
            } else {
                GatewayWorkerOperation::INITIALIZE
            },
            state_dir: context.state_dir.to_path_buf(),
            target_dir: self.root.clone(),
            target_identity: get_worker_identity(&self.identity)?,
            owner_identity: get_worker_identity(
                layout
                    .owner_identity
                    .as_deref()
                    .ok_or(GatewayStoreError::STATE)?,
            )?,
            scratch_identity: get_worker_identity(
                layout
                    .scratch_identity
                    .as_deref()
                    .ok_or(GatewayStoreError::STATE)?,
            )?,
            resource_id: resource.binding.resource_id.clone(),
            receiver_epoch: resource.receiver_epoch,
            fence_generation: resource.fence_generation,
            admission_id: None,
            execution_ordinal: None,
            source_repository_dir: None,
            source_password: None,
            source_key_ref: None,
            target_password: context.target_password.into(),
            target_key_ref: context.target_key_ref.into(),
            repository_max_bytes: context.repository_max_bytes,
            memory_max_bytes: context.worker_limits.memory_max_bytes,
            timeout_seconds: context.worker_limits.max_runtime.as_secs().clamp(1, 900),
        };
        let body =
            Zeroizing::new(serde_json::to_vec(&request).map_err(|_| GatewayStoreError::INVALID)?);
        if body.len() > 65536 {
            return Err(GatewayStoreError::INVALID);
        }
        let mut input = Zeroizing::new((body.len() as u32).to_be_bytes().to_vec());
        input.extend_from_slice(&body);
        let read_paths = vec![context.state_dir.to_path_buf(), self.root.clone()];
        let write_paths = if is_inspection {
            vec![]
        } else {
            vec![self.root.clone()]
        };
        self.check_coordinator(coordinator)?;
        let mut pending_lock = Some(
            coordinator
                .try_clone()
                .map_err(|_| GatewayStoreError::STORAGE)?,
        );
        if !is_inspection {
            state
                .start_gateway_initialization(
                    &resource.binding.resource_id,
                    resource.receiver_epoch,
                    resource.fence_generation,
                )
                .map_err(|_| GatewayStoreError::STATE)?;
        }
        let outcome = (|| {
            let output = execute_worker_recorded(
                context.executable,
                &input,
                &read_paths,
                &write_paths,
                context.worker_limits,
                context.guard,
                |identity| {
                    if !is_inspection {
                        state
                            .bind_gateway_initialization_worker(
                                &resource.binding.resource_id,
                                resource.receiver_epoch,
                                resource.fence_generation,
                                identity,
                            )
                            .map_err(|_| WorkerError::INVALID)?;
                    }
                    Ok(())
                },
            )
            .map_err(|error| {
                if let WorkerError::OUTCOME_UNKNOWN(mut stop) = error
                    && let Some(worker) = stop.recovery.take()
                {
                    let pending = PendingGateway {
                        worker,
                        reservation: reservation.take(),
                        coordinator: pending_lock.take(),
                    };
                    match self.pending.lock() {
                        Ok(mut entries) => {
                            entries.insert(resource.binding.resource_id.clone(), pending);
                        }
                        Err(_) => drop(pending),
                    }
                }
                GatewayStoreError::OUTCOME_UNKNOWN
            })?;
            let stdout = Zeroizing::new(output.stdout);
            if stdout.len() < 4 {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            let size = u32::from_be_bytes(
                stdout[..4]
                    .try_into()
                    .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?,
            ) as usize;
            if size > 16384 || size != stdout.len() - 4 {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            let value = crate::config::parse_json_bytes(&stdout[4..])
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            let report: GatewayWorkerReport =
                serde_json::from_value(value).map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            if report.protocol_version != 1
                || report.resource_id != resource.binding.resource_id
                || report.receiver_epoch != resource.receiver_epoch
                || report.fence_generation != resource.fence_generation
                || report.admission_id.is_some()
                || report.execution_ordinal.is_some()
                || report.native_snapshot_id.is_some()
                || report.manifest_digest.is_some()
                || report.entry_count != 0
                || report.file_count != 0
                || report.payload_bytes != 0
                || report.repository_bytes > context.repository_max_bytes
                || report.repository_id.len() != 64
                || !report
                    .repository_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            self.check_coordinator(coordinator)?;
            let current = state
                .get_gateway_layout(&resource.binding.resource_id)
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?;
            let (owner, _scratch) = self.open_bound_layout(&current)?;
            acquire_file_lock(&owner)?;
            context
                .guard
                .check()
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            state
                .complete_gateway_initialization(
                    &resource.binding.resource_id,
                    resource.receiver_epoch,
                    resource.fence_generation,
                    &report.repository_id,
                )
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            state
                .get_gateway_resource(&resource.binding.resource_id)
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)
        })();
        if outcome.is_err() {
            state
                .mark_gateway_initialization_unknown(
                    &resource.binding.resource_id,
                    resource.receiver_epoch,
                    resource.fence_generation,
                )
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
        }
        outcome
    }
}

fn resolve_endpoint(path: &Path) -> Result<LocalEndpoint, GatewayStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| GatewayStoreError::STORAGE)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(GatewayStoreError::STORAGE);
    }
    LocalEndpoint::resolve(
        path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .map_err(|_| GatewayStoreError::STORAGE)
}
