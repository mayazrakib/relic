use serde::{Deserialize, Serialize};

pub const MAX_STAGING_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_STAGING_OBJECTS: u64 = 10_000;
pub const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingQuotaBinding {
    pub object_kind: String,
    pub object_id: String,
    pub storage_endpoint_id: String,
    pub storage_identity: String,
    pub volume_identity: String,
    pub max_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingQuotaRecord {
    pub binding: StagingQuotaBinding,
}

/// Admit a reservation against a physically pinned root and its actual capacity.
/// First use requires an empty root. Existing registered roots still require trusted
/// inventory and protection from external writers; this check is not a census.
#[cfg(unix)]
pub fn reserve_owned_staging_quota(
    state: &mut crate::state::StateStore,
    endpoint: &crate::local_endpoint::LocalEndpoint,
    binding: &StagingQuotaBinding,
) -> Result<StagingQuotaRecord, crate::state::StateError> {
    use crate::state::StateError;
    endpoint
        .revalidate()
        .map_err(|_| StateError::EffectConflict)?;
    let identity = endpoint.identity();
    if binding.storage_identity != format!("unix:{}:{}", identity.device, identity.inode)
        || binding.volume_identity != format!("unix:{}", identity.device)
    {
        return Err(StateError::InvalidInput);
    }
    #[cfg(target_os = "linux")]
    if binding.object_kind != "gateway_scratch" {
        use crate::physical_registry::{
            PhysicalRegistryError, PhysicalRootClaim, PhysicalRootKind,
        };
        crate::physical_registry::register_roots(
            state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::STAGING,
                owner_id: &binding.storage_endpoint_id,
                endpoint,
            }],
            &crate::resources::StageGuard::default(),
        )
        .map_err(|error| match error {
            PhysicalRegistryError::INVENTORY_REQUIRED => StateError::InventoryRequired,
            PhysicalRegistryError::LIMIT => StateError::QuotaExceeded,
            _ => StateError::EffectConflict,
        })?;
    }
    if !state.has_staging_quota_storage(&binding.storage_identity)? && !is_empty(endpoint)? {
        state.require_staging_quota_inventory()?;
        return Err(StateError::EffectConflict);
    }
    endpoint
        .revalidate()
        .map_err(|_| StateError::EffectConflict)?;
    let capacity = endpoint
        .capacity()
        .map_err(|_| StateError::EffectConflict)?;
    state.reserve_staging_quota(binding, capacity.capacity_bytes, capacity.available_bytes)
}

#[cfg(unix)]
fn is_empty(
    endpoint: &crate::local_endpoint::LocalEndpoint,
) -> Result<bool, crate::state::StateError> {
    use crate::state::StateError;
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;

    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: the stream is uniquely owned and was returned by fdopendir.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    // SAFETY: opening dot relative to the pinned directory creates an independent
    // directory description, so readdir cannot alter another reader's offset.
    let opened = unsafe {
        libc::openat(
            endpoint.directory().as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(StateError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: opened is live and this duplicates it with close-on-exec.
    let fd = unsafe { libc::fcntl(opened, libc::F_DUPFD_CLOEXEC, 3) };
    let duplicate_error = if fd < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: opened is independently owned and no longer needed.
    unsafe {
        libc::close(opened);
    }
    if let Some(error) = duplicate_error {
        return Err(StateError::Io(error));
    }
    // SAFETY: fd is an owned readable directory descriptor; ownership transfers on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd remains owned here.
        unsafe {
            libc::close(fd);
        }
        return Err(StateError::Io(error));
    }
    let stream = Directory(stream);
    for _ in 0..3 {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: errno is thread-local and reset immediately before readdir.
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        // SAFETY: errno is thread-local and reset immediately before readdir.
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: the stream is live and accessed only by this function.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(true)
            } else {
                Err(StateError::Io(error))
            };
        }
        // SAFETY: readdir supplies a valid NUL-terminated d_name until the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Err(StateError::EffectConflict)
}

#[cfg(not(unix))]
pub fn reserve_owned_staging_quota(
    _state: &mut crate::state::StateStore,
    _endpoint: &crate::local_endpoint::LocalEndpoint,
    _binding: &StagingQuotaBinding,
) -> Result<StagingQuotaRecord, crate::state::StateError> {
    Err(crate::state::StateError::EffectConflict)
}
