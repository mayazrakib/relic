use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageCapacity {
    pub available_bytes: u64,
    pub capacity_bytes: u64,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum EndpointError {
    INVALID_PATH,
    IDENTITY_CHANGED,
    OVERLAP,
    AMBIGUOUS_SCOPE,
    LIMIT_EXCEEDED,
    IO(std::io::Error),
    UNSUPPORTED_PLATFORM,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID_PATH => "invalid local endpoint path",
            Self::IDENTITY_CHANGED => "local endpoint identity changed",
            Self::OVERLAP => "local endpoint scopes overlap",
            Self::AMBIGUOUS_SCOPE => "local endpoint disjointness cannot be established",
            Self::LIMIT_EXCEEDED => "local endpoint limit exceeded",
            Self::IO(_) => "local endpoint I/O failed",
            Self::UNSUPPORTED_PLATFORM => "local endpoint resolution unavailable",
        })
    }
}

impl std::error::Error for EndpointError {}

impl From<std::io::Error> for EndpointError {
    fn from(error: std::io::Error) -> Self {
        Self::IO(error)
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    use super::{EndpointError, FileIdentity, StorageCapacity};
    use crate::planner::ScopeEvidence;

    const MAX_DEPTH: usize = 128;
    const MAX_ENDPOINTS: usize = 128;
    const MAX_PATH_BYTES: usize = 65_536;
    const MAX_COMPONENT_BYTES: usize = 4096;

    #[cfg(target_os = "linux")]
    const DIRECTORY_ACCESS: i32 = libc::O_PATH;
    #[cfg(not(target_os = "linux"))]
    const DIRECTORY_ACCESS: i32 = libc::O_RDONLY;

    pub struct LocalEndpoint {
        directories: Vec<File>,
        names: Vec<CString>,
        identities: Vec<FileIdentity>,
        mount_id: Option<u64>,
    }

    fn build_identity(value: &libc::stat) -> FileIdentity {
        // Unix dev_t is signed on macOS and unsigned on Linux.
        #[allow(clippy::unnecessary_cast)]
        let device = value.st_dev as u64;

        FileIdentity {
            device,
            inode: value.st_ino,
        }
    }

    fn get_identity(fd: RawFd) -> Result<FileIdentity, EndpointError> {
        let mut value = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the descriptor is live and value is writable stat storage.
        if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful fstat initialized value.
        let value = unsafe { value.assume_init() };
        Ok(build_identity(&value))
    }

    fn get_entry_identity(fd: RawFd, name: &CStr) -> Result<FileIdentity, EndpointError> {
        let mut value = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: name is NUL-terminated and value is writable stat storage.
        if unsafe {
            libc::fstatat(
                fd,
                name.as_ptr(),
                value.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful fstatat initialized value.
        let value = unsafe { value.assume_init() };
        if value.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(EndpointError::IDENTITY_CHANGED);
        }
        Ok(build_identity(&value))
    }

    fn open_directory(fd: RawFd, name: &CStr) -> Result<File, EndpointError> {
        // SAFETY: fd is a live directory and name is NUL-terminated.
        let result = unsafe {
            libc::openat(
                fd,
                name.as_ptr(),
                DIRECTORY_ACCESS
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(result) })
    }

    #[cfg(target_os = "linux")]
    fn get_mount_id(fd: RawFd) -> Option<u64> {
        let mut value = MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: empty string and AT_EMPTY_PATH address the live descriptor; value is writable.
        let result = unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_MNT_ID,
                value.as_mut_ptr(),
            )
        };
        if result != 0 {
            return None;
        }
        // SAFETY: successful statx initialized value.
        let value = unsafe { value.assume_init() };
        if value.stx_mask & libc::STATX_MNT_ID == 0 {
            None
        } else {
            Some(value.stx_mnt_id)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn get_mount_id(_fd: RawFd) -> Option<u64> {
        None
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct MountEntry {
        id: u64,
        major: u32,
        minor: u32,
        root: Vec<Vec<u8>>,
        mountpoint: Vec<Vec<u8>>,
        fs_type: String,
    }

    #[cfg(target_os = "linux")]
    fn decode_mount_path(input: &[u8]) -> Result<Vec<Vec<u8>>, EndpointError> {
        let mut decoded = Vec::with_capacity(input.len());
        let mut index = 0;
        while index < input.len() {
            if input[index] == b'\\' {
                if index + 3 >= input.len() {
                    return Err(EndpointError::AMBIGUOUS_SCOPE);
                }
                let escaped = &input[index + 1..index + 4];
                decoded.push(match escaped {
                    b"040" => b' ',
                    b"011" => b'\t',
                    b"012" => b'\n',
                    b"134" => b'\\',
                    _ => return Err(EndpointError::AMBIGUOUS_SCOPE),
                });
                index += 4;
            } else {
                if input[index] == 0 {
                    return Err(EndpointError::AMBIGUOUS_SCOPE);
                }
                decoded.push(input[index]);
                index += 1;
            }
        }
        if decoded.first() != Some(&b'/') {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let mut result = Vec::new();
        if decoded.len() == 1 {
            return Ok(result);
        }
        for component in decoded[1..].split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." || component == b".." {
                return Err(EndpointError::AMBIGUOUS_SCOPE);
            }
            result.push(component.to_vec());
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn parse_mountinfo(data: &[u8]) -> Result<Vec<MountEntry>, EndpointError> {
        if data.len() > 512 * 1024 {
            return Err(EndpointError::LIMIT_EXCEEDED);
        }
        let mut result = Vec::new();
        for line in data
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if result.len() >= 4096 {
                return Err(EndpointError::LIMIT_EXCEEDED);
            }
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
            let separator = fields
                .iter()
                .position(|field| *field == b"-")
                .ok_or(EndpointError::AMBIGUOUS_SCOPE)?;
            if separator < 6
                || fields.len() < separator + 4
                || fields.iter().any(|field| field.is_empty())
            {
                return Err(EndpointError::AMBIGUOUS_SCOPE);
            }
            let parse = |value: &[u8]| -> Result<u64, EndpointError> {
                let text =
                    std::str::from_utf8(value).map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
                let n = text
                    .parse::<u64>()
                    .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
                if n.to_string() != text {
                    return Err(EndpointError::AMBIGUOUS_SCOPE);
                }
                Ok(n)
            };
            let id = parse(fields[0])?;
            let _parent = parse(fields[1])?;
            let device = fields[2];
            let colon = device
                .iter()
                .position(|byte| *byte == b':')
                .ok_or(EndpointError::AMBIGUOUS_SCOPE)?;
            let major = u32::try_from(parse(&device[..colon])?)
                .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
            let minor = u32::try_from(parse(&device[colon + 1..])?)
                .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
            if id == 0 || result.iter().any(|entry: &MountEntry| entry.id == id) {
                return Err(EndpointError::AMBIGUOUS_SCOPE);
            }
            result.push(MountEntry {
                id,
                major,
                minor,
                root: decode_mount_path(fields[3])?,
                mountpoint: decode_mount_path(fields[4])?,
                fs_type: std::str::from_utf8(fields[separator + 1])
                    .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?
                    .to_owned(),
            });
        }
        if result.is_empty() {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn read_mountinfo() -> Result<Vec<u8>, EndpointError> {
        use std::io::Read;
        let file = File::open("/proc/thread-self/mountinfo")
            .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        let mut result = Vec::new();
        file.take(512 * 1024 + 1)
            .read_to_end(&mut result)
            .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        if result.len() > 512 * 1024 {
            return Err(EndpointError::LIMIT_EXCEEDED);
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn get_mount_origin(
        id: u64,
        device: u64,
        namespace: &[Vec<u8>],
        mounts: &[MountEntry],
    ) -> Result<Vec<Vec<u8>>, EndpointError> {
        let selected = mounts
            .iter()
            .find(|mount| mount.id == id)
            .ok_or(EndpointError::AMBIGUOUS_SCOPE)?;
        if !matches!(selected.fs_type.as_str(), "ext4" | "btrfs" | "xfs")
            || libc::major(device) != selected.major
            || libc::minor(device) != selected.minor
        {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        if !namespace.starts_with(&selected.mountpoint) {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        if mounts
            .iter()
            .any(|mount| mount.id != id && mount.mountpoint.starts_with(namespace))
        {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let mut origin = selected.root.clone();
        origin.extend_from_slice(&namespace[selected.mountpoint.len()..]);
        Ok(origin)
    }

    #[cfg(target_os = "linux")]
    fn split_native_path(bytes: &[u8]) -> Result<Vec<Vec<u8>>, EndpointError> {
        if bytes.is_empty()
            || bytes.len() > MAX_PATH_BYTES
            || bytes[0] != b'/'
            || bytes.contains(&0)
        {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        if bytes == b"/" {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for component in bytes[1..].split(|byte| *byte == b'/') {
            if component.is_empty()
                || component.len() > MAX_COMPONENT_BYTES
                || component == b"."
                || component == b".."
            {
                return Err(EndpointError::AMBIGUOUS_SCOPE);
            }
            result.push(component.to_vec());
            if result.len() > MAX_DEPTH {
                return Err(EndpointError::LIMIT_EXCEEDED);
            }
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn get_kernel_path(endpoint: &LocalEndpoint) -> Result<Vec<u8>, EndpointError> {
        let proc_path = CString::new(format!(
            "/proc/thread-self/fd/{}",
            endpoint.directory().as_raw_fd()
        ))
        .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        let mut bytes = vec![0u8; MAX_PATH_BYTES + 1];
        // SAFETY: the proc path and writable bounded buffer are valid for readlink.
        let count =
            unsafe { libc::readlink(proc_path.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let count = usize::try_from(count).map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        if count > MAX_PATH_BYTES {
            return Err(EndpointError::LIMIT_EXCEEDED);
        }
        bytes.truncate(count);
        split_native_path(&bytes)?;
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    fn get_origin(
        endpoint: &LocalEndpoint,
        mounts: &[MountEntry],
    ) -> Result<Vec<Vec<u8>>, EndpointError> {
        let id = endpoint.mount_id.ok_or(EndpointError::AMBIGUOUS_SCOPE)?;
        let namespace = split_native_path(&get_kernel_path(endpoint)?)?;
        get_mount_origin(id, endpoint.identity().device, &namespace, mounts)
    }

    /// Kernel-derived snapshot for registry admission; callers must reobserve it at the effect boundary.
    #[cfg(target_os = "linux")]
    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PhysicalScopeObservation {
        pub path_base64url: String,
        pub device: u64,
        pub inode: u64,
        pub mount_id: u64,
        pub ancestor_identities: Vec<FileIdentity>,
        pub boot_id: String,
        pub mount_namespace_inode: u64,
        pub fs_type: String,
        pub origin_components_base64url: Vec<String>,
        pub mountinfo_sha256: String,
    }

    #[cfg(target_os = "linux")]
    fn get_boot_id() -> Result<String, EndpointError> {
        let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        let value = value.trim();
        let parsed = uuid::Uuid::parse_str(value).map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        if parsed.to_string() != value {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        Ok(value.to_owned())
    }

    #[cfg(target_os = "linux")]
    fn get_mount_namespace() -> Result<u64, EndpointError> {
        use std::os::unix::fs::MetadataExt;
        let inode = std::fs::metadata("/proc/thread-self/ns/mnt")
            .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?
            .ino();
        if inode == 0 {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        Ok(inode)
    }

    #[cfg(target_os = "linux")]
    fn hash_mountinfo(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let encoded: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("sha256:{encoded}")
    }

    /// Reads bounded mount evidence around a pinned, revalidated directory.
    #[cfg(target_os = "linux")]
    pub fn get_physical_scope_observation(
        endpoint: &LocalEndpoint,
    ) -> Result<PhysicalScopeObservation, EndpointError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        endpoint.revalidate()?;
        let boot_id = get_boot_id()?;
        let mount_namespace_inode = get_mount_namespace()?;
        let path = get_kernel_path(endpoint)?;
        let namespace = split_native_path(&path)?;
        let mount_snapshot = read_mountinfo()?;
        let mounts = parse_mountinfo(&mount_snapshot)?;
        let mount_id = endpoint.mount_id.ok_or(EndpointError::AMBIGUOUS_SCOPE)?;
        let origin = get_mount_origin(mount_id, endpoint.identity().device, &namespace, &mounts)?;
        let fs_type = mounts
            .iter()
            .find(|entry| entry.id == mount_id)
            .ok_or(EndpointError::AMBIGUOUS_SCOPE)?
            .fs_type
            .clone();
        if endpoint.identities.len() != namespace.len() + 1 {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        if get_kernel_path(endpoint)? != path
            || read_mountinfo()? != mount_snapshot
            || get_boot_id()? != boot_id
            || get_mount_namespace()? != mount_namespace_inode
        {
            return Err(EndpointError::IDENTITY_CHANGED);
        }
        endpoint.revalidate()?;
        let observation = PhysicalScopeObservation {
            path_base64url: URL_SAFE_NO_PAD.encode(path),
            device: endpoint.identity().device,
            inode: endpoint.identity().inode,
            mount_id,
            ancestor_identities: endpoint.identities.clone(),
            boot_id,
            mount_namespace_inode,
            fs_type,
            origin_components_base64url: origin
                .iter()
                .map(|component| URL_SAFE_NO_PAD.encode(component))
                .collect(),
            mountinfo_sha256: hash_mountinfo(&mount_snapshot),
        };
        validate_observation(&observation)?;
        Ok(observation)
    }

    #[cfg(target_os = "linux")]
    fn decode_component(value: &str, max_bytes: usize) -> Result<Vec<u8>, EndpointError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        if value.len() > max_bytes.saturating_mul(4).div_ceil(3) {
            return Err(EndpointError::LIMIT_EXCEEDED);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        if bytes.len() > max_bytes || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    type ObservationPaths = (Vec<Vec<u8>>, Vec<Vec<u8>>);

    #[cfg(target_os = "linux")]
    fn validate_observation(
        value: &PhysicalScopeObservation,
    ) -> Result<ObservationPaths, EndpointError> {
        if value.mount_id == 0
            || value.inode == 0
            || value.mount_namespace_inode == 0
            || !matches!(value.fs_type.as_str(), "ext4" | "btrfs" | "xfs")
            || value.ancestor_identities.is_empty()
            || value.ancestor_identities.len() > MAX_DEPTH + 1
            || value.origin_components_base64url.len() > MAX_DEPTH * 2
            || value.mountinfo_sha256.len() != 71
            || !value.mountinfo_sha256.starts_with("sha256:")
            || !value.mountinfo_sha256[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let boot =
            uuid::Uuid::parse_str(&value.boot_id).map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
        if boot.to_string() != value.boot_id {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let path = split_native_path(&decode_component(&value.path_base64url, MAX_PATH_BYTES)?)?;
        if path.len() + 1 != value.ancestor_identities.len()
            || value.ancestor_identities.last()
                != Some(&FileIdentity {
                    device: value.device,
                    inode: value.inode,
                })
            || value.ancestor_identities.iter().any(|item| item.inode == 0)
        {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let mut total = value.path_base64url.len();
        let mut origins = Vec::with_capacity(value.origin_components_base64url.len());
        for encoded in &value.origin_components_base64url {
            total = total
                .checked_add(encoded.len())
                .ok_or(EndpointError::LIMIT_EXCEEDED)?;
            if total > 256 * 1024 {
                return Err(EndpointError::LIMIT_EXCEEDED);
            }
            let component = decode_component(encoded, MAX_COMPONENT_BYTES)?;
            if component.is_empty()
                || component.contains(&0)
                || component.contains(&b'/')
                || component == b"."
                || component == b".."
            {
                return Err(EndpointError::AMBIGUOUS_SCOPE);
            }
            origins.push(component);
        }
        if serde_json::to_vec(value)
            .map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?
            .len()
            > 256 * 1024
        {
            return Err(EndpointError::LIMIT_EXCEEDED);
        }
        Ok((path, origins))
    }

    /// Validates the encoding and internal structure of one observation.
    #[cfg(target_os = "linux")]
    pub fn validate_physical_scope_observation(
        value: &PhysicalScopeObservation,
    ) -> Result<(), EndpointError> {
        validate_observation(value).map(|_| ())
    }

    /// Compares validated snapshots; this does not replace exclusive control or fresh re-observation.
    #[cfg(target_os = "linux")]
    pub fn compare_physical_scope_observations(
        left: &PhysicalScopeObservation,
        right: &PhysicalScopeObservation,
    ) -> Result<(), EndpointError> {
        let (left_path, left_origin) = validate_observation(left)?;
        let (right_path, right_origin) = validate_observation(right)?;
        if left.boot_id != right.boot_id
            || left.mount_namespace_inode != right.mount_namespace_inode
            || left.mountinfo_sha256 != right.mountinfo_sha256
        {
            return Err(EndpointError::AMBIGUOUS_SCOPE);
        }
        let left_id = FileIdentity {
            device: left.device,
            inode: left.inode,
        };
        let right_id = FileIdentity {
            device: right.device,
            inode: right.inode,
        };
        if left.ancestor_identities.contains(&right_id)
            || right.ancestor_identities.contains(&left_id)
            || left_path.starts_with(&right_path)
            || right_path.starts_with(&left_path)
        {
            return Err(EndpointError::OVERLAP);
        }
        if left.device == right.device {
            if left.fs_type != right.fs_type {
                return Err(EndpointError::AMBIGUOUS_SCOPE);
            }
            if left_origin.starts_with(&right_origin) || right_origin.starts_with(&left_origin) {
                return Err(EndpointError::OVERLAP);
            }
        }
        Ok(())
    }

    impl LocalEndpoint {
        pub fn resolve(path: &Path, expected: FileIdentity) -> Result<Self, EndpointError> {
            Self::resolve_with_access(path, expected, true)
        }

        /// Pin the endpoint for identity and scope checks without directory-read authority.
        #[cfg(target_os = "linux")]
        pub fn resolve_metadata(
            path: &Path,
            expected: FileIdentity,
        ) -> Result<Self, EndpointError> {
            Self::resolve_with_access(path, expected, false)
        }

        fn resolve_with_access(
            path: &Path,
            expected: FileIdentity,
            readable: bool,
        ) -> Result<Self, EndpointError> {
            #[cfg(not(target_os = "linux"))]
            let _ = readable;
            if !path.is_absolute() {
                return Err(EndpointError::INVALID_PATH);
            }
            if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
                return Err(EndpointError::LIMIT_EXCEEDED);
            }
            // SAFETY: root is NUL-terminated and open returns a fresh descriptor.
            let fd = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    DIRECTORY_ACCESS | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: open returned a new owned descriptor.
            let root = unsafe { File::from_raw_fd(fd) };
            let mut identities = vec![get_identity(root.as_raw_fd())?];
            let mut directories = vec![root];
            let mut names = Vec::new();
            for component in path.components() {
                let name = match component {
                    Component::RootDir => continue,
                    Component::Normal(name) => name,
                    _ => return Err(EndpointError::INVALID_PATH),
                };
                if names.len() >= MAX_DEPTH {
                    return Err(EndpointError::LIMIT_EXCEEDED);
                }
                if name.as_bytes().len() > MAX_COMPONENT_BYTES {
                    return Err(EndpointError::LIMIT_EXCEEDED);
                }
                let name =
                    CString::new(name.as_bytes()).map_err(|_| EndpointError::INVALID_PATH)?;
                let parent = directories.last().unwrap().as_raw_fd();
                let before = get_entry_identity(parent, &name)?;
                let child = open_directory(parent, &name)?;
                let actual = get_identity(child.as_raw_fd())?;
                if before != actual {
                    return Err(EndpointError::IDENTITY_CHANGED);
                }
                names.push(name);
                directories.push(child);
                identities.push(actual);
            }
            if identities.last().copied() != Some(expected) {
                return Err(EndpointError::IDENTITY_CHANGED);
            }

            #[cfg(target_os = "linux")]
            if readable {
                // Ancestors need identity/traversal authority, not directory listing.
                // Only the selected endpoint receives a readable directory handle.
                let pinned = directories.last().unwrap();
                // SAFETY: the pinned directory and NUL-terminated dot component are live.
                let fd = unsafe {
                    libc::openat(
                        pinned.as_raw_fd(),
                        c".".as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };

                if fd < 0 {
                    return Err(io::Error::last_os_error().into());
                }

                // SAFETY: the newly opened descriptor is transferred exactly once to File.
                let directory = unsafe { File::from_raw_fd(fd) };

                if get_identity(directory.as_raw_fd())? != expected {
                    return Err(EndpointError::IDENTITY_CHANGED);
                }

                *directories.last_mut().unwrap() = directory;
            }

            let mount_id = get_mount_id(directories.last().unwrap().as_raw_fd());
            let endpoint = Self {
                directories,
                names,
                identities,
                mount_id,
            };
            endpoint.revalidate()?;
            Ok(endpoint)
        }

        pub fn identity(&self) -> FileIdentity {
            *self.identities.last().unwrap()
        }

        pub fn mount_id(&self) -> Option<u64> {
            self.mount_id
        }

        pub fn directory(&self) -> &File {
            self.directories.last().unwrap()
        }

        pub fn revalidate(&self) -> Result<(), EndpointError> {
            for (index, file) in self.directories.iter().enumerate() {
                if get_identity(file.as_raw_fd())? != self.identities[index] {
                    return Err(EndpointError::IDENTITY_CHANGED);
                }
                if index > 0
                    && get_entry_identity(
                        self.directories[index - 1].as_raw_fd(),
                        &self.names[index - 1],
                    )? != self.identities[index]
                {
                    return Err(EndpointError::IDENTITY_CHANGED);
                }
            }
            if self.mount_id.is_some()
                && get_mount_id(self.directory().as_raw_fd()) != self.mount_id
            {
                return Err(EndpointError::IDENTITY_CHANGED);
            }
            Ok(())
        }

        // statvfs integer widths vary between Unix ABIs.
        #[allow(clippy::unnecessary_cast)]
        pub fn capacity(&self) -> Result<StorageCapacity, EndpointError> {
            self.revalidate()?;
            let mut stat = MaybeUninit::<libc::statvfs>::uninit();
            // SAFETY: directory is live and stat is writable.
            if unsafe { libc::fstatvfs(self.directory().as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: successful fstatvfs initialized stat.
            let stat = unsafe { stat.assume_init() };
            let block = stat.f_frsize as u64;
            let capacity_bytes = (stat.f_blocks as u64)
                .checked_mul(block)
                .ok_or(EndpointError::LIMIT_EXCEEDED)?;
            let available_bytes = (stat.f_bavail as u64)
                .checked_mul(block)
                .ok_or(EndpointError::LIMIT_EXCEEDED)?;
            if block == 0 || available_bytes > capacity_bytes {
                return Err(EndpointError::LIMIT_EXCEEDED);
            }
            self.revalidate()?;
            Ok(StorageCapacity {
                available_bytes,
                capacity_bytes,
            })
        }
    }

    pub fn get_disjoint_scope_evidence(
        endpoints: &[&LocalEndpoint],
    ) -> Result<Vec<ScopeEvidence>, EndpointError> {
        if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS {
            return Err(EndpointError::LIMIT_EXCEEDED);
        }
        let mut descriptor_count = 0usize;
        for endpoint in endpoints {
            descriptor_count = descriptor_count
                .checked_add(endpoint.directories.len())
                .ok_or(EndpointError::LIMIT_EXCEEDED)?;
            if descriptor_count > 1024 {
                return Err(EndpointError::LIMIT_EXCEEDED);
            }
            endpoint.revalidate()?;
        }
        for (index, left) in endpoints.iter().enumerate() {
            for right in &endpoints[index + 1..] {
                if left.identities.contains(&right.identity())
                    || right.identities.contains(&left.identity())
                {
                    return Err(EndpointError::OVERLAP);
                }
            }
        }
        #[cfg(target_os = "linux")]
        let (mount_snapshot, origins, kernel_paths) = {
            let snapshot = read_mountinfo()?;
            let mounts = parse_mountinfo(&snapshot)?;
            let paths: Vec<Vec<u8>> = endpoints
                .iter()
                .map(|endpoint| get_kernel_path(endpoint))
                .collect::<Result<_, _>>()?;
            let origins: Vec<Vec<Vec<u8>>> = endpoints
                .iter()
                .map(|endpoint| get_origin(endpoint, &mounts))
                .collect::<Result<_, _>>()?;
            for (endpoint, path) in endpoints.iter().zip(&paths) {
                if get_kernel_path(endpoint)? != *path {
                    return Err(EndpointError::IDENTITY_CHANGED);
                }
            }
            (snapshot, origins, paths)
        };
        for (index, left) in endpoints.iter().enumerate() {
            for (offset, right) in endpoints[index + 1..].iter().enumerate() {
                #[cfg(target_os = "linux")]
                {
                    if left.identity().device == right.identity().device {
                        let a = &origins[index];
                        let b = &origins[index + 1 + offset];
                        if a.starts_with(b) || b.starts_with(a) {
                            return Err(EndpointError::OVERLAP);
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = offset;
                    if left.mount_id.is_none() || left.mount_id != right.mount_id {
                        return Err(EndpointError::AMBIGUOUS_SCOPE);
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        if read_mountinfo()? != mount_snapshot {
            return Err(EndpointError::IDENTITY_CHANGED);
        }
        #[cfg(target_os = "linux")]
        for (endpoint, path) in endpoints.iter().zip(&kernel_paths) {
            if get_kernel_path(endpoint)? != *path {
                return Err(EndpointError::IDENTITY_CHANGED);
            }
        }
        let scopes = endpoints
            .iter()
            .map(|endpoint| {
                let identity = endpoint.identity();
                ScopeEvidence {
                    domain: format!("local:{}:{}", identity.device, identity.inode),
                    components: Vec::new(),
                }
            })
            .collect();
        for endpoint in endpoints {
            endpoint.revalidate()?;
        }
        Ok(scopes)
    }
    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        use super::{decode_mount_path, get_mount_origin, parse_mountinfo};
        use crate::local_endpoint::EndpointError;

        #[test]
        fn origin_uses_kernel_fd_path_not_cached_spelling() {
            use std::os::unix::fs::MetadataExt;
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("actual_name");
            std::fs::create_dir(&path).unwrap();
            let metadata = std::fs::metadata(&path).unwrap();
            let mut endpoint = super::LocalEndpoint::resolve(
                &path,
                super::FileIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            )
            .unwrap();
            let mounts = super::parse_mountinfo(&super::read_mountinfo().unwrap()).unwrap();
            let before = match super::get_origin(&endpoint, &mounts) {
                Ok(origin) => origin,
                Err(super::EndpointError::AMBIGUOUS_SCOPE) => return,
                Err(error) => panic!("unexpected origin error: {error}"),
            };
            *endpoint.names.last_mut().unwrap() =
                std::ffi::CString::new("different_spelling").unwrap();
            assert_eq!(super::get_origin(&endpoint, &mounts).unwrap(), before);
        }

        #[test]
        fn mount_parser_decodes_kernel_escapes_and_rejects_bad_input() {
            assert_eq!(
                decode_mount_path(br"/space\040name/back\134slash").unwrap(),
                vec![b"space name".to_vec(), b"back\\slash".to_vec()]
            );
            assert!(decode_mount_path(br"/bad\777").is_err());
            assert!(parse_mountinfo(b"bad input\n").is_err());
            assert!(matches!(
                parse_mountinfo(&vec![b'x'; 512 * 1024 + 1]),
                Err(EndpointError::LIMIT_EXCEEDED)
            ));
        }

        #[test]
        fn mount_origins_expose_hidden_bind_ancestor_and_missing_ids() {
            let table = b"1 1 8:48 / / rw - ext4 /dev/root rw\n2 1 8:48 /source/deep /alias rw - ext4 /dev/root rw\n";
            let mounts = parse_mountinfo(table).unwrap();
            let device = libc::makedev(8, 48);
            let source = get_mount_origin(1, device, &[b"source".to_vec()], &mounts).unwrap();
            let alias = get_mount_origin(2, device, &[b"alias".to_vec()], &mounts).unwrap();
            assert!(alias.starts_with(&source));
            assert!(get_mount_origin(3, device, &[b"alias".to_vec()], &mounts).is_err());
            assert!(
                get_mount_origin(2, libc::makedev(8, 49), &[b"alias".to_vec()], &mounts).is_err()
            );
        }

        #[test]
        fn refuses_nested_mount_under_owned_root() {
            let table = b"1 1 8:48 / / rw - ext4 /dev/root rw\n2 1 8:48 /foreign /source/nested rw - ext4 /dev/root rw\n";
            let mounts = parse_mountinfo(table).unwrap();
            assert!(
                get_mount_origin(1, libc::makedev(8, 48), &[b"source".to_vec()], &mounts).is_err()
            );
        }
    }
}

#[cfg(unix)]
pub use unix::{LocalEndpoint, get_disjoint_scope_evidence};
#[cfg(target_os = "linux")]
pub use unix::{
    PhysicalScopeObservation, compare_physical_scope_observations, get_physical_scope_observation,
    validate_physical_scope_observation,
};

#[cfg(not(unix))]
pub struct LocalEndpoint;

#[cfg(not(unix))]
impl LocalEndpoint {
    pub fn resolve(
        _path: &std::path::Path,
        _expected: FileIdentity,
    ) -> Result<Self, EndpointError> {
        Err(EndpointError::UNSUPPORTED_PLATFORM)
    }
    pub fn capacity(&self) -> Result<StorageCapacity, EndpointError> {
        Err(EndpointError::UNSUPPORTED_PLATFORM)
    }
    pub fn revalidate(&self) -> Result<(), EndpointError> {
        Err(EndpointError::UNSUPPORTED_PLATFORM)
    }
}

#[cfg(not(unix))]
pub fn get_disjoint_scope_evidence(
    _endpoints: &[&LocalEndpoint],
) -> Result<Vec<crate::planner::ScopeEvidence>, EndpointError> {
    Err(EndpointError::UNSUPPORTED_PLATFORM)
}
