use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        native: bool,
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
                native: matches!(fields[separator + 1], b"ext4" | b"btrfs" | b"xfs"),
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
        let file =
            File::open("/proc/self/mountinfo").map_err(|_| EndpointError::AMBIGUOUS_SCOPE)?;
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
        if !selected.native
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
    fn get_origin(
        endpoint: &LocalEndpoint,
        mounts: &[MountEntry],
    ) -> Result<Vec<Vec<u8>>, EndpointError> {
        let id = endpoint.mount_id.ok_or(EndpointError::AMBIGUOUS_SCOPE)?;
        let namespace: Vec<Vec<u8>> = endpoint
            .names
            .iter()
            .map(|name| name.as_bytes().to_vec())
            .collect();
        get_mount_origin(id, endpoint.identity().device, &namespace, mounts)
    }

    impl LocalEndpoint {
        pub fn resolve(path: &Path, expected: FileIdentity) -> Result<Self, EndpointError> {
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
            {
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
        let (mount_snapshot, origins) = {
            let snapshot = read_mountinfo()?;
            let mounts = parse_mountinfo(&snapshot)?;
            let origins: Vec<Vec<Vec<u8>>> = endpoints
                .iter()
                .map(|endpoint| get_origin(endpoint, &mounts))
                .collect::<Result<_, _>>()?;
            (snapshot, origins)
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
