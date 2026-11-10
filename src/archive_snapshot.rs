use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use rustic_core::repofile::SnapshotFile;
use rustic_core::{Open, Repository};

use crate::local_endpoint::LocalEndpoint;
use crate::resources::StageGuard;

#[derive(Clone, Copy)]
pub struct SnapshotLimits {
    pub max_snapshots: usize,
    /// Maximum total on-disk ciphertext bytes across all snapshots.
    pub max_ciphertext_bytes: u64,
    /// Maximum total serialized metadata bytes; not an allocator or RSS bound.
    pub max_metadata_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum SnapshotError {
    INVALID,
    STORAGE,
    LIMIT,
    RESOURCE,
    ENGINE,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid native snapshot discovery request",
            Self::STORAGE => "native snapshot storage changed or cannot be enumerated",
            Self::LIMIT => "native snapshot discovery limit exceeded",
            Self::RESOURCE => "native snapshot discovery resource guard stopped the operation",
            Self::ENGINE => "native snapshot authentication or decoding failed",
        })
    }
}

impl std::error::Error for SnapshotError {}

#[derive(PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    mode: u32,
    owner: u32,
    links: u64,
}

fn get_stamp(metadata: &Metadata) -> Stamp {
    Stamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        links: metadata.nlink(),
    }
}

fn check_slot(
    parent: &File,
    name: &std::ffi::CStr,
    expected: &Metadata,
) -> Result<(), SnapshotError> {
    let mut actual = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent and the NUL-terminated component remain live; actual is writable stat storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            actual.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(SnapshotError::STORAGE);
    }
    // SAFETY: successful fstatat initialized the output.
    let actual = unsafe { actual.assume_init() };
    if actual.st_dev != expected.dev()
        || actual.st_ino != expected.ino()
        || actual.st_mode & libc::S_IFMT != expected.mode() & libc::S_IFMT
    {
        return Err(SnapshotError::STORAGE);
    }
    Ok(())
}

struct Census {
    directory: File,
    directory_stamp: Stamp,
    files: BTreeMap<String, Stamp>,
}

fn get_census(
    endpoint: &LocalEndpoint,
    limits: SnapshotLimits,
    guard: &StageGuard,
) -> Result<Census, SnapshotError> {
    guard.check().map_err(|_| SnapshotError::RESOURCE)?;
    endpoint.revalidate().map_err(|_| SnapshotError::STORAGE)?;
    if limits.max_snapshots == 0
        || limits.max_snapshots > 1024
        || limits.max_ciphertext_bytes == 0
        || limits.max_ciphertext_bytes > 16 * 1024 * 1024
        || limits.max_metadata_bytes == 0
        || limits.max_metadata_bytes > 8 * 1024 * 1024
    {
        return Err(SnapshotError::INVALID);
    }
    // SAFETY: the pinned parent and constant component are valid; no-follow rejects aliases.
    let fd = unsafe {
        libc::openat(
            endpoint.directory().as_raw_fd(),
            c"snapshots".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(SnapshotError::STORAGE);
    }
    // SAFETY: the fresh descriptor is transferred exactly once to File.
    let directory = unsafe { File::from_raw_fd(fd) };
    let metadata = directory.metadata().map_err(|_| SnapshotError::STORAGE)?;
    // SAFETY: geteuid has no arguments or retained memory.
    if metadata.dev() != endpoint.identity().device
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(SnapshotError::STORAGE);
    }
    check_slot(endpoint.directory(), c"snapshots", &metadata)?;
    let directory_stamp = get_stamp(&metadata);
    let mut files = BTreeMap::new();
    let mut total_bytes = 0u64;
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| SnapshotError::STORAGE)?
    {
        guard.check().map_err(|_| SnapshotError::RESOURCE)?;
        let entry = entry.map_err(|_| SnapshotError::STORAGE)?;
        if files.len() >= limits.max_snapshots {
            return Err(SnapshotError::LIMIT);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SnapshotError::STORAGE)?;
        if name.len() != 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SnapshotError::STORAGE);
        }
        let component =
            std::ffi::CString::new(name.as_str()).map_err(|_| SnapshotError::STORAGE)?;
        // SAFETY: O_PATH pins the entry without opening a potential device node.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(SnapshotError::STORAGE);
        }
        // SAFETY: the fresh descriptor is transferred exactly once to File.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| SnapshotError::STORAGE)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.dev() != endpoint.identity().device
            // SAFETY: geteuid has no arguments or retained memory.
            || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0
        {
            return Err(SnapshotError::STORAGE);
        }
        if metadata.len() == 0 || metadata.len() > limits.max_ciphertext_bytes {
            return Err(SnapshotError::LIMIT);
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(SnapshotError::LIMIT)?;
        if total_bytes > limits.max_ciphertext_bytes {
            return Err(SnapshotError::LIMIT);
        }
        check_slot(&directory, &component, &metadata)?;
        if files.insert(name, get_stamp(&metadata)).is_some() {
            return Err(SnapshotError::STORAGE);
        }
    }
    if get_stamp(&directory.metadata().map_err(|_| SnapshotError::STORAGE)?) != directory_stamp {
        return Err(SnapshotError::STORAGE);
    }
    check_slot(endpoint.directory(), c"snapshots", &metadata)?;
    endpoint.revalidate().map_err(|_| SnapshotError::STORAGE)?;
    Ok(Census {
        directory,
        directory_stamp,
        files,
    })
}

struct MetadataCounter<'a> {
    used: u64,
    limit: u64,
    guard: &'a StageGuard,
    failure: Option<SnapshotError>,
}

impl std::io::Write for MetadataCounter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.guard.check().is_err() {
            self.failure = Some(SnapshotError::RESOURCE);
            return Err(std::io::Error::other("snapshot guard stopped"));
        }
        let size = u64::try_from(bytes.len()).ok();
        let next = size.and_then(|size| self.used.checked_add(size));
        if next.is_none_or(|next| next > self.limit) {
            self.failure = Some(SnapshotError::LIMIT);
            return Err(std::io::Error::other("snapshot metadata limit exceeded"));
        }
        self.used = next.ok_or_else(|| std::io::Error::other("snapshot metadata overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn count_metadata<T: serde::Serialize>(
    value: &T,
    counter: &mut MetadataCounter<'_>,
) -> Result<(), SnapshotError> {
    if serde_json::to_writer(&mut *counter, value).is_err() {
        return Err(counter.failure.take().unwrap_or(SnapshotError::ENGINE));
    }
    Ok(())
}

/// Authenticate every physical snapshot by its full ID; native listings that skip errors are not used.
/// The caller owns serialization and external-writer exclusion for the repository.
pub fn get_snapshots_checked<S: Open>(
    repository: &Repository<S>,
    endpoint: &LocalEndpoint,
    limits: SnapshotLimits,
    guard: &StageGuard,
) -> Result<Vec<SnapshotFile>, SnapshotError> {
    let before = get_census(endpoint, limits, guard)?;
    let mut snapshots = Vec::with_capacity(before.files.len());
    // Counting serialized metadata bounds retained logical content, not transient
    // SDK decoding allocations or the in-memory representation's allocator overhead.
    let mut metadata = MetadataCounter {
        used: 0,
        limit: limits.max_metadata_bytes,
        guard,
        failure: None,
    };
    for id in before.files.keys() {
        guard.check().map_err(|_| SnapshotError::RESOURCE)?;
        let snapshot = repository
            .get_snapshot_from_str(id, |_| true)
            .map_err(|_| SnapshotError::ENGINE)?;
        if snapshot.id.to_hex().as_str() != id {
            return Err(SnapshotError::ENGINE);
        }
        count_metadata(&snapshot, &mut metadata)?;
        snapshots.push(snapshot);
    }
    let after = get_census(endpoint, limits, guard)?;
    if before.files != after.files
        || before.directory_stamp != after.directory_stamp
        || get_stamp(
            &before
                .directory
                .metadata()
                .map_err(|_| SnapshotError::STORAGE)?,
        ) != before.directory_stamp
    {
        return Err(SnapshotError::STORAGE);
    }
    guard.check().map_err(|_| SnapshotError::RESOURCE)?;
    Ok(snapshots)
}

#[cfg(test)]
mod tests {
    use super::{MetadataCounter, SnapshotError, SnapshotLimits, count_metadata, get_census};
    use crate::local_endpoint::{FileIdentity, LocalEndpoint};
    use crate::resources::StageGuard;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::Path;

    fn create_endpoint(path: &Path) -> LocalEndpoint {
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
    fn get_limits() -> SnapshotLimits {
        SnapshotLimits {
            max_snapshots: 2,
            max_ciphertext_bytes: 8,
            max_metadata_bytes: 1024,
        }
    }
    fn create_snapshots(path: &Path) {
        fs::create_dir(path.join("snapshots")).unwrap();
        fs::set_permissions(path.join("snapshots"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn get_name(value: char) -> String {
        value.to_string().repeat(64)
    }
    fn get_error(endpoint: &LocalEndpoint, guard: &StageGuard) -> Option<SnapshotError> {
        get_census(endpoint, get_limits(), guard).err()
    }

    #[test]
    fn accepts_only_bounded_canonical_regular_snapshots() {
        let root = tempfile::tempdir().unwrap();
        create_snapshots(root.path());
        let endpoint = create_endpoint(root.path());
        let guard = StageGuard::default();
        assert!(
            get_census(&endpoint, get_limits(), &guard)
                .unwrap()
                .files
                .is_empty()
        );
        let path = root.path().join("snapshots").join(get_name('a'));
        fs::write(&path, b"12345678").unwrap();
        assert_eq!(
            get_census(&endpoint, get_limits(), &guard)
                .unwrap()
                .files
                .len(),
            1
        );
        fs::write(&path, b"").unwrap();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::LIMIT));
        fs::write(&path, b"123456789").unwrap();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::LIMIT));
        fs::remove_file(&path).unwrap();
        fs::write(root.path().join("snapshots").join(get_name('A')), b"x").unwrap();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::STORAGE));
    }

    #[test]
    fn rejects_hardlinks_symlinks_and_special_files() {
        let root = tempfile::tempdir().unwrap();
        create_snapshots(root.path());
        let endpoint = create_endpoint(root.path());
        let guard = StageGuard::default();
        let external = root.path().join("other");
        fs::write(&external, b"x").unwrap();
        let path = root.path().join("snapshots").join(get_name('a'));
        fs::hard_link(&external, &path).unwrap();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::STORAGE));
        fs::remove_file(&path).unwrap();
        symlink(&external, &path).unwrap();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::STORAGE));
        fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live NUL-terminated string in a private temporary directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::STORAGE));
    }

    #[test]
    fn caps_snapshot_count_and_honors_cancellation() {
        let root = tempfile::tempdir().unwrap();
        create_snapshots(root.path());
        let endpoint = create_endpoint(root.path());
        for value in ['a', 'b', 'c'] {
            fs::write(root.path().join("snapshots").join(get_name(value)), b"x").unwrap();
        }
        let guard = StageGuard::default();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::LIMIT));
        guard.cancellation.cancel();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::RESOURCE));
    }

    #[test]
    fn refuses_missing_or_symlinked_snapshot_directory() {
        let root = tempfile::tempdir().unwrap();
        let endpoint = create_endpoint(root.path());
        let guard = StageGuard::default();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::STORAGE));
        let external = tempfile::tempdir().unwrap();
        symlink(external.path(), root.path().join("snapshots")).unwrap();
        assert_eq!(get_error(&endpoint, &guard), Some(SnapshotError::STORAGE));
    }
    #[test]
    fn ciphertext_budget_applies_to_all_snapshots_together() {
        let root = tempfile::tempdir().unwrap();
        create_snapshots(root.path());
        let endpoint = create_endpoint(root.path());
        for value in ['a', 'b'] {
            fs::write(
                root.path().join("snapshots").join(get_name(value)),
                b"12345",
            )
            .unwrap();
        }
        assert_eq!(
            get_error(&endpoint, &StageGuard::default()),
            Some(SnapshotError::LIMIT)
        );
    }

    #[test]
    fn metadata_counter_bounds_cumulative_serialization_and_checks_cancellation() {
        let guard = StageGuard::default();
        let snapshot = rustic_core::repofile::SnapshotFile::default();
        let size = serde_json::to_vec(&snapshot).unwrap().len() as u64;
        let mut counter = MetadataCounter {
            used: 0,
            limit: size,
            guard: &guard,
            failure: None,
        };
        count_metadata(&snapshot, &mut counter).unwrap();
        assert_eq!(counter.used, size);
        assert_eq!(
            count_metadata(&snapshot, &mut counter),
            Err(SnapshotError::LIMIT)
        );
        let mut canceled = MetadataCounter {
            used: 0,
            limit: size,
            guard: &guard,
            failure: None,
        };
        guard.cancellation.cancel();
        assert_eq!(
            count_metadata(&snapshot, &mut canceled),
            Err(SnapshotError::RESOURCE)
        );
    }
}
