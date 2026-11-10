use std::fmt;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::path::Path;

use crate::manifest_spool::{ManifestSpool, SpoolError};
use crate::resources::{ResourceError, StageGuard};

#[derive(Clone, Copy, Debug)]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_open_files: usize,
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ScanError {
    INVALID_LIMITS,
    LIMIT_EXCEEDED,
    UNSUPPORTED_ENTRY,
    CHANGED,
    MOUNT_BOUNDARY,
    IO(std::io::Error),
    SPOOL(SpoolError),
    RESOURCE(ResourceError),
    UNSUPPORTED_PLATFORM,
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID_LIMITS => "invalid scanner limits",
            Self::LIMIT_EXCEEDED => "scanner limit exceeded",
            Self::UNSUPPORTED_ENTRY => "unsupported source entry",
            Self::CHANGED => "source changed during scan",
            Self::MOUNT_BOUNDARY => "source mount traversal is disabled",
            Self::IO(_) => "source I/O failed",
            Self::SPOOL(_) => "manifest spool failed",
            Self::RESOURCE(_) => "source scan canceled or resource limit reached",
            Self::UNSUPPORTED_PLATFORM => "source scanner is unavailable on this platform",
        })
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(error: std::io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<SpoolError> for ScanError {
    fn from(error: SpoolError) -> Self {
        Self::SPOOL(error)
    }
}

impl From<ResourceError> for ScanError {
    fn from(error: ResourceError) -> Self {
        Self::RESOURCE(error)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{self, Read};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    use super::{ManifestSpool, ScanError, ScanLimits, StageGuard};
    use crate::manifest::ManifestEntry;

    struct Directory(*mut libc::DIR);

    impl Directory {
        fn open(file: File) -> Result<Self, ScanError> {
            let fd = file.into_raw_fd();
            // SAFETY: fd is owned and valid; fdopendir takes ownership only on success.
            let directory = unsafe { libc::fdopendir(fd) };
            if directory.is_null() {
                // SAFETY: fd remains owned here when fdopendir fails.
                unsafe {
                    libc::close(fd);
                }
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self(directory))
        }

        fn fd(&self) -> RawFd {
            // SAFETY: the directory stream remains open for self's lifetime.
            unsafe { libc::dirfd(self.0) }
        }

        fn next(&mut self) -> Result<Option<Vec<u8>>, ScanError> {
            // SAFETY: errno points to this thread's errno storage.
            unsafe {
                *errno_pointer() = 0;
            }
            // SAFETY: self owns a live directory stream and access is exclusive.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(error.into())
                };
            }
            // SAFETY: readdir returns a live entry with a NUL-terminated name until the next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_bytes()
                .to_vec();
            Ok(Some(name))
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this object uniquely owns a live directory stream.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn errno_pointer() -> *mut libc::c_int {
        // SAFETY: libc returns thread-local errno storage.
        unsafe { libc::__errno_location() }
    }

    #[cfg(target_os = "macos")]
    unsafe fn errno_pointer() -> *mut libc::c_int {
        // SAFETY: libc returns thread-local errno storage.
        unsafe { libc::__error() }
    }

    fn get_stat(fd: RawFd) -> Result<libc::stat, ScanError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable memory and fd is a live descriptor.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful fstat initialized stat.
        Ok(unsafe { stat.assume_init() })
    }

    fn get_entry_stat(fd: RawFd, name: &CStr) -> Result<libc::stat, ScanError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: name and stat are valid, and AT_SYMLINK_NOFOLLOW prevents following the entry.
        if unsafe {
            libc::fstatat(
                fd,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful fstatat initialized stat.
        Ok(unsafe { stat.assume_init() })
    }

    fn matches_stat(first: &libc::stat, second: &libc::stat) -> bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_size == second.st_size
            && first.st_mtime == second.st_mtime
            && first.st_mtime_nsec == second.st_mtime_nsec
            && first.st_ctime == second.st_ctime
            && first.st_ctime_nsec == second.st_ctime_nsec
    }

    fn open_at(fd: RawFd, name: &CStr, is_directory: bool) -> Result<File, ScanError> {
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

        #[cfg(target_os = "linux")]
        if !is_directory {
            // O_PATH pins the inode without invoking a device's open operation.
            flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        }

        if is_directory {
            flags |= libc::O_DIRECTORY;
        }
        // SAFETY: name is NUL-terminated and fd refers to the pinned parent directory.
        let opened = unsafe { libc::openat(fd, name.as_ptr(), flags) };
        if opened < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(opened) })
    }

    fn open_file_for_reading(file: File) -> Result<File, ScanError> {
        let before = get_stat(file.as_raw_fd())?;

        if before.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(ScanError::UNSUPPORTED_ENTRY);
        }

        #[cfg(target_os = "linux")]
        {
            let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .map_err(|_| ScanError::UNSUPPORTED_ENTRY)?;
            // The live O_PATH descriptor pins a verified regular inode. This kernel
            // procfs reference intentionally follows that descriptor, not a source name.
            let descriptor = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };

            if descriptor < 0 {
                return Err(io::Error::last_os_error().into());
            }

            // A successful open returned a fresh descriptor owned only by this File.
            let readable = unsafe { File::from_raw_fd(descriptor) };

            if !matches_stat(&before, &get_stat(readable.as_raw_fd())?) {
                return Err(ScanError::CHANGED);
            }

            Ok(readable)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(file)
        }
    }

    struct Scanner<'a> {
        source_id: &'a str,
        spool: &'a mut ManifestSpool,
        limits: ScanLimits,
        guard: &'a StageGuard,
        entries: u64,
        total_bytes: u64,
        root_device: libc::dev_t,
        path: Vec<String>,
    }

    impl Scanner<'_> {
        fn add_entry(
            &mut self,
            kind: &str,
            size: Option<u64>,
            digest: Option<String>,
        ) -> Result<(), ScanError> {
            self.entries = self
                .entries
                .checked_add(1)
                .ok_or(ScanError::LIMIT_EXCEEDED)?;
            if self.entries > self.limits.max_entries {
                return Err(ScanError::LIMIT_EXCEEDED);
            }
            self.spool.add_entry(&ManifestEntry {
                source_id: self.source_id.to_owned(),
                path_encoding: "unix_bytes".to_owned(),
                path: self.path.clone(),
                kind: kind.to_owned(),
                size_bytes: size.map(|value| value.to_string()),
                content_digest: digest,
                link_target_base64url: None,
                metadata: Vec::new(),
            })?;
            Ok(())
        }

        fn scan_file(&mut self, mut file: File, before: &libc::stat) -> Result<(), ScanError> {
            let size = u64::try_from(before.st_size).map_err(|_| ScanError::CHANGED)?;
            let total = self
                .total_bytes
                .checked_add(size)
                .ok_or(ScanError::LIMIT_EXCEEDED)?;
            if size > self.limits.max_file_bytes || total > self.limits.max_total_bytes {
                return Err(ScanError::LIMIT_EXCEEDED);
            }
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65_536];
            let mut read_bytes = 0u64;
            loop {
                self.guard.check()?;
                let length = file.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                read_bytes = read_bytes
                    .checked_add(length as u64)
                    .ok_or(ScanError::LIMIT_EXCEEDED)?;
                if read_bytes > size {
                    return Err(ScanError::CHANGED);
                }
                hasher.update(&buffer[..length]);
            }
            if read_bytes != size || !matches_stat(before, &get_stat(file.as_raw_fd())?) {
                return Err(ScanError::CHANGED);
            }
            self.total_bytes = total;
            let hex: String = hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            self.add_entry("file", Some(size), Some(format!("sha256:{hex}")))
        }

        fn scan_directory(
            &mut self,
            file: File,
            before: &libc::stat,
            depth: usize,
        ) -> Result<(), ScanError> {
            self.guard.check()?;
            self.add_entry("directory", None, None)?;
            let mut directory = Directory::open(file)?;
            while let Some(name) = directory.next()? {
                self.guard.check()?;
                if name == b"." || name == b".." {
                    continue;
                }
                if depth >= self.limits.max_depth || self.entries >= self.limits.max_entries {
                    return Err(ScanError::LIMIT_EXCEEDED);
                }
                let name_c =
                    CString::new(name.clone()).map_err(|_| ScanError::UNSUPPORTED_ENTRY)?;
                let initial = get_entry_stat(directory.fd(), &name_c)?;

                if initial.st_dev != self.root_device {
                    return Err(ScanError::MOUNT_BOUNDARY);
                }

                let kind = initial.st_mode & libc::S_IFMT;
                if kind != libc::S_IFREG && kind != libc::S_IFDIR {
                    return Err(ScanError::UNSUPPORTED_ENTRY);
                }
                let child = open_at(directory.fd(), &name_c, kind == libc::S_IFDIR)?;
                let opened = get_stat(child.as_raw_fd())?;
                if !matches_stat(&initial, &opened) {
                    return Err(ScanError::CHANGED);
                }
                self.path.push(URL_SAFE_NO_PAD.encode(&name));
                if kind == libc::S_IFDIR {
                    self.scan_directory(child, &opened, depth + 1)?;
                } else {
                    self.scan_file(open_file_for_reading(child)?, &opened)?;
                }
                self.path.pop();
                if !matches_stat(&opened, &get_entry_stat(directory.fd(), &name_c)?) {
                    return Err(ScanError::CHANGED);
                }
            }
            if !matches_stat(before, &get_stat(directory.fd())?) {
                return Err(ScanError::CHANGED);
            }
            Ok(())
        }
    }

    pub fn scan_source(
        root: &Path,
        source_id: &str,
        mut spool: ManifestSpool,
        limits: ScanLimits,
        guard: &StageGuard,
    ) -> Result<ManifestSpool, ScanError> {
        if limits.max_depth > 128
            || limits.max_open_files < limits.max_depth.saturating_add(3)
            || limits.max_entries == 0
            || limits.max_file_bytes == 0
            || limits.max_total_bytes == 0
        {
            return Err(ScanError::INVALID_LIMITS);
        }
        guard.check()?;
        let path =
            CString::new(root.as_os_str().as_bytes()).map_err(|_| ScanError::UNSUPPORTED_ENTRY)?;
        // SAFETY: path is NUL-terminated; flags reject a symlink as the source root.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: open returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let before = get_stat(file.as_raw_fd())?;
        let mut scanner = Scanner {
            source_id,
            spool: &mut spool,
            limits,
            guard,
            entries: 0,
            total_bytes: 0,
            root_device: before.st_dev,
            path: Vec::new(),
        };
        scanner.scan_directory(file, &before, 0)?;
        if !matches_stat(&before, &get_entry_stat(libc::AT_FDCWD, &path)?) {
            return Err(ScanError::CHANGED);
        }
        guard.check()?;
        Ok(spool)
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        use std::fs::{self, File, OpenOptions};
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{OpenOptionsExt, symlink};

        use super::{ScanError, open_at, open_file_for_reading};

        #[test]
        fn pinned_regular_file_is_not_reopened_by_mutable_source_name() {
            let temporary = tempfile::tempdir().unwrap();
            let original = temporary.path().join("content");
            fs::write(&original, b"verified content").unwrap();
            let directory = File::open(temporary.path()).unwrap();
            let pinned = open_at(directory.as_raw_fd(), c"content", false).unwrap();
            fs::rename(&original, temporary.path().join("moved")).unwrap();
            symlink("/dev/null", &original).unwrap();
            let mut readable = open_file_for_reading(pinned).unwrap();
            let mut bytes = Vec::new();
            readable.read_to_end(&mut bytes).unwrap();

            assert_eq!(bytes, b"verified content");
        }

        #[test]
        fn device_path_handle_is_rejected_before_content_open() {
            let path_handle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open("/dev/null")
                .unwrap();

            assert!(matches!(
                open_file_for_reading(path_handle),
                Err(ScanError::UNSUPPORTED_ENTRY)
            ));
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::scan_source;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn scan_source(
    _root: &Path,
    _source_id: &str,
    _spool: ManifestSpool,
    _limits: ScanLimits,
    _guard: &StageGuard,
) -> Result<ManifestSpool, ScanError> {
    Err(ScanError::UNSUPPORTED_PLATFORM)
}
