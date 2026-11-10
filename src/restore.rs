#[cfg(not(unix))]
use std::fs::File;
#[cfg(not(unix))]
use std::io::Read;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum RestoreError {
    INVALID_NAME,
    UNSUPPORTED,
    BUDGET_EXCEEDED,
    CANCELLED,
    SIZE_MISMATCH,
    DIGEST_MISMATCH,
    DEPTH_EXCEEDED,
    IO(std::io::Error),
    CLEANUP_FAILED(std::io::Error),
    OUTCOME_UNKNOWN(std::io::Error),
}

pub struct RestoreName(Vec<u8>);

impl RestoreName {
    pub fn new(bytes: &[u8]) -> Result<Self, RestoreError> {
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&0)
            || bytes.contains(&b'/')
        {
            return Err(RestoreError::INVALID_NAME);
        }

        Ok(Self(bytes.to_vec()))
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    use sha2::{Digest, Sha256};

    use super::{RestoreError, RestoreName};

    const BUFFER_BYTES: usize = 64 * 1024;
    const MAX_DIRECTORY_DEPTH: usize = 32;

    pub fn open_restore_directory(
        root: &File,
        components: &[RestoreName],
        is_create: bool,
        is_cancelled: impl Fn() -> bool,
    ) -> Result<File, RestoreError> {
        if components.len() > MAX_DIRECTORY_DEPTH {
            return Err(RestoreError::DEPTH_EXCEEDED);
        }

        if is_cancelled() {
            return Err(RestoreError::CANCELLED);
        }

        let root_metadata = root.metadata().map_err(RestoreError::IO)?;

        if !root_metadata.is_dir() {
            return Err(RestoreError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "root handle is not a directory",
            )));
        }

        let mut directory = root.try_clone().map_err(RestoreError::IO)?;

        for component in components {
            if is_cancelled() {
                return Err(RestoreError::CANCELLED);
            }

            let name =
                CString::new(component.0.as_slice()).map_err(|_| RestoreError::INVALID_NAME)?;
            let open_component = || {
                // The parent descriptor and validated single component remain live for this call.
                unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                }
            };
            let mut descriptor = open_component();
            let mut is_created = false;

            if descriptor < 0 {
                let error = std::io::Error::last_os_error();

                if !is_create || error.kind() != std::io::ErrorKind::NotFound {
                    return Err(RestoreError::IO(error));
                }

                // The parent descriptor and validated name are live; an existing entry is never replaced.
                let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };

                if result != 0 {
                    return Err(RestoreError::IO(std::io::Error::last_os_error()));
                }

                is_created = true;
                descriptor = open_component();

                if descriptor < 0 {
                    return Err(RestoreError::IO(std::io::Error::last_os_error()));
                }
            }

            // A successful openat returns a new descriptor transferred once to File.
            let child = unsafe { File::from_raw_fd(descriptor) };
            let metadata = child.metadata().map_err(RestoreError::IO)?;

            if metadata.dev() != root_metadata.dev() {
                return Err(RestoreError::UNSUPPORTED);
            }

            if is_created {
                // geteuid has no pointer arguments and reads only the process identity.
                let owner = unsafe { libc::geteuid() };

                if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
                    return Err(RestoreError::IO(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "created directory is not private",
                    )));
                }

                directory.sync_all().map_err(RestoreError::IO)?;
            }

            directory = child;
        }

        Ok(directory)
    }

    struct Staging<'a> {
        parent: &'a File,
        directory: File,
        name: CString,
        is_file_present: bool,
        is_directory_present: bool,
    }

    impl Staging<'_> {
        fn remove(&mut self) -> Result<(), std::io::Error> {
            if self.is_file_present {
                // The pinned staging handle and the static component stay valid throughout the call.
                let result =
                    unsafe { libc::unlinkat(self.directory.as_raw_fd(), c"content".as_ptr(), 0) };

                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                self.is_file_present = false;
            }

            if self.is_directory_present {
                let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
                // The output buffer is valid for fstatat, and AT_SYMLINK_NOFOLLOW inspects the entry itself.
                let result = unsafe {
                    libc::fstatat(
                        self.parent.as_raw_fd(),
                        self.name.as_ptr(),
                        observed.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };

                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Successful fstatat initialized the stat structure.
                let observed = unsafe { observed.assume_init() };
                let pinned = self.directory.metadata()?;

                // POSIX dev_t is signed on macOS and unsigned on Linux.
                #[allow(clippy::unnecessary_cast)]
                let observed_device = observed.st_dev as u64;

                if observed_device != pinned.dev() || observed.st_ino != pinned.ino() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "staging directory identity changed",
                    ));
                }

                // The parent handle and staging name remain valid; AT_REMOVEDIR never follows a link.
                let result = unsafe {
                    libc::unlinkat(
                        self.parent.as_raw_fd(),
                        self.name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };

                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                self.is_directory_present = false;
            }

            Ok(())
        }
    }

    impl Drop for Staging<'_> {
        fn drop(&mut self) {
            let _ = self.remove();
        }
    }

    pub fn restore_file<R: Read>(
        directory: &File,
        name: &RestoreName,
        source: &mut R,
        expected_bytes: u64,
        expected_digest: [u8; 32],
        max_spool_bytes: u64,
        is_cancelled: impl Fn() -> bool,
    ) -> Result<(), RestoreError> {
        if expected_bytes > max_spool_bytes {
            return Err(RestoreError::BUDGET_EXCEEDED);
        }

        if is_cancelled() {
            return Err(RestoreError::CANCELLED);
        }

        if !directory.metadata().map_err(RestoreError::IO)?.is_dir() {
            return Err(RestoreError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination handle is not a directory",
            )));
        }

        let final_name = CString::new(name.0.as_slice()).map_err(|_| RestoreError::INVALID_NAME)?;
        let staging_name = CString::new(format!(".relic-{}.tmp", uuid::Uuid::now_v7()))
            .map_err(|_| RestoreError::INVALID_NAME)?;
        // The directory handle and NUL-terminated single component remain valid during mkdirat.
        let result = unsafe { libc::mkdirat(directory.as_raw_fd(), staging_name.as_ptr(), 0o700) };

        if result != 0 {
            return Err(RestoreError::IO(std::io::Error::last_os_error()));
        }

        // Open the new directory without following a replacement symlink.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                staging_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };

        if descriptor < 0 {
            let error = std::io::Error::last_os_error();

            return Err(RestoreError::CLEANUP_FAILED(error));
        }

        // openat returned a new owned descriptor, transferred exactly once to File.
        let staging_directory = unsafe { File::from_raw_fd(descriptor) };
        let mut staging = Staging {
            parent: directory,
            directory: staging_directory,
            name: staging_name,
            is_file_present: false,
            is_directory_present: true,
        };
        let metadata = staging.directory.metadata().map_err(RestoreError::IO)?;
        // geteuid has no pointer arguments and reads only the current process identity.
        let owner = unsafe { libc::geteuid() };

        if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            staging.remove().map_err(RestoreError::CLEANUP_FAILED)?;
            return Err(RestoreError::IO(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "staging directory is not private",
            )));
        }

        // The staging directory is pinned. O_EXCL prevents following an existing name.
        let descriptor = unsafe {
            libc::openat(
                staging.directory.as_raw_fd(),
                c"content".as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };

        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            staging.remove().map_err(RestoreError::CLEANUP_FAILED)?;
            return Err(RestoreError::IO(error));
        }

        // openat returned a new owned descriptor, transferred exactly once to File.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        staging.is_file_present = true;
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut total_bytes = 0_u64;
            let mut buffer = [0_u8; BUFFER_BYTES];

            loop {
                if is_cancelled() {
                    return Err(RestoreError::CANCELLED);
                }

                let count = source.read(&mut buffer).map_err(RestoreError::IO)?;

                if count == 0 {
                    break;
                }

                total_bytes = total_bytes
                    .checked_add(count as u64)
                    .ok_or(RestoreError::BUDGET_EXCEEDED)?;

                if total_bytes > max_spool_bytes {
                    return Err(RestoreError::BUDGET_EXCEEDED);
                }

                if total_bytes > expected_bytes {
                    return Err(RestoreError::SIZE_MISMATCH);
                }

                file.write_all(&buffer[..count]).map_err(RestoreError::IO)?;
                hasher.update(&buffer[..count]);
            }

            if total_bytes != expected_bytes {
                return Err(RestoreError::SIZE_MISMATCH);
            }

            if hasher.finalize().as_slice() != expected_digest {
                return Err(RestoreError::DIGEST_MISMATCH);
            }

            if is_cancelled() {
                return Err(RestoreError::CANCELLED);
            }

            file.sync_all().map_err(RestoreError::IO)?;

            if is_cancelled() {
                return Err(RestoreError::CANCELLED);
            }

            // Both names are single components relative to live pinned directory descriptors.
            let result = unsafe {
                libc::linkat(
                    staging.directory.as_raw_fd(),
                    c"content".as_ptr(),
                    directory.as_raw_fd(),
                    final_name.as_ptr(),
                    0,
                )
            };

            if result != 0 {
                return Err(RestoreError::IO(std::io::Error::last_os_error()));
            }

            staging.remove().map_err(RestoreError::OUTCOME_UNKNOWN)?;
            directory
                .sync_all()
                .map_err(RestoreError::OUTCOME_UNKNOWN)?;
            Ok(())
        })();

        match result {
            Ok(()) => Ok(()),
            Err(error @ RestoreError::OUTCOME_UNKNOWN(_)) => Err(error),
            Err(error) => {
                staging.remove().map_err(RestoreError::CLEANUP_FAILED)?;
                Err(error)
            }
        }
    }
}

#[cfg(unix)]
pub use unix::{open_restore_directory, restore_file};

#[cfg(not(unix))]
pub fn open_restore_directory(
    _root: &File,
    _components: &[RestoreName],
    _is_create: bool,
    _is_cancelled: impl Fn() -> bool,
) -> Result<File, RestoreError> {
    Err(RestoreError::UNSUPPORTED)
}

#[cfg(not(unix))]
pub fn restore_file<R: Read>(
    _directory: &File,
    _name: &RestoreName,
    _source: &mut R,
    _expected_bytes: u64,
    _expected_digest: [u8; 32],
    _max_spool_bytes: u64,
    _is_cancelled: impl Fn() -> bool,
) -> Result<(), RestoreError> {
    Err(RestoreError::UNSUPPORTED)
}
