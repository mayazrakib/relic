use std::fmt;

use crate::manifest_artifact;
use crate::resources::ResourceError;
use crate::state::StateError;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ArtifactStoreError {
    INVALID,
    WRONG_STORAGE,
    WRONG_KEY_REFERENCE,
    BUSY,
    CAPACITY,
    RECONCILIATION_REQUIRED,
    OUTCOME_UNKNOWN,
    UNSUPPORTED,
    RESOURCE(ResourceError),
    STATE(StateError),
    MANIFEST(manifest_artifact::ArtifactError),
    IO(std::io::Error),
}

impl fmt::Display for ArtifactStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid artifact operation",
            Self::WRONG_STORAGE => "artifact storage identity changed",
            Self::WRONG_KEY_REFERENCE => "artifact key reference changed",
            Self::BUSY => "artifact has a live owner",
            Self::CAPACITY => "artifact capacity unavailable",
            Self::RECONCILIATION_REQUIRED => "artifact requires reconciliation",
            Self::OUTCOME_UNKNOWN => "artifact storage outcome requires reconciliation",
            Self::UNSUPPORTED => "artifact storage is unavailable on this platform",
            Self::RESOURCE(_) => "artifact resource guard stopped the operation",
            Self::STATE(_) => "artifact journal rejected the operation",
            Self::MANIFEST(_) => "artifact authentication or manifest validation failed",
            Self::IO(_) => "artifact storage I/O failed",
        })
    }
}

impl std::error::Error for ArtifactStoreError {}

impl From<std::io::Error> for ArtifactStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<StateError> for ArtifactStoreError {
    fn from(error: StateError) -> Self {
        Self::STATE(error)
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::{ArtifactStoreError, manifest_artifact};
    use crate::encrypted_spool::SpoolLimits;
    use crate::local_endpoint::LocalEndpoint;
    use crate::manifest_artifact::ManifestArtifact;
    use crate::resources::StageGuard;
    use crate::state::{ManifestArtifactBinding, ManifestArtifactRecord, StateStore};

    const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

    #[derive(PartialEq, Eq)]
    struct FileStamp {
        device: u64,
        inode: u64,
        length_bytes: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
        links: u64,
        mode: u32,
        owner: u32,
    }

    struct CiphertextReader<'a> {
        file: &'a mut File,
        guard: &'a StageGuard,
        hasher: Sha256,
        read_bytes: u64,
        limit_bytes: u64,
    }

    impl Read for CiphertextReader<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.guard.check().map_err(std::io::Error::other)?;
            let count = self.file.read(bytes)?;
            let total = self
                .read_bytes
                .checked_add(count as u64)
                .ok_or_else(|| std::io::Error::other("artifact length overflow"))?;

            if total > self.limit_bytes {
                return Err(std::io::Error::other("artifact length changed"));
            }

            self.hasher.update(&bytes[..count]);
            self.read_bytes = total;

            Ok(count)
        }
    }

    pub struct ArtifactStore {
        endpoint: LocalEndpoint,
        endpoint_id: String,
        identity: String,
    }

    pub struct ArtifactStage<'a> {
        store: &'a ArtifactStore,
        binding: ManifestArtifactBinding,
        file: File,
        _lock: File,
        limits: SpoolLimits,
        guard: StageGuard,
        written_bytes: u64,
        is_failed: bool,
    }

    fn is_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }

    fn check_limits(limits: SpoolLimits) -> Result<(), ArtifactStoreError> {
        if limits.plaintext_bytes == 0
            || limits.plaintext_bytes > MAX_ARTIFACT_BYTES
            || limits.ciphertext_bytes < 60
            || limits.ciphertext_bytes > MAX_ARTIFACT_BYTES
        {
            return Err(ArtifactStoreError::CAPACITY);
        }

        Ok(())
    }

    fn check_file(file: &File) -> Result<(), ArtifactStoreError> {
        let metadata = file.metadata()?;
        // geteuid reads only the current process identity and has no pointer arguments.
        let owner = unsafe { libc::geteuid() };

        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() == 0
            || metadata.nlink() > 2
        {
            return Err(ArtifactStoreError::INVALID);
        }

        Ok(())
    }

    fn get_stamp(file: &File) -> Result<FileStamp, ArtifactStoreError> {
        let metadata = file.metadata()?;

        Ok(FileStamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            length_bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            owner: metadata.uid(),
        })
    }

    impl ArtifactStore {
        pub fn new(endpoint: LocalEndpoint, endpoint_id: &str) -> Result<Self, ArtifactStoreError> {
            if !is_id(endpoint_id) {
                return Err(ArtifactStoreError::INVALID);
            }

            endpoint
                .revalidate()
                .map_err(|_| ArtifactStoreError::WRONG_STORAGE)?;
            let metadata = endpoint.directory().metadata()?;
            // geteuid reads only the process identity and takes no arguments.
            let owner = unsafe { libc::geteuid() };

            if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
                return Err(ArtifactStoreError::INVALID);
            }

            let identity = format!("unix:{}:{}", metadata.dev(), metadata.ino());

            Ok(Self {
                endpoint,
                endpoint_id: endpoint_id.to_owned(),
                identity,
            })
        }

        pub fn storage_identity(&self) -> &str {
            &self.identity
        }

        fn check_binding(
            &self,
            binding: &ManifestArtifactBinding,
        ) -> Result<(), ArtifactStoreError> {
            if !is_id(&binding.artifact_id)
                || binding.capture_id.is_empty()
                || binding.capture_id.len() > 128
                || binding.relative_name != format!("artifact_{}.sealed", binding.artifact_id)
            {
                return Err(ArtifactStoreError::INVALID);
            }

            self.endpoint
                .revalidate()
                .map_err(|_| ArtifactStoreError::WRONG_STORAGE)?;

            if binding.storage_endpoint_id != self.endpoint_id
                || binding.storage_identity != self.identity
            {
                return Err(ArtifactStoreError::WRONG_STORAGE);
            }

            Ok(())
        }

        fn open_file(&self, name: &str, flags: libc::c_int) -> Result<File, ArtifactStoreError> {
            let name = CString::new(name).map_err(|_| ArtifactStoreError::INVALID)?;
            // Both the directory descriptor and the validated generated component remain live.
            let descriptor = unsafe {
                libc::openat(
                    self.endpoint.directory().as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    0o600,
                )
            };

            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            // A successful openat returns a fresh descriptor, transferred exactly once to File.
            let file = unsafe { File::from_raw_fd(descriptor) };
            check_file(&file)?;

            Ok(file)
        }

        fn acquire_lock(&self, id: &str, guard: &StageGuard) -> Result<File, ArtifactStoreError> {
            guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            let digest = Sha256::digest(id.as_bytes());
            let name = format!(
                ".capture_{}.lock",
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let file = self.open_file(&name, libc::O_RDWR | libc::O_CREAT)?;

            if file.metadata()?.nlink() != 1 {
                return Err(ArtifactStoreError::INVALID);
            }

            match file.try_lock() {
                Ok(()) => Ok(file),
                Err(fs::TryLockError::WouldBlock) => Err(ArtifactStoreError::BUSY),
                Err(fs::TryLockError::Error(error)) => Err(error.into()),
            }
        }

        fn is_present(&self, name: &str) -> Result<bool, ArtifactStoreError> {
            let name = CString::new(name).map_err(|_| ArtifactStoreError::INVALID)?;
            let mut output = std::mem::MaybeUninit::<libc::stat>::uninit();
            // fstatat writes only into this live stat buffer and does not follow the final link.
            let result = unsafe {
                libc::fstatat(
                    self.endpoint.directory().as_raw_fd(),
                    name.as_ptr(),
                    output.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };

            if result == 0 {
                return Ok(true);
            }

            let error = std::io::Error::last_os_error();

            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }

            Err(error.into())
        }

        pub fn begin<'a>(
            &'a self,
            state: &mut StateStore,
            binding: &ManifestArtifactBinding,
            limits: SpoolLimits,
            guard: &StageGuard,
        ) -> Result<ArtifactStage<'a>, ArtifactStoreError> {
            check_limits(limits)?;
            self.check_binding(binding)?;
            state
                .get_capture(&binding.capture_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let lock = self.acquire_lock(&binding.capture_id, guard)?;
            let capacity = self
                .endpoint
                .capacity()
                .map_err(|_| ArtifactStoreError::WRONG_STORAGE)?;
            let reserve = MIN_FREE_BYTES.max(capacity.capacity_bytes.div_ceil(20));

            if limits
                .ciphertext_bytes
                .checked_add(reserve)
                .is_none_or(|bytes| bytes > capacity.available_bytes)
            {
                return Err(ArtifactStoreError::CAPACITY);
            }

            let record = state.prepare_manifest_artifact(binding)?;
            let pending = format!(".artifact_{}.pending", binding.artifact_id);

            if record.effect_state != "prepared"
                || self.is_present(&pending)?
                || self.is_present(&binding.relative_name)?
            {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            let file = self.open_file(&pending, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?;

            Ok(ArtifactStage {
                store: self,
                binding: binding.clone(),
                file,
                _lock: lock,
                limits,
                guard: guard.clone(),
                written_bytes: 0,
                is_failed: false,
            })
        }

        fn verify_file(
            &self,
            state: &StateStore,
            record: &ManifestArtifactRecord,
            file: &mut File,
            key: &Zeroizing<[u8; 32]>,
            limits: SpoolLimits,
            guard: &StageGuard,
        ) -> Result<(String, u64, ManifestArtifact), ArtifactStoreError> {
            check_file(file)?;
            let before = get_stamp(file)?;
            let length = before.length_bytes;

            if length < 60 || length > limits.ciphertext_bytes {
                return Err(ArtifactStoreError::CAPACITY);
            }

            let capture = state
                .get_capture(&record.binding.capture_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            file.seek(SeekFrom::Start(0))?;
            let (manifest, read_bytes, hash) = {
                let mut reader = CiphertextReader {
                    file,
                    guard,
                    hasher: Sha256::new(),
                    read_bytes: 0,
                    limit_bytes: length,
                };
                let manifest = manifest_artifact::inspect_sealed_manifest(
                    &mut reader,
                    &capture.binding,
                    key,
                    limits,
                    guard,
                )
                .map_err(ArtifactStoreError::MANIFEST)?;

                (manifest, reader.read_bytes, reader.hasher)
            };

            if read_bytes != length || get_stamp(file)? != before {
                return Err(ArtifactStoreError::INVALID);
            }

            let digest = format!(
                "sha256:{}",
                hash.finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );

            if capture
                .manifest_digest
                .as_deref()
                .is_some_and(|value| value != manifest.digest)
                || capture
                    .manifest_entry_count
                    .as_deref()
                    .is_some_and(|value| value != manifest.entry_count.to_string())
                || capture
                    .manifest_artifact_id
                    .as_deref()
                    .is_some_and(|value| value != record.binding.artifact_id)
            {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            if record.effect_state == "sealed"
                && (record.ciphertext_digest.as_deref() != Some(digest.as_str())
                    || record.ciphertext_bytes.as_deref() != Some(length.to_string().as_str())
                    || record.manifest_digest.as_deref() != Some(manifest.digest.as_str())
                    || record.manifest_entry_count.as_deref()
                        != Some(manifest.entry_count.to_string().as_str()))
            {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            Ok((digest, length, manifest))
        }

        fn publish_file(
            &self,
            binding: &ManifestArtifactBinding,
            file: &File,
        ) -> Result<(), ArtifactStoreError> {
            let staged = self.open_file(
                &format!(".artifact_{}.pending", binding.artifact_id),
                libc::O_RDONLY,
            )?;
            let expected = file.metadata()?;
            let observed = staged.metadata()?;

            if expected.dev() != observed.dev() || expected.ino() != observed.ino() {
                return Err(ArtifactStoreError::OUTCOME_UNKNOWN);
            }

            let pending = CString::new(format!(".artifact_{}.pending", binding.artifact_id))
                .map_err(|_| ArtifactStoreError::INVALID)?;
            let final_name = CString::new(binding.relative_name.as_str())
                .map_err(|_| ArtifactStoreError::INVALID)?;
            // Generated single components and the pinned directory descriptor stay valid throughout linkat.
            let result = unsafe {
                libc::linkat(
                    self.endpoint.directory().as_raw_fd(),
                    pending.as_ptr(),
                    self.endpoint.directory().as_raw_fd(),
                    final_name.as_ptr(),
                    0,
                )
            };

            if result != 0 {
                let error = std::io::Error::last_os_error();

                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(ArtifactStoreError::OUTCOME_UNKNOWN);
                }
            }

            let final_file = self.open_file(&binding.relative_name, libc::O_RDONLY)?;
            let expected = file.metadata()?;
            let actual = final_file.metadata()?;

            if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
                return Err(ArtifactStoreError::OUTCOME_UNKNOWN);
            }

            // unlinkat removes only the known staging component; it never follows a link.
            if unsafe { libc::unlinkat(self.endpoint.directory().as_raw_fd(), pending.as_ptr(), 0) }
                != 0
            {
                return Err(ArtifactStoreError::OUTCOME_UNKNOWN);
            }

            self.endpoint
                .directory()
                .sync_all()
                .map_err(|_| ArtifactStoreError::OUTCOME_UNKNOWN)?;
            self.check_binding(binding)
                .map_err(|_| ArtifactStoreError::OUTCOME_UNKNOWN)
        }

        pub fn commit(
            &self,
            mut stage: ArtifactStage<'_>,
            state: &mut StateStore,
            key_ref: &str,
            key: &Zeroizing<[u8; 32]>,
            expected: &ManifestArtifact,
        ) -> Result<ManifestArtifactRecord, ArtifactStoreError> {
            if !std::ptr::eq(stage.store, self) || stage.is_failed {
                return Err(ArtifactStoreError::INVALID);
            }

            self.check_binding(&stage.binding)?;

            if key_ref != stage.binding.key_ref {
                return Err(ArtifactStoreError::WRONG_KEY_REFERENCE);
            }

            stage.guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            stage.file.sync_all()?;
            let record = state
                .get_manifest_artifact(&stage.binding.artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let (cipher_digest, length, actual) = self.verify_file(
                state,
                &record,
                &mut stage.file,
                key,
                stage.limits,
                &stage.guard,
            )?;

            if actual != *expected
                || record.binding != stage.binding
                || record.effect_state != "prepared"
            {
                return Err(ArtifactStoreError::INVALID);
            }

            stage.guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            self.publish_file(&stage.binding, &stage.file)?;
            state
                .seal_manifest_artifact(
                    &stage.binding.artifact_id,
                    &cipher_digest,
                    length,
                    &actual.digest,
                    actual.entry_count,
                )
                .map_err(|_| ArtifactStoreError::OUTCOME_UNKNOWN)
        }

        pub fn reconcile(
            &self,
            state: &mut StateStore,
            artifact_id: &str,
            key_ref: &str,
            key: &Zeroizing<[u8; 32]>,
            limits: SpoolLimits,
            guard: &StageGuard,
        ) -> Result<ManifestArtifactRecord, ArtifactStoreError> {
            check_limits(limits)?;
            let record = state
                .get_manifest_artifact(artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            self.check_binding(&record.binding)?;

            if key_ref != record.binding.key_ref {
                return Err(ArtifactStoreError::WRONG_KEY_REFERENCE);
            }

            let _lock = self.acquire_lock(&record.binding.capture_id, guard)?;

            if record.effect_state == "abandoned" {
                return Ok(record);
            }

            let pending = format!(".artifact_{artifact_id}.pending");
            let has_final = self.is_present(&record.binding.relative_name)?;
            let has_pending = self.is_present(&pending)?;

            if !has_final && !has_pending {
                if record.effect_state != "prepared" {
                    return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
                }

                return Ok(state.abandon_manifest_artifact(artifact_id)?);
            }

            let name = if has_final {
                &record.binding.relative_name
            } else {
                &pending
            };
            let mut file = self.open_file(name, libc::O_RDONLY)?;
            let (cipher_digest, length, manifest) =
                self.verify_file(state, &record, &mut file, key, limits, guard)?;
            file.sync_all()?;
            guard.check().map_err(ArtifactStoreError::RESOURCE)?;

            if has_pending {
                self.publish_file(&record.binding, &file)?;
            } else {
                self.endpoint.directory().sync_all()?;
                self.check_binding(&record.binding)?;
            }

            state
                .seal_manifest_artifact(
                    artifact_id,
                    &cipher_digest,
                    length,
                    &manifest.digest,
                    manifest.entry_count,
                )
                .map_err(|_| ArtifactStoreError::OUTCOME_UNKNOWN)
        }
    }

    impl Write for ArtifactStage<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.is_failed {
                return Err(std::io::Error::other("artifact stage failed"));
            }

            let result = (|| {
                self.guard.check().map_err(std::io::Error::other)?;
                let maximum = self
                    .written_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| std::io::Error::other("artifact quota exceeded"))?;

                if maximum > self.limits.ciphertext_bytes {
                    return Err(std::io::Error::other("artifact quota exceeded"));
                }

                let count = self.file.write(bytes)?;
                self.written_bytes += count as u64;

                Ok(count)
            })();

            if result.is_err() {
                self.is_failed = true;
            }

            result
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.is_failed {
                return Err(std::io::Error::other("artifact stage failed"));
            }

            let result = self
                .guard
                .check()
                .map_err(std::io::Error::other)
                .and_then(|()| self.file.flush());

            if result.is_err() {
                self.is_failed = true;
            }

            result
        }
    }
}

#[cfg(unix)]
pub use unix::{ArtifactStage, ArtifactStore};

#[cfg(not(unix))]
pub struct ArtifactStore;

#[cfg(not(unix))]
impl ArtifactStore {
    pub fn new(
        _endpoint: crate::local_endpoint::LocalEndpoint,
        _endpoint_id: &str,
    ) -> Result<Self, ArtifactStoreError> {
        Err(ArtifactStoreError::UNSUPPORTED)
    }
}
