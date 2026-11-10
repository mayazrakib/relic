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
    PAYLOAD(crate::payload_capture::PayloadError),
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
            Self::PAYLOAD(_) => "payload authentication or manifest verification failed",
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
    use crate::encrypted_manifest_sort::EncryptedManifestSort;
    use crate::encrypted_spool::SpoolLimits;
    use crate::local_endpoint::LocalEndpoint;
    use crate::manifest_artifact::ManifestArtifact;
    use crate::payload_capture::{
        DiscardPayload, PayloadLimits, PayloadVisitor, verify_payload_with_visitor,
    };
    use crate::resources::StageGuard;
    use crate::state::{
        ManifestArtifactBinding, ManifestArtifactRecord, PayloadArtifactBinding,
        PayloadArtifactRecord, PayloadArtifactSeal, StateStore,
    };

    const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

    #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ArtifactKind {
        MANIFEST,
        PAYLOAD,
    }

    impl ArtifactKind {
        fn get_prefix(self) -> &'static str {
            match self {
                Self::MANIFEST => "artifact",
                Self::PAYLOAD => "payload",
            }
        }

        fn get_lock_prefix(self) -> &'static str {
            match self {
                Self::MANIFEST => "capture",
                Self::PAYLOAD => "payload_capture",
            }
        }

        fn get_pending_name(self, id: &str) -> String {
            format!(".{}_{id}.pending", self.get_prefix())
        }
    }

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
        kind: ArtifactKind,
        file: File,
        _lock: File,
        limits: SpoolLimits,
        guard: StageGuard,
        written_bytes: u64,
        is_failed: bool,
    }

    pub struct PayloadStage<'a>(ArtifactStage<'a>);

    pub struct PayloadVerification<'a> {
        pub key_ref: &'a str,
        pub key: &'a Zeroizing<[u8; 32]>,
        pub limits: PayloadLimits,
        pub sorter: &'a mut EncryptedManifestSort,
    }

    fn get_payload_location(binding: &PayloadArtifactBinding) -> ManifestArtifactBinding {
        ManifestArtifactBinding {
            artifact_id: binding.artifact_id.clone(),
            capture_id: binding.capture_id.clone(),
            storage_endpoint_id: binding.storage_endpoint_id.clone(),
            storage_identity: binding.storage_identity.clone(),
            relative_name: binding.relative_name.clone(),
            key_ref: binding.key_ref.clone(),
        }
    }

    fn get_payload_binding(binding: &ManifestArtifactBinding) -> PayloadArtifactBinding {
        PayloadArtifactBinding {
            artifact_id: binding.artifact_id.clone(),
            capture_id: binding.capture_id.clone(),
            storage_endpoint_id: binding.storage_endpoint_id.clone(),
            storage_identity: binding.storage_identity.clone(),
            relative_name: binding.relative_name.clone(),
            key_ref: binding.key_ref.clone(),
        }
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
            kind: ArtifactKind,
        ) -> Result<(), ArtifactStoreError> {
            if !is_id(&binding.artifact_id)
                || binding.capture_id.is_empty()
                || binding.capture_id.len() > 128
                || binding.relative_name
                    != format!("{}_{}.sealed", kind.get_prefix(), binding.artifact_id)
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

        fn acquire_lock(
            &self,
            id: &str,
            kind: ArtifactKind,
            guard: &StageGuard,
        ) -> Result<File, ArtifactStoreError> {
            guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            let digest = Sha256::digest(id.as_bytes());
            let name = format!(
                ".{}_{}.lock",
                kind.get_lock_prefix(),
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
            self.begin_stage(state, binding, ArtifactKind::MANIFEST, limits, guard)
        }

        pub fn begin_payload<'a>(
            &'a self,
            state: &mut StateStore,
            binding: &PayloadArtifactBinding,
            limits: SpoolLimits,
            guard: &StageGuard,
        ) -> Result<PayloadStage<'a>, ArtifactStoreError> {
            self.begin_stage(
                state,
                &get_payload_location(binding),
                ArtifactKind::PAYLOAD,
                limits,
                guard,
            )
            .map(PayloadStage)
        }

        fn begin_stage<'a>(
            &'a self,
            state: &mut StateStore,
            binding: &ManifestArtifactBinding,
            kind: ArtifactKind,
            limits: SpoolLimits,
            guard: &StageGuard,
        ) -> Result<ArtifactStage<'a>, ArtifactStoreError> {
            check_limits(limits)?;
            self.check_binding(binding, kind)?;
            state
                .get_capture(&binding.capture_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let lock = self.acquire_lock(&binding.capture_id, kind, guard)?;
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

            let effect_state = match kind {
                ArtifactKind::MANIFEST => state.prepare_manifest_artifact(binding)?.effect_state,
                ArtifactKind::PAYLOAD => {
                    state
                        .prepare_payload_artifact(&get_payload_binding(binding))?
                        .effect_state
                }
            };
            let pending = kind.get_pending_name(&binding.artifact_id);

            if effect_state != "prepared"
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
                kind,
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
            let capture = state
                .get_capture(&record.binding.capture_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let (digest, length, manifest) =
                Self::inspect_file(file, limits.ciphertext_bytes, guard, |reader| {
                    manifest_artifact::inspect_sealed_manifest(
                        reader,
                        &capture.binding,
                        key,
                        limits,
                        guard,
                    )
                    .map_err(ArtifactStoreError::MANIFEST)
                })?;

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

        fn inspect_file<T>(
            file: &mut File,
            max_ciphertext_bytes: u64,
            guard: &StageGuard,
            inspect: impl FnOnce(&mut CiphertextReader<'_>) -> Result<T, ArtifactStoreError>,
        ) -> Result<(String, u64, T), ArtifactStoreError> {
            check_file(file)?;
            let before = get_stamp(file)?;
            let length = before.length_bytes;

            if length < 60 || length > max_ciphertext_bytes {
                return Err(ArtifactStoreError::CAPACITY);
            }

            file.seek(SeekFrom::Start(0))?;
            let (manifest, read_bytes, hash) = {
                let mut reader = CiphertextReader {
                    file,
                    guard,
                    hasher: Sha256::new(),
                    read_bytes: 0,
                    limit_bytes: length,
                };
                let manifest = inspect(&mut reader)?;

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

            Ok((digest, length, manifest))
        }

        fn publish_file(
            &self,
            binding: &ManifestArtifactBinding,
            file: &File,
            kind: ArtifactKind,
        ) -> Result<(), ArtifactStoreError> {
            let staged =
                self.open_file(&kind.get_pending_name(&binding.artifact_id), libc::O_RDONLY)?;
            let expected = file.metadata()?;
            let observed = staged.metadata()?;

            if expected.dev() != observed.dev() || expected.ino() != observed.ino() {
                return Err(ArtifactStoreError::OUTCOME_UNKNOWN);
            }

            let pending = CString::new(kind.get_pending_name(&binding.artifact_id))
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
            self.check_binding(binding, kind)
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
            if !std::ptr::eq(stage.store, self)
                || stage.is_failed
                || stage.kind != ArtifactKind::MANIFEST
            {
                return Err(ArtifactStoreError::INVALID);
            }

            self.check_binding(&stage.binding, ArtifactKind::MANIFEST)?;

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
            self.publish_file(&stage.binding, &stage.file, ArtifactKind::MANIFEST)?;
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

        fn verify_payload_file(
            &self,
            state: &StateStore,
            record: &PayloadArtifactRecord,
            file: &mut File,
            verification: &mut PayloadVerification<'_>,
            guard: &StageGuard,
            visitor: &mut dyn PayloadVisitor,
        ) -> Result<PayloadArtifactSeal, ArtifactStoreError> {
            check_limits(verification.limits.spool)?;
            let capture = state
                .get_capture(&record.binding.capture_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let manifest_id = capture
                .manifest_artifact_id
                .as_deref()
                .ok_or(ArtifactStoreError::RECONCILIATION_REQUIRED)?;
            let manifest_record = state
                .get_manifest_artifact(manifest_id)?
                .ok_or(ArtifactStoreError::RECONCILIATION_REQUIRED)?;

            if manifest_record.effect_state != "sealed"
                || manifest_record.binding.capture_id != record.binding.capture_id
                || manifest_record.manifest_digest != capture.manifest_digest
                || manifest_record.manifest_entry_count != capture.manifest_entry_count
                || capture
                    .payload_artifact_id
                    .as_deref()
                    .is_some_and(|id| id != record.binding.artifact_id)
            {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            let expected = ManifestArtifact {
                digest: capture
                    .manifest_digest
                    .ok_or(ArtifactStoreError::RECONCILIATION_REQUIRED)?,
                entry_count: capture
                    .manifest_entry_count
                    .as_deref()
                    .ok_or(ArtifactStoreError::RECONCILIATION_REQUIRED)?
                    .parse()
                    .map_err(|_| ArtifactStoreError::INVALID)?,
            };
            let (ciphertext_digest, ciphertext_bytes, summary) = Self::inspect_file(
                file,
                verification.limits.spool.ciphertext_bytes,
                guard,
                |reader| {
                    verify_payload_with_visitor(
                        reader,
                        &capture.binding,
                        verification.key,
                        verification.limits,
                        guard,
                        verification.sorter,
                        &expected,
                        visitor,
                    )
                    .map_err(ArtifactStoreError::PAYLOAD)
                },
            )?;
            let seal = PayloadArtifactSeal {
                ciphertext_digest,
                ciphertext_bytes,
                manifest_digest: expected.digest,
                manifest_entry_count: expected.entry_count,
                file_count: summary.file_count,
                payload_bytes: summary.payload_bytes,
            };

            if record.effect_state == "sealed"
                && (record.ciphertext_digest.as_deref() != Some(seal.ciphertext_digest.as_str())
                    || record.ciphertext_bytes.as_deref()
                        != Some(seal.ciphertext_bytes.to_string().as_str())
                    || record.manifest_digest.as_deref() != Some(seal.manifest_digest.as_str())
                    || record.manifest_entry_count.as_deref()
                        != Some(seal.manifest_entry_count.to_string().as_str())
                    || record.file_count.as_deref() != Some(seal.file_count.to_string().as_str())
                    || record.payload_bytes.as_deref()
                        != Some(seal.payload_bytes.to_string().as_str()))
            {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            Ok(seal)
        }

        pub fn commit_payload(
            &self,
            stage: PayloadStage<'_>,
            state: &mut StateStore,
            verification: &mut PayloadVerification<'_>,
        ) -> Result<PayloadArtifactRecord, ArtifactStoreError> {
            let mut stage = stage.0;

            if !std::ptr::eq(stage.store, self)
                || stage.is_failed
                || stage.kind != ArtifactKind::PAYLOAD
                || stage.limits.ciphertext_bytes != verification.limits.spool.ciphertext_bytes
                || stage.limits.plaintext_bytes != verification.limits.spool.plaintext_bytes
            {
                return Err(ArtifactStoreError::INVALID);
            }

            self.check_binding(&stage.binding, ArtifactKind::PAYLOAD)?;

            if verification.key_ref != stage.binding.key_ref {
                return Err(ArtifactStoreError::WRONG_KEY_REFERENCE);
            }

            stage.guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            let record = state
                .get_payload_artifact(&stage.binding.artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;

            if record.effect_state != "prepared"
                || get_payload_location(&record.binding) != stage.binding
            {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            stage.file.sync_all()?;
            let seal = self.verify_payload_file(
                state,
                &record,
                &mut stage.file,
                verification,
                &stage.guard,
                &mut DiscardPayload,
            )?;
            stage.guard.check().map_err(ArtifactStoreError::RESOURCE)?;
            self.publish_file(&stage.binding, &stage.file, ArtifactKind::PAYLOAD)?;
            state
                .seal_payload_artifact(&stage.binding.artifact_id, &seal)
                .map_err(|_| ArtifactStoreError::OUTCOME_UNKNOWN)
        }

        pub fn reconcile_payload(
            &self,
            state: &mut StateStore,
            artifact_id: &str,
            verification: &mut PayloadVerification<'_>,
            guard: &StageGuard,
        ) -> Result<PayloadArtifactRecord, ArtifactStoreError> {
            check_limits(verification.limits.spool)?;
            let record = state
                .get_payload_artifact(artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let location = get_payload_location(&record.binding);
            self.check_binding(&location, ArtifactKind::PAYLOAD)?;

            if verification.key_ref != record.binding.key_ref {
                return Err(ArtifactStoreError::WRONG_KEY_REFERENCE);
            }

            let _lock =
                self.acquire_lock(&record.binding.capture_id, ArtifactKind::PAYLOAD, guard)?;
            let record = state
                .get_payload_artifact(artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;

            if record.effect_state == "abandoned" {
                return Ok(record);
            }

            let pending = ArtifactKind::PAYLOAD.get_pending_name(artifact_id);
            let has_final = self.is_present(&location.relative_name)?;
            let has_pending = self.is_present(&pending)?;

            if !has_final && !has_pending {
                if record.effect_state != "prepared" {
                    return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
                }

                return Ok(state.abandon_payload_artifact(artifact_id)?);
            }

            let name = if has_final {
                &location.relative_name
            } else {
                &pending
            };
            let mut file = self.open_file(name, libc::O_RDONLY)?;
            let seal = self.verify_payload_file(
                state,
                &record,
                &mut file,
                verification,
                guard,
                &mut DiscardPayload,
            )?;
            file.sync_all()?;
            guard.check().map_err(ArtifactStoreError::RESOURCE)?;

            if has_pending {
                self.publish_file(&location, &file, ArtifactKind::PAYLOAD)?;
            } else {
                self.endpoint.directory().sync_all()?;
                self.check_binding(&location, ArtifactKind::PAYLOAD)?;
            }

            state
                .seal_payload_artifact(artifact_id, &seal)
                .map_err(|_| ArtifactStoreError::OUTCOME_UNKNOWN)
        }

        /// Consumer writes remain provisional until this method succeeds. The
        /// lease excludes storage mutation and never exposes a raw file handle.
        pub fn visit_sealed_payload(
            &self,
            state: &StateStore,
            artifact_id: &str,
            verification: &mut PayloadVerification<'_>,
            guard: &StageGuard,
            visitor: &mut dyn PayloadVisitor,
        ) -> Result<PayloadArtifactRecord, ArtifactStoreError> {
            let record = state
                .get_payload_artifact(artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;
            let location = get_payload_location(&record.binding);
            self.check_binding(&location, ArtifactKind::PAYLOAD)?;

            if verification.key_ref != record.binding.key_ref {
                return Err(ArtifactStoreError::WRONG_KEY_REFERENCE);
            }

            let _lock =
                self.acquire_lock(&record.binding.capture_id, ArtifactKind::PAYLOAD, guard)?;
            let record = state
                .get_payload_artifact(artifact_id)?
                .ok_or(ArtifactStoreError::INVALID)?;

            if record.effect_state != "sealed" {
                return Err(ArtifactStoreError::RECONCILIATION_REQUIRED);
            }

            let mut file = self.open_file(&location.relative_name, libc::O_RDONLY)?;
            self.verify_payload_file(state, &record, &mut file, verification, guard, visitor)?;
            self.check_binding(&location, ArtifactKind::PAYLOAD)?;
            guard.check().map_err(ArtifactStoreError::RESOURCE)?;

            Ok(record)
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
            self.check_binding(&record.binding, ArtifactKind::MANIFEST)?;

            if key_ref != record.binding.key_ref {
                return Err(ArtifactStoreError::WRONG_KEY_REFERENCE);
            }

            let _lock =
                self.acquire_lock(&record.binding.capture_id, ArtifactKind::MANIFEST, guard)?;

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
                self.publish_file(&record.binding, &file, ArtifactKind::MANIFEST)?;
            } else {
                self.endpoint.directory().sync_all()?;
                self.check_binding(&record.binding, ArtifactKind::MANIFEST)?;
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

    impl Write for PayloadStage<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
}

#[cfg(unix)]
pub use unix::{ArtifactStage, ArtifactStore, PayloadStage, PayloadVerification};

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
