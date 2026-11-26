use std::fmt;

#[derive(Clone, Copy)]
pub struct RestoreLimits {
    pub max_entries: u64,
    pub max_payload_bytes: u64,
    pub max_depth: usize,
    pub max_open_files: usize,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RestoreStoreError {
    INVALID,
    BUSY,
    CONFLICT,
    CHANGED,
    CAPACITY,
    RECONCILIATION_REQUIRED,
    OUTCOME_UNKNOWN,
    UNSUPPORTED,
    RESOURCE,
    STATE(crate::state::StateError),
    ARTIFACT(crate::artifact_store::ArtifactStoreError),
    IO(std::io::Error),
}

impl fmt::Display for RestoreStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid restore operation",
            Self::BUSY => "restore has a live owner",
            Self::CONFLICT => "restore destination already exists or conflicts",
            Self::CHANGED => "restore storage or tree identity changed",
            Self::CAPACITY => "restore capacity unavailable",
            Self::RECONCILIATION_REQUIRED => "restore requires reconciliation",
            Self::OUTCOME_UNKNOWN => "restore publication requires reconciliation",
            Self::UNSUPPORTED => "restore storage is unavailable on this platform",
            Self::RESOURCE => "restore resource guard stopped the operation",
            Self::STATE(_) => "restore journal rejected the operation",
            Self::ARTIFACT(_) => "restore payload verification failed",
            Self::IO(_) => "restore storage I/O failed",
        })
    }
}

impl std::error::Error for RestoreStoreError {}

impl From<std::io::Error> for RestoreStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<crate::state::StateError> for RestoreStoreError {
    fn from(error: crate::state::StateError) -> Self {
        Self::STATE(error)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::ffi::{CStr, CString};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use zeroize::Zeroizing;

    use super::{RestoreLimits, RestoreStoreError};
    use crate::artifact_store::{ArtifactStore, PayloadVerification};
    use crate::local_endpoint::LocalEndpoint;
    use crate::manifest::ManifestEntry;
    use crate::payload_capture::{PayloadError, PayloadFile, PayloadVisitor};
    use crate::resources::StageGuard;
    use crate::restore::{RestoreName, open_restore_directory};
    use crate::source_scan::{
        Directory, get_entry_stat, get_stat, matches_stat, open_at, open_file_for_reading,
    };
    use crate::state::{RestoreBinding, RestoreRecord, StateStore};

    const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
    const BUFFER_BYTES: usize = 64 * 1024;

    pub struct RestoreStore {
        endpoint: LocalEndpoint,
        endpoint_id: String,
        identity: String,
    }

    pub struct RestoreStage<'a> {
        store: &'a RestoreStore,
        binding: RestoreBinding,
        container: File,
        tree: File,
        _lock: File,
        limits: RestoreLimits,
        guard: StageGuard,
        is_verified: bool,
        is_failed: bool,
    }

    struct ActiveFile {
        file: File,
        parent: File,
        initial: libc::stat,
        expected_bytes: u64,
        processed_bytes: u64,
    }

    struct TreeVisitor<'a> {
        root: &'a File,
        limits: RestoreLimits,
        guard: &'a StageGuard,
        active: Option<ActiveFile>,
        is_compare: bool,
        buffer: Zeroizing<[u8; BUFFER_BYTES]>,
    }

    #[derive(Default, PartialEq, Eq)]
    struct Census {
        entries: u64,
        files: u64,
        bytes: u64,
    }

    fn is_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }

    fn get_identity(file: &File) -> Result<String, RestoreStoreError> {
        let metadata = file.metadata()?;

        Ok(format!("unix:{}:{}", metadata.dev(), metadata.ino()))
    }

    fn check_private(file: &File, is_directory: bool) -> Result<(), RestoreStoreError> {
        let metadata = file.metadata()?;
        // geteuid has no memory arguments and reads the process identity.
        let owner = unsafe { libc::geteuid() };
        let expected_mode = if is_directory { 0o700 } else { 0o600 };

        if metadata.uid() != owner
            || metadata.mode() & 0o7777 != expected_mode
            || metadata.is_dir() != is_directory
            || (!is_directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(RestoreStoreError::CHANGED);
        }

        Ok(())
    }

    fn open_file(
        parent: &File,
        name: &CStr,
        flags: libc::c_int,
    ) -> Result<File, RestoreStoreError> {
        // The live parent descriptor and validated component remain valid through openat.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };

        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // A successful openat transfers one new descriptor to this File.
        let file = unsafe { File::from_raw_fd(descriptor) };
        check_private(&file, false)?;

        Ok(file)
    }

    fn open_directory(parent: &File, name: &CStr) -> Result<File, RestoreStoreError> {
        let file =
            open_at(parent.as_raw_fd(), name, true).map_err(|_| RestoreStoreError::CHANGED)?;
        check_private(&file, true)?;

        if file.metadata()?.dev() != parent.metadata()?.dev() {
            return Err(RestoreStoreError::CHANGED);
        }

        Ok(file)
    }

    fn create_directory(parent: &File, name: &CStr) -> Result<File, RestoreStoreError> {
        // mkdirat operates on a validated component relative to the pinned parent.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let file = open_directory(parent, name)?;
        file.sync_all()?;
        parent.sync_all()?;

        Ok(file)
    }

    fn is_present(parent: &File, name: &CStr) -> Result<bool, RestoreStoreError> {
        match get_entry_stat(parent.as_raw_fd(), name) {
            Ok(_) => Ok(true),
            Err(crate::source_scan::ScanError::IO(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(_) => Err(RestoreStoreError::CHANGED),
        }
    }

    fn get_pending_name(id: &str) -> Result<CString, RestoreStoreError> {
        CString::new(format!(".restore_{id}.pending")).map_err(|_| RestoreStoreError::INVALID)
    }

    fn check_limits(limits: RestoreLimits) -> Result<(), RestoreStoreError> {
        if limits.max_entries == 0
            || limits.max_payload_bytes == 0
            || limits.max_depth > 128
            || limits.max_open_files < limits.max_depth.saturating_add(8)
        {
            return Err(RestoreStoreError::CAPACITY);
        }

        Ok(())
    }

    fn get_expected(
        record: &RestoreRecord,
        limits: RestoreLimits,
    ) -> Result<Census, RestoreStoreError> {
        let expected = Census {
            entries: record
                .manifest_entry_count
                .parse()
                .map_err(|_| RestoreStoreError::INVALID)?,
            files: record
                .file_count
                .parse()
                .map_err(|_| RestoreStoreError::INVALID)?,
            bytes: record
                .payload_bytes
                .parse()
                .map_err(|_| RestoreStoreError::INVALID)?,
        };

        if expected.entries == 0
            || expected.entries > limits.max_entries
            || expected.bytes > limits.max_payload_bytes
        {
            return Err(RestoreStoreError::CAPACITY);
        }

        Ok(expected)
    }

    fn get_path(
        source_id: &str,
        path: &[String],
        limits: RestoreLimits,
    ) -> Result<Vec<RestoreName>, PayloadError> {
        if source_id.is_empty()
            || source_id.len() > 128
            || !source_id.as_bytes()[0].is_ascii_alphanumeric()
            || !source_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
            || path.len() > limits.max_depth
        {
            return Err(PayloadError::INVALID);
        }

        let mut components = Vec::with_capacity(path.len() + 1);
        components.push(RestoreName::new(source_id.as_bytes()).map_err(|_| PayloadError::INVALID)?);

        for component in path {
            let bytes = URL_SAFE_NO_PAD
                .decode(component)
                .map_err(|_| PayloadError::INVALID)?;
            components.push(RestoreName::new(&bytes).map_err(|_| PayloadError::INVALID)?);
        }

        Ok(components)
    }

    impl PayloadVisitor for TreeVisitor<'_> {
        fn begin_file(&mut self, header: &PayloadFile) -> Result<(), PayloadError> {
            self.guard.check().map_err(|_| PayloadError::RESOURCE)?;

            if self.active.is_some() || header.path.is_empty() {
                return Err(PayloadError::INVALID);
            }

            let components = get_path(&header.source_id, &header.path, self.limits)?;
            let parent = open_restore_directory(
                self.root,
                &components[..components.len() - 1],
                !self.is_compare,
                || self.guard.check().is_err(),
            )
            .map_err(|_| PayloadError::SINK)?;
            let name = CString::new(
                URL_SAFE_NO_PAD
                    .decode(header.path.last().ok_or(PayloadError::INVALID)?)
                    .map_err(|_| PayloadError::INVALID)?,
            )
            .map_err(|_| PayloadError::INVALID)?;
            let file = if self.is_compare {
                let pinned =
                    open_at(parent.as_raw_fd(), &name, false).map_err(|_| PayloadError::SINK)?;
                open_file_for_reading(pinned).map_err(|_| PayloadError::SINK)?
            } else {
                open_file(
                    &parent,
                    &name,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                )
                .map_err(|_| PayloadError::SINK)?
            };
            check_private(&file, false).map_err(|_| PayloadError::SINK)?;
            let initial = get_stat(file.as_raw_fd()).map_err(|_| PayloadError::SINK)?;
            let expected_bytes = header
                .size_bytes
                .parse()
                .map_err(|_| PayloadError::INVALID)?;

            if self.is_compare && file.metadata()?.len() != expected_bytes {
                return Err(PayloadError::INVALID);
            }

            self.active = Some(ActiveFile {
                file,
                parent,
                initial,
                expected_bytes,
                processed_bytes: 0,
            });

            Ok(())
        }

        fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
            self.guard.check().map_err(|_| PayloadError::RESOURCE)?;
            let active = self.active.as_mut().ok_or(PayloadError::INVALID)?;
            let total = active
                .processed_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(PayloadError::LIMIT)?;

            if bytes.len() > BUFFER_BYTES || total > active.expected_bytes {
                return Err(PayloadError::LIMIT);
            }

            if self.is_compare {
                active.file.read_exact(&mut self.buffer[..bytes.len()])?;

                if bytes != &self.buffer[..bytes.len()] {
                    return Err(PayloadError::INVALID);
                }
            } else {
                active.file.write_all(bytes)?;
            }

            active.processed_bytes = total;

            Ok(())
        }

        fn finish_entry(&mut self, entry: &ManifestEntry) -> Result<(), PayloadError> {
            self.guard.check().map_err(|_| PayloadError::RESOURCE)?;

            if entry.kind == "directory" {
                if self.active.is_some() {
                    return Err(PayloadError::INVALID);
                }

                let components = get_path(&entry.source_id, &entry.path, self.limits)?;
                let directory =
                    open_restore_directory(self.root, &components, !self.is_compare, || {
                        self.guard.check().is_err()
                    })
                    .map_err(|_| PayloadError::SINK)?;
                check_private(&directory, true).map_err(|_| PayloadError::SINK)?;
                directory.sync_all()?;
            } else {
                let mut active = self.active.take().ok_or(PayloadError::INVALID)?;

                if active.processed_bytes != active.expected_bytes {
                    return Err(PayloadError::INVALID);
                }

                if self.is_compare {
                    let mut trailing = [0];

                    if active.file.read(&mut trailing)? != 0
                        || !matches_stat(
                            &active.initial,
                            &get_stat(active.file.as_raw_fd()).map_err(|_| PayloadError::SINK)?,
                        )
                    {
                        return Err(PayloadError::INVALID);
                    }
                } else {
                    active.file.sync_all()?;
                    active.parent.sync_all()?;
                }
            }

            Ok(())
        }
    }

    fn count_tree(
        file: File,
        depth: usize,
        limits: RestoreLimits,
        guard: &StageGuard,
        total: &mut Census,
    ) -> Result<(), RestoreStoreError> {
        guard.check().map_err(|_| RestoreStoreError::RESOURCE)?;
        let before = get_stat(file.as_raw_fd()).map_err(|_| RestoreStoreError::CHANGED)?;
        let mut directory = Directory::open(file).map_err(|_| RestoreStoreError::CHANGED)?;

        while let Some(name) = directory.next().map_err(|_| RestoreStoreError::CHANGED)? {
            guard.check().map_err(|_| RestoreStoreError::RESOURCE)?;

            if name == b"." || name == b".." {
                continue;
            }

            total.entries = total
                .entries
                .checked_add(1)
                .ok_or(RestoreStoreError::CAPACITY)?;

            if total.entries > limits.max_entries || depth > limits.max_depth + 1 {
                return Err(RestoreStoreError::CAPACITY);
            }

            let name = CString::new(name).map_err(|_| RestoreStoreError::CHANGED)?;
            let stat =
                get_entry_stat(directory.fd(), &name).map_err(|_| RestoreStoreError::CHANGED)?;

            if stat.st_dev != before.st_dev {
                return Err(RestoreStoreError::CHANGED);
            }

            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                let child =
                    open_at(directory.fd(), &name, true).map_err(|_| RestoreStoreError::CHANGED)?;
                check_private(&child, true)?;
                count_tree(child, depth + 1, limits, guard, total)?;
            } else if stat.st_mode & libc::S_IFMT == libc::S_IFREG && depth > 0 {
                // geteuid takes no arguments and reads only the current identity.
                let owner = unsafe { libc::geteuid() };

                if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o600 || stat.st_nlink != 1 {
                    return Err(RestoreStoreError::CHANGED);
                }

                total.files = total
                    .files
                    .checked_add(1)
                    .ok_or(RestoreStoreError::CAPACITY)?;
                total.bytes = total
                    .bytes
                    .checked_add(
                        u64::try_from(stat.st_size).map_err(|_| RestoreStoreError::CHANGED)?,
                    )
                    .ok_or(RestoreStoreError::CAPACITY)?;

                if total.bytes > limits.max_payload_bytes {
                    return Err(RestoreStoreError::CAPACITY);
                }
            } else {
                return Err(RestoreStoreError::CHANGED);
            }
        }

        let after = get_stat(directory.fd()).map_err(|_| RestoreStoreError::CHANGED)?;

        if !matches_stat(&before, &after) {
            return Err(RestoreStoreError::CHANGED);
        }

        Ok(())
    }

    impl RestoreStore {
        pub fn new(endpoint: LocalEndpoint, endpoint_id: &str) -> Result<Self, RestoreStoreError> {
            if !crate::state::valid_identifier_text(endpoint_id) {
                return Err(RestoreStoreError::INVALID);
            }

            endpoint
                .revalidate()
                .map_err(|_| RestoreStoreError::CHANGED)?;
            check_private(endpoint.directory(), true)?;
            let identity = get_identity(endpoint.directory())?;

            Ok(Self {
                endpoint,
                endpoint_id: endpoint_id.to_owned(),
                identity,
            })
        }

        pub fn get_storage_identity(&self) -> &str {
            &self.identity
        }

        fn check_physical_root(
            &self,
            state: &StateStore,
            binding: &RestoreBinding,
            guard: &StageGuard,
        ) -> Result<(), RestoreStoreError> {
            #[cfg(target_os = "linux")]
            crate::physical_registry::check_registered_roots(
                state,
                &[crate::physical_registry::PhysicalRootClaim {
                    kind: crate::physical_registry::PhysicalRootKind::RESTORE,
                    owner_id: &binding.target_endpoint_id,
                    endpoint: &self.endpoint,
                }],
                guard,
            )
            .map_err(|_| RestoreStoreError::RECONCILIATION_REQUIRED)?;
            #[cfg(not(target_os = "linux"))]
            let _ = (state, binding, guard);
            Ok(())
        }

        fn check_binding(&self, binding: &RestoreBinding) -> Result<(), RestoreStoreError> {
            self.endpoint
                .revalidate()
                .map_err(|_| RestoreStoreError::CHANGED)?;
            check_private(self.endpoint.directory(), true)?;

            if !is_id(&binding.restore_id)
                || binding.target_endpoint_id != self.endpoint_id
                || binding.target_identity != self.identity
                || binding.relative_name.len() > 255
                || binding.relative_name.starts_with(".restore_")
                || binding.relative_name.contains('\\')
                || RestoreName::new(binding.relative_name.as_bytes()).is_err()
            {
                return Err(RestoreStoreError::CHANGED);
            }

            Ok(())
        }

        fn acquire_lock(&self, id: &str, guard: &StageGuard) -> Result<File, RestoreStoreError> {
            guard.check().map_err(|_| RestoreStoreError::RESOURCE)?;
            let name = CString::new(format!(".restore_{id}.lock"))
                .map_err(|_| RestoreStoreError::INVALID)?;
            let file = open_file(
                self.endpoint.directory(),
                &name,
                libc::O_RDWR | libc::O_CREAT,
            )?;

            match file.try_lock() {
                Ok(()) => Ok(file),
                Err(fs::TryLockError::WouldBlock) => Err(RestoreStoreError::BUSY),
                Err(fs::TryLockError::Error(error)) => Err(error.into()),
            }
        }

        fn check_stage(&self, stage: &RestoreStage<'_>) -> Result<(), RestoreStoreError> {
            if !std::ptr::eq(stage.store, self) || stage.is_failed {
                return Err(RestoreStoreError::INVALID);
            }

            self.check_binding(&stage.binding)?;
            stage
                .guard
                .check()
                .map_err(|_| RestoreStoreError::RESOURCE)?;
            let pending = get_pending_name(&stage.binding.restore_id)?;
            let container = open_directory(self.endpoint.directory(), &pending)?;
            let tree = open_directory(&container, c"tree")?;

            if get_identity(&container)? != get_identity(&stage.container)?
                || get_identity(&tree)? != get_identity(&stage.tree)?
            {
                return Err(RestoreStoreError::CHANGED);
            }

            Ok(())
        }

        pub fn begin<'a>(
            &'a self,
            state: &mut StateStore,
            binding: &RestoreBinding,
            limits: RestoreLimits,
            guard: &StageGuard,
        ) -> Result<RestoreStage<'a>, RestoreStoreError> {
            check_limits(limits)?;
            self.check_binding(binding)?;
            #[cfg(target_os = "linux")]
            crate::physical_registry::register_roots(
                state,
                &[crate::physical_registry::PhysicalRootClaim {
                    kind: crate::physical_registry::PhysicalRootKind::RESTORE,
                    owner_id: &binding.target_endpoint_id,
                    endpoint: &self.endpoint,
                }],
                guard,
            )
            .map_err(|_| RestoreStoreError::RECONCILIATION_REQUIRED)?;
            let record = state.prepare_restore(binding)?;
            let lock = self.acquire_lock(&binding.restore_id, guard)?;
            let expected = get_expected(&record, limits)?;
            let pending = get_pending_name(&binding.restore_id)?;
            let final_name = CString::new(binding.relative_name.as_bytes())
                .map_err(|_| RestoreStoreError::INVALID)?;

            if record.effect_state != "prepared" || is_present(self.endpoint.directory(), &pending)?
            {
                return Err(RestoreStoreError::RECONCILIATION_REQUIRED);
            }

            if is_present(self.endpoint.directory(), &final_name)? {
                return Err(RestoreStoreError::CONFLICT);
            }

            let capacity = self
                .endpoint
                .capacity()
                .map_err(|_| RestoreStoreError::CHANGED)?;
            let required = expected
                .entries
                .checked_mul(4096)
                .and_then(|bytes| bytes.checked_add(expected.bytes))
                .and_then(|bytes| {
                    bytes.checked_add(MIN_FREE_BYTES.max(capacity.capacity_bytes.div_ceil(20)))
                })
                .ok_or(RestoreStoreError::CAPACITY)?;

            if required > capacity.available_bytes {
                return Err(RestoreStoreError::CAPACITY);
            }

            self.check_binding(binding)?;
            guard.check().map_err(|_| RestoreStoreError::RESOURCE)?;
            let container = create_directory(self.endpoint.directory(), &pending)?;
            let tree = create_directory(&container, c"tree")?;
            state.mark_restore_staging(&binding.restore_id, &get_identity(&tree)?)?;

            Ok(RestoreStage {
                store: self,
                binding: binding.clone(),
                container,
                tree,
                _lock: lock,
                limits,
                guard: guard.clone(),
                is_verified: false,
                is_failed: false,
            })
        }

        #[allow(clippy::too_many_arguments)]
        fn verify_tree(
            &self,
            tree: &File,
            record: &RestoreRecord,
            state: &StateStore,
            artifacts: &ArtifactStore,
            verification: &mut PayloadVerification<'_>,
            limits: RestoreLimits,
            guard: &StageGuard,
            is_compare: bool,
        ) -> Result<(), RestoreStoreError> {
            let expected = get_expected(record, limits)?;
            let payload = state
                .get_payload_artifact(&record.binding.payload_artifact_id)?
                .ok_or(RestoreStoreError::INVALID)?;

            if payload.binding.capture_id != record.binding.capture_id
                || payload.manifest_digest.as_deref() != Some(record.manifest_digest.as_str())
                || payload.ciphertext_digest.as_deref()
                    != Some(record.payload_ciphertext_digest.as_str())
            {
                return Err(RestoreStoreError::CHANGED);
            }

            let mut visitor = TreeVisitor {
                root: tree,
                limits,
                guard,
                active: None,
                is_compare,
                buffer: Zeroizing::new([0; BUFFER_BYTES]),
            };
            artifacts
                .visit_sealed_payload(
                    state,
                    &record.binding.payload_artifact_id,
                    verification,
                    guard,
                    &mut visitor,
                )
                .map_err(RestoreStoreError::ARTIFACT)?;

            if visitor.active.is_some() {
                return Err(RestoreStoreError::CHANGED);
            }

            let mut actual = Census::default();
            count_tree(open_directory(tree, c".")?, 0, limits, guard, &mut actual)?;

            if actual != expected {
                return Err(RestoreStoreError::CHANGED);
            }

            tree.sync_all()?;
            self.check_binding(&record.binding)?;
            guard.check().map_err(|_| RestoreStoreError::RESOURCE)?;

            Ok(())
        }

        pub fn build(
            &self,
            stage: &mut RestoreStage<'_>,
            state: &mut StateStore,
            artifacts: &ArtifactStore,
            verification: &mut PayloadVerification<'_>,
        ) -> Result<RestoreRecord, RestoreStoreError> {
            let result = (|| {
                if !std::ptr::eq(stage.store, self) || stage.is_failed || stage.is_verified {
                    return Err(RestoreStoreError::INVALID);
                }

                self.check_stage(stage)?;
                self.check_physical_root(state, &stage.binding, &stage.guard)?;
                let record = state
                    .get_restore(&stage.binding.restore_id)?
                    .ok_or(RestoreStoreError::INVALID)?;

                if record.effect_state != "staging"
                    || record.staging_identity.as_deref()
                        != Some(get_identity(&stage.tree)?.as_str())
                {
                    return Err(RestoreStoreError::RECONCILIATION_REQUIRED);
                }

                self.verify_tree(
                    &stage.tree,
                    &record,
                    state,
                    artifacts,
                    verification,
                    stage.limits,
                    &stage.guard,
                    false,
                )?;
                self.check_stage(stage)?;
                stage.container.sync_all()?;
                let record = state.mark_restore_verified(&stage.binding.restore_id)?;
                stage.is_verified = true;

                Ok(record)
            })();
            stage.is_failed |= result.is_err();

            result
        }

        pub fn publish(
            &self,
            stage: RestoreStage<'_>,
            state: &mut StateStore,
            artifacts: &ArtifactStore,
            verification: &mut PayloadVerification<'_>,
        ) -> Result<RestoreRecord, RestoreStoreError> {
            if !std::ptr::eq(stage.store, self) || stage.is_failed || !stage.is_verified {
                return Err(RestoreStoreError::INVALID);
            }

            self.check_stage(&stage)?;
            self.check_physical_root(state, &stage.binding, &stage.guard)?;
            let record = state
                .get_restore(&stage.binding.restore_id)?
                .ok_or(RestoreStoreError::INVALID)?;
            self.verify_tree(
                &stage.tree,
                &record,
                state,
                artifacts,
                verification,
                stage.limits,
                &stage.guard,
                true,
            )?;

            self.publish_verified(stage, state)
        }

        fn publish_verified(
            &self,
            stage: RestoreStage<'_>,
            state: &mut StateStore,
        ) -> Result<RestoreRecord, RestoreStoreError> {
            if !std::ptr::eq(stage.store, self) || stage.is_failed || !stage.is_verified {
                return Err(RestoreStoreError::INVALID);
            }

            self.check_stage(&stage)?;
            stage
                .guard
                .check()
                .map_err(|_| RestoreStoreError::RESOURCE)?;
            let record = state
                .get_restore(&stage.binding.restore_id)?
                .ok_or(RestoreStoreError::INVALID)?;
            let identity = get_identity(&stage.tree)?;

            if record.effect_state != "verified"
                || record.staging_identity.as_deref() != Some(identity.as_str())
            {
                return Err(RestoreStoreError::RECONCILIATION_REQUIRED);
            }

            let current = open_directory(&stage.container, c"tree")?;

            if get_identity(&current)? != identity {
                return Err(RestoreStoreError::CHANGED);
            }

            let final_name = CString::new(stage.binding.relative_name.as_bytes())
                .map_err(|_| RestoreStoreError::INVALID)?;
            // Both pinned directories and validated components remain live. The
            // exclusive rename primitive never replaces an existing destination.
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::renameat2(
                    stage.container.as_raw_fd(),
                    c"tree".as_ptr(),
                    self.endpoint.directory().as_raw_fd(),
                    final_name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            #[cfg(target_os = "macos")]
            let result = unsafe {
                libc::renameatx_np(
                    stage.container.as_raw_fd(),
                    c"tree".as_ptr(),
                    self.endpoint.directory().as_raw_fd(),
                    final_name.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };

            if result != 0 {
                let error = std::io::Error::last_os_error();

                return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                    RestoreStoreError::CONFLICT
                } else {
                    RestoreStoreError::OUTCOME_UNKNOWN
                });
            }

            stage
                .container
                .sync_all()
                .map_err(|_| RestoreStoreError::OUTCOME_UNKNOWN)?;
            self.endpoint
                .directory()
                .sync_all()
                .map_err(|_| RestoreStoreError::OUTCOME_UNKNOWN)?;
            self.check_binding(&stage.binding)
                .map_err(|_| RestoreStoreError::OUTCOME_UNKNOWN)?;
            state
                .mark_restore_published(&stage.binding.restore_id, &identity)
                .map_err(|_| RestoreStoreError::OUTCOME_UNKNOWN)
        }

        pub fn reconcile(
            &self,
            state: &mut StateStore,
            restore_id: &str,
            artifacts: &ArtifactStore,
            verification: &mut PayloadVerification<'_>,
            limits: RestoreLimits,
            guard: &StageGuard,
        ) -> Result<RestoreRecord, RestoreStoreError> {
            check_limits(limits)?;
            let record = state
                .get_restore(restore_id)?
                .ok_or(RestoreStoreError::INVALID)?;
            self.check_binding(&record.binding)?;
            self.check_physical_root(state, &record.binding, guard)?;
            let lock = self.acquire_lock(restore_id, guard)?;
            let record = state
                .get_restore(restore_id)?
                .ok_or(RestoreStoreError::INVALID)?;

            if record.effect_state == "abandoned" {
                return Ok(record);
            }

            let pending = get_pending_name(restore_id)?;
            let final_name = CString::new(record.binding.relative_name.as_bytes())
                .map_err(|_| RestoreStoreError::INVALID)?;
            let has_container = is_present(self.endpoint.directory(), &pending)?;
            let has_final = is_present(self.endpoint.directory(), &final_name)?;

            if record.effect_state == "prepared" {
                if !has_container && !has_final {
                    return Ok(state.abandon_restore(restore_id)?);
                }

                return Err(RestoreStoreError::RECONCILIATION_REQUIRED);
            }

            let identity = record
                .staging_identity
                .as_deref()
                .ok_or(RestoreStoreError::RECONCILIATION_REQUIRED)?;

            if has_final {
                let final_tree = open_directory(self.endpoint.directory(), &final_name)?;

                if get_identity(&final_tree)? != identity
                    || !matches!(record.effect_state.as_str(), "verified" | "published")
                {
                    return Err(RestoreStoreError::CONFLICT);
                }

                if has_container {
                    let container = open_directory(self.endpoint.directory(), &pending)?;

                    if is_present(&container, c"tree")? {
                        return Err(RestoreStoreError::CONFLICT);
                    }

                    container.sync_all()?;
                }

                self.verify_tree(
                    &final_tree,
                    &record,
                    state,
                    artifacts,
                    verification,
                    limits,
                    guard,
                    true,
                )?;
                self.endpoint.directory().sync_all()?;

                return Ok(state.mark_restore_published(restore_id, identity)?);
            }

            if !has_container || record.effect_state == "published" {
                return Err(RestoreStoreError::RECONCILIATION_REQUIRED);
            }

            let container = open_directory(self.endpoint.directory(), &pending)?;
            let tree = open_directory(&container, c"tree")?;

            if get_identity(&tree)? != identity {
                return Err(RestoreStoreError::CHANGED);
            }

            self.verify_tree(
                &tree,
                &record,
                state,
                artifacts,
                verification,
                limits,
                guard,
                true,
            )?;
            state.mark_restore_verified(restore_id)?;
            let stage = RestoreStage {
                store: self,
                binding: record.binding,
                container,
                tree,
                _lock: lock,
                limits,
                guard: guard.clone(),
                is_verified: true,
                is_failed: false,
            };

            self.publish_verified(stage, state)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::{RestoreStage, RestoreStore};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct RestoreStore;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl RestoreStore {
    pub fn new(
        _endpoint: crate::local_endpoint::LocalEndpoint,
        _endpoint_id: &str,
    ) -> Result<Self, RestoreStoreError> {
        Err(RestoreStoreError::UNSUPPORTED)
    }
}
