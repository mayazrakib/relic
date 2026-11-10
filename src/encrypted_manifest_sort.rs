use std::fmt;
use std::io;

use crate::resources::ResourceError;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum SortError {
    UNSUPPORTED,
    INVALID,
    LIMIT,
    DUPLICATE,
    RESOURCE(ResourceError),
    IO(io::Error),
    ENCRYPTED(crate::encrypted_spool::SpoolError),
    MANIFEST(crate::manifest::ManifestError),
}

impl fmt::Display for SortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "encrypted manifest sort: {self:?}")
    }
}

impl std::error::Error for SortError {}

#[derive(Clone, Copy, Debug)]
pub struct SortLimits {
    pub max_entries: u64,
    pub max_frame_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_chunk_entries: usize,
    pub max_runs: usize,
    pub max_fan_in: usize,
    pub max_cipher_bytes: u64,
    pub max_memory_bytes: usize,
}

#[cfg(unix)]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use zeroize::{Zeroize, Zeroizing};

    use crate::encrypted_spool::{EncryptedSpoolReader, EncryptedSpoolWriter, SpoolLimits};
    use crate::manifest::{ManifestEntry, ManifestHeader, ManifestValidator};
    use crate::resources::StageGuard;

    use super::{SortError, SortLimits};

    const FRAME_MAX: usize = 256 * 1024;
    const MEMORY_MAX: usize = 8 * 1024 * 1024;
    const FAN_IN_MAX: usize = 4;
    const VALIDATION_RESERVE: usize = 1024 * 1024;
    const CHUNK_BYTES: u64 = 65536;
    const RUN_OVERHEAD: u64 = 60;
    const RUN_CHUNK_OVERHEAD: u64 = 20;

    struct Row {
        key: Zeroizing<Vec<u8>>,
        frame: Zeroizing<Vec<u8>>,
    }

    struct Run {
        name: std::ffi::CString,
        context: Vec<u8>,
        plain_bytes: u64,
        cipher_bytes: u64,
    }

    pub struct EncryptedManifestSort {
        directory: File,
        key: Zeroizing<[u8; 32]>,
        guard: StageGuard,
        limits: SortLimits,
        rows: Vec<Row>,
        row_bytes: usize,
        entry_count: u64,
        runs: Vec<Run>,
        ciphertext_bytes: u64,
        nonce: [u8; 16],
        is_failed: bool,
    }

    fn io_error() -> SortError {
        SortError::IO(std::io::Error::last_os_error())
    }

    impl EncryptedManifestSort {
        pub fn create(
            directory: &Path,
            key: &Zeroizing<[u8; 32]>,
            limits: SortLimits,
            guard: &StageGuard,
        ) -> Result<Self, SortError> {
            guard.check().map_err(SortError::RESOURCE)?;
            let merge_bytes = limits
                .max_fan_in
                .checked_mul(
                    limits
                        .max_frame_bytes
                        .checked_mul(3)
                        .ok_or(SortError::LIMIT)?
                        .checked_add(2 * 65536)
                        .ok_or(SortError::LIMIT)?,
                )
                .ok_or(SortError::LIMIT)?;
            if limits.max_entries == 0
                || limits.max_frame_bytes == 0
                || limits.max_frame_bytes > FRAME_MAX
                || limits.max_chunk_bytes == 0
                || limits.max_chunk_entries == 0
                || limits.max_runs == 0
                || limits.max_runs > limits.max_fan_in
                || limits.max_fan_in > FAN_IN_MAX
                || limits.max_memory_bytes > MEMORY_MAX
                || merge_bytes
                    .checked_add(
                        limits
                            .max_frame_bytes
                            .checked_mul(4)
                            .ok_or(SortError::LIMIT)?,
                    )
                    .and_then(|value| value.checked_add(limits.max_chunk_bytes))
                    .and_then(|value| value.checked_add(VALIDATION_RESERVE))
                    .ok_or(SortError::LIMIT)?
                    > limits.max_memory_bytes
                || limits
                    .max_chunk_bytes
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(VALIDATION_RESERVE))
                    .ok_or(SortError::LIMIT)?
                    > limits.max_memory_bytes
                || limits.max_cipher_bytes < RUN_OVERHEAD
            {
                return Err(SortError::INVALID);
            }
            let canonical = std::fs::canonicalize(directory).map_err(SortError::IO)?;
            let handle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(canonical)
                .map_err(SortError::IO)?;
            let metadata = handle.metadata().map_err(SortError::IO)?;
            // SAFETY: geteuid has no arguments or memory safety preconditions.
            let owner = unsafe { libc::geteuid() };
            if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
                return Err(SortError::INVALID);
            }
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).map_err(|_| SortError::INVALID)?;
            Ok(Self {
                directory: handle,
                key: Zeroizing::new(**key),
                guard: guard.clone(),
                limits,
                rows: Vec::new(),
                row_bytes: 0,
                entry_count: 0,
                runs: Vec::new(),
                ciphertext_bytes: 0,
                nonce,
                is_failed: false,
            })
        }

        pub fn add_entry(&mut self, entry: &ManifestEntry) -> Result<(), SortError> {
            self.guard.check().map_err(SortError::RESOURCE)?;
            if self.is_failed {
                return Err(SortError::INVALID);
            }
            if self.entry_count >= self.limits.max_entries {
                return Err(SortError::LIMIT);
            }
            let header = ManifestHeader {
                schema_version: 1,
                capture_id: "sort_validation".into(),
                entry_count: "1".into(),
            };
            let mut validator = ManifestValidator::new(&header).map_err(SortError::MANIFEST)?;
            validator.add_entry(entry).map_err(SortError::MANIFEST)?;
            validator.finish().map_err(SortError::MANIFEST)?;
            let frame = Zeroizing::new(serde_jcs::to_vec(entry).map_err(|_| SortError::INVALID)?);
            if frame.len() > self.limits.max_frame_bytes {
                return Err(SortError::LIMIT);
            }
            let key = Zeroizing::new(sort_key(entry)?);
            let row_size = frame
                .len()
                .checked_add(key.len())
                .and_then(|size| size.checked_add(std::mem::size_of::<Row>()))
                .ok_or(SortError::LIMIT)?;
            if row_size > self.limits.max_chunk_bytes {
                return Err(SortError::LIMIT);
            }
            if self.rows.len() >= self.limits.max_chunk_entries
                || self
                    .row_bytes
                    .checked_add(row_size)
                    .ok_or(SortError::LIMIT)?
                    > self.limits.max_chunk_bytes
            {
                self.flush_run()?;
            }
            self.rows.push(Row { key, frame });
            self.row_bytes += row_size;
            self.entry_count += 1;
            Ok(())
        }

        fn flush_run(&mut self) -> Result<(), SortError> {
            if self.rows.is_empty() {
                return Ok(());
            }
            if self.runs.len() >= self.limits.max_runs {
                return Err(SortError::LIMIT);
            }
            self.guard.check().map_err(SortError::RESOURCE)?;
            self.rows
                .sort_unstable_by(|left, right| left.key.cmp(&right.key));
            if self.rows.windows(2).any(|pair| pair[0].key == pair[1].key) {
                return Err(SortError::DUPLICATE);
            }
            let mut plain_bytes = 0_u64;
            for row in &self.rows {
                plain_bytes = plain_bytes
                    .checked_add(4 + row.frame.len() as u64)
                    .ok_or(SortError::LIMIT)?;
            }
            let chunks = plain_bytes.div_ceil(CHUNK_BYTES);
            let cipher_bytes = RUN_OVERHEAD
                .checked_add(plain_bytes)
                .and_then(|size| size.checked_add(chunks.checked_mul(RUN_CHUNK_OVERHEAD)?))
                .ok_or(SortError::LIMIT)?;
            if self
                .ciphertext_bytes
                .checked_add(cipher_bytes)
                .ok_or(SortError::LIMIT)?
                > self.limits.max_cipher_bytes
            {
                return Err(SortError::LIMIT);
            }
            let index = self.runs.len();
            let mut context = self.nonce.to_vec();
            context.extend_from_slice(&(index as u64).to_be_bytes());
            let name = std::ffi::CString::new(format!(
                "run_{}_{}",
                self.nonce
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                index
            ))
            .map_err(|_| SortError::INVALID)?;
            // SAFETY: the directory descriptor is live, name is NUL-terminated, and flags create one private file.
            let descriptor = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if descriptor < 0 {
                return Err(io_error());
            }
            // SAFETY: openat returned a new descriptor owned by this process.
            let file = unsafe { File::from_raw_fd(descriptor) };
            self.runs.push(Run {
                name,
                context: context.clone(),
                plain_bytes,
                cipher_bytes,
            });
            self.ciphertext_bytes += cipher_bytes;
            let result = (|| {
                let mut writer = EncryptedSpoolWriter::new(
                    file,
                    &self.key,
                    &context,
                    SpoolLimits {
                        plaintext_bytes: plain_bytes,
                        ciphertext_bytes: cipher_bytes,
                    },
                    &self.guard,
                )
                .map_err(SortError::ENCRYPTED)?;
                for row in &self.rows {
                    self.guard.check().map_err(SortError::RESOURCE)?;
                    writer
                        .write_all(&(row.frame.len() as u32).to_be_bytes())
                        .map_err(SortError::IO)?;
                    writer.write_all(&row.frame).map_err(SortError::IO)?;
                }
                writer.finish().map_err(SortError::ENCRYPTED)?;
                Ok(())
            })();
            if result.is_err() {
                self.is_failed = true;
            }
            result?;
            self.rows.clear();
            self.row_bytes = 0;
            Ok(())
        }

        pub fn visit_sorted<F>(
            &mut self,
            capture_id: &str,
            mut visit: F,
        ) -> Result<String, SortError>
        where
            F: FnMut(&ManifestEntry) -> Result<(), SortError>,
        {
            self.guard.check().map_err(SortError::RESOURCE)?;
            if self.is_failed {
                return Err(SortError::INVALID);
            }
            self.flush_run()?;
            let header = ManifestHeader {
                schema_version: 1,
                capture_id: capture_id.to_owned(),
                entry_count: self.entry_count.to_string(),
            };
            let mut validator = ManifestValidator::new(&header).map_err(SortError::MANIFEST)?;
            let mut readers = Vec::with_capacity(self.runs.len());
            let mut heads = Vec::with_capacity(self.runs.len());
            for run in &self.runs {
                // SAFETY: the directory descriptor and filename remain live and no symlink is followed.
                let descriptor = unsafe {
                    libc::openat(
                        self.directory.as_raw_fd(),
                        run.name.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if descriptor < 0 {
                    return Err(io_error());
                }
                // SAFETY: openat returned a new owned descriptor.
                let file = unsafe { File::from_raw_fd(descriptor) };
                let mut reader = EncryptedSpoolReader::new(
                    file,
                    &self.key,
                    &run.context,
                    SpoolLimits {
                        plaintext_bytes: run.plain_bytes,
                        ciphertext_bytes: run.cipher_bytes,
                    },
                    &self.guard,
                )
                .map_err(SortError::ENCRYPTED)?;
                heads.push(read_row(&mut reader, self.limits.max_frame_bytes)?);
                readers.push(reader);
            }
            loop {
                self.guard.check().map_err(SortError::RESOURCE)?;
                let next = heads
                    .iter()
                    .enumerate()
                    .filter_map(|(index, row)| row.as_ref().map(|row| (index, &row.key)))
                    .min_by(|left, right| left.1.cmp(right.1))
                    .map(|value| value.0);
                let Some(index) = next else {
                    break;
                };
                let row = heads[index].take().ok_or(SortError::INVALID)?;
                let entry: ManifestEntry =
                    serde_json::from_slice(&row.frame).map_err(|_| SortError::INVALID)?;
                validator.add_entry(&entry).map_err(SortError::MANIFEST)?;
                visit(&entry)?;
                self.guard.check().map_err(SortError::RESOURCE)?;
                heads[index] = read_row(&mut readers[index], self.limits.max_frame_bytes)?;
            }
            for reader in readers {
                reader.finish().map_err(SortError::ENCRYPTED)?;
            }
            self.guard.check().map_err(SortError::RESOURCE)?;
            let digest = validator.finish().map_err(SortError::MANIFEST)?;
            self.guard.check().map_err(SortError::RESOURCE)?;
            Ok(digest)
        }
    }

    impl Drop for EncryptedManifestSort {
        fn drop(&mut self) {
            for run in &mut self.runs {
                // SAFETY: the directory descriptor and NUL-terminated owned filename are valid.
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), run.name.as_ptr(), 0);
                }
                run.context.zeroize();
            }
        }
    }

    fn read_row<R: Read>(reader: &mut R, max_frame: usize) -> Result<Option<Row>, SortError> {
        let mut length = [0_u8; 4];
        let read = reader.read(&mut length[..1]).map_err(SortError::IO)?;
        if read == 0 {
            return Ok(None);
        }
        reader.read_exact(&mut length[1..]).map_err(SortError::IO)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > max_frame {
            return Err(SortError::INVALID);
        }
        let mut frame = Zeroizing::new(vec![0_u8; length]);
        reader.read_exact(&mut frame).map_err(SortError::IO)?;
        let entry: ManifestEntry =
            serde_json::from_slice(&frame).map_err(|_| SortError::INVALID)?;
        let key = Zeroizing::new(sort_key(&entry)?);
        Ok(Some(Row { key, frame }))
    }

    fn sort_key(entry: &ManifestEntry) -> Result<Vec<u8>, SortError> {
        let mut result = entry.source_id.as_bytes().to_vec();
        result.push(0);
        for component in &entry.path {
            let bytes = URL_SAFE_NO_PAD
                .decode(component)
                .map_err(|_| SortError::INVALID)?;
            for byte in bytes {
                result.push(1);
                result.push(byte);
            }
            result.push(0);
        }
        Ok(result)
    }
}

#[cfg(unix)]
pub use platform::EncryptedManifestSort;

#[cfg(not(unix))]
pub struct EncryptedManifestSort;

#[cfg(not(unix))]
impl EncryptedManifestSort {
    pub fn create(
        _directory: &std::path::Path,
        _key: &zeroize::Zeroizing<[u8; 32]>,
        _limits: SortLimits,
        _guard: &crate::resources::StageGuard,
    ) -> Result<Self, SortError> {
        Err(SortError::UNSUPPORTED)
    }
    pub fn add_entry(&mut self, _entry: &crate::manifest::ManifestEntry) -> Result<(), SortError> {
        Err(SortError::UNSUPPORTED)
    }
    pub fn visit_sorted<F>(&mut self, _capture_id: &str, _visit: F) -> Result<String, SortError>
    where
        F: FnMut(&crate::manifest::ManifestEntry) -> Result<(), SortError>,
    {
        Err(SortError::UNSUPPORTED)
    }
}
