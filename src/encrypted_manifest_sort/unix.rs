use std::ffi::CString;
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

use super::{SortError, SortLimits, SortUsage};

const FRAME_MAX_BYTES: usize = 256 * 1024;
const MEMORY_MAX_BYTES: usize = 8 * 1024 * 1024;
const FAN_IN_MAX: usize = 4;
const RUNS_MAX: usize = 128;
const LEVELS_MAX: usize = 64;
const RUN_METADATA_BYTES: usize = 512;
const VALIDATION_RESERVE_BYTES: usize = 1024 * 1024;
const CHUNK_BYTES: u64 = 65_536;
const RUN_OVERHEAD_BYTES: u64 = 60;
const RUN_CHUNK_OVERHEAD_BYTES: u64 = 20;

struct Row {
    key: Zeroizing<Vec<u8>>,
    frame: Zeroizing<Vec<u8>>,
}

struct Run {
    name: CString,
    context: Zeroizing<Vec<u8>>,
    plain_bytes: u64,
    cipher_bytes: u64,
    entry_count: u64,
    level: usize,
    device: u64,
    inode: u64,
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
    peak_ciphertext_bytes: u64,
    total_ciphertext_bytes: u64,
    merges_completed: u64,
    next_run_id: u64,
    nonce: [u8; 16],
    is_failed: bool,
}

fn get_io_error() -> SortError {
    SortError::IO(std::io::Error::last_os_error())
}

fn get_cipher_bytes(plain_bytes: u64) -> Result<u64, SortError> {
    RUN_OVERHEAD_BYTES
        .checked_add(plain_bytes)
        .and_then(|bytes| {
            bytes.checked_add(
                plain_bytes
                    .div_ceil(CHUNK_BYTES)
                    .checked_mul(RUN_CHUNK_OVERHEAD_BYTES)?,
            )
        })
        .ok_or(SortError::LIMIT)
}

impl EncryptedManifestSort {
    pub fn create(
        directory: &Path,
        key: &Zeroizing<[u8; 32]>,
        limits: SortLimits,
        guard: &StageGuard,
    ) -> Result<Self, SortError> {
        guard.check().map_err(SortError::RESOURCE)?;
        let metadata_bytes = limits
            .max_runs
            .checked_add(1)
            .and_then(|count| count.checked_mul(RUN_METADATA_BYTES))
            .ok_or(SortError::LIMIT)?;
        let merge_bytes = limits
            .max_fan_in
            .checked_mul(
                limits
                    .max_frame_bytes
                    .checked_mul(3)
                    .and_then(|bytes| bytes.checked_add(2 * CHUNK_BYTES as usize))
                    .ok_or(SortError::LIMIT)?,
            )
            .ok_or(SortError::LIMIT)?;
        let merge_total = merge_bytes
            .checked_add(
                limits
                    .max_frame_bytes
                    .checked_mul(4)
                    .ok_or(SortError::LIMIT)?,
            )
            .and_then(|bytes| bytes.checked_add(limits.max_chunk_bytes))
            .and_then(|bytes| bytes.checked_add(VALIDATION_RESERVE_BYTES))
            .and_then(|bytes| bytes.checked_add(metadata_bytes))
            .ok_or(SortError::LIMIT)?;
        let sort_total = limits
            .max_chunk_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(VALIDATION_RESERVE_BYTES))
            .and_then(|bytes| bytes.checked_add(metadata_bytes))
            .ok_or(SortError::LIMIT)?;

        if limits.max_entries == 0
            || limits.max_frame_bytes == 0
            || limits.max_frame_bytes > FRAME_MAX_BYTES
            || limits.max_chunk_bytes == 0
            || limits.max_chunk_entries == 0
            || !(2..=FAN_IN_MAX).contains(&limits.max_fan_in)
            || limits.max_runs < limits.max_fan_in
            || limits.max_runs > RUNS_MAX
            || limits.max_memory_bytes > MEMORY_MAX_BYTES
            || merge_total > limits.max_memory_bytes
            || sort_total > limits.max_memory_bytes
            || limits.max_cipher_bytes < RUN_OVERHEAD_BYTES
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
        // geteuid has no arguments and reads only the current process identity.
        let owner = unsafe { libc::geteuid() };

        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(SortError::INVALID);
        }

        let mut nonce = [0; 16];
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
            peak_ciphertext_bytes: 0,
            total_ciphertext_bytes: 0,
            merges_completed: 0,
            next_run_id: 0,
            nonce,
            is_failed: false,
        })
    }

    pub fn add_entry(&mut self, entry: &ManifestEntry) -> Result<(), SortError> {
        let result = self.append_entry(entry);
        self.is_failed |= result.is_err();

        result
    }

    pub fn get_usage(&self) -> SortUsage {
        SortUsage {
            entry_count: self.entry_count,
            run_count: self.runs.len(),
            run_ids_allocated: self.next_run_id,
            merges_completed: self.merges_completed,
            reserved_ciphertext_bytes: self.ciphertext_bytes,
            peak_reserved_ciphertext_bytes: self.peak_ciphertext_bytes,
            total_reserved_ciphertext_bytes: self.total_ciphertext_bytes,
        }
    }

    fn append_entry(&mut self, entry: &ManifestEntry) -> Result<(), SortError> {
        self.guard.check().map_err(SortError::RESOURCE)?;

        if self.is_failed {
            return Err(SortError::INVALID);
        }

        if self.entry_count >= self.limits.max_entries {
            return Err(SortError::LIMIT);
        }

        let mut validator = ManifestValidator::new(&ManifestHeader {
            schema_version: 1,
            capture_id: "sort_validation".into(),
            entry_count: "1".into(),
        })
        .map_err(SortError::MANIFEST)?;
        validator.add_entry(entry).map_err(SortError::MANIFEST)?;
        validator.finish().map_err(SortError::MANIFEST)?;
        let frame = Zeroizing::new(serde_jcs::to_vec(entry).map_err(|_| SortError::INVALID)?);

        if frame.len() > self.limits.max_frame_bytes {
            return Err(SortError::LIMIT);
        }

        let key = Zeroizing::new(get_sort_key(entry)?);
        let row_bytes = frame
            .len()
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Row>()))
            .ok_or(SortError::LIMIT)?;

        if row_bytes > self.limits.max_chunk_bytes {
            return Err(SortError::LIMIT);
        }

        if self.rows.len() >= self.limits.max_chunk_entries
            || self
                .row_bytes
                .checked_add(row_bytes)
                .ok_or(SortError::LIMIT)?
                > self.limits.max_chunk_bytes
        {
            self.flush_run()?;
        }

        self.rows.push(Row { key, frame });
        self.row_bytes += row_bytes;
        self.entry_count += 1;

        Ok(())
    }

    fn create_run(
        &mut self,
        plain_bytes: u64,
        entry_count: u64,
        level: usize,
    ) -> Result<File, SortError> {
        self.guard.check().map_err(SortError::RESOURCE)?;

        if level > LEVELS_MAX || self.runs.len() > self.limits.max_runs {
            return Err(SortError::LIMIT);
        }

        let cipher_bytes = get_cipher_bytes(plain_bytes)?;
        let total = self
            .ciphertext_bytes
            .checked_add(cipher_bytes)
            .ok_or(SortError::LIMIT)?;

        if total > self.limits.max_cipher_bytes {
            return Err(SortError::LIMIT);
        }

        let lifetime_total = self
            .total_ciphertext_bytes
            .checked_add(cipher_bytes)
            .ok_or(SortError::LIMIT)?;

        let id = self.next_run_id;
        self.next_run_id = id.checked_add(1).ok_or(SortError::LIMIT)?;
        let mut context = Zeroizing::new(self.nonce.to_vec());
        context.extend_from_slice(&id.to_be_bytes());
        let name = CString::new(format!(
            "run_{}_{}",
            self.nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            id
        ))
        .map_err(|_| SortError::INVALID)?;
        // The pinned directory and generated component stay live during exclusive creation.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };

        if descriptor < 0 {
            return Err(get_io_error());
        }

        // A successful openat returns one descriptor transferred to File exactly once.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(SortError::IO)?;
        self.runs.push(Run {
            name,
            context,
            plain_bytes,
            cipher_bytes,
            entry_count,
            level,
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        self.ciphertext_bytes = total;
        self.peak_ciphertext_bytes = self.peak_ciphertext_bytes.max(total);
        self.total_ciphertext_bytes = lifetime_total;

        Ok(file)
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

        let plain_bytes = self.rows.iter().try_fold(0_u64, |bytes, row| {
            bytes
                .checked_add(4 + row.frame.len() as u64)
                .ok_or(SortError::LIMIT)
        })?;
        let file = self.create_run(plain_bytes, self.rows.len() as u64, 0)?;
        let run = self.runs.last().ok_or(SortError::INVALID)?;
        let mut writer = EncryptedSpoolWriter::new(
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

        for row in &self.rows {
            self.guard.check().map_err(SortError::RESOURCE)?;
            writer
                .write_all(&(row.frame.len() as u32).to_be_bytes())
                .map_err(SortError::IO)?;
            writer.write_all(&row.frame).map_err(SortError::IO)?;
        }

        writer.finish().map_err(SortError::ENCRYPTED)?;
        self.rows.clear();
        self.row_bytes = 0;
        self.compact_levels()
    }

    fn open_run(&self, run: &Run) -> Result<File, SortError> {
        // Nonblocking and no-follow prevent hanging on a substituted FIFO or symlink.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                run.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };

        if descriptor < 0 {
            return Err(get_io_error());
        }

        // The descriptor is newly owned and transferred exactly once.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(SortError::IO)?;
        // geteuid reads only the current process identity.
        let owner = unsafe { libc::geteuid() };

        if !metadata.is_file()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != owner
            || metadata.nlink() != 1
            || metadata.dev() != run.device
            || metadata.ino() != run.inode
            || metadata.len() != run.cipher_bytes
        {
            return Err(SortError::INVALID);
        }

        Ok(file)
    }

    fn merge_rows(
        &self,
        indices: &[usize],
        mut visit: impl FnMut(&Row) -> Result<(), SortError>,
    ) -> Result<(), SortError> {
        if indices.len() > self.limits.max_fan_in {
            return Err(SortError::LIMIT);
        }

        let mut readers = Vec::with_capacity(indices.len());
        let mut heads = Vec::with_capacity(indices.len());
        let mut expected_entries = 0_u64;
        let mut expected_plain_bytes = 0_u64;

        for index in indices {
            let run = self.runs.get(*index).ok_or(SortError::INVALID)?;
            expected_entries = expected_entries
                .checked_add(run.entry_count)
                .ok_or(SortError::LIMIT)?;
            expected_plain_bytes = expected_plain_bytes
                .checked_add(run.plain_bytes)
                .ok_or(SortError::LIMIT)?;
            let mut reader = EncryptedSpoolReader::new(
                self.open_run(run)?,
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

        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        let mut entries = 0_u64;
        let mut plain_bytes = 0_u64;

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

            if let Some(prior) = &previous {
                if **prior == *row.key {
                    return Err(SortError::DUPLICATE);
                }

                if **prior > *row.key {
                    return Err(SortError::INVALID);
                }
            }

            entries = entries.checked_add(1).ok_or(SortError::LIMIT)?;
            plain_bytes = plain_bytes
                .checked_add(4 + row.frame.len() as u64)
                .ok_or(SortError::LIMIT)?;

            if entries > expected_entries || plain_bytes > expected_plain_bytes {
                return Err(SortError::INVALID);
            }

            visit(&row)?;
            previous = Some(row.key);
            self.guard.check().map_err(SortError::RESOURCE)?;
            heads[index] = read_row(&mut readers[index], self.limits.max_frame_bytes)?;
        }

        for reader in readers {
            reader.finish().map_err(SortError::ENCRYPTED)?;
        }

        if entries != expected_entries || plain_bytes != expected_plain_bytes {
            return Err(SortError::INVALID);
        }

        self.guard.check().map_err(SortError::RESOURCE)?;

        Ok(())
    }

    fn merge_runs(&mut self, indices: &[usize]) -> Result<(), SortError> {
        if indices.len() < 2 || indices.len() > self.limits.max_fan_in {
            return Err(SortError::INVALID);
        }

        let mut plain_bytes = 0_u64;
        let mut entries = 0_u64;
        let mut level = 0;

        for index in indices {
            let run = self.runs.get(*index).ok_or(SortError::INVALID)?;
            plain_bytes = plain_bytes
                .checked_add(run.plain_bytes)
                .ok_or(SortError::LIMIT)?;
            entries = entries
                .checked_add(run.entry_count)
                .ok_or(SortError::LIMIT)?;
            level = level.max(run.level.checked_add(1).ok_or(SortError::LIMIT)?);
        }

        let file = self.create_run(plain_bytes, entries, level)?;
        let output = self.runs.last().ok_or(SortError::INVALID)?;
        let mut writer = EncryptedSpoolWriter::new(
            file,
            &self.key,
            &output.context,
            SpoolLimits {
                plaintext_bytes: output.plain_bytes,
                ciphertext_bytes: output.cipher_bytes,
            },
            &self.guard,
        )
        .map_err(SortError::ENCRYPTED)?;
        self.merge_rows(indices, |row| {
            writer
                .write_all(&(row.frame.len() as u32).to_be_bytes())
                .map_err(SortError::IO)?;
            writer.write_all(&row.frame).map_err(SortError::IO)
        })?;
        // Final output authentication is withheld until all input final records,
        // strict ordering, and declared counts have been verified.
        writer.finish().map_err(SortError::ENCRYPTED)?;
        let mut retired = indices.to_vec();
        retired.sort_unstable_by(|left, right| right.cmp(left));

        for index in retired {
            self.remove_run(index)?;
        }

        self.merges_completed = self
            .merges_completed
            .checked_add(1)
            .ok_or(SortError::LIMIT)?;

        Ok(())
    }

    fn compact_levels(&mut self) -> Result<(), SortError> {
        loop {
            self.guard.check().map_err(SortError::RESOURCE)?;
            let mut counts = [0_usize; LEVELS_MAX + 1];

            for run in &self.runs {
                counts[run.level] += 1;
            }

            let Some(level) = counts
                .iter()
                .position(|count| *count >= self.limits.max_fan_in)
            else {
                return Ok(());
            };
            let indices: Vec<usize> = self
                .runs
                .iter()
                .enumerate()
                .filter(|(_, run)| run.level == level)
                .take(self.limits.max_fan_in)
                .map(|(index, _)| index)
                .collect();
            self.merge_runs(&indices)?;
        }
    }

    fn compact_final(&mut self) -> Result<(), SortError> {
        while self.runs.len() > self.limits.max_fan_in {
            self.guard.check().map_err(SortError::RESOURCE)?;
            let mut indices: Vec<usize> = (0..self.runs.len()).collect();
            indices.sort_unstable_by_key(|index| (self.runs[*index].plain_bytes, *index));
            indices.truncate(self.limits.max_fan_in);
            self.merge_runs(&indices)?;
        }

        Ok(())
    }

    #[allow(clippy::unnecessary_cast)]
    fn is_registered_run(&self, run: &Run) -> bool {
        let mut output = std::mem::MaybeUninit::<libc::stat>::uninit();
        // fstatat inspects only the generated component and never follows symlinks.
        let result = unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                run.name.as_ptr(),
                output.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };

        if result != 0 {
            return false;
        }

        // Successful fstatat initialized this stat buffer. dev_t differs across Unix targets.
        let output = unsafe { output.assume_init() };

        output.st_dev as u64 == run.device
            && output.st_ino as u64 == run.inode
            && output.st_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn remove_run(&mut self, index: usize) -> Result<(), SortError> {
        let run = self.runs.get(index).ok_or(SortError::INVALID)?;

        if !self.is_registered_run(run) {
            return Err(SortError::INVALID);
        }

        // Only the registered inode's owned name is removed; replacements are preserved.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), run.name.as_ptr(), 0) } != 0 {
            return Err(get_io_error());
        }

        self.ciphertext_bytes = self
            .ciphertext_bytes
            .checked_sub(run.cipher_bytes)
            .ok_or(SortError::INVALID)?;
        self.runs.remove(index);

        Ok(())
    }

    pub fn visit_sorted<F>(&mut self, capture_id: &str, visit: F) -> Result<String, SortError>
    where
        F: FnMut(&ManifestEntry) -> Result<(), SortError>,
    {
        let result = self.read_sorted(capture_id, visit);
        self.is_failed |= result.is_err();

        result
    }

    fn read_sorted<F>(&mut self, capture_id: &str, mut visit: F) -> Result<String, SortError>
    where
        F: FnMut(&ManifestEntry) -> Result<(), SortError>,
    {
        self.guard.check().map_err(SortError::RESOURCE)?;

        if self.is_failed {
            return Err(SortError::INVALID);
        }

        self.flush_run()?;
        self.compact_final()?;
        let mut validator = ManifestValidator::new(&ManifestHeader {
            schema_version: 1,
            capture_id: capture_id.to_owned(),
            entry_count: self.entry_count.to_string(),
        })
        .map_err(SortError::MANIFEST)?;
        let indices: Vec<usize> = (0..self.runs.len()).collect();
        self.merge_rows(&indices, |row| {
            let entry: ManifestEntry =
                serde_json::from_slice(&row.frame).map_err(|_| SortError::INVALID)?;
            validator.add_entry(&entry).map_err(SortError::MANIFEST)?;
            visit(&entry)
        })?;
        let digest = validator.finish().map_err(SortError::MANIFEST)?;
        self.guard.check().map_err(SortError::RESOURCE)?;

        Ok(digest)
    }
}

impl Drop for EncryptedManifestSort {
    fn drop(&mut self) {
        for run in &self.runs {
            if self.is_registered_run(run) {
                // The pinned descriptor, generated name, and matching inode belong to this sorter.
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), run.name.as_ptr(), 0);
                }
            }
        }

        self.nonce.zeroize();
    }
}

fn read_row<R: Read>(reader: &mut R, max_frame_bytes: usize) -> Result<Option<Row>, SortError> {
    let mut length = [0; 4];

    if reader.read(&mut length[..1]).map_err(SortError::IO)? == 0 {
        return Ok(None);
    }

    reader.read_exact(&mut length[1..]).map_err(SortError::IO)?;
    let length = u32::from_be_bytes(length) as usize;

    if length == 0 || length > max_frame_bytes {
        return Err(SortError::INVALID);
    }

    let mut frame = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut frame).map_err(SortError::IO)?;
    let entry: ManifestEntry = serde_json::from_slice(&frame).map_err(|_| SortError::INVALID)?;
    let canonical = Zeroizing::new(serde_jcs::to_vec(&entry).map_err(|_| SortError::INVALID)?);

    if *canonical != *frame {
        return Err(SortError::INVALID);
    }

    let key = Zeroizing::new(get_sort_key(&entry)?);

    Ok(Some(Row { key, frame }))
}

fn get_sort_key(entry: &ManifestEntry) -> Result<Vec<u8>, SortError> {
    let capacity = entry.path.iter().try_fold(
        entry
            .source_id
            .len()
            .checked_add(1)
            .ok_or(SortError::LIMIT)?,
        |bytes, component| {
            let decoded_bytes = component.len().checked_mul(3).ok_or(SortError::LIMIT)? / 4;
            bytes
                .checked_add(
                    decoded_bytes
                        .checked_mul(2)
                        .and_then(|length| length.checked_add(1))
                        .ok_or(SortError::LIMIT)?,
                )
                .ok_or(SortError::LIMIT)
        },
    )?;
    let mut result = Zeroizing::new(Vec::new());
    result
        .try_reserve_exact(capacity)
        .map_err(|_| SortError::LIMIT)?;
    result.extend_from_slice(entry.source_id.as_bytes());
    result.push(0);

    for component in &entry.path {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(component)
                .map_err(|_| SortError::INVALID)?,
        );

        for byte in bytes.iter() {
            result.push(1);
            result.push(*byte);
        }

        result.push(0);
    }

    Ok(std::mem::take(&mut *result))
}
