use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustic_core::{
    ErrorKind, ReadSource, ReadSourceEntry, ReadSourceOpen, RusticError, RusticResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_source::{VerifiedArchiveReader, get_file_details, validate_entry};
use crate::artifact_store::{ArtifactStore, PayloadVerification};
use crate::encrypted_spool::{
    EncryptedSpoolReader, EncryptedSpoolWriter, SpoolLimits, encrypt_spool,
};
use crate::local_endpoint::LocalEndpoint;
use crate::manifest::{ManifestEntry, ManifestHeader, ManifestValidator};
use crate::payload_capture::{PayloadError, PayloadFile, PayloadVisitor};
use crate::resources::{ActiveJob, Demand, StageGuard, StageReservation};
use crate::state::{ArchiveStageBinding, ArchiveStageRecord, CaptureBinding, StateStore};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_CATALOG_BYTES: u64 = 1024 * 1024;
const CATALOG_CIPHER_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CIPHER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: u64 = 10_000;
const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
const WORKING_BYTES: u64 = 16 * 1024 * 1024;
const MAX_READERS: usize = 4;

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum ArchiveDiskError {
    INVALID,
    LIMIT,
    BUSY,
    RESOURCE,
    STATE,
    STORAGE,
    CONTENT,
    RECONCILIATION_REQUIRED,
}

impl fmt::Display for ArchiveDiskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid archive staging request",
            Self::LIMIT => "archive staging capacity unavailable",
            Self::BUSY => "archive staging has a live owner",
            Self::RESOURCE => "archive staging resource guard stopped the operation",
            Self::STATE => "archive staging journal rejected the operation",
            Self::STORAGE => "archive staging storage identity or I/O failed",
            Self::CONTENT => "archive staging content verification failed",
            Self::RECONCILIATION_REQUIRED => "archive staging requires reconciliation",
        })
    }
}

impl std::error::Error for ArchiveDiskError {}

#[derive(Clone, Copy)]
pub struct ArchiveDiskLimits {
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_ciphertext_bytes: u64,
    pub max_catalog_bytes: u64,
}

pub struct ArchiveDiskRequest<'a> {
    pub binding: &'a ArchiveStageBinding,
    pub key: &'a Zeroizing<[u8; 32]>,
    pub limits: ArchiveDiskLimits,
    pub guard: &'a StageGuard,
}

struct Storage {
    endpoint: LocalEndpoint,
    endpoint_id: String,
    identity: String,
}

#[derive(Clone)]
pub struct ArchiveDiskStore(Arc<Storage>);

#[derive(Clone, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length_bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn get_stamp(file: &File) -> Result<FileStamp, ArchiveDiskError> {
    let metadata = file.metadata().map_err(|_| ArchiveDiskError::STORAGE)?;
    // SAFETY: geteuid has no arguments and reads the current process identity.
    let owner = unsafe { libc::geteuid() };

    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ArchiveDiskError::STORAGE);
    }

    Ok(FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        length_bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn get_identity(stamp: &FileStamp) -> String {
    format!("unix:{}:{}", stamp.device, stamp.inode)
}

fn get_digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn encode_digest(hasher: Sha256) -> String {
    format!(
        "sha256:{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn is_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn get_file_name(stage_id: &str, file_id: &str) -> String {
    format!("archive_{stage_id}_{file_id}.spool")
}

fn get_catalog_name(stage_id: &str) -> String {
    format!("archive_{stage_id}.catalog")
}

fn get_file_header(entry: &ManifestEntry) -> Result<PayloadFile, ArchiveDiskError> {
    Ok(PayloadFile {
        source_id: entry.source_id.clone(),
        path_encoding: entry.path_encoding.clone(),
        path: entry.path.clone(),
        size_bytes: entry.size_bytes.clone().ok_or(ArchiveDiskError::CONTENT)?,
    })
}

fn get_file_context(
    binding: &ArchiveStageBinding,
    capture: &CaptureBinding,
    file_id: &str,
    header: &PayloadFile,
) -> Result<[u8; 32], ArchiveDiskError> {
    let bytes = serde_jcs::to_vec(&(binding, capture, file_id, header))
        .map_err(|_| ArchiveDiskError::INVALID)?;
    let mut hasher = Sha256::new();
    hasher.update(b"relic/disk-archive-file/v1\0");
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn get_catalog_context(
    binding: &ArchiveStageBinding,
    capture: &CaptureBinding,
) -> Result<[u8; 32], ArchiveDiskError> {
    let bytes = serde_jcs::to_vec(&(binding, capture)).map_err(|_| ArchiveDiskError::INVALID)?;
    let mut hasher = Sha256::new();
    hasher.update(b"relic/disk-archive-catalog/v1\0");
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

impl Storage {
    fn revalidate(&self) -> Result<(), ArchiveDiskError> {
        self.endpoint
            .revalidate()
            .map_err(|_| ArchiveDiskError::STORAGE)?;
        let metadata = self
            .endpoint
            .directory()
            .metadata()
            .map_err(|_| ArchiveDiskError::STORAGE)?;
        // SAFETY: geteuid has no arguments and reads the current process identity.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
            return Err(ArchiveDiskError::STORAGE);
        }
        Ok(())
    }

    fn open_file(&self, name: &str, flags: i32) -> Result<File, ArchiveDiskError> {
        self.revalidate()?;
        if name.is_empty() || name.len() > 255 || name.contains('/') || name.contains('\\') {
            return Err(ArchiveDiskError::INVALID);
        }
        let name = CString::new(name).map_err(|_| ArchiveDiskError::INVALID)?;
        if flags & libc::O_CREAT != 0 {
            // SAFETY: the live directory descriptor and single component are valid;
            // O_EXCL prevents opening an existing inode before its type is checked.
            let fd = unsafe {
                libc::openat(
                    self.endpoint.directory().as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd >= 0 {
                // SAFETY: the new descriptor is transferred exactly once to File.
                let file = unsafe { File::from_raw_fd(fd) };
                get_stamp(&file)?;
                return Ok(file);
            }
            if flags & libc::O_EXCL != 0
                || io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err(ArchiveDiskError::STORAGE);
            }
        }
        let access = flags & !(libc::O_CREAT | libc::O_EXCL);
        #[cfg(target_os = "linux")]
        {
            // SAFETY: O_PATH pins without invoking a device's open implementation.
            let fd = unsafe {
                libc::openat(
                    self.endpoint.directory().as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(ArchiveDiskError::STORAGE);
            }
            // SAFETY: openat returned a fresh descriptor owned by this File.
            let pinned = unsafe { File::from_raw_fd(fd) };
            let stamp = get_stamp(&pinned)?;
            let proc_path = CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
                .map_err(|_| ArchiveDiskError::STORAGE)?;
            // SAFETY: this deliberate trusted-procfs reopen targets the pinned regular inode.
            let fd = unsafe {
                libc::open(
                    proc_path.as_ptr(),
                    access | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(ArchiveDiskError::STORAGE);
            }
            // SAFETY: the fresh read descriptor is transferred exactly once to File.
            let file = unsafe { File::from_raw_fd(fd) };
            if get_stamp(&file)? != stamp {
                return Err(ArchiveDiskError::STORAGE);
            }
            Ok(file)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstatat initializes this live storage and does not follow a symlink.
            if unsafe {
                libc::fstatat(
                    self.endpoint.directory().as_raw_fd(),
                    name.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(ArchiveDiskError::STORAGE);
            }
            // SAFETY: successful fstatat initialized metadata.
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(ArchiveDiskError::STORAGE);
            }
            // SAFETY: descriptor/name are valid. This platform still needs isolated
            // worker containment against a raced mutable device replacement.
            let fd = unsafe {
                libc::openat(
                    self.endpoint.directory().as_raw_fd(),
                    name.as_ptr(),
                    access | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(ArchiveDiskError::STORAGE);
            }
            // SAFETY: the fresh descriptor is transferred exactly once to File.
            let file = unsafe { File::from_raw_fd(fd) };
            let stamp = get_stamp(&file)?;
            #[allow(clippy::unnecessary_cast)]
            let device = metadata.st_dev as u64;
            if stamp.device != device || stamp.inode != metadata.st_ino {
                return Err(ArchiveDiskError::STORAGE);
            }
            Ok(file)
        }
    }

    fn sync_directory(&self) -> Result<(), ArchiveDiskError> {
        self.revalidate()?;
        self.endpoint
            .directory()
            .sync_all()
            .map_err(|_| ArchiveDiskError::STORAGE)
    }

    fn check_slot(&self, name: &str, stamp: &FileStamp) -> Result<(), ArchiveDiskError> {
        let actual = self.open_file(name, libc::O_RDONLY)?;
        if get_stamp(&actual)? != *stamp {
            return Err(ArchiveDiskError::STORAGE);
        }
        Ok(())
    }

    fn acquire_lock(&self, stage_id: &str) -> Result<File, ArchiveDiskError> {
        let name = format!(".archive_{stage_id}.lock");
        let file = self.open_file(&name, libc::O_RDWR | libc::O_CREAT)?;
        match file.try_lock() {
            Ok(()) => {
                self.check_slot(&name, &get_stamp(&file)?)?;
                Ok(file)
            }
            Err(fs::TryLockError::WouldBlock) => Err(ArchiveDiskError::BUSY),
            Err(fs::TryLockError::Error(_)) => Err(ArchiveDiskError::STORAGE),
        }
    }
}

struct Lease {
    storage: Arc<Storage>,
    lock: File,
    lock_name: String,
    key: Arc<Zeroizing<[u8; 32]>>,
    guard: StageGuard,
    readers: AtomicUsize,
    _reservation: StageReservation,
}

impl Lease {
    fn check(&self) -> Result<(), ArchiveDiskError> {
        self.guard.check().map_err(|_| ArchiveDiskError::RESOURCE)?;
        self.storage
            .check_slot(&self.lock_name, &get_stamp(&self.lock)?)
    }
}

struct ReaderPermit(Arc<Lease>);

impl ReaderPermit {
    fn acquire(lease: &Arc<Lease>) -> Result<Self, ArchiveDiskError> {
        lease.check()?;
        lease
            .readers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_READERS).then_some(count + 1)
            })
            .map_err(|_| ArchiveDiskError::LIMIT)?;
        Ok(Self(lease.clone()))
    }
}

impl Drop for ReaderPermit {
    fn drop(&mut self) {
        self.0.readers.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct CheckedArchiveFile {
    file: File,
    name: String,
    stamp: FileStamp,
    digest: String,
    hasher: Sha256,
    read_bytes: u64,
    is_finished: bool,
    is_failed: bool,
    permit: ReaderPermit,
}

impl Read for CheckedArchiveFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.is_failed {
            return Err(io::Error::other("archive file verification failed"));
        }
        if bytes.is_empty() || self.is_finished {
            return Ok(0);
        }
        let result = (|| {
            self.permit
                .0
                .guard
                .check()
                .map_err(|_| io::Error::other("archive file stopped"))?;
            let count = self.file.read(bytes)?;
            self.read_bytes = self
                .read_bytes
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::other("archive length overflow"))?;
            if self.read_bytes > self.stamp.length_bytes {
                return Err(io::Error::other("archive length changed"));
            }
            self.hasher.update(&bytes[..count]);
            if count == 0 {
                if self.read_bytes != self.stamp.length_bytes
                    || encode_digest(self.hasher.clone()) != self.digest
                    || get_stamp(&self.file)
                        .map_err(|_| io::Error::other("archive file changed"))?
                        != self.stamp
                {
                    return Err(io::Error::other("archive ciphertext changed"));
                }
                self.permit
                    .0
                    .check()
                    .and_then(|_| self.permit.0.storage.check_slot(&self.name, &self.stamp))
                    .map_err(|_| io::Error::other("archive storage changed"))?;
                self.is_finished = true;
            }
            Ok(count)
        })();
        self.is_failed |= result.is_err();
        result
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    entry: ManifestEntry,
    file_id: Option<String>,
}

struct ActiveFile {
    file_id: String,
    header: PayloadFile,
    writer: EncryptedSpoolWriter<File>,
    hasher: Sha256,
    plaintext_bytes: u64,
}

struct CaptureVisitor<'a> {
    state: &'a StateStore,
    record: &'a ArchiveStageRecord,
    capture: &'a CaptureBinding,
    lease: Arc<Lease>,
    limits: ArchiveDiskLimits,
    active: Option<ActiveFile>,
    entries: BTreeMap<PathBuf, CatalogEntry>,
    metadata_bytes: u64,
    ciphertext_bytes: u64,
}

impl CaptureVisitor<'_> {
    fn begin(&mut self, header: &PayloadFile) -> Result<(), ArchiveDiskError> {
        self.lease.check()?;
        if self.active.is_some() {
            return Err(ArchiveDiskError::CONTENT);
        }
        let plaintext_bytes = header
            .size_bytes
            .parse::<u64>()
            .map_err(|_| ArchiveDiskError::CONTENT)?;
        if plaintext_bytes > self.limits.max_file_bytes
            || header.size_bytes != plaintext_bytes.to_string()
        {
            return Err(ArchiveDiskError::LIMIT);
        }
        let file_id = uuid::Uuid::now_v7().simple().to_string();
        let header_bytes =
            Zeroizing::new(serde_jcs::to_vec(header).map_err(|_| ArchiveDiskError::CONTENT)?);
        self.state
            .prepare_archive_file(
                &self.record.binding.stage_id,
                &file_id,
                &get_digest(&header_bytes),
                plaintext_bytes,
            )
            .map_err(|_| ArchiveDiskError::STATE)?;
        let file = self.lease.storage.open_file(
            &get_file_name(&self.record.binding.stage_id, &file_id),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )?;
        let context = get_file_context(&self.record.binding, self.capture, &file_id, header)?;
        let remaining_bytes = self
            .limits
            .max_ciphertext_bytes
            .checked_sub(self.ciphertext_bytes)
            .ok_or(ArchiveDiskError::LIMIT)?;
        let writer = EncryptedSpoolWriter::new(
            file,
            &self.lease.key,
            &context,
            SpoolLimits {
                plaintext_bytes: self.limits.max_file_bytes,
                ciphertext_bytes: remaining_bytes,
            },
            &self.lease.guard,
        )
        .map_err(|_| ArchiveDiskError::CONTENT)?;
        self.active = Some(ActiveFile {
            file_id,
            header: PayloadFile {
                source_id: header.source_id.clone(),
                path_encoding: header.path_encoding.clone(),
                path: header.path.clone(),
                size_bytes: header.size_bytes.clone(),
            },
            writer,
            hasher: Sha256::new(),
            plaintext_bytes: 0,
        });
        Ok(())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), ArchiveDiskError> {
        self.lease
            .guard
            .check()
            .map_err(|_| ArchiveDiskError::RESOURCE)?;
        if bytes.len() > CHUNK_BYTES {
            return Err(ArchiveDiskError::LIMIT);
        }
        let active = self.active.as_mut().ok_or(ArchiveDiskError::CONTENT)?;
        active.plaintext_bytes = active
            .plaintext_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(ArchiveDiskError::LIMIT)?;
        if active.plaintext_bytes > self.limits.max_file_bytes {
            return Err(ArchiveDiskError::LIMIT);
        }
        active.hasher.update(bytes);
        active
            .writer
            .write_all(bytes)
            .map_err(|_| ArchiveDiskError::CONTENT)
    }

    fn finish(&mut self, entry: &ManifestEntry) -> Result<(), ArchiveDiskError> {
        self.lease.check()?;
        let (path, _) =
            validate_entry(entry, self.capture).map_err(|_| ArchiveDiskError::CONTENT)?;
        if self.entries.len() as u64 >= self.limits.max_entries || self.entries.contains_key(&path)
        {
            return Err(ArchiveDiskError::LIMIT);
        }
        let metadata =
            Zeroizing::new(serde_jcs::to_vec(entry).map_err(|_| ArchiveDiskError::CONTENT)?);
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(metadata.len() as u64 + 128)
            .ok_or(ArchiveDiskError::LIMIT)?;
        if self.metadata_bytes > self.limits.max_catalog_bytes {
            return Err(ArchiveDiskError::LIMIT);
        }
        let file_id = if entry.kind == "file" {
            let active = self.active.take().ok_or(ArchiveDiskError::CONTENT)?;
            let header = get_file_header(entry)?;
            let (expected_bytes, _) =
                get_file_details(entry).map_err(|_| ArchiveDiskError::CONTENT)?;
            if active.header != header
                || active.plaintext_bytes != expected_bytes
                || Some(encode_digest(active.hasher)) != entry.content_digest
            {
                return Err(ArchiveDiskError::CONTENT);
            }
            let mut file = active
                .writer
                .finish()
                .map_err(|_| ArchiveDiskError::CONTENT)?;
            file.sync_all().map_err(|_| ArchiveDiskError::STORAGE)?;
            self.lease.storage.sync_directory()?;
            let stamp = get_stamp(&file)?;
            self.ciphertext_bytes = self
                .ciphertext_bytes
                .checked_add(stamp.length_bytes)
                .ok_or(ArchiveDiskError::LIMIT)?;
            if self.ciphertext_bytes > self.limits.max_ciphertext_bytes {
                return Err(ArchiveDiskError::LIMIT);
            }
            file.rewind().map_err(|_| ArchiveDiskError::STORAGE)?;
            let digest = hash_file(&mut file, &self.lease.guard)?;
            self.lease.storage.check_slot(
                &get_file_name(&self.record.binding.stage_id, &active.file_id),
                &stamp,
            )?;
            self.state
                .seal_archive_file(
                    &self.record.binding.stage_id,
                    &active.file_id,
                    &digest,
                    stamp.length_bytes,
                    &get_identity(&stamp),
                )
                .map_err(|_| ArchiveDiskError::STATE)?;
            Some(active.file_id)
        } else {
            if self.active.is_some() {
                return Err(ArchiveDiskError::CONTENT);
            }
            None
        };
        self.entries.insert(
            path,
            CatalogEntry {
                entry: entry.clone(),
                file_id,
            },
        );
        Ok(())
    }
}

impl PayloadVisitor for CaptureVisitor<'_> {
    fn begin_file(&mut self, file: &PayloadFile) -> Result<(), PayloadError> {
        self.begin(file).map_err(|_| PayloadError::SINK)
    }
    fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
        self.write_chunk(bytes).map_err(|_| PayloadError::SINK)
    }
    fn finish_entry(&mut self, entry: &ManifestEntry) -> Result<(), PayloadError> {
        self.finish(entry).map_err(|_| PayloadError::SINK)
    }
}

fn hash_file(file: &mut File, guard: &StageGuard) -> Result<String, ArchiveDiskError> {
    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new([0; CHUNK_BYTES]);
    loop {
        guard.check().map_err(|_| ArchiveDiskError::RESOURCE)?;
        let count = file
            .read(&mut buffer[..])
            .map_err(|_| ArchiveDiskError::STORAGE)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(encode_digest(hasher))
}

impl ArchiveDiskStore {
    pub fn new(endpoint: LocalEndpoint, endpoint_id: &str) -> Result<Self, ArchiveDiskError> {
        if !crate::state::valid_identifier_text(endpoint_id) {
            return Err(ArchiveDiskError::INVALID);
        }
        let identity = endpoint.identity();
        let storage = Storage {
            endpoint,
            endpoint_id: endpoint_id.to_owned(),
            identity: format!("unix:{}:{}", identity.device, identity.inode),
        };
        storage.revalidate()?;
        Ok(Self(Arc::new(storage)))
    }

    pub fn storage_identity(&self) -> &str {
        &self.0.identity
    }

    fn acquire_lease(
        &self,
        request: &ArchiveDiskRequest<'_>,
        job: &ActiveJob,
    ) -> Result<Arc<Lease>, ArchiveDiskError> {
        let limits = request.limits;
        if !is_id(&request.binding.stage_id)
            || limits.max_entries == 0
            || limits.max_entries > MAX_ENTRIES
            || limits.max_file_bytes > limits.max_ciphertext_bytes
            || limits.max_ciphertext_bytes == 0
            || limits.max_ciphertext_bytes > MAX_CIPHER_BYTES
            || limits.max_catalog_bytes == 0
            || limits.max_catalog_bytes > MAX_CATALOG_BYTES
            || request.binding.storage_endpoint_id != self.0.endpoint_id
            || request.binding.storage_identity != self.0.identity
        {
            return Err(ArchiveDiskError::INVALID);
        }
        request
            .guard
            .check()
            .map_err(|_| ArchiveDiskError::RESOURCE)?;
        self.0.revalidate()?;
        let capacity = self
            .0
            .endpoint
            .capacity()
            .map_err(|_| ArchiveDiskError::STORAGE)?;
        let spool_bytes = limits
            .max_ciphertext_bytes
            .checked_add(CATALOG_CIPHER_BYTES)
            .ok_or(ArchiveDiskError::LIMIT)?;
        let reserve_bytes = MIN_FREE_BYTES.max(capacity.capacity_bytes.div_ceil(20));
        if capacity.available_bytes < spool_bytes.saturating_add(reserve_bytes) {
            return Err(ArchiveDiskError::LIMIT);
        }
        let lock = self.0.acquire_lock(&request.binding.stage_id)?;
        let reservation = job
            .reserve_stage(
                Some(&self.0.endpoint_id),
                Demand {
                    data_bytes: WORKING_BYTES,
                    spool_bytes,
                    open_files: 32,
                    streams: MAX_READERS as u64,
                    cpu_workers: 1,
                    ..Demand::default()
                },
                request.guard,
            )
            .map_err(|_| ArchiveDiskError::RESOURCE)?;
        Ok(Arc::new(Lease {
            storage: self.0.clone(),
            lock,
            lock_name: format!(".archive_{}.lock", request.binding.stage_id),
            key: Arc::new(Zeroizing::new(**request.key)),
            guard: request.guard.clone(),
            readers: AtomicUsize::new(0),
            _reservation: reservation,
        }))
    }

    pub fn create_source(
        &self,
        state: &mut StateStore,
        artifacts: &ArtifactStore,
        verification: &mut PayloadVerification<'_>,
        request: ArchiveDiskRequest<'_>,
        job: &ActiveJob,
    ) -> Result<DiskArchiveSource, ArchiveDiskError> {
        let _verification_reservation = job
            .reserve_stage(
                None,
                Demand {
                    data_bytes: 8 * 1024 * 1024,
                    ..Demand::default()
                },
                request.guard,
            )
            .map_err(|_| ArchiveDiskError::RESOURCE)?;
        let lease = self.acquire_lease(&request, job)?;
        let record = state
            .prepare_archive_stage(request.binding)
            .map_err(|_| ArchiveDiskError::STATE)?;
        if record.effect_state != "prepared"
            || !state
                .list_archive_files(&record.binding.stage_id, "", 1)
                .map_err(|_| ArchiveDiskError::STATE)?
                .is_empty()
        {
            return Err(ArchiveDiskError::RECONCILIATION_REQUIRED);
        }
        if record
            .manifest_entry_count
            .parse::<u64>()
            .map_err(|_| ArchiveDiskError::STATE)?
            > request.limits.max_entries
            || record
                .payload_bytes
                .parse::<u64>()
                .map_err(|_| ArchiveDiskError::STATE)?
                > request.limits.max_ciphertext_bytes
        {
            return Err(ArchiveDiskError::LIMIT);
        }
        let capture = state
            .get_capture(&record.binding.capture_id)
            .map_err(|_| ArchiveDiskError::STATE)?
            .ok_or(ArchiveDiskError::STATE)?
            .binding;
        let mut visitor = CaptureVisitor {
            state,
            record: &record,
            capture: &capture,
            lease: lease.clone(),
            limits: request.limits,
            active: None,
            entries: BTreeMap::new(),
            metadata_bytes: 0,
            ciphertext_bytes: 0,
        };
        artifacts
            .visit_sealed_payload(
                state,
                &record.binding.payload_artifact_id,
                verification,
                request.guard,
                &mut visitor,
            )
            .map_err(|_| ArchiveDiskError::CONTENT)?;
        if visitor.active.is_some() {
            return Err(ArchiveDiskError::CONTENT);
        }
        let entries = visitor.entries.into_values().collect::<Vec<_>>();
        validate_catalog(&entries, &record, &capture, request.limits)?;
        let plaintext =
            Zeroizing::new(serde_jcs::to_vec(&entries).map_err(|_| ArchiveDiskError::CONTENT)?);
        if plaintext.len() as u64 > request.limits.max_catalog_bytes {
            return Err(ArchiveDiskError::LIMIT);
        }
        let name = get_catalog_name(&record.binding.stage_id);
        let mut file = lease
            .storage
            .open_file(&name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?;
        let context = get_catalog_context(&record.binding, &capture)?;
        encrypt_spool(
            &mut plaintext.as_slice(),
            &mut file,
            &lease.key,
            &context,
            SpoolLimits {
                plaintext_bytes: request.limits.max_catalog_bytes,
                ciphertext_bytes: CATALOG_CIPHER_BYTES,
            },
            request.guard,
        )
        .map_err(|_| ArchiveDiskError::CONTENT)?;
        file.sync_all().map_err(|_| ArchiveDiskError::STORAGE)?;
        lease.storage.sync_directory()?;
        let stamp = get_stamp(&file)?;
        file.rewind().map_err(|_| ArchiveDiskError::STORAGE)?;
        let digest = hash_file(&mut file, request.guard)?;
        lease.storage.check_slot(&name, &stamp)?;
        lease.check()?;
        state
            .seal_archive_stage(
                &record.binding.stage_id,
                &digest,
                stamp.length_bytes,
                &get_identity(&stamp),
            )
            .map_err(|_| ArchiveDiskError::STATE)?;
        build_source(state, &record, &capture, entries, lease, request.limits)
    }

    pub fn reconcile_source(
        &self,
        state: &mut StateStore,
        request: ArchiveDiskRequest<'_>,
        job: &ActiveJob,
    ) -> Result<DiskArchiveSource, ArchiveDiskError> {
        let mut record = state
            .get_archive_stage(&request.binding.stage_id)
            .map_err(|_| ArchiveDiskError::STATE)?
            .ok_or(ArchiveDiskError::STATE)?;
        if record.effect_state == "sealed" {
            return self.reopen_source(state, request, job);
        }
        if record.binding != *request.binding || record.effect_state != "prepared" {
            return Err(ArchiveDiskError::RECONCILIATION_REQUIRED);
        }
        let lease = self.acquire_lease(&request, job)?;
        let capture = state
            .get_capture(&record.binding.capture_id)
            .map_err(|_| ArchiveDiskError::STATE)?
            .ok_or(ArchiveDiskError::STATE)?
            .binding;
        let name = get_catalog_name(&record.binding.stage_id);
        let mut file = lease
            .storage
            .open_file(&name, libc::O_RDONLY)
            .map_err(|_| ArchiveDiskError::RECONCILIATION_REQUIRED)?;
        let stamp = get_stamp(&file)?;
        if stamp.length_bytes > CATALOG_CIPHER_BYTES {
            return Err(ArchiveDiskError::LIMIT);
        }
        let digest = hash_file(&mut file, request.guard)?;
        lease.storage.check_slot(&name, &stamp)?;
        record.catalog_ciphertext_digest = Some(digest.clone());
        record.catalog_ciphertext_bytes = Some(stamp.length_bytes.to_string());
        record.catalog_identity = Some(get_identity(&stamp));
        let entries = read_catalog(&lease, &record, &capture, request.limits)?;
        let source = build_source(
            state,
            &record,
            &capture,
            entries,
            lease.clone(),
            request.limits,
        )?;
        let mut buffer = Zeroizing::new([0; CHUNK_BYTES]);
        for item in source.entries() {
            let item = item.map_err(|_| ArchiveDiskError::CONTENT)?;
            if let Some(open) = item.open {
                let mut reader = open.open().map_err(|_| ArchiveDiskError::CONTENT)?;
                while reader
                    .read(&mut buffer[..])
                    .map_err(|_| ArchiveDiskError::CONTENT)?
                    != 0
                {
                    request
                        .guard
                        .check()
                        .map_err(|_| ArchiveDiskError::RESOURCE)?;
                }
            }
        }
        file.sync_all().map_err(|_| ArchiveDiskError::STORAGE)?;
        lease.storage.sync_directory()?;
        lease.storage.check_slot(&name, &stamp)?;
        lease.check()?;
        state
            .seal_archive_stage(
                &record.binding.stage_id,
                &digest,
                stamp.length_bytes,
                &get_identity(&stamp),
            )
            .map_err(|_| ArchiveDiskError::STATE)?;
        Ok(source)
    }

    pub fn reopen_source(
        &self,
        state: &StateStore,
        request: ArchiveDiskRequest<'_>,
        job: &ActiveJob,
    ) -> Result<DiskArchiveSource, ArchiveDiskError> {
        let lease = self.acquire_lease(&request, job)?;
        let record = state
            .get_archive_stage(&request.binding.stage_id)
            .map_err(|_| ArchiveDiskError::STATE)?
            .ok_or(ArchiveDiskError::STATE)?;
        if record.binding != *request.binding || record.effect_state != "sealed" {
            return Err(ArchiveDiskError::RECONCILIATION_REQUIRED);
        }
        let capture = state
            .get_capture(&record.binding.capture_id)
            .map_err(|_| ArchiveDiskError::STATE)?
            .ok_or(ArchiveDiskError::STATE)?
            .binding;
        let entries = read_catalog(&lease, &record, &capture, request.limits)?;
        build_source(state, &record, &capture, entries, lease, request.limits)
    }
}

fn read_catalog(
    lease: &Arc<Lease>,
    record: &ArchiveStageRecord,
    capture: &CaptureBinding,
    limits: ArchiveDiskLimits,
) -> Result<Vec<CatalogEntry>, ArchiveDiskError> {
    let file = open_checked(
        lease,
        &get_catalog_name(&record.binding.stage_id),
        record
            .catalog_identity
            .as_deref()
            .ok_or(ArchiveDiskError::STATE)?,
        record
            .catalog_ciphertext_digest
            .as_deref()
            .ok_or(ArchiveDiskError::STATE)?,
        record
            .catalog_ciphertext_bytes
            .as_deref()
            .ok_or(ArchiveDiskError::STATE)?
            .parse()
            .map_err(|_| ArchiveDiskError::STATE)?,
    )?;
    let context = get_catalog_context(&record.binding, capture)?;
    let mut reader = EncryptedSpoolReader::new(
        file,
        &lease.key,
        &context,
        SpoolLimits {
            plaintext_bytes: limits.max_catalog_bytes,
            ciphertext_bytes: CATALOG_CIPHER_BYTES,
        },
        &lease.guard,
    )
    .map_err(|_| ArchiveDiskError::CONTENT)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| ArchiveDiskError::CONTENT)?;
    let entries: Vec<CatalogEntry> =
        serde_json::from_slice(&plaintext).map_err(|_| ArchiveDiskError::CONTENT)?;
    validate_catalog(&entries, record, capture, limits)?;
    drop(reader);
    Ok(entries)
}

fn validate_catalog(
    entries: &[CatalogEntry],
    record: &ArchiveStageRecord,
    capture: &CaptureBinding,
    limits: ArchiveDiskLimits,
) -> Result<(), ArchiveDiskError> {
    if entries.len() as u64 > limits.max_entries
        || entries.len().to_string() != record.manifest_entry_count
    {
        return Err(ArchiveDiskError::CONTENT);
    }
    let mut validator = ManifestValidator::new(&ManifestHeader {
        schema_version: 1,
        capture_id: capture.capture_id.clone(),
        entry_count: record.manifest_entry_count.clone(),
    })
    .map_err(|_| ArchiveDiskError::CONTENT)?;
    let mut paths = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut file_ids = BTreeSet::new();
    let mut metadata_bytes = 0_u64;
    for item in entries {
        let (path, _) =
            validate_entry(&item.entry, capture).map_err(|_| ArchiveDiskError::CONTENT)?;
        let bytes =
            Zeroizing::new(serde_jcs::to_vec(&item.entry).map_err(|_| ArchiveDiskError::CONTENT)?);
        metadata_bytes = metadata_bytes
            .checked_add(bytes.len() as u64 + 128)
            .ok_or(ArchiveDiskError::LIMIT)?;
        if metadata_bytes > limits.max_catalog_bytes
            || !folded.insert(path.to_string_lossy().to_ascii_lowercase())
            || paths.insert(path, item.entry.kind == "directory").is_some()
        {
            return Err(ArchiveDiskError::CONTENT);
        }
        match (&item.file_id, item.entry.kind.as_str()) {
            (Some(id), "file") if is_id(id) && file_ids.insert(id) => {
                if get_file_details(&item.entry)
                    .map_err(|_| ArchiveDiskError::CONTENT)?
                    .0
                    > limits.max_file_bytes
                {
                    return Err(ArchiveDiskError::LIMIT);
                }
            }
            (None, "directory") => {}
            _ => return Err(ArchiveDiskError::CONTENT),
        }
        validator
            .add_entry(&item.entry)
            .map_err(|_| ArchiveDiskError::CONTENT)?;
    }
    for path in paths.keys() {
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            if parent == std::path::Path::new("sources") || parent.as_os_str().is_empty() {
                break;
            }
            if paths.get(parent) != Some(&true) {
                return Err(ArchiveDiskError::CONTENT);
            }
            ancestor = parent.parent();
        }
    }
    if validator.finish().map_err(|_| ArchiveDiskError::CONTENT)? != record.manifest_digest {
        return Err(ArchiveDiskError::CONTENT);
    }
    Ok(())
}

fn open_checked(
    lease: &Arc<Lease>,
    name: &str,
    identity: &str,
    digest: &str,
    ciphertext_bytes: u64,
) -> Result<CheckedArchiveFile, ArchiveDiskError> {
    let permit = ReaderPermit::acquire(lease)?;
    let file = lease.storage.open_file(name, libc::O_RDONLY)?;
    let stamp = get_stamp(&file)?;
    if get_identity(&stamp) != identity || stamp.length_bytes != ciphertext_bytes {
        return Err(ArchiveDiskError::STORAGE);
    }
    Ok(CheckedArchiveFile {
        file,
        name: name.to_owned(),
        stamp,
        digest: digest.to_owned(),
        hasher: Sha256::new(),
        read_bytes: 0,
        is_finished: false,
        is_failed: false,
        permit,
    })
}

struct DiskItem {
    path: PathBuf,
    file: Option<FileLocator>,
}

struct FileLocator {
    name: String,
    context: [u8; 32],
    identity: String,
    ciphertext_digest: String,
    ciphertext_bytes: u64,
    expected_bytes: u64,
    expected_digest: [u8; 32],
}

fn build_source(
    state: &StateStore,
    record: &ArchiveStageRecord,
    capture: &CaptureBinding,
    entries: Vec<CatalogEntry>,
    lease: Arc<Lease>,
    limits: ArchiveDiskLimits,
) -> Result<DiskArchiveSource, ArchiveDiskError> {
    let mut items = vec![DiskItem {
        path: PathBuf::from("sources"),
        file: None,
    }];
    let mut ciphertext_bytes = 0_u64;
    for item in entries {
        lease.check()?;
        let (path, _) =
            validate_entry(&item.entry, capture).map_err(|_| ArchiveDiskError::CONTENT)?;
        let file = if let Some(file_id) = item.file_id {
            let row = state
                .get_archive_file(&record.binding.stage_id, &file_id)
                .map_err(|_| ArchiveDiskError::STATE)?
                .ok_or(ArchiveDiskError::STATE)?;
            let header = get_file_header(&item.entry)?;
            let header_bytes =
                Zeroizing::new(serde_jcs::to_vec(&header).map_err(|_| ArchiveDiskError::CONTENT)?);
            let (expected_bytes, expected_digest) =
                get_file_details(&item.entry).map_err(|_| ArchiveDiskError::CONTENT)?;
            if row.effect_state != "sealed"
                || row.header_digest != get_digest(&header_bytes)
                || row.plaintext_bytes != expected_bytes.to_string()
            {
                return Err(ArchiveDiskError::CONTENT);
            }
            let bytes = row
                .ciphertext_bytes
                .ok_or(ArchiveDiskError::STATE)?
                .parse::<u64>()
                .map_err(|_| ArchiveDiskError::STATE)?;
            ciphertext_bytes = ciphertext_bytes
                .checked_add(bytes)
                .ok_or(ArchiveDiskError::LIMIT)?;
            if ciphertext_bytes > limits.max_ciphertext_bytes {
                return Err(ArchiveDiskError::LIMIT);
            }
            let name = get_file_name(&record.binding.stage_id, &file_id);
            let identity = row.identity.ok_or(ArchiveDiskError::STATE)?;
            let ciphertext_digest = row.ciphertext_digest.ok_or(ArchiveDiskError::STATE)?;
            let checked = open_checked(&lease, &name, &identity, &ciphertext_digest, bytes)?;
            drop(checked);
            Some(FileLocator {
                name,
                context: get_file_context(&record.binding, capture, &file_id, &header)?,
                identity,
                ciphertext_digest,
                ciphertext_bytes: bytes,
                expected_bytes,
                expected_digest,
            })
        } else {
            None
        };
        items.push(DiskItem { path, file });
    }
    lease.check()?;
    Ok(DiskArchiveSource {
        items: Arc::from(items),
        lease,
        limits,
        payload_bytes: record
            .payload_bytes
            .parse()
            .map_err(|_| ArchiveDiskError::STATE)?,
    })
}

pub struct DiskArchiveSource {
    items: Arc<[DiskItem]>,
    lease: Arc<Lease>,
    limits: ArchiveDiskLimits,
    payload_bytes: u64,
}

pub struct DiskArchiveIter {
    source: DiskArchiveSource,
    position: usize,
}

pub struct DiskArchiveOpen {
    lease: Arc<Lease>,
    name: String,
    context: [u8; 32],
    identity: String,
    ciphertext_digest: String,
    ciphertext_bytes: u64,
    expected_bytes: u64,
    expected_digest: [u8; 32],
    limits: ArchiveDiskLimits,
}

fn get_engine_error() -> Box<RusticError> {
    RusticError::new(ErrorKind::InputOutput, "Owned archive source failed")
}

impl ReadSourceOpen for DiskArchiveOpen {
    type Reader = VerifiedArchiveReader<CheckedArchiveFile>;

    fn open(self) -> RusticResult<Self::Reader> {
        let checked = open_checked(
            &self.lease,
            &self.name,
            &self.identity,
            &self.ciphertext_digest,
            self.ciphertext_bytes,
        )
        .map_err(|_| get_engine_error())?;
        let reader = EncryptedSpoolReader::new(
            checked,
            &self.lease.key,
            &self.context,
            SpoolLimits {
                plaintext_bytes: self.limits.max_file_bytes,
                ciphertext_bytes: self.limits.max_ciphertext_bytes,
            },
            &self.lease.guard,
        )
        .map_err(|_| get_engine_error())?;
        Ok(VerifiedArchiveReader::new(
            reader,
            self.expected_bytes,
            self.expected_digest,
        ))
    }
}

impl Iterator for DiskArchiveIter {
    type Item = RusticResult<ReadSourceEntry<DiskArchiveOpen>>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.source.items.get(self.position)?;
        self.position += 1;
        if self.source.lease.check().is_err() {
            return Some(Err(get_engine_error()));
        }
        let is_directory = item.file.is_none();
        let name = item.path.file_name()?.to_str()?;
        let node = match serde_json::from_value(
            serde_json::json!({ "name": name, "type": if is_directory { "dir" } else { "file" }, "size": item.file.as_ref().map_or(0, |file| file.expected_bytes), "mode": if is_directory { 0o700 } else { 0o600 } }),
        ) {
            Ok(node) => node,
            Err(_) => return Some(Err(get_engine_error())),
        };
        let open = item.file.as_ref().map(|file| DiskArchiveOpen {
            lease: self.source.lease.clone(),
            name: file.name.clone(),
            context: file.context,
            identity: file.identity.clone(),
            ciphertext_digest: file.ciphertext_digest.clone(),
            ciphertext_bytes: file.ciphertext_bytes,
            expected_bytes: file.expected_bytes,
            expected_digest: file.expected_digest,
            limits: self.source.limits,
        });
        Some(Ok(ReadSourceEntry {
            path: item.path.clone(),
            node,
            open,
        }))
    }
}

impl ReadSource for DiskArchiveSource {
    type Open = DiskArchiveOpen;
    type Iter = DiskArchiveIter;

    fn size(&self) -> RusticResult<Option<u64>> {
        Ok(Some(self.payload_bytes))
    }

    fn entries(&self) -> Self::Iter {
        DiskArchiveIter {
            source: DiskArchiveSource {
                items: self.items.clone(),
                lease: self.lease.clone(),
                limits: self.limits,
                payload_bytes: self.payload_bytes,
            },
            position: 0,
        }
    }
}
