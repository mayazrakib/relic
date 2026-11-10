use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustic_core::{
    ErrorKind, ReadSource, ReadSourceEntry, ReadSourceOpen, RusticError, RusticResult,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encrypted_spool::{EncryptedSpoolReader, EncryptedSpoolWriter, SpoolLimits};
use crate::manifest::{ManifestEntry, ManifestHeader, ManifestValidator};
use crate::resources::StageGuard;
use crate::state::{CaptureBinding, validate_capture_binding};

const MAX_CIPHERTEXT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: u64 = 1024;
const MAX_DEPTH: usize = 32;
const CONTEXT_DOMAIN: &[u8] = b"relic/frozen-archive-file/v1\0";
const BUFFER_BYTES: usize = 64 * 1024;
const SPOOL_FIXED_BYTES: u64 = 60;
const SPOOL_RECORD_BYTES: u64 = 20;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum ArchiveSourceError {
    INVALID,
    LIMIT,
    CONTENT,
    RESOURCE,
    IO,
}

impl fmt::Display for ArchiveSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid frozen archive source",
            Self::LIMIT => "frozen archive source capacity unavailable",
            Self::CONTENT => "frozen archive source content or authentication failed",
            Self::RESOURCE => "frozen archive source resource guard stopped the operation",
            Self::IO => "frozen archive source I/O failed",
        })
    }
}

impl std::error::Error for ArchiveSourceError {}

#[derive(Clone, Copy)]
pub struct ArchiveSourceLimits {
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_ciphertext_bytes: u64,
    pub max_metadata_bytes: usize,
}

pub struct FrozenArchiveEntry {
    pub entry: ManifestEntry,
    pub ciphertext: Option<Arc<[u8]>>,
}

struct CatalogItem {
    path: PathBuf,
    is_directory: bool,
    data: Option<FileData>,
}

struct FileData {
    ciphertext: Arc<[u8]>,
    context: [u8; 32],
    expected_bytes: u64,
    expected_digest: [u8; 32],
}

pub struct FrozenArchiveSource {
    catalog: Arc<[CatalogItem]>,
    key: Arc<Zeroizing<[u8; 32]>>,
    guard: StageGuard,
    max_file_bytes: u64,
    max_ciphertext_bytes: u64,
}

fn check_limits(limits: ArchiveSourceLimits) -> Result<(), ArchiveSourceError> {
    if limits.max_entries == 0
        || limits.max_entries > MAX_ENTRIES
        || limits.max_file_bytes > MAX_CIPHERTEXT_BYTES
        || limits.max_ciphertext_bytes == 0
        || limits.max_ciphertext_bytes > MAX_CIPHERTEXT_BYTES
        || limits.max_metadata_bytes == 0
        || limits.max_metadata_bytes > MAX_METADATA_BYTES
    {
        return Err(ArchiveSourceError::LIMIT);
    }

    Ok(())
}

fn is_portable(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value.ends_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return false;
    }

    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn get_path(entry: &ManifestEntry) -> Result<PathBuf, ArchiveSourceError> {
    if entry.path_encoding != "unix_bytes"
        || !is_portable(&entry.source_id)
        || entry.path.len() > MAX_DEPTH
    {
        return Err(ArchiveSourceError::INVALID);
    }

    let mut path = PathBuf::from("sources");
    path.push(&entry.source_id);

    for component in &entry.path {
        let bytes = URL_SAFE_NO_PAD
            .decode(component)
            .map_err(|_| ArchiveSourceError::INVALID)?;

        if URL_SAFE_NO_PAD.encode(&bytes) != *component {
            return Err(ArchiveSourceError::INVALID);
        }

        let value = std::str::from_utf8(&bytes).map_err(|_| ArchiveSourceError::INVALID)?;

        if !is_portable(value) {
            return Err(ArchiveSourceError::INVALID);
        }

        path.push(value);
    }

    Ok(path)
}

fn validate_entry(
    entry: &ManifestEntry,
    binding: &CaptureBinding,
) -> Result<(PathBuf, usize), ArchiveSourceError> {
    validate_capture_binding(binding).map_err(|_| ArchiveSourceError::INVALID)?;

    if entry.path.len() > MAX_DEPTH
        || !entry.metadata.is_empty()
        || !matches!(entry.kind.as_str(), "file" | "directory")
    {
        return Err(ArchiveSourceError::INVALID);
    }

    let size = entry
        .source_id
        .len()
        .saturating_add(entry.path_encoding.len())
        .saturating_add(entry.kind.len())
        .saturating_add(
            entry
                .path
                .iter()
                .fold(0_usize, |total, value| total.saturating_add(value.len())),
        )
        .saturating_add(entry.size_bytes.as_ref().map_or(0, String::len))
        .saturating_add(entry.content_digest.as_ref().map_or(0, String::len));

    if size > MAX_METADATA_BYTES {
        return Err(ArchiveSourceError::LIMIT);
    }

    let path = get_path(entry)?;
    let mut validator = ManifestValidator::new(&ManifestHeader {
        schema_version: 1,
        capture_id: binding.capture_id.clone(),
        entry_count: "1".to_owned(),
    })
    .map_err(|_| ArchiveSourceError::INVALID)?;
    validator
        .add_entry(entry)
        .map_err(|_| ArchiveSourceError::INVALID)?;
    validator
        .finish()
        .map_err(|_| ArchiveSourceError::INVALID)?;
    Ok((path, size))
}

fn get_context(
    entry: &ManifestEntry,
    binding: &CaptureBinding,
) -> Result<[u8; 32], ArchiveSourceError> {
    let bytes = serde_jcs::to_vec(&(binding, entry)).map_err(|_| ArchiveSourceError::INVALID)?;
    let mut digest = Sha256::new();
    digest.update(CONTEXT_DOMAIN);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn get_file_details(entry: &ManifestEntry) -> Result<(u64, [u8; 32]), ArchiveSourceError> {
    let text = entry
        .size_bytes
        .as_deref()
        .ok_or(ArchiveSourceError::INVALID)?;
    let size = text
        .parse::<u64>()
        .map_err(|_| ArchiveSourceError::INVALID)?;

    if size.to_string() != text {
        return Err(ArchiveSourceError::INVALID);
    }

    let text = entry
        .content_digest
        .as_deref()
        .ok_or(ArchiveSourceError::INVALID)?;
    let hex = text
        .strip_prefix("sha256:")
        .ok_or(ArchiveSourceError::INVALID)?;

    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArchiveSourceError::INVALID);
    }

    let mut digest = [0_u8; 32];

    for (index, value) in digest.iter_mut().enumerate() {
        *value = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| ArchiveSourceError::INVALID)?;
    }

    Ok((size, digest))
}

struct CountingReader<'a, R> {
    source: &'a mut R,
    read_bytes: u64,
    max_bytes: u64,
    digest: Sha256,
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(bytes)?;
        self.read_bytes = self
            .read_bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("source limit exceeded"))?;

        if self.read_bytes > self.max_bytes {
            return Err(io::Error::other("source limit exceeded"));
        }

        self.digest.update(&bytes[..count]);
        Ok(count)
    }
}

pub fn encrypt_archive_file<R: Read>(
    entry: &ManifestEntry,
    binding: &CaptureBinding,
    source: &mut R,
    key: &Zeroizing<[u8; 32]>,
    limits: SpoolLimits,
    guard: &StageGuard,
) -> Result<Arc<[u8]>, ArchiveSourceError> {
    validate_entry(entry, binding)?;

    if entry.kind != "file"
        || limits.ciphertext_bytes > MAX_CIPHERTEXT_BYTES
        || limits.plaintext_bytes > MAX_CIPHERTEXT_BYTES
    {
        return Err(ArchiveSourceError::LIMIT);
    }

    let (expected_bytes, expected_digest) = get_file_details(entry)?;

    if expected_bytes > limits.plaintext_bytes {
        return Err(ArchiveSourceError::LIMIT);
    }

    let context = get_context(entry, binding)?;
    let mut input = CountingReader {
        source,
        read_bytes: 0,
        max_bytes: expected_bytes,
        digest: Sha256::new(),
    };
    let reserved_bytes = expected_bytes
        .checked_add(SPOOL_FIXED_BYTES)
        .and_then(|bytes| {
            bytes.checked_add(
                expected_bytes
                    .div_ceil(BUFFER_BYTES as u64)
                    .checked_mul(SPOOL_RECORD_BYTES)?,
            )
        })
        .ok_or(ArchiveSourceError::LIMIT)?;

    if reserved_bytes > limits.ciphertext_bytes {
        return Err(ArchiveSourceError::LIMIT);
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(reserved_bytes as usize)
        .map_err(|_| ArchiveSourceError::LIMIT)?;
    let mut writer = EncryptedSpoolWriter::new(output, key, &context, limits, guard)
        .map_err(|_| ArchiveSourceError::CONTENT)?;
    let mut buffer = Zeroizing::new([0; BUFFER_BYTES]);

    loop {
        guard.check().map_err(|_| ArchiveSourceError::RESOURCE)?;
        let count = input
            .read(&mut buffer[..])
            .map_err(|_| ArchiveSourceError::IO)?;

        if count == 0 {
            break;
        }

        writer
            .write_all(&buffer[..count])
            .map_err(|_| ArchiveSourceError::CONTENT)?;
    }
    let digest: [u8; 32] = input.digest.finalize().into();

    if input.read_bytes != expected_bytes || digest != expected_digest {
        return Err(ArchiveSourceError::CONTENT);
    }

    let output = writer.finish().map_err(|_| ArchiveSourceError::CONTENT)?;

    Ok(Arc::from(output))
}

impl FrozenArchiveSource {
    pub fn new(
        entries: Vec<FrozenArchiveEntry>,
        binding: &CaptureBinding,
        key: &Zeroizing<[u8; 32]>,
        limits: ArchiveSourceLimits,
        guard: &StageGuard,
    ) -> Result<Self, ArchiveSourceError> {
        check_limits(limits)?;
        validate_capture_binding(binding).map_err(|_| ArchiveSourceError::INVALID)?;
        guard.check().map_err(|_| ArchiveSourceError::RESOURCE)?;

        if entries.len() as u64 > limits.max_entries {
            return Err(ArchiveSourceError::LIMIT);
        }

        let mut catalog = BTreeMap::<PathBuf, CatalogItem>::new();
        let mut explicit = BTreeSet::new();
        let mut ciphertext_bytes = 0_u64;
        let mut metadata_bytes = 0_usize;
        catalog.insert(
            PathBuf::from("sources"),
            CatalogItem {
                path: PathBuf::from("sources"),
                is_directory: true,
                data: None,
            },
        );

        for frozen in entries {
            guard.check().map_err(|_| ArchiveSourceError::RESOURCE)?;
            let (path, entry_bytes) = validate_entry(&frozen.entry, binding)?;
            metadata_bytes = metadata_bytes
                .checked_add(entry_bytes)
                .ok_or(ArchiveSourceError::LIMIT)?;

            if metadata_bytes > limits.max_metadata_bytes || !explicit.insert(path.clone()) {
                return Err(ArchiveSourceError::INVALID);
            }

            let mut parent = path.parent();

            while let Some(ancestor) = parent {
                if ancestor.as_os_str().is_empty() {
                    break;
                }

                if let Some(item) = catalog.get(ancestor) {
                    if !item.is_directory {
                        return Err(ArchiveSourceError::INVALID);
                    }
                } else {
                    metadata_bytes = metadata_bytes
                        .checked_add(ancestor.as_os_str().len())
                        .ok_or(ArchiveSourceError::LIMIT)?;
                    catalog.insert(
                        ancestor.to_path_buf(),
                        CatalogItem {
                            path: ancestor.to_path_buf(),
                            is_directory: true,
                            data: None,
                        },
                    );
                }

                parent = ancestor.parent();
            }

            let is_directory = frozen.entry.kind == "directory";

            if catalog.contains_key(&path) && !is_directory {
                return Err(ArchiveSourceError::INVALID);
            }

            let data = if is_directory {
                if frozen.ciphertext.is_some() {
                    return Err(ArchiveSourceError::INVALID);
                }

                None
            } else {
                if frozen.entry.path.is_empty() {
                    return Err(ArchiveSourceError::INVALID);
                }

                let ciphertext = frozen.ciphertext.ok_or(ArchiveSourceError::INVALID)?;
                let (expected_bytes, expected_digest) = get_file_details(&frozen.entry)?;
                ciphertext_bytes = ciphertext_bytes
                    .checked_add(ciphertext.len() as u64)
                    .ok_or(ArchiveSourceError::LIMIT)?;

                if expected_bytes > limits.max_file_bytes
                    || ciphertext_bytes > limits.max_ciphertext_bytes
                {
                    return Err(ArchiveSourceError::LIMIT);
                }

                Some(FileData {
                    ciphertext,
                    context: get_context(&frozen.entry, binding)?,
                    expected_bytes,
                    expected_digest,
                })
            };
            catalog.insert(
                path.clone(),
                CatalogItem {
                    path,
                    is_directory,
                    data,
                },
            );

            if catalog.len() as u64 > limits.max_entries
                || metadata_bytes > limits.max_metadata_bytes
            {
                return Err(ArchiveSourceError::LIMIT);
            }
        }

        let mut folded = BTreeSet::new();

        for path in catalog.keys() {
            let value = path
                .to_str()
                .ok_or(ArchiveSourceError::INVALID)?
                .to_ascii_lowercase();

            if !folded.insert(value) {
                return Err(ArchiveSourceError::INVALID);
            }
        }

        Ok(Self {
            catalog: Arc::from(catalog.into_values().collect::<Vec<_>>()),
            key: Arc::new(Zeroizing::new(**key)),
            guard: guard.clone(),
            max_file_bytes: limits.max_file_bytes,
            max_ciphertext_bytes: limits.max_ciphertext_bytes,
        })
    }
}

pub struct FrozenArchiveOpen {
    ciphertext: Arc<[u8]>,
    context: [u8; 32],
    expected_bytes: u64,
    expected_digest: [u8; 32],
    key: Arc<Zeroizing<[u8; 32]>>,
    guard: StageGuard,
    limits: SpoolLimits,
}

pub struct VerifiedArchiveReader {
    reader: EncryptedSpoolReader<Cursor<Arc<[u8]>>>,
    expected_bytes: u64,
    expected_digest: [u8; 32],
    actual_bytes: u64,
    digest: Sha256,
    is_verified: bool,
    is_failed: bool,
}

fn get_rustic_error() -> Box<RusticError> {
    RusticError::new(ErrorKind::InputOutput, "Frozen archive source failed")
}

impl ReadSourceOpen for FrozenArchiveOpen {
    type Reader = VerifiedArchiveReader;

    fn open(self) -> RusticResult<Self::Reader> {
        let reader = EncryptedSpoolReader::new(
            Cursor::new(self.ciphertext),
            &self.key,
            &self.context,
            self.limits,
            &self.guard,
        )
        .map_err(|_| get_rustic_error())?;
        Ok(VerifiedArchiveReader {
            reader,
            expected_bytes: self.expected_bytes,
            expected_digest: self.expected_digest,
            actual_bytes: 0,
            digest: Sha256::new(),
            is_verified: false,
            is_failed: false,
        })
    }
}

impl Read for VerifiedArchiveReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.is_failed {
            return Err(io::Error::other("frozen archive source failed"));
        }

        if bytes.is_empty() || self.is_verified {
            return Ok(0);
        }

        let result = (|| {
            let count = self.reader.read(bytes)?;
            self.actual_bytes = self
                .actual_bytes
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::other("frozen archive source failed"))?;

            if self.actual_bytes > self.expected_bytes {
                return Err(io::Error::other("frozen archive source failed"));
            }

            self.digest.update(&bytes[..count]);

            if count == 0 {
                let actual: [u8; 32] = self.digest.clone().finalize().into();

                if self.actual_bytes != self.expected_bytes || actual != self.expected_digest {
                    return Err(io::Error::other("frozen archive source failed"));
                }

                self.is_verified = true;
            }

            Ok(count)
        })();

        if result.is_err() {
            self.is_failed = true;
        }

        result
    }
}

pub struct FrozenArchiveIter {
    catalog: Arc<[CatalogItem]>,
    position: usize,
    key: Arc<Zeroizing<[u8; 32]>>,
    guard: StageGuard,
    max_file_bytes: u64,
    max_ciphertext_bytes: u64,
}

impl Iterator for FrozenArchiveIter {
    type Item = RusticResult<ReadSourceEntry<FrozenArchiveOpen>>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.catalog.get(self.position)?;
        self.position += 1;

        if self.guard.check().is_err() {
            return Some(Err(get_rustic_error()));
        }

        let name = item.path.file_name()?.to_str()?;
        let node = serde_json::from_value(json!({
            "name": name,
            "type": if item.is_directory { "dir" } else { "file" },
            "size": item.data.as_ref().map_or(0, |data| data.expected_bytes),
            "mode": if item.is_directory { DIRECTORY_MODE } else { FILE_MODE },
        }));
        let node = match node {
            Ok(node) => node,
            Err(_) => return Some(Err(get_rustic_error())),
        };
        let open = item.data.as_ref().map(|data| FrozenArchiveOpen {
            ciphertext: data.ciphertext.clone(),
            context: data.context,
            expected_bytes: data.expected_bytes,
            expected_digest: data.expected_digest,
            key: self.key.clone(),
            guard: self.guard.clone(),
            limits: SpoolLimits {
                plaintext_bytes: self.max_file_bytes,
                ciphertext_bytes: self.max_ciphertext_bytes,
            },
        });
        Some(Ok(ReadSourceEntry {
            path: item.path.clone(),
            node,
            open,
        }))
    }
}

impl ReadSource for FrozenArchiveSource {
    type Open = FrozenArchiveOpen;
    type Iter = FrozenArchiveIter;

    fn size(&self) -> RusticResult<Option<u64>> {
        let mut total = 0_u64;

        for item in self.catalog.iter() {
            if let Some(data) = &item.data {
                total = total
                    .checked_add(data.expected_bytes)
                    .ok_or_else(get_rustic_error)?;
            }
        }

        Ok(Some(total))
    }

    fn entries(&self) -> Self::Iter {
        FrozenArchiveIter {
            catalog: self.catalog.clone(),
            position: 0,
            key: self.key.clone(),
            guard: self.guard.clone(),
            max_file_bytes: self.max_file_bytes,
            max_ciphertext_bytes: self.max_ciphertext_bytes,
        }
    }
}
