use std::fmt;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encrypted_manifest_sort::EncryptedManifestSort;
use crate::encrypted_spool::{EncryptedSpoolReader, EncryptedSpoolWriter, SpoolLimits};
use crate::manifest::{ManifestEntry, ManifestHeader, ManifestValidator};
use crate::manifest_artifact::ManifestArtifact;
use crate::resources::StageGuard;
use crate::source_scan::{ManifestSink, ScanError};
use crate::state::{CaptureBinding, validate_capture_binding};

const DOMAIN: &[u8] = b"relic/source-payload/v1\0";
const MAX_FRAME_BYTES: usize = 256 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;
const END: u8 = 0;
const DIRECTORY: u8 = 1;
const FILE: u8 = 2;
const FILE_END: u8 = 3;

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum PayloadError {
    INVALID,
    LIMIT,
    POISONED,
    RESOURCE,
    SINK,
    ENCRYPTED(crate::encrypted_spool::SpoolError),
    IO(std::io::Error),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid source payload",
            Self::LIMIT => "source payload limit exceeded",
            Self::POISONED => "source payload capture failed",
            Self::RESOURCE => "source payload resource guard stopped the operation",
            Self::SINK => "source payload consumer failed",
            Self::ENCRYPTED(_) => "source payload authentication or encryption failed",
            Self::IO(_) => "source payload I/O failed",
        })
    }
}

impl std::error::Error for PayloadError {}

impl From<std::io::Error> for PayloadError {
    fn from(error: std::io::Error) -> Self {
        Self::IO(error)
    }
}

#[derive(Clone, Copy)]
pub struct PayloadLimits {
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
    pub spool: SpoolLimits,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PayloadSummary {
    pub entry_count: u64,
    pub file_count: u64,
    pub payload_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadFile {
    pub source_id: String,
    pub path_encoding: String,
    pub path: Vec<String>,
    pub size_bytes: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SummaryFrame {
    entry_count: String,
    file_count: String,
    payload_bytes: String,
}

impl From<&PayloadSummary> for SummaryFrame {
    fn from(summary: &PayloadSummary) -> Self {
        Self {
            entry_count: summary.entry_count.to_string(),
            file_count: summary.file_count.to_string(),
            payload_bytes: summary.payload_bytes.to_string(),
        }
    }
}

struct ActiveFile {
    header: PayloadFile,
    size_bytes: u64,
    written_bytes: u64,
    hasher: Sha256,
}

pub struct PayloadCapture<S: ManifestSink, W: Write> {
    metadata: S,
    writer: EncryptedSpoolWriter<W>,
    capture_id: String,
    limits: PayloadLimits,
    guard: StageGuard,
    active: Option<ActiveFile>,
    summary: PayloadSummary,
    is_failed: bool,
}

pub struct CapturedPayload<S, W> {
    pub metadata: S,
    pub destination: W,
    pub summary: PayloadSummary,
}

/// Callbacks receive provisional plaintext. Only a successful visit authenticates
/// the complete stream; consumers must withhold publication until then.
pub trait PayloadVisitor {
    fn begin_file(&mut self, file: &PayloadFile) -> Result<(), PayloadError>;
    fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), PayloadError>;
    fn finish_entry(&mut self, entry: &ManifestEntry) -> Result<(), PayloadError>;
}

fn check_limits(limits: PayloadLimits) -> Result<(), PayloadError> {
    if limits.max_entries == 0
        || limits.max_file_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_file_bytes > limits.max_total_bytes
        || limits.max_depth > 128
        || limits.spool.plaintext_bytes == 0
        || limits.spool.ciphertext_bytes < 60
    {
        return Err(PayloadError::LIMIT);
    }

    Ok(())
}

fn get_context(binding: &CaptureBinding) -> Result<[u8; 32], PayloadError> {
    validate_capture_binding(binding).map_err(|_| PayloadError::INVALID)?;
    let bytes = serde_jcs::to_vec(binding).map_err(|_| PayloadError::INVALID)?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(bytes);

    Ok(hasher.finalize().into())
}

fn parse_size(text: &str) -> Result<u64, PayloadError> {
    let value = text.parse::<u64>().map_err(|_| PayloadError::INVALID)?;

    if text != value.to_string() {
        return Err(PayloadError::INVALID);
    }

    Ok(value)
}

fn check_entry(
    entry: &ManifestEntry,
    capture_id: &str,
    max_depth: usize,
) -> Result<(), PayloadError> {
    if entry.path.len() > max_depth
        || entry.path_encoding != "unix_bytes"
        || !entry.metadata.is_empty()
        || !matches!(entry.kind.as_str(), "file" | "directory")
    {
        return Err(PayloadError::INVALID);
    }

    let mut validator = ManifestValidator::new(&ManifestHeader {
        schema_version: 1,
        capture_id: capture_id.to_owned(),
        entry_count: "1".to_owned(),
    })
    .map_err(|_| PayloadError::INVALID)?;
    validator
        .add_entry(entry)
        .map_err(|_| PayloadError::INVALID)?;
    validator.finish().map_err(|_| PayloadError::INVALID)?;

    Ok(())
}

fn get_header(entry: &ManifestEntry) -> Result<PayloadFile, PayloadError> {
    Ok(PayloadFile {
        source_id: entry.source_id.clone(),
        path_encoding: entry.path_encoding.clone(),
        path: entry.path.clone(),
        size_bytes: entry.size_bytes.clone().ok_or(PayloadError::INVALID)?,
    })
}

fn check_file(
    file: &PayloadFile,
    capture_id: &str,
    limits: PayloadLimits,
) -> Result<u64, PayloadError> {
    let size = parse_size(&file.size_bytes)?;

    if size > limits.max_file_bytes {
        return Err(PayloadError::LIMIT);
    }

    check_entry(
        &ManifestEntry {
            source_id: file.source_id.clone(),
            path_encoding: file.path_encoding.clone(),
            path: file.path.clone(),
            kind: "file".to_owned(),
            size_bytes: Some(file.size_bytes.clone()),
            content_digest: Some(format!("sha256:{}", "0".repeat(64))),
            link_target_base64url: None,
            metadata: Vec::new(),
        },
        capture_id,
        limits.max_depth,
    )?;

    Ok(size)
}

fn get_digest(hasher: Sha256) -> String {
    format!(
        "sha256:{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn write_frame<W: Write, T: Serialize>(
    writer: &mut W,
    tag: u8,
    value: &T,
) -> Result<(), PayloadError> {
    let bytes = Zeroizing::new(serde_jcs::to_vec(value).map_err(|_| PayloadError::INVALID)?);

    if bytes.len() > MAX_FRAME_BYTES {
        return Err(PayloadError::LIMIT);
    }

    writer.write_all(&[tag])?;
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;

    Ok(())
}

fn read_frame<R: Read, T: for<'a> Deserialize<'a> + Serialize>(
    reader: &mut R,
) -> Result<T, PayloadError> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;

    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PayloadError::LIMIT);
    }

    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|_| PayloadError::INVALID)?;
    let canonical = Zeroizing::new(serde_jcs::to_vec(&value).map_err(|_| PayloadError::INVALID)?);

    if *canonical != *bytes {
        return Err(PayloadError::INVALID);
    }

    Ok(value)
}

fn count_entry(summary: &mut PayloadSummary, limits: PayloadLimits) -> Result<(), PayloadError> {
    summary.entry_count = summary
        .entry_count
        .checked_add(1)
        .ok_or(PayloadError::LIMIT)?;

    if summary.entry_count > limits.max_entries {
        return Err(PayloadError::LIMIT);
    }

    Ok(())
}

impl<S: ManifestSink, W: Write> PayloadCapture<S, W> {
    pub fn new(
        metadata: S,
        destination: W,
        binding: &CaptureBinding,
        key: &Zeroizing<[u8; 32]>,
        limits: PayloadLimits,
        guard: &StageGuard,
    ) -> Result<Self, PayloadError> {
        check_limits(limits)?;
        let context = get_context(binding)?;
        let mut writer = EncryptedSpoolWriter::new(destination, key, &context, limits.spool, guard)
            .map_err(PayloadError::ENCRYPTED)?;
        writer.write_all(DOMAIN)?;

        Ok(Self {
            metadata,
            writer,
            capture_id: binding.capture_id.clone(),
            limits,
            guard: guard.clone(),
            active: None,
            summary: PayloadSummary::default(),
            is_failed: false,
        })
    }

    fn check_live(&self) -> Result<(), PayloadError> {
        if self.is_failed {
            return Err(PayloadError::POISONED);
        }

        self.guard.check().map_err(|_| PayloadError::RESOURCE)
    }

    fn start_file(
        &mut self,
        source_id: &str,
        path: &[String],
        size_bytes: u64,
    ) -> Result<(), PayloadError> {
        self.check_live()?;

        if self.active.is_some() || self.summary.entry_count >= self.limits.max_entries {
            return Err(PayloadError::INVALID);
        }

        if source_id.len() > 128
            || path.len() > self.limits.max_depth
            || path
                .iter()
                .try_fold(0_usize, |sum, component| sum.checked_add(component.len()))
                .is_none_or(|bytes| bytes > MAX_FRAME_BYTES)
        {
            return Err(PayloadError::LIMIT);
        }

        let header = PayloadFile {
            source_id: source_id.to_owned(),
            path_encoding: "unix_bytes".to_owned(),
            path: path.to_vec(),
            size_bytes: size_bytes.to_string(),
        };
        check_file(&header, &self.capture_id, self.limits)?;
        let total = self
            .summary
            .payload_bytes
            .checked_add(size_bytes)
            .ok_or(PayloadError::LIMIT)?;

        if total > self.limits.max_total_bytes {
            return Err(PayloadError::LIMIT);
        }

        write_frame(&mut self.writer, FILE, &header)?;
        self.active = Some(ActiveFile {
            header,
            size_bytes,
            written_bytes: 0,
            hasher: Sha256::new(),
        });

        Ok(())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
        self.check_live()?;
        let file = self.active.as_mut().ok_or(PayloadError::INVALID)?;
        let total = file
            .written_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(PayloadError::LIMIT)?;

        if total > file.size_bytes {
            return Err(PayloadError::INVALID);
        }

        self.writer.write_all(bytes)?;
        file.hasher.update(bytes);
        file.written_bytes = total;

        Ok(())
    }

    fn add_entry(&mut self, entry: &ManifestEntry) -> Result<(), PayloadError> {
        self.check_live()?;
        check_entry(entry, &self.capture_id, self.limits.max_depth)?;

        if entry.kind == "file" {
            let file = self.active.take().ok_or(PayloadError::INVALID)?;

            if file.header != get_header(entry)?
                || file.written_bytes != file.size_bytes
                || entry.content_digest.as_deref() != Some(get_digest(file.hasher).as_str())
            {
                return Err(PayloadError::INVALID);
            }

            write_frame(&mut self.writer, FILE_END, entry)?;
            self.summary.file_count = self
                .summary
                .file_count
                .checked_add(1)
                .ok_or(PayloadError::LIMIT)?;
            self.summary.payload_bytes = self
                .summary
                .payload_bytes
                .checked_add(file.size_bytes)
                .ok_or(PayloadError::LIMIT)?;
        } else {
            if self.active.is_some() {
                return Err(PayloadError::INVALID);
            }

            write_frame(&mut self.writer, DIRECTORY, entry)?;
        }

        count_entry(&mut self.summary, self.limits)?;

        Ok(())
    }

    pub fn finish(mut self) -> Result<CapturedPayload<S, W>, PayloadError> {
        self.check_live()?;

        if self.active.is_some() || self.summary.entry_count == 0 {
            return Err(PayloadError::INVALID);
        }

        write_frame(&mut self.writer, END, &SummaryFrame::from(&self.summary))?;
        let destination = self.writer.finish().map_err(PayloadError::ENCRYPTED)?;

        Ok(CapturedPayload {
            metadata: self.metadata,
            destination,
            summary: self.summary,
        })
    }
}

impl<S: ManifestSink, W: Write> ManifestSink for PayloadCapture<S, W> {
    fn begin_file(
        &mut self,
        source_id: &str,
        path: &[String],
        size_bytes: u64,
    ) -> Result<(), ScanError> {
        let result = self.start_file(source_id, path, size_bytes);
        self.is_failed |= result.is_err();

        result.map_err(ScanError::PAYLOAD)
    }

    fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), ScanError> {
        let result = self.write_chunk(bytes);
        self.is_failed |= result.is_err();

        result.map_err(ScanError::PAYLOAD)
    }

    fn append_entry(&mut self, entry: &ManifestEntry) -> Result<(), ScanError> {
        let result = self
            .add_entry(entry)
            .map_err(ScanError::PAYLOAD)
            .and_then(|()| self.metadata.append_entry(entry));
        self.is_failed |= result.is_err();

        result
    }
}

pub fn visit_payload<R: Read, V: PayloadVisitor>(
    source: R,
    binding: &CaptureBinding,
    key: &Zeroizing<[u8; 32]>,
    limits: PayloadLimits,
    guard: &StageGuard,
    visitor: &mut V,
) -> Result<PayloadSummary, PayloadError> {
    check_limits(limits)?;
    let context = get_context(binding)?;
    let mut reader = EncryptedSpoolReader::new(source, key, &context, limits.spool, guard)
        .map_err(PayloadError::ENCRYPTED)?;
    let mut domain = [0; DOMAIN.len()];
    reader.read_exact(&mut domain)?;

    if domain != DOMAIN {
        return Err(PayloadError::INVALID);
    }

    let mut summary = PayloadSummary::default();
    let mut buffer = Zeroizing::new([0; BUFFER_BYTES]);

    loop {
        guard.check().map_err(|_| PayloadError::RESOURCE)?;
        let mut tag = [0];
        reader.read_exact(&mut tag)?;

        match tag[0] {
            END => {
                let declared: SummaryFrame = read_frame(&mut reader)?;

                if declared != SummaryFrame::from(&summary) || summary.entry_count == 0 {
                    return Err(PayloadError::INVALID);
                }

                let mut trailing = [0];

                if reader.read(&mut trailing)? != 0 {
                    return Err(PayloadError::INVALID);
                }

                reader.finish().map_err(PayloadError::ENCRYPTED)?;

                return Ok(summary);
            }
            DIRECTORY => {
                count_entry(&mut summary, limits)?;
                let entry: ManifestEntry = read_frame(&mut reader)?;
                check_entry(&entry, &binding.capture_id, limits.max_depth)?;

                if entry.kind != "directory" {
                    return Err(PayloadError::INVALID);
                }

                visitor.finish_entry(&entry)?;
            }
            FILE => {
                count_entry(&mut summary, limits)?;
                let header: PayloadFile = read_frame(&mut reader)?;
                let size_bytes = check_file(&header, &binding.capture_id, limits)?;
                let total = summary
                    .payload_bytes
                    .checked_add(size_bytes)
                    .ok_or(PayloadError::LIMIT)?;

                if total > limits.max_total_bytes {
                    return Err(PayloadError::LIMIT);
                }

                visitor.begin_file(&header)?;
                let mut remaining = size_bytes;
                let mut hasher = Sha256::new();

                while remaining > 0 {
                    guard.check().map_err(|_| PayloadError::RESOURCE)?;
                    let length = remaining.min(BUFFER_BYTES as u64) as usize;
                    reader.read_exact(&mut buffer[..length])?;
                    hasher.update(&buffer[..length]);
                    visitor.write_file_chunk(&buffer[..length])?;
                    remaining -= length as u64;
                }

                reader.read_exact(&mut tag)?;

                if tag[0] != FILE_END {
                    return Err(PayloadError::INVALID);
                }

                let entry: ManifestEntry = read_frame(&mut reader)?;
                check_entry(&entry, &binding.capture_id, limits.max_depth)?;

                if entry.kind != "file"
                    || header != get_header(&entry)?
                    || entry.content_digest.as_deref() != Some(get_digest(hasher).as_str())
                {
                    return Err(PayloadError::INVALID);
                }

                summary.file_count = summary
                    .file_count
                    .checked_add(1)
                    .ok_or(PayloadError::LIMIT)?;
                summary.payload_bytes = total;
                visitor.finish_entry(&entry)?;
            }
            _ => return Err(PayloadError::INVALID),
        }
    }
}

struct ManifestVisitor<'a, V: PayloadVisitor + ?Sized> {
    sorter: &'a mut EncryptedManifestSort,
    visitor: &'a mut V,
}

impl<V: PayloadVisitor + ?Sized> PayloadVisitor for ManifestVisitor<'_, V> {
    fn begin_file(&mut self, file: &PayloadFile) -> Result<(), PayloadError> {
        self.visitor.begin_file(file)
    }

    fn write_file_chunk(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
        self.visitor.write_file_chunk(bytes)
    }

    fn finish_entry(&mut self, entry: &ManifestEntry) -> Result<(), PayloadError> {
        self.sorter
            .add_entry(entry)
            .map_err(|_| PayloadError::SINK)?;

        self.visitor.finish_entry(entry)
    }
}

pub(crate) struct DiscardPayload;

impl PayloadVisitor for DiscardPayload {
    fn begin_file(&mut self, _file: &PayloadFile) -> Result<(), PayloadError> {
        Ok(())
    }

    fn write_file_chunk(&mut self, _bytes: &[u8]) -> Result<(), PayloadError> {
        Ok(())
    }

    fn finish_entry(&mut self, _entry: &ManifestEntry) -> Result<(), PayloadError> {
        Ok(())
    }
}

/// The sorter is a disposable, fresh ordering sink. A failed verification leaves
/// its provisional entries unusable for publication and requires dropping it.
pub fn verify_payload<R: Read>(
    source: R,
    binding: &CaptureBinding,
    key: &Zeroizing<[u8; 32]>,
    limits: PayloadLimits,
    guard: &StageGuard,
    sorter: &mut EncryptedManifestSort,
    expected: &ManifestArtifact,
) -> Result<PayloadSummary, PayloadError> {
    verify_payload_with_visitor(
        source,
        binding,
        key,
        limits,
        guard,
        sorter,
        expected,
        &mut DiscardPayload,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_payload_with_visitor<R: Read, V: PayloadVisitor + ?Sized>(
    source: R,
    binding: &CaptureBinding,
    key: &Zeroizing<[u8; 32]>,
    limits: PayloadLimits,
    guard: &StageGuard,
    sorter: &mut EncryptedManifestSort,
    expected: &ManifestArtifact,
    visitor: &mut V,
) -> Result<PayloadSummary, PayloadError> {
    let summary = visit_payload(
        source,
        binding,
        key,
        limits,
        guard,
        &mut ManifestVisitor { sorter, visitor },
    )?;

    if summary.entry_count != expected.entry_count {
        return Err(PayloadError::INVALID);
    }

    let digest = sorter
        .visit_sorted(&binding.capture_id, |_| Ok(()))
        .map_err(|_| PayloadError::SINK)?;

    if digest != expected.digest {
        return Err(PayloadError::INVALID);
    }

    guard.check().map_err(|_| PayloadError::RESOURCE)?;

    Ok(summary)
}
