use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::encrypted_spool::{self, EncryptedSpoolWriter};
use crate::manifest::{ManifestEntry, ManifestHeader, ManifestValidator};
use crate::manifest_spool::ManifestSpool;
use crate::resources::StageGuard;
use crate::state::CaptureBinding;

const DOMAIN: &[u8] = b"relic/logical-manifest/v1\0";
const CONTEXT_DOMAIN: &[u8] = b"relic/manifest-artifact/context/v1\0";
const MAX_FRAME: usize = 1024 * 1024;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ArtifactError {
    INVALID,
    AUTHENTICATION,
    IO(io::Error),
    SPOOL(crate::manifest_spool::SpoolError),
    SORT(crate::encrypted_manifest_sort::SortError),
    ENCRYPTED(encrypted_spool::SpoolError),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "manifest artifact: {self:?}")
    }
}

impl std::error::Error for ArtifactError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestArtifact {
    pub digest: String,
    pub entry_count: u64,
}

fn context(binding: &CaptureBinding) -> Result<[u8; 32], ArtifactError> {
    let values = [
        &binding.authority_id,
        &binding.job_id,
        &binding.occurrence_id,
        &binding.capture_id,
        &binding.source_view_id,
        &binding.consistency,
        &binding.source_selection_digest,
    ];
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > 128)
    {
        return Err(ArtifactError::INVALID);
    }
    let canonical = serde_jcs::to_vec(binding).map_err(|_| ArtifactError::INVALID)?;
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_DOMAIN);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), io::Error> {
    let frame = serde_jcs::to_vec(value).map_err(io::Error::other)?;
    if frame.len() > MAX_FRAME {
        return Err(io::Error::other("manifest frame too large"));
    }
    writer.write_all(&(frame.len() as u32).to_be_bytes())?;
    writer.write_all(&frame)
}

pub struct ManifestArtifactWriter<W: Write> {
    writer: EncryptedSpoolWriter<W>,
    validator: ManifestValidator,
    entry_count: u64,
    is_failed: bool,
    guard: StageGuard,
}

impl<W: Write> ManifestArtifactWriter<W> {
    pub fn new(
        binding: &CaptureBinding,
        entry_count: u64,
        destination: W,
        key: &Zeroizing<[u8; 32]>,
        limits: encrypted_spool::SpoolLimits,
        guard: &StageGuard,
    ) -> Result<Self, ArtifactError> {
        let context = context(binding)?;
        let mut writer = EncryptedSpoolWriter::new(destination, key, &context, limits, guard)
            .map_err(ArtifactError::ENCRYPTED)?;
        let header = ManifestHeader {
            schema_version: 1,
            capture_id: binding.capture_id.clone(),
            entry_count: entry_count.to_string(),
        };
        let validator = ManifestValidator::new(&header).map_err(|_| ArtifactError::INVALID)?;
        writer.write_all(DOMAIN).map_err(ArtifactError::IO)?;
        write_frame(&mut writer, &header).map_err(ArtifactError::IO)?;
        Ok(Self {
            writer,
            validator,
            entry_count,
            is_failed: false,
            guard: guard.clone(),
        })
    }

    pub fn add_entry(&mut self, entry: &ManifestEntry) -> Result<(), ArtifactError> {
        if self.is_failed {
            return Err(ArtifactError::INVALID);
        }

        if self.guard.check().is_err() {
            self.is_failed = true;

            return Err(ArtifactError::ENCRYPTED(
                encrypted_spool::SpoolError::RESOURCE,
            ));
        }

        let result = self
            .validator
            .add_entry(entry)
            .map_err(|_| ArtifactError::INVALID)
            .and_then(|()| write_frame(&mut self.writer, entry).map_err(ArtifactError::IO));
        if result.is_err() {
            self.is_failed = true;
        }
        result
    }

    pub fn finish(self) -> Result<ManifestArtifact, ArtifactError> {
        self.guard
            .check()
            .map_err(|_| ArtifactError::ENCRYPTED(encrypted_spool::SpoolError::RESOURCE))?;

        if self.is_failed {
            return Err(ArtifactError::INVALID);
        }
        let digest = self
            .validator
            .finish()
            .map_err(|_| ArtifactError::INVALID)?;
        self.writer.finish().map_err(ArtifactError::ENCRYPTED)?;
        Ok(ManifestArtifact {
            digest,
            entry_count: self.entry_count,
        })
    }
}

pub fn seal_manifest<W: Write>(
    spool: &ManifestSpool,
    binding: &CaptureBinding,
    destination: W,
    key: &Zeroizing<[u8; 32]>,
    limits: encrypted_spool::SpoolLimits,
    guard: &StageGuard,
) -> Result<ManifestArtifact, ArtifactError> {
    let mut writer = ManifestArtifactWriter::new(
        binding,
        spool.get_entry_count(),
        destination,
        key,
        limits,
        guard,
    )?;
    spool
        .visit_sorted_with_guard(guard, |entry| {
            writer.add_entry(entry).map_err(|_| {
                crate::manifest_spool::SpoolError::MANIFEST(
                    crate::manifest::ManifestError::INVALID("artifact write failed"),
                )
            })
        })
        .map_err(ArtifactError::SPOOL)?;
    writer.finish()
}

pub fn seal_sorted_manifest<W: Write>(
    sorter: &mut crate::encrypted_manifest_sort::EncryptedManifestSort,
    entry_count: u64,
    binding: &CaptureBinding,
    destination: W,
    key: &Zeroizing<[u8; 32]>,
    limits: encrypted_spool::SpoolLimits,
    guard: &StageGuard,
) -> Result<ManifestArtifact, ArtifactError> {
    let mut writer =
        ManifestArtifactWriter::new(binding, entry_count, destination, key, limits, guard)?;
    let digest = sorter
        .visit_sorted(&binding.capture_id, |entry| {
            writer
                .add_entry(entry)
                .map_err(|_| crate::encrypted_manifest_sort::SortError::INVALID)
        })
        .map_err(ArtifactError::SORT)?;
    guard.check().map_err(|_| ArtifactError::INVALID)?;
    let artifact = writer.finish()?;
    if artifact.digest != digest {
        return Err(ArtifactError::INVALID);
    }
    Ok(artifact)
}

struct FrameParser<'a> {
    binding: &'a CaptureBinding,
    guard: &'a StageGuard,
    prefix: usize,
    length: [u8; 4],
    length_bytes: usize,
    expected: Option<usize>,
    frame: Zeroizing<Vec<u8>>,
    validator: Option<ManifestValidator>,
    declared_count: u64,
    count: u64,
    is_invalid: bool,
}

impl<'a> FrameParser<'a> {
    fn new(binding: &'a CaptureBinding, guard: &'a StageGuard) -> Self {
        Self {
            binding,
            guard,
            prefix: 0,
            length: [0; 4],
            length_bytes: 0,
            expected: None,
            frame: Zeroizing::new(Vec::new()),
            validator: None,
            declared_count: 0,
            count: 0,
            is_invalid: false,
        }
    }

    fn consume_frame(&mut self) -> Result<(), ()> {
        if self.validator.is_none() {
            let header: ManifestHeader = serde_json::from_slice(&self.frame).map_err(|_| ())?;
            if header.capture_id != self.binding.capture_id
                || serde_jcs::to_vec(&header).map_err(|_| ())?.as_slice() != self.frame.as_slice()
            {
                return Err(());
            }
            self.declared_count = header.entry_count.parse().map_err(|_| ())?;
            self.validator = Some(ManifestValidator::new(&header).map_err(|_| ())?);
        } else {
            let entry: ManifestEntry = serde_json::from_slice(&self.frame).map_err(|_| ())?;
            if serde_jcs::to_vec(&entry).map_err(|_| ())?.as_slice() != self.frame.as_slice() {
                return Err(());
            }
            self.validator
                .as_mut()
                .ok_or(())?
                .add_entry(&entry)
                .map_err(|_| ())?;
            self.count = self.count.checked_add(1).ok_or(())?;
        }
        self.frame.as_mut_slice().zeroize();
        self.frame.clear();
        self.expected = None;
        Ok(())
    }

    fn accept(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        while !bytes.is_empty() {
            self.guard.check().map_err(|_| ())?;
            if self.prefix < DOMAIN.len() {
                let count = (DOMAIN.len() - self.prefix).min(bytes.len());
                if bytes[..count] != DOMAIN[self.prefix..self.prefix + count] {
                    return Err(());
                }
                self.prefix += count;
                bytes = &bytes[count..];
            } else if self.expected.is_none() {
                let count = (4 - self.length_bytes).min(bytes.len());
                self.length[self.length_bytes..self.length_bytes + count]
                    .copy_from_slice(&bytes[..count]);
                self.length_bytes += count;
                bytes = &bytes[count..];
                if self.length_bytes == 4 {
                    let length = u32::from_be_bytes(self.length) as usize;
                    if length == 0 || length > MAX_FRAME {
                        return Err(());
                    }
                    self.length_bytes = 0;
                    self.expected = Some(length);
                }
            } else {
                let expected = self.expected.ok_or(())?;
                let count = (expected - self.frame.len()).min(bytes.len());
                self.frame.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if self.frame.len() == expected {
                    self.consume_frame()?;
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<ManifestArtifact, ArtifactError> {
        self.guard.check().map_err(|_| ArtifactError::INVALID)?;
        if self.is_invalid
            || self.prefix != DOMAIN.len()
            || self.length_bytes != 0
            || self.expected.is_some()
            || self.count != self.declared_count
        {
            return Err(ArtifactError::INVALID);
        }
        let digest = self
            .validator
            .ok_or(ArtifactError::INVALID)?
            .finish()
            .map_err(|_| ArtifactError::INVALID)?;
        Ok(ManifestArtifact {
            digest,
            entry_count: self.count,
        })
    }
}

impl Write for FrameParser<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.accept(bytes).is_err() {
            self.is_invalid = true;
            return Err(io::Error::other("invalid manifest stream"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn verify_sealed_manifest<R: Read>(
    source: &mut R,
    binding: &CaptureBinding,
    key: &Zeroizing<[u8; 32]>,
    limits: encrypted_spool::SpoolLimits,
    guard: &StageGuard,
    expected_digest: &str,
) -> Result<ManifestArtifact, ArtifactError> {
    let artifact = inspect_sealed_manifest(source, binding, key, limits, guard)?;

    if artifact.digest != expected_digest {
        return Err(ArtifactError::AUTHENTICATION);
    }

    Ok(artifact)
}

pub fn inspect_sealed_manifest<R: Read>(
    source: &mut R,
    binding: &CaptureBinding,
    key: &Zeroizing<[u8; 32]>,
    limits: encrypted_spool::SpoolLimits,
    guard: &StageGuard,
) -> Result<ManifestArtifact, ArtifactError> {
    let context = context(binding)?;
    let mut parser = FrameParser::new(binding, guard);
    encrypted_spool::decrypt_spool(source, &mut parser, key, &context, limits, guard)
        .map_err(ArtifactError::ENCRYPTED)?;
    parser.finish()
}
