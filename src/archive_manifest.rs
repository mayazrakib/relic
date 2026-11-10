use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustic_core::repofile::SnapshotFile;
use rustic_core::{IndexedFull, LsOptions, Repository};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encrypted_manifest_sort::{EncryptedManifestSort, SortError};
use crate::manifest::ManifestEntry;
use crate::manifest_artifact::ManifestArtifact;
use crate::resources::StageGuard;
use crate::state::{CaptureBinding, valid_identifier_text, validate_capture_binding};

const READ_BYTES: usize = 64 * 1024;
const MAX_SOURCES: usize = 1024;
const MAX_PREFIX_DEPTH: usize = 8;
const MAX_COMPONENT_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 128 * 1024;

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum ArchiveManifestError {
    INVALID,
    LIMIT,
    UNSUPPORTED,
    MISMATCH,
    RESOURCE,
    ENGINE,
    SORT,
}

impl fmt::Display for ArchiveManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid archive verification request or native tree",
            Self::LIMIT => "archive verification limit exceeded",
            Self::UNSUPPORTED => "archive projection is unsupported",
            Self::MISMATCH => "native archive does not match the frozen capture",
            Self::RESOURCE => "archive verification resource guard stopped the operation",
            Self::ENGINE => "native archive reading failed",
            Self::SORT => "native archive manifest ordering failed",
        })
    }
}

impl std::error::Error for ArchiveManifestError {}

#[derive(Clone, Copy)]
pub struct ArchiveManifestLimits {
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

pub struct ArchiveManifestProjection<'a> {
    pub binding: &'a CaptureBinding,
    pub expected: &'a ManifestArtifact,
    pub virtual_prefix: &'a Path,
    pub source_encodings: &'a BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ArchiveManifestReport {
    pub manifest: ManifestArtifact,
    pub file_count: u64,
    pub payload_bytes: u64,
}

fn map_sort_error(error: SortError) -> ArchiveManifestError {
    match error {
        SortError::RESOURCE(_) => ArchiveManifestError::RESOURCE,
        SortError::LIMIT => ArchiveManifestError::LIMIT,
        _ => ArchiveManifestError::SORT,
    }
}

fn get_components(path: &Path, limit: usize) -> Result<Vec<&OsStr>, ArchiveManifestError> {
    let mut components = Vec::new();

    for component in path.components() {
        if components.len() >= limit {
            return Err(ArchiveManifestError::LIMIT);
        }

        match component {
            Component::Normal(value) if value.as_encoded_bytes().len() <= MAX_COMPONENT_BYTES => {
                components.push(value);
            }
            _ => return Err(ArchiveManifestError::INVALID),
        }
    }

    Ok(components)
}

fn encode_component(component: &OsStr, encoding: &str) -> Result<String, ArchiveManifestError> {
    if component.as_encoded_bytes().len() > MAX_COMPONENT_BYTES {
        return Err(ArchiveManifestError::LIMIT);
    }

    let bytes = match encoding {
        "unix_bytes" => {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                Zeroizing::new(component.as_bytes().to_vec())
            }

            #[cfg(not(unix))]
            {
                let text = component
                    .to_str()
                    .filter(|text| text.is_ascii())
                    .ok_or(ArchiveManifestError::UNSUPPORTED)?;
                Zeroizing::new(text.as_bytes().to_vec())
            }
        }
        "windows_utf16le" => {
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                Zeroizing::new(
                    component
                        .encode_wide()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
            }

            #[cfg(not(windows))]
            {
                let text = component
                    .to_str()
                    .ok_or(ArchiveManifestError::UNSUPPORTED)?;
                Zeroizing::new(
                    text.encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
            }
        }
        _ => return Err(ArchiveManifestError::UNSUPPORTED),
    };

    Ok(URL_SAFE_NO_PAD.encode(&*bytes))
}

fn validate_request(
    projection: &ArchiveManifestProjection<'_>,
    limits: ArchiveManifestLimits,
) -> Result<(), ArchiveManifestError> {
    validate_capture_binding(projection.binding).map_err(|_| ArchiveManifestError::INVALID)?;
    let digest = &projection.expected.digest;

    if limits.max_entries == 0
        || limits.max_file_bytes == 0
        || limits.max_file_bytes > limits.max_total_bytes
        || limits.max_depth > 128
        || projection.expected.entry_count > limits.max_entries
        || projection.source_encodings.is_empty()
        || projection.source_encodings.len() > MAX_SOURCES
        || digest.len() != 71
        || !digest.starts_with("sha256:")
        || !digest.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ArchiveManifestError::INVALID);
    }

    for (source_id, encoding) in projection.source_encodings {
        if !valid_identifier_text(source_id)
            || !matches!(encoding.as_str(), "unix_bytes" | "windows_utf16le")
        {
            return Err(ArchiveManifestError::INVALID);
        }
    }

    if get_components(projection.virtual_prefix, MAX_PREFIX_DEPTH)?.is_empty() {
        return Err(ArchiveManifestError::INVALID);
    }

    Ok(())
}

/// This checks logical coverage and content, not destination publication authority.
/// SDK index/tree/blob allocations and blocking calls still need worker containment.
pub fn verify_snapshot<S: IndexedFull>(
    repository: &Repository<S>,
    snapshot: &SnapshotFile,
    projection: ArchiveManifestProjection<'_>,
    sorter: &mut EncryptedManifestSort,
    limits: ArchiveManifestLimits,
    guard: &StageGuard,
) -> Result<ArchiveManifestReport, ArchiveManifestError> {
    validate_request(&projection, limits)?;
    guard.check().map_err(|_| ArchiveManifestError::RESOURCE)?;
    let prefix = get_components(projection.virtual_prefix, MAX_PREFIX_DEPTH)?;
    let root = repository
        .node_from_snapshot_and_path(snapshot, "")
        .map_err(|_| ArchiveManifestError::ENGINE)?;

    if !root.is_dir() || root.subtree.is_none() || root.content.is_some() {
        return Err(ArchiveManifestError::INVALID);
    }

    let options = LsOptions::default();
    let listing = repository
        .ls(&root, &options)
        .map_err(|_| ArchiveManifestError::ENGINE)?;
    let mut physical_count = 0_u64;
    let mut logical_count = 0_u64;
    let mut file_count = 0_u64;
    let mut total_bytes = 0_u64;
    let physical_limit = limits
        .max_entries
        .checked_add(prefix.len() as u64 + 1)
        .ok_or(ArchiveManifestError::LIMIT)?;
    let mut synthetic = BTreeSet::new();
    let mut seen_sources = BTreeSet::new();

    for item in listing {
        guard.check().map_err(|_| ArchiveManifestError::RESOURCE)?;
        let (path, node) = item.map_err(|_| ArchiveManifestError::ENGINE)?;
        physical_count = physical_count
            .checked_add(1)
            .ok_or(ArchiveManifestError::LIMIT)?;

        if physical_count > physical_limit {
            return Err(ArchiveManifestError::LIMIT);
        }

        let components = get_components(&path, prefix.len() + 1 + limits.max_depth)?;

        if components.is_empty() {
            if !node.is_dir() || !synthetic.insert(path.clone()) {
                return Err(ArchiveManifestError::INVALID);
            }

            continue;
        }

        let name = node.name();
        let name_components = get_components(Path::new(&name), 1)?;

        if name_components.len() != 1 || components.last().copied() != Some(name.as_ref()) {
            return Err(ArchiveManifestError::INVALID);
        }

        if components.len() <= prefix.len() {
            if components != prefix[..components.len()]
                || !node.is_dir()
                || node.subtree.is_none()
                || node.content.is_some()
                || !synthetic.insert(path.clone())
            {
                return Err(ArchiveManifestError::MISMATCH);
            }

            continue;
        }

        if components[..prefix.len()] != prefix {
            return Err(ArchiveManifestError::MISMATCH);
        }

        let source_id = components[prefix.len()]
            .to_str()
            .ok_or(ArchiveManifestError::MISMATCH)?;
        let encoding = projection
            .source_encodings
            .get(source_id)
            .ok_or(ArchiveManifestError::MISMATCH)?;
        let native_path = &components[prefix.len() + 1..];

        if native_path.is_empty() && (!node.is_dir() || !seen_sources.insert(source_id.to_owned()))
        {
            return Err(ArchiveManifestError::MISMATCH);
        }

        let mut logical_path = Vec::with_capacity(native_path.len());
        let mut path_bytes = 0_usize;

        for component in native_path {
            let encoded = encode_component(component, encoding)?;
            path_bytes = path_bytes
                .checked_add(encoded.len())
                .ok_or(ArchiveManifestError::LIMIT)?;

            if path_bytes > MAX_PATH_BYTES {
                return Err(ArchiveManifestError::LIMIT);
            }

            logical_path.push(encoded);
        }

        logical_count = logical_count
            .checked_add(1)
            .ok_or(ArchiveManifestError::LIMIT)?;

        if logical_count > limits.max_entries || logical_count > projection.expected.entry_count {
            return Err(ArchiveManifestError::MISMATCH);
        }

        let (kind, size_bytes, content_digest) = if node.is_dir() {
            if node.subtree.is_none() || node.content.is_some() {
                return Err(ArchiveManifestError::INVALID);
            }

            ("directory", None, None)
        } else if node.is_file() {
            if node.subtree.is_some()
                || node.content.is_none()
                || node.meta.size > limits.max_file_bytes
            {
                return Err(ArchiveManifestError::LIMIT);
            }

            total_bytes = total_bytes
                .checked_add(node.meta.size)
                .ok_or(ArchiveManifestError::LIMIT)?;

            if total_bytes > limits.max_total_bytes {
                return Err(ArchiveManifestError::LIMIT);
            }

            file_count = file_count
                .checked_add(1)
                .ok_or(ArchiveManifestError::LIMIT)?;
            let opened = repository
                .open_file(&node)
                .map_err(|_| ArchiveManifestError::ENGINE)?;
            let mut offset = 0_u64;
            let mut hasher = Sha256::new();

            while offset < node.meta.size {
                guard.check().map_err(|_| ArchiveManifestError::RESOURCE)?;
                let length = (node.meta.size - offset).min(READ_BYTES as u64) as usize;
                let position = usize::try_from(offset).map_err(|_| ArchiveManifestError::LIMIT)?;
                let bytes = repository
                    .read_file_at(&opened, position, length)
                    .map_err(|_| ArchiveManifestError::ENGINE)?;

                if bytes.is_empty() || bytes.len() > length {
                    return Err(ArchiveManifestError::MISMATCH);
                }

                hasher.update(&bytes);
                offset = offset
                    .checked_add(bytes.len() as u64)
                    .ok_or(ArchiveManifestError::LIMIT)?;
            }

            guard.check().map_err(|_| ArchiveManifestError::RESOURCE)?;
            let position = usize::try_from(offset).map_err(|_| ArchiveManifestError::LIMIT)?;

            if !repository
                .read_file_at(&opened, position, 1)
                .map_err(|_| ArchiveManifestError::ENGINE)?
                .is_empty()
            {
                return Err(ArchiveManifestError::MISMATCH);
            }

            let digest = format!(
                "sha256:{}",
                hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );

            ("file", Some(node.meta.size.to_string()), Some(digest))
        } else {
            return Err(ArchiveManifestError::UNSUPPORTED);
        };
        sorter
            .add_entry(&ManifestEntry {
                source_id: source_id.to_owned(),
                path_encoding: encoding.clone(),
                path: logical_path,
                kind: kind.to_owned(),
                size_bytes,
                content_digest,
                link_target_base64url: None,
                metadata: Vec::new(),
            })
            .map_err(map_sort_error)?;
    }

    if seen_sources.len() != projection.source_encodings.len() {
        return Err(ArchiveManifestError::MISMATCH);
    }

    let digest = sorter
        .visit_sorted(&projection.binding.capture_id, |_| Ok(()))
        .map_err(map_sort_error)?;

    if logical_count != projection.expected.entry_count || digest != projection.expected.digest {
        return Err(ArchiveManifestError::MISMATCH);
    }

    guard.check().map_err(|_| ArchiveManifestError::RESOURCE)?;

    Ok(ArchiveManifestReport {
        manifest: ManifestArtifact {
            digest,
            entry_count: logical_count,
        },
        file_count,
        payload_bytes: total_bytes,
    })
}
