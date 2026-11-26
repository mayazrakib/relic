use std::fmt;
use std::io::{self, Read};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{FramedDigest, IdentityError};

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_COMPONENTS: usize = 1024;
const MAX_VALUE_ENCODED_BYTES: usize = 131_072;

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum ManifestError {
    INVALID(&'static str),
    IDENTITY(IdentityError),
    IO(io::Error),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::INVALID(message) => write!(formatter, "invalid manifest: {message}"),
            Self::IDENTITY(error) => write!(formatter, "manifest framing: {error}"),
            Self::IO(error) => write!(formatter, "manifest content: {error}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<IdentityError> for ManifestError {
    fn from(error: IdentityError) -> Self {
        Self::IDENTITY(error)
    }
}

impl From<io::Error> for ManifestError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestHeader {
    pub schema_version: u32,
    pub capture_id: String,
    pub entry_count: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataValue {
    pub namespace: String,
    pub name: String,
    pub value_base64url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub source_id: String,
    pub path_encoding: String,
    pub path: Vec<String>,
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "deserialize_present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub size_bytes: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_digest: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub link_target_base64url: Option<String>,
    pub metadata: Vec<MetadataValue>,
}

fn deserialize_present_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn parse_count(value: &str) -> Result<u64, ManifestError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ManifestError::INVALID("noncanonical count"));
    }

    value
        .parse()
        .map_err(|_| ManifestError::INVALID("count overflow"))
}

fn decode(value: &str) -> Result<Vec<u8>, ManifestError> {
    if value.len() > MAX_VALUE_ENCODED_BYTES {
        return Err(ManifestError::INVALID("encoded value exceeds limit"));
    }

    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ManifestError::INVALID("invalid base64url"))?;

    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ManifestError::INVALID("noncanonical base64url"));
    }

    Ok(bytes)
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn get_path_key(entry: &ManifestEntry) -> Result<Vec<Vec<u8>>, ManifestError> {
    if entry.path.len() > MAX_COMPONENTS {
        return Err(ManifestError::INVALID("too many path components"));
    }

    let mut components = Vec::with_capacity(entry.path.len());

    for component in &entry.path {
        let bytes = decode(component)?;
        let is_safe = match entry.path_encoding.as_str() {
            "unix_bytes" => {
                !bytes.is_empty()
                    && !bytes.contains(&0)
                    && !bytes.contains(&b'/')
                    && bytes != b"."
                    && bytes != b".."
            }
            "windows_utf16le" => {
                if bytes.is_empty() || bytes.len() % 2 != 0 {
                    false
                } else {
                    let units: Vec<u16> = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect();
                    !units.iter().any(|unit| matches!(*unit, 0 | 47 | 92))
                        && units != [46]
                        && units != [46, 46]
                }
            }
            _ => return Err(ManifestError::INVALID("unknown path encoding")),
        };

        if !is_safe {
            return Err(ManifestError::INVALID("unsafe path component"));
        }

        components.push(bytes);
    }

    if !matches!(
        entry.path_encoding.as_str(),
        "unix_bytes" | "windows_utf16le"
    ) {
        return Err(ManifestError::INVALID("unknown path encoding"));
    }

    Ok(components)
}

pub struct ManifestValidator {
    digest: FramedDigest,
    prior: Option<(String, Vec<Vec<u8>>)>,
    prior_encoding: Option<String>,
}

impl ManifestValidator {
    pub fn new(header: &ManifestHeader) -> Result<Self, ManifestError> {
        if header.schema_version != 1 || !is_identifier(&header.capture_id) {
            return Err(ManifestError::INVALID("invalid header"));
        }

        let count = parse_count(&header.entry_count)?;
        let digest = FramedDigest::new("relic/logical-manifest/v1", header, count)?;

        Ok(Self {
            digest,
            prior: None,
            prior_encoding: None,
        })
    }

    pub fn add_entry(&mut self, entry: &ManifestEntry) -> Result<(), ManifestError> {
        if !is_identifier(&entry.source_id)
            || entry.metadata.len() > 1024
            || entry.path.len() > MAX_COMPONENTS
        {
            return Err(ManifestError::INVALID("invalid source or metadata count"));
        }

        // Reject oversized input before JCS allocates an escaped copy of the record.
        let fields = std::iter::once(entry.source_id.as_str())
            .chain(std::iter::once(entry.path_encoding.as_str()))
            .chain(std::iter::once(entry.kind.as_str()))
            .chain(entry.path.iter().map(String::as_str))
            .chain(entry.size_bytes.as_deref())
            .chain(entry.content_digest.as_deref())
            .chain(entry.link_target_base64url.as_deref())
            .chain(entry.metadata.iter().flat_map(|value| {
                [
                    value.namespace.as_str(),
                    value.name.as_str(),
                    value.value_base64url.as_str(),
                ]
            }));
        let mut input_bytes = 0_usize;

        for field in fields {
            input_bytes = input_bytes
                .checked_add(field.len())
                .ok_or(ManifestError::INVALID("frame size overflow"))?;

            if input_bytes > MAX_FRAME_BYTES {
                return Err(ManifestError::INVALID("frame exceeds limit"));
            }
        }

        let canonical =
            serde_jcs::to_vec(entry).map_err(|_| ManifestError::INVALID("invalid frame"))?;

        if canonical.len() > MAX_FRAME_BYTES {
            return Err(ManifestError::INVALID("frame exceeds limit"));
        }

        let path = get_path_key(entry)?;
        let key = (entry.source_id.clone(), path);

        if self.prior.as_ref().is_some_and(|prior| prior >= &key) {
            return Err(ManifestError::INVALID("entries are not strictly ordered"));
        }

        if self
            .prior
            .as_ref()
            .is_some_and(|prior| prior.0 == entry.source_id)
            && self
                .prior_encoding
                .as_ref()
                .is_some_and(|encoding| encoding != &entry.path_encoding)
        {
            return Err(ManifestError::INVALID("mixed source path encodings"));
        }

        let mut prior_metadata: Option<(&str, &str)> = None;

        for value in &entry.metadata {
            let key = (value.namespace.as_str(), value.name.as_str());

            if !is_identifier(key.0)
                || !is_identifier(key.1)
                || prior_metadata.is_some_and(|prior| prior >= key)
            {
                return Err(ManifestError::INVALID("invalid metadata order or key"));
            }

            decode(&value.value_base64url)?;
            prior_metadata = Some(key);
        }

        match entry.kind.as_str() {
            "file" => {
                parse_count(
                    entry
                        .size_bytes
                        .as_deref()
                        .ok_or(ManifestError::INVALID("missing size"))?,
                )?;
                if !entry.content_digest.as_deref().is_some_and(is_digest)
                    || entry.link_target_base64url.is_some()
                {
                    return Err(ManifestError::INVALID("invalid file content fields"));
                }
            }
            "symlink" | "hardlink" => {
                let target = decode(
                    entry
                        .link_target_base64url
                        .as_deref()
                        .ok_or(ManifestError::INVALID("missing link target"))?,
                )?;
                if target.is_empty()
                    || (entry.path_encoding == "windows_utf16le" && target.len() % 2 != 0)
                    || entry.size_bytes.is_some()
                    || entry.content_digest.is_some()
                {
                    return Err(ManifestError::INVALID("invalid link fields"));
                }
            }
            "directory" | "special" => {
                if entry.size_bytes.is_some()
                    || entry.content_digest.is_some()
                    || entry.link_target_base64url.is_some()
                {
                    return Err(ManifestError::INVALID("unexpected content fields"));
                }
            }
            _ => return Err(ManifestError::INVALID("unknown entry kind")),
        }

        self.digest.add_entry(entry)?;
        self.prior_encoding = Some(entry.path_encoding.clone());
        self.prior = Some(key);

        Ok(())
    }

    pub fn finish(self) -> Result<String, ManifestError> {
        Ok(self.digest.finish()?)
    }
}

pub fn verify_file_content<R: Read>(
    entry: &ManifestEntry,
    reader: &mut R,
) -> Result<(), ManifestError> {
    if entry.kind != "file" {
        return Err(ManifestError::INVALID(
            "content verification requires a file",
        ));
    }

    let expected = parse_count(
        entry
            .size_bytes
            .as_deref()
            .ok_or(ManifestError::INVALID("missing size"))?,
    )?;
    let mut count = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];

    loop {
        let length = reader.read(&mut buffer)?;

        if length == 0 {
            break;
        }

        count = count
            .checked_add(length as u64)
            .ok_or(ManifestError::INVALID("content size overflow"))?;
        if count > expected {
            return Err(ManifestError::INVALID("content size mismatch"));
        }
        hasher.update(&buffer[..length]);
    }

    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    let digest = format!("sha256:{hex}");
    if count != expected || entry.content_digest.as_deref() != Some(digest.as_str()) {
        return Err(ManifestError::INVALID("content mismatch"));
    }

    Ok(())
}
