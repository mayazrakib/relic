use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

macro_rules! identifier {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
            #[serde(transparent)]
            pub struct $name(pub String);
        )+
    };
}

identifier!(
    AuthorityId,
    NodeId,
    ClusterId,
    JobId,
    TriggerId,
    EndpointId,
    RepositoryId,
    OccurrenceId,
    AttemptId,
    DestinationId,
    CaptureId,
    SourceViewId,
    EventId,
    CommitId,
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitKey {
    pub authority_id: AuthorityId,
    pub job_id: JobId,
    pub occurrence_id: OccurrenceId,
    pub destination_id: DestinationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarOccurrence {
    pub job_id: JobId,
    pub schedule_revision: String,
    pub trigger_id: TriggerId,
    pub intended_local_time: String,
    pub intended_utc_instant: String,
    pub fold_ordinal: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationBinding {
    pub commit_key: CommitKey,
    pub capture_id: CaptureId,
    pub source_view_id: SourceViewId,
    pub consistency: String,
    pub destination_config_revision: String,
    pub manifest_digest: String,
    pub policy_digest: String,
}

#[derive(Debug)]
pub enum IdentityError {
    InvalidInput(&'static str),
    Canonicalization(serde_json::Error),
    FrameTooLarge,
    EntryCountMismatch,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid identity input: {message}"),
            Self::Canonicalization(error) => write!(formatter, "canonicalization failed: {error}"),
            Self::FrameTooLarge => write!(formatter, "canonical frame exceeds 1 MiB"),
            Self::EntryCountMismatch => write!(formatter, "frame count does not match declaration"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn is_positive_decimal(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

fn has_timestamp_shape(value: &str, is_utc: bool) -> bool {
    let bytes = value.as_bytes();
    let expected = if is_utc { 30 } else { 29 };
    bytes.len() == expected
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && (!is_utc || bytes[29] == b'Z')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 29) || byte.is_ascii_digit()
        })
}

fn finish_hash(hasher: Sha256) -> String {
    let bytes = hasher.finalize();
    let mut result = String::from("sha256:");

    for byte in bytes {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("writing to a string cannot fail");
    }

    result
}

pub fn hash_domain<T: Serialize>(domain: &str, value: &T) -> Result<String, IdentityError> {
    let canonical = serde_jcs::to_vec(value).map_err(IdentityError::Canonicalization)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);

    Ok(finish_hash(hasher))
}

impl CalendarOccurrence {
    pub fn digest(&self) -> Result<OccurrenceId, IdentityError> {
        if !is_positive_decimal(&self.schedule_revision)
            || self.fold_ordinal > 1
            || !has_timestamp_shape(&self.intended_local_time, false)
            || !has_timestamp_shape(&self.intended_utc_instant, true)
        {
            return Err(IdentityError::InvalidInput("invalid calendar tuple"));
        }

        Ok(OccurrenceId(hash_domain(
            "relic/occurrence/calendar/v1",
            self,
        )?))
    }
}

impl PublicationBinding {
    pub fn digest(&self) -> Result<String, IdentityError> {
        if !is_positive_decimal(&self.destination_config_revision) {
            return Err(IdentityError::InvalidInput("invalid destination revision"));
        }

        hash_domain("relic/publication/payload/v1", self)
    }
}

/// Streams canonical frames; callers validate schema, ordering, and content separately.
pub struct FramedDigest {
    hasher: Sha256,
    expected_entries: u64,
    actual_entries: u64,
}

impl FramedDigest {
    pub fn new<T: Serialize>(
        domain: &str,
        header: &T,
        expected_entries: u64,
    ) -> Result<Self, IdentityError> {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0]);
        let mut digest = Self {
            hasher,
            expected_entries,
            actual_entries: 0,
        };
        digest.write_frame(header)?;

        Ok(digest)
    }

    fn write_frame<T: Serialize>(&mut self, value: &T) -> Result<(), IdentityError> {
        let bytes = serde_jcs::to_vec(value).map_err(IdentityError::Canonicalization)?;

        if bytes.len() > 1024 * 1024 {
            return Err(IdentityError::FrameTooLarge);
        }

        self.hasher.update((bytes.len() as u32).to_be_bytes());
        self.hasher.update(bytes);

        Ok(())
    }

    pub fn add_entry<T: Serialize>(&mut self, entry: &T) -> Result<(), IdentityError> {
        if self.actual_entries >= self.expected_entries {
            return Err(IdentityError::EntryCountMismatch);
        }

        self.write_frame(entry)?;
        self.actual_entries += 1;

        Ok(())
    }

    pub fn finish(self) -> Result<String, IdentityError> {
        if self.actual_entries != self.expected_entries {
            return Err(IdentityError::EntryCountMismatch);
        }

        Ok(finish_hash(self.hasher))
    }
}
