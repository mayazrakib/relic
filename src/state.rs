use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::staging_quota::{
    MAX_STAGING_BYTES, MAX_STAGING_OBJECTS, MIN_FREE_BYTES, StagingQuotaBinding, StagingQuotaRecord,
};

const INITIALIZATION_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const CURRENT_SCHEMA_VERSION: u32 = 9;

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    Database(rusqlite::Error),
    Json(serde_json::Error),
    InvalidInput,
    RevisionConflict,
    IdempotencyConflict,
    EffectConflict,
    UnsupportedVersion,
    InsecureDirectory,
    QuotaExceeded,
    InventoryRequired,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io(_) => "State storage I/O failed.",
            Self::Database(_) => "State database operation failed.",
            Self::Json(_) => "State record encoding failed.",
            Self::InvalidInput => "The state record is invalid.",
            Self::RevisionConflict => "The expected job revision does not match.",
            Self::IdempotencyConflict => "The commit key is already bound to another payload.",
            Self::EffectConflict => "The effect transition requires reconciliation.",
            Self::UnsupportedVersion => "The state database requires a different schema version.",
            Self::QuotaExceeded => "The staging quota or free-space reserve is exhausted.",
            Self::InventoryRequired => "The staging quota inventory is incomplete.",
            Self::InsecureDirectory => {
                "The state directory must be private and must not be a symbolic link."
            }
        };

        formatter.write_str(message)
    }
}

impl Error for StateError {}

impl From<rusqlite::Error> for StateError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<serde_json::Error> for StateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<std::io::Error> for StateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub job_id: String,
    pub revision: u32,
    pub definition: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationRecord {
    pub commit_key: Value,
    pub payload_hash: String,
    pub binding: Value,
    pub effect_state: String,
    pub native_result_id: Option<String>,
    pub receipt: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBinding {
    pub authority_id: String,
    pub job_id: String,
    pub occurrence_id: String,
    pub capture_id: String,
    pub source_view_id: String,
    pub consistency: String,
    pub source_selection_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRecord {
    pub binding: CaptureBinding,
    pub manifest_digest: Option<String>,
    pub manifest_entry_count: Option<String>,
    pub manifest_artifact_id: Option<String>,
    pub payload_artifact_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestArtifactBinding {
    pub artifact_id: String,
    pub capture_id: String,
    pub storage_endpoint_id: String,
    pub storage_identity: String,
    pub relative_name: String,
    pub key_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifactRecord {
    pub binding: ManifestArtifactBinding,
    pub effect_state: String,
    pub ciphertext_digest: Option<String>,
    pub ciphertext_bytes: Option<String>,
    pub manifest_digest: Option<String>,
    pub manifest_entry_count: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadArtifactBinding {
    pub artifact_id: String,
    pub capture_id: String,
    pub storage_endpoint_id: String,
    pub storage_identity: String,
    pub relative_name: String,
    pub key_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadArtifactRecord {
    pub binding: PayloadArtifactBinding,
    pub effect_state: String,
    pub ciphertext_digest: Option<String>,
    pub ciphertext_bytes: Option<String>,
    pub manifest_digest: Option<String>,
    pub manifest_entry_count: Option<String>,
    pub file_count: Option<String>,
    pub payload_bytes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadArtifactSeal {
    pub ciphertext_digest: String,
    pub ciphertext_bytes: u64,
    pub manifest_digest: String,
    pub manifest_entry_count: u64,
    pub file_count: u64,
    pub payload_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBinding {
    pub restore_id: String,
    pub capture_id: String,
    pub payload_artifact_id: String,
    pub target_endpoint_id: String,
    pub target_identity: String,
    pub relative_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRecord {
    pub binding: RestoreBinding,
    pub effect_state: String,
    pub manifest_digest: String,
    pub payload_ciphertext_digest: String,
    pub manifest_entry_count: String,
    pub file_count: String,
    pub payload_bytes: String,
    pub staging_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveStageBinding {
    pub stage_id: String,
    pub capture_id: String,
    pub payload_artifact_id: String,
    pub storage_endpoint_id: String,
    pub storage_identity: String,
    pub key_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveStageRecord {
    pub binding: ArchiveStageBinding,
    pub effect_state: String,
    pub manifest_digest: String,
    pub manifest_entry_count: String,
    pub payload_ciphertext_digest: String,
    pub file_count: String,
    pub payload_bytes: String,
    pub catalog_ciphertext_digest: Option<String>,
    pub catalog_ciphertext_bytes: Option<String>,
    pub catalog_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveFileRecord {
    pub stage_id: String,
    pub file_id: String,
    pub header_digest: String,
    pub plaintext_bytes: String,
    pub effect_state: String,
    pub ciphertext_digest: Option<String>,
    pub ciphertext_bytes: Option<String>,
    pub identity: Option<String>,
}

type ArchiveFileSealRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
type ArchiveStageSealRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRunBinding {
    pub run_id: String,
    pub stage_id: String,
    pub storage_endpoint_id: String,
    pub storage_identity: String,
    pub relative_name: String,
    pub repository_key_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRunRecord {
    pub binding: NativeRunBinding,
    pub capture_id: String,
    pub manifest_digest: String,
    pub manifest_entry_count: String,
    pub file_count: String,
    pub payload_bytes: String,
    pub source_catalog_digest: String,
    pub source_key_ref: String,
    pub effect_state: String,
    pub container_identity: Option<String>,
    pub repository_identity: Option<String>,
    pub owner_lock_identity: Option<String>,
    pub scratch_identity: Option<String>,
    pub native_snapshot_id: Option<String>,
    pub active_operation: Option<String>,
    pub creation_attempts: u32,
    pub verification_attempts: u64,
    pub verification_failures: u32,
}

type RestoreSnapshot = (String, String, String, String, String);
type RestorePrior = (String, String, String, String, String, String);

type PublicationRow = (String, String, String, Option<String>, Option<String>);
type ArtifactSealRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

type PayloadSealRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type PayloadCaptureRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub struct StateStore {
    pub(crate) connection: Connection,
}

impl StateStore {
    /// Opens the current schema without initialization; a writer must retain the existing WAL and SHM files.
    pub fn open_readonly(directory: &Path) -> Result<Self, StateError> {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(StateError::InsecureDirectory);
        }

        let canonical_directory = fs::canonicalize(directory)?;
        let canonical_metadata = fs::metadata(&canonical_directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
            let owner = unsafe { libc::geteuid() };
            if metadata.dev() != canonical_metadata.dev()
                || metadata.ino() != canonical_metadata.ino()
                || metadata.uid() != owner
                || metadata.mode() & 0o077 != 0
            {
                return Err(StateError::InsecureDirectory);
            }
        }
        #[cfg(not(unix))]
        if !canonical_metadata.is_dir() {
            return Err(StateError::InsecureDirectory);
        }

        let path = canonical_directory.join("state.sqlite3");
        let database = validate_readonly_state_file(&path)?;
        validate_readonly_state_file(&canonical_directory.join("state.sqlite3-wal"))?;
        validate_readonly_state_file(&canonical_directory.join("state.sqlite3-shm"))?;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", true)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != CURRENT_SCHEMA_VERSION {
            return Err(StateError::UnsupportedVersion);
        }
        let current = validate_readonly_state_file(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if database.dev() != current.dev() || database.ino() != current.ino() {
                return Err(StateError::InsecureDirectory);
            }
        }
        #[cfg(not(unix))]
        let _ = (database, current);
        Ok(Self { connection })
    }

    pub fn open(directory: &Path) -> Result<Self, StateError> {
        if !directory.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }

            builder.create(directory)?;
        }

        let metadata = fs::symlink_metadata(directory)?;

        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(StateError::InsecureDirectory);
        }

        let canonical_directory = fs::canonicalize(directory)?;
        let canonical_metadata = fs::metadata(&canonical_directory)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if canonical_metadata.dev() != metadata.dev()
                || canonical_metadata.ino() != metadata.ino()
            {
                return Err(StateError::InsecureDirectory);
            }
        }

        #[cfg(not(unix))]
        if !canonical_metadata.is_dir() {
            return Err(StateError::InsecureDirectory);
        }

        let directory = canonical_directory.as_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            // SAFETY: geteuid has no arguments and no memory safety preconditions.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(StateError::InsecureDirectory);
            }
        }

        let mut lock_options = fs::OpenOptions::new();
        lock_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }

        let bootstrap_lock = lock_options.open(directory.join("state.lock"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let lock_metadata = bootstrap_lock.metadata()?;

            if !lock_metadata.is_file()
                || lock_metadata.uid() != metadata.uid()
                || lock_metadata.mode() & 0o077 != 0
                || lock_metadata.nlink() != 1
            {
                return Err(StateError::InsecureDirectory);
            }
        }

        let deadline = Instant::now() + INITIALIZATION_LOCK_TIMEOUT;

        loop {
            match bootstrap_lock.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "state initialization lock timed out",
                    )
                    .into());
                }
                Err(fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

            // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
            let effective_user = unsafe { libc::geteuid() };

            if metadata.uid() != effective_user || metadata.mode() & 0o077 != 0 {
                return Err(StateError::InsecureDirectory);
            }

            let path = directory.join("state.sqlite3");
            let creation = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path);

            if let Err(error) = creation
                && error.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(error.into());
            }

            let file = fs::symlink_metadata(&path)?;

            if !file.is_file()
                || file.uid() != effective_user
                || file.mode() & 0o077 != 0
                || file.nlink() != 1
            {
                return Err(StateError::InsecureDirectory);
            }
        }

        let path = directory.join("state.sqlite3");

        if fs::symlink_metadata(&path).is_ok_and(|value| value.file_type().is_symlink()) {
            return Err(StateError::InsecureDirectory);
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let journal: String =
            connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        let synchronous: u32 =
            connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;

        if journal != "wal" || synchronous != 2 {
            return Err(StateError::EffectConflict);
        }

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;

        if version > CURRENT_SCHEMA_VERSION {
            return Err(StateError::UnsupportedVersion);
        }
        if version == 0 {
            transaction
                .execute_batch(include_str!("../database/migrations/00001_initialize.sql"))?;
        }
        if version <= 1 {
            transaction.execute_batch(include_str!("../database/migrations/00002_capture.sql"))?;
        }
        if version <= 2 {
            transaction.execute_batch(include_str!(
                "../database/migrations/00003_manifest_artifacts.sql"
            ))?;
        }
        if version <= 3 {
            transaction.execute_batch(include_str!(
                "../database/migrations/00004_payload_artifacts.sql"
            ))?;
        }
        if version <= 4 {
            transaction.execute_batch(include_str!(
                "../database/migrations/00005_restore_intents.sql"
            ))?;
        }

        if version <= 5 {
            transaction.execute_batch(include_str!(
                "../database/migrations/00006_archive_stages.sql"
            ))?;
        }

        if version <= 6 {
            transaction
                .execute_batch(include_str!("../database/migrations/00007_native_runs.sql"))?;
        }

        if version <= 7 {
            transaction.execute_batch(include_str!(
                "../database/migrations/00008_staging_quota.sql"
            ))?;
        }

        if version <= 8 {
            transaction.execute_batch(include_str!("../database/migrations/00009_gateway.sql"))?;
        }

        transaction.commit()?;
        drop(bootstrap_lock);

        Ok(Self { connection })
    }

    pub fn check_integrity(&self) -> Result<bool, StateError> {
        let result: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        let synchronous: u32 = self
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))?;
        let journal: String = self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))?;

        Ok(result == "ok" && synchronous == 2 && journal == "wal")
    }

    pub fn get_node_id(&mut self) -> Result<String, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO node_metadata (key, value) VALUES ('node_id', ?1)",
            [uuid::Uuid::now_v7().to_string()],
        )?;
        let node_id = transaction.query_row(
            "SELECT value FROM node_metadata WHERE key = 'node_id'",
            [],
            |row| row.get(0),
        )?;
        transaction.commit()?;

        Ok(node_id)
    }

    pub fn put_job(
        &mut self,
        definition: &Value,
        expected_revision: Option<u32>,
    ) -> Result<JobRecord, StateError> {
        self.put_job_internal(definition, expected_revision, None)
    }

    pub fn put_job_idempotent(
        &mut self,
        definition: &Value,
        expected_revision: Option<u32>,
        request_key: &str,
    ) -> Result<JobRecord, StateError> {
        if request_key.is_empty() || request_key.len() > 128 {
            return Err(StateError::InvalidInput);
        }

        self.put_job_internal(definition, expected_revision, Some(request_key))
    }

    fn put_job_internal(
        &mut self,
        definition: &Value,
        expected_revision: Option<u32>,
        request_key: Option<&str>,
    ) -> Result<JobRecord, StateError> {
        let job_id = definition
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or(StateError::InvalidInput)?;
        let revision = definition
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or(StateError::InvalidInput)?;

        if !(1..=i32::MAX as u64).contains(&revision) {
            return Err(StateError::InvalidInput);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_binding = serde_jcs::to_string(
            &serde_json::json!({"definition":definition,"expected_revision":expected_revision}),
        )?;

        if let Some(key) = request_key {
            let previous: Option<(String, String)> = transaction
                .query_row(
                    "SELECT binding, result FROM job_requests WHERE request_key = ?1",
                    [key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            if let Some((binding, result)) = previous {
                if binding != request_binding {
                    return Err(StateError::IdempotencyConflict);
                }

                return Ok(serde_json::from_str(&result)?);
            }
        }

        let prior: Option<u32> = transaction
            .query_row(
                "SELECT revision FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| row.get(0),
            )
            .optional()?;

        if prior != expected_revision
            || prior.is_some_and(|value| revision != u64::from(value) + 1)
            || (prior.is_none() && revision != 1)
        {
            return Err(StateError::RevisionConflict);
        }

        transaction.execute(
            "INSERT INTO jobs (job_id, revision, definition) VALUES (?1, ?2, ?3) ON CONFLICT(job_id) DO UPDATE SET revision = excluded.revision, definition = excluded.definition, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![job_id, revision as i64, serde_json::to_string(definition)?],
        )?;
        transaction.execute(
            "INSERT INTO events (event_type, subject_id) VALUES ('job_changed', ?1)",
            [job_id],
        )?;
        let result = JobRecord {
            job_id: job_id.to_owned(),
            revision: revision as u32,
            definition: definition.clone(),
        };

        if let Some(key) = request_key {
            transaction.execute(
                "INSERT INTO job_requests (request_key, binding, result) VALUES (?1, ?2, ?3)",
                params![key, request_binding, serde_json::to_string(&result)?],
            )?;
        }

        transaction.commit()?;

        Ok(result)
    }

    pub fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>, StateError> {
        let value: Option<(u32, String)> = self
            .connection
            .query_row(
                "SELECT revision, definition FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        value
            .map(|(revision, text)| {
                Ok(JobRecord {
                    job_id: job_id.to_owned(),
                    revision,
                    definition: serde_json::from_str(&text)?,
                })
            })
            .transpose()
    }

    pub fn list_jobs(&self, after: &str, limit: u32) -> Result<Vec<JobRecord>, StateError> {
        if !(1..=1_000).contains(&limit) {
            return Err(StateError::InvalidInput);
        }

        let mut statement = self.connection.prepare("SELECT job_id, revision, definition FROM jobs WHERE job_id > ?1 ORDER BY job_id LIMIT ?2")?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut jobs = Vec::new();

        for row in rows {
            let (job_id, revision, text) = row?;
            jobs.push(JobRecord {
                job_id,
                revision,
                definition: serde_json::from_str(&text)?,
            });
        }

        Ok(jobs)
    }

    pub fn bind_capture(&mut self, binding: &CaptureBinding) -> Result<CaptureRecord, StateError> {
        validate_capture_binding(binding)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(String, String, String, String, String, String, String)> = transaction.query_row(
            "SELECT capture_id, authority_id, job_id, occurrence_id, source_view_id, consistency, source_selection_digest FROM captures WHERE capture_id = ?1 OR (authority_id = ?2 AND job_id = ?3 AND occurrence_id = ?4)",
            params![binding.capture_id, binding.authority_id, binding.job_id, binding.occurrence_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).optional()?;
        if let Some(previous) = previous {
            let expected = (
                binding.capture_id.clone(),
                binding.authority_id.clone(),
                binding.job_id.clone(),
                binding.occurrence_id.clone(),
                binding.source_view_id.clone(),
                binding.consistency.clone(),
                binding.source_selection_digest.clone(),
            );
            if previous != expected {
                return Err(StateError::IdempotencyConflict);
            }
        } else {
            transaction.execute("INSERT INTO captures (capture_id, authority_id, job_id, occurrence_id, source_view_id, consistency, source_selection_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![binding.capture_id, binding.authority_id, binding.job_id, binding.occurrence_id, binding.source_view_id, binding.consistency, binding.source_selection_digest])?;
        }
        transaction.commit()?;
        self.get_capture(&binding.capture_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn get_capture(&self, capture_id: &str) -> Result<Option<CaptureRecord>, StateError> {
        self.connection.query_row("SELECT authority_id, job_id, occurrence_id, capture_id, source_view_id, consistency, source_selection_digest, manifest_digest, manifest_entry_count, manifest_artifact_id, payload_artifact_id FROM captures WHERE capture_id = ?1", [capture_id], |row| {
            Ok(CaptureRecord { binding: CaptureBinding { authority_id: row.get(0)?, job_id: row.get(1)?, occurrence_id: row.get(2)?, capture_id: row.get(3)?, source_view_id: row.get(4)?, consistency: row.get(5)?, source_selection_digest: row.get(6)? }, manifest_digest: row.get(7)?, manifest_entry_count: row.get(8)?, manifest_artifact_id: row.get(9)?, payload_artifact_id: row.get(10)? })
        }).optional().map_err(StateError::from)
    }

    pub fn freeze_capture_manifest(
        &mut self,
        capture_id: &str,
        manifest_digest: &str,
        entry_count: u64,
    ) -> Result<CaptureRecord, StateError> {
        if !is_digest(&Value::String(manifest_digest.to_owned())) {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(Option<String>, Option<String>)> = transaction
            .query_row(
                "SELECT manifest_digest, manifest_entry_count FROM captures WHERE capture_id = ?1",
                [capture_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (digest, count) = previous.ok_or(StateError::EffectConflict)?;
        let entry_count = entry_count.to_string();
        if digest
            .as_deref()
            .is_some_and(|value| value != manifest_digest)
            || count.as_deref().is_some_and(|value| value != entry_count)
        {
            return Err(StateError::IdempotencyConflict);
        }
        if digest.is_none() {
            transaction.execute("UPDATE captures SET manifest_digest = ?1, manifest_entry_count = ?2, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE capture_id = ?3", params![manifest_digest, entry_count, capture_id])?;
        }
        transaction.commit()?;
        self.get_capture(capture_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn list_pending_captures(
        &self,
        after_capture_id: &str,
        limit: u32,
    ) -> Result<Vec<CaptureRecord>, StateError> {
        if !(1..=1000).contains(&limit) || after_capture_id.len() > 128 {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT capture_id FROM captures WHERE manifest_digest IS NULL AND capture_id > ?1 ORDER BY capture_id LIMIT ?2")?;
        let rows = statement.query_map(params![after_capture_id, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(self.get_capture(&row?)?.ok_or(StateError::EffectConflict)?);
        }
        Ok(records)
    }

    pub fn prepare_manifest_artifact(
        &mut self,
        binding: &ManifestArtifactBinding,
    ) -> Result<ManifestArtifactRecord, StateError> {
        validate_artifact_binding(binding)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String, String, String, String, String)> = transaction.query_row(
            "SELECT artifact_id, capture_id, storage_endpoint_id, storage_identity, relative_name, key_ref, effect_state FROM manifest_artifacts WHERE artifact_id = ?1 OR capture_id = ?2",
            params![binding.artifact_id, binding.capture_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).optional()?;
        if let Some((artifact_id, capture_id, endpoint, identity, name, key_ref, state)) = existing
        {
            if artifact_id != binding.artifact_id
                || capture_id != binding.capture_id
                || endpoint != binding.storage_endpoint_id
                || identity != binding.storage_identity
                || name != binding.relative_name
                || key_ref != binding.key_ref
            {
                return Err(StateError::IdempotencyConflict);
            }
            if state == "abandoned" {
                return Err(StateError::EffectConflict);
            }
        } else {
            let capture_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM captures WHERE capture_id = ?1)",
                [&binding.capture_id],
                |row| row.get(0),
            )?;
            if !capture_exists {
                return Err(StateError::EffectConflict);
            }
            transaction.execute("INSERT INTO manifest_artifacts (artifact_id, capture_id, storage_endpoint_id, storage_identity, relative_name, key_ref, effect_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared')", params![binding.artifact_id, binding.capture_id, binding.storage_endpoint_id, binding.storage_identity, binding.relative_name, binding.key_ref])?;
        }
        transaction.commit()?;
        self.get_manifest_artifact(&binding.artifact_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn get_manifest_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ManifestArtifactRecord>, StateError> {
        if !valid_identifier_text(artifact_id) {
            return Err(StateError::InvalidInput);
        }
        self.connection.query_row("SELECT artifact_id, capture_id, storage_endpoint_id, storage_identity, relative_name, key_ref, effect_state, ciphertext_digest, ciphertext_bytes, manifest_digest, manifest_entry_count FROM manifest_artifacts WHERE artifact_id = ?1", [artifact_id], |row| {
            Ok(ManifestArtifactRecord { binding: ManifestArtifactBinding { artifact_id: row.get(0)?, capture_id: row.get(1)?, storage_endpoint_id: row.get(2)?, storage_identity: row.get(3)?, relative_name: row.get(4)?, key_ref: row.get(5)? }, effect_state: row.get(6)?, ciphertext_digest: row.get(7)?, ciphertext_bytes: row.get(8)?, manifest_digest: row.get(9)?, manifest_entry_count: row.get(10)? })
        }).optional().map_err(StateError::from)
    }

    pub fn get_capture_artifact(
        &self,
        capture_id: &str,
    ) -> Result<Option<ManifestArtifactRecord>, StateError> {
        if !valid_identifier_text(capture_id) {
            return Err(StateError::InvalidInput);
        }
        let artifact_id: Option<String> = self
            .connection
            .query_row(
                "SELECT artifact_id FROM manifest_artifacts WHERE capture_id = ?1",
                [capture_id],
                |row| row.get(0),
            )
            .optional()?;
        artifact_id
            .map(|id| {
                self.get_manifest_artifact(&id)?
                    .ok_or(StateError::EffectConflict)
            })
            .transpose()
    }

    pub fn list_pending_artifacts(
        &self,
        after_artifact_id: &str,
        limit: u32,
    ) -> Result<Vec<ManifestArtifactRecord>, StateError> {
        if !(1..=1000).contains(&limit) || after_artifact_id.len() > 128 {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT artifact_id FROM manifest_artifacts WHERE effect_state = 'prepared' AND artifact_id > ?1 ORDER BY artifact_id LIMIT ?2")?;
        let rows = statement.query_map(params![after_artifact_id, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(
                self.get_manifest_artifact(&row?)?
                    .ok_or(StateError::EffectConflict)?,
            );
        }
        Ok(records)
    }

    pub fn seal_manifest_artifact(
        &mut self,
        artifact_id: &str,
        ciphertext_digest: &str,
        ciphertext_bytes: u64,
        manifest_digest: &str,
        manifest_entry_count: u64,
    ) -> Result<ManifestArtifactRecord, StateError> {
        if !valid_identifier_text(artifact_id)
            || !valid_digest_text(ciphertext_digest)
            || !valid_digest_text(manifest_digest)
        {
            return Err(StateError::InvalidInput);
        }
        let ciphertext_bytes = ciphertext_bytes.to_string();
        let manifest_entry_count = manifest_entry_count.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<ArtifactSealRow> = transaction.query_row("SELECT capture_id, effect_state, ciphertext_digest, ciphertext_bytes, manifest_digest, manifest_entry_count FROM manifest_artifacts WHERE artifact_id = ?1", [artifact_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).optional()?;
        let (capture_id, state, prior_cipher, prior_size, prior_manifest, prior_count) =
            prior.ok_or(StateError::EffectConflict)?;
        if state == "abandoned" {
            return Err(StateError::EffectConflict);
        }
        if state == "sealed" {
            if prior_cipher.as_deref() != Some(ciphertext_digest)
                || prior_size.as_deref() != Some(ciphertext_bytes.as_str())
                || prior_manifest.as_deref() != Some(manifest_digest)
                || prior_count.as_deref() != Some(manifest_entry_count.as_str())
            {
                return Err(StateError::IdempotencyConflict);
            }
        } else if state == "prepared" {
            let capture: (Option<String>, Option<String>, Option<String>) = transaction.query_row("SELECT manifest_digest, manifest_entry_count, manifest_artifact_id FROM captures WHERE capture_id = ?1", [&capture_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            if capture
                .0
                .as_deref()
                .is_some_and(|value| value != manifest_digest)
                || capture
                    .1
                    .as_deref()
                    .is_some_and(|value| value != manifest_entry_count)
                || capture
                    .2
                    .as_deref()
                    .is_some_and(|value| value != artifact_id)
            {
                return Err(StateError::IdempotencyConflict);
            }
            transaction.execute("UPDATE captures SET manifest_digest = ?1, manifest_entry_count = ?2, manifest_artifact_id = ?3, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE capture_id = ?4", params![manifest_digest, manifest_entry_count, artifact_id, capture_id])?;
            transaction.execute("UPDATE manifest_artifacts SET effect_state = 'sealed', ciphertext_digest = ?1, ciphertext_bytes = ?2, manifest_digest = ?3, manifest_entry_count = ?4, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE artifact_id = ?5 AND effect_state = 'prepared'", params![ciphertext_digest, ciphertext_bytes, manifest_digest, manifest_entry_count, artifact_id])?;
        } else {
            return Err(StateError::EffectConflict);
        }
        transaction.commit()?;
        self.get_manifest_artifact(artifact_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn abandon_manifest_artifact(
        &mut self,
        artifact_id: &str,
    ) -> Result<ManifestArtifactRecord, StateError> {
        if !valid_identifier_text(artifact_id) {
            return Err(StateError::InvalidInput);
        }
        let changed = self.connection.execute("UPDATE manifest_artifacts SET effect_state = 'abandoned', system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE artifact_id = ?1 AND effect_state = 'prepared'", [artifact_id])?;
        if changed != 1 {
            return Err(StateError::EffectConflict);
        }
        self.get_manifest_artifact(artifact_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn prepare_payload_artifact(
        &mut self,
        binding: &PayloadArtifactBinding,
    ) -> Result<PayloadArtifactRecord, StateError> {
        validate_payload_binding(binding)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String, String, String, String, String)> = transaction.query_row(
            "SELECT artifact_id, capture_id, storage_endpoint_id, storage_identity, relative_name, key_ref, effect_state FROM payload_artifacts WHERE artifact_id = ?1 OR capture_id = ?2",
            params![binding.artifact_id, binding.capture_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).optional()?;
        if let Some((artifact_id, capture_id, endpoint, identity, name, key_ref, state)) = existing
        {
            if artifact_id != binding.artifact_id
                || capture_id != binding.capture_id
                || endpoint != binding.storage_endpoint_id
                || identity != binding.storage_identity
                || name != binding.relative_name
                || key_ref != binding.key_ref
            {
                return Err(StateError::IdempotencyConflict);
            }
            if state == "abandoned" {
                return Err(StateError::EffectConflict);
            }
        } else {
            let capture_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM captures WHERE capture_id = ?1)",
                [&binding.capture_id],
                |row| row.get(0),
            )?;
            if !capture_exists {
                return Err(StateError::EffectConflict);
            }
            transaction.execute("INSERT INTO payload_artifacts (artifact_id, capture_id, storage_endpoint_id, storage_identity, relative_name, key_ref, effect_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared')", params![binding.artifact_id, binding.capture_id, binding.storage_endpoint_id, binding.storage_identity, binding.relative_name, binding.key_ref])?;
        }
        transaction.commit()?;
        self.get_payload_artifact(&binding.artifact_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn get_payload_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<PayloadArtifactRecord>, StateError> {
        if !valid_identifier_text(artifact_id) {
            return Err(StateError::InvalidInput);
        }
        self.connection.query_row("SELECT artifact_id, capture_id, storage_endpoint_id, storage_identity, relative_name, key_ref, effect_state, ciphertext_digest, ciphertext_bytes, manifest_digest, manifest_entry_count, file_count, payload_bytes FROM payload_artifacts WHERE artifact_id = ?1", [artifact_id], |row| {
            Ok(PayloadArtifactRecord { binding: PayloadArtifactBinding { artifact_id: row.get(0)?, capture_id: row.get(1)?, storage_endpoint_id: row.get(2)?, storage_identity: row.get(3)?, relative_name: row.get(4)?, key_ref: row.get(5)? }, effect_state: row.get(6)?, ciphertext_digest: row.get(7)?, ciphertext_bytes: row.get(8)?, manifest_digest: row.get(9)?, manifest_entry_count: row.get(10)?, file_count: row.get(11)?, payload_bytes: row.get(12)? })
        }).optional().map_err(StateError::from)
    }

    pub fn get_capture_payload(
        &self,
        capture_id: &str,
    ) -> Result<Option<PayloadArtifactRecord>, StateError> {
        if !valid_identifier_text(capture_id) {
            return Err(StateError::InvalidInput);
        }
        let artifact_id: Option<String> = self
            .connection
            .query_row(
                "SELECT artifact_id FROM payload_artifacts WHERE capture_id = ?1",
                [capture_id],
                |row| row.get(0),
            )
            .optional()?;
        artifact_id
            .map(|id| {
                self.get_payload_artifact(&id)?
                    .ok_or(StateError::EffectConflict)
            })
            .transpose()
    }

    pub fn list_pending_payloads(
        &self,
        after_artifact_id: &str,
        limit: u32,
    ) -> Result<Vec<PayloadArtifactRecord>, StateError> {
        if !(1..=1000).contains(&limit) || after_artifact_id.len() > 128 {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT artifact_id FROM payload_artifacts WHERE effect_state = 'prepared' AND artifact_id > ?1 ORDER BY artifact_id LIMIT ?2")?;
        let rows = statement.query_map(params![after_artifact_id, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(
                self.get_payload_artifact(&row?)?
                    .ok_or(StateError::EffectConflict)?,
            );
        }
        Ok(records)
    }

    pub fn seal_payload_artifact(
        &mut self,
        artifact_id: &str,
        seal: &PayloadArtifactSeal,
    ) -> Result<PayloadArtifactRecord, StateError> {
        if !valid_identifier_text(artifact_id)
            || artifact_id.contains(':')
            || !valid_digest_text(&seal.ciphertext_digest)
            || !valid_digest_text(&seal.manifest_digest)
            || seal.ciphertext_bytes < 60
            || seal.file_count > seal.manifest_entry_count
            || (seal.file_count == 0 && seal.payload_bytes != 0)
        {
            return Err(StateError::InvalidInput);
        }
        let cipher_bytes = seal.ciphertext_bytes.to_string();
        let manifest_count = seal.manifest_entry_count.to_string();
        let file_count = seal.file_count.to_string();
        let payload_bytes = seal.payload_bytes.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<PayloadSealRow> = transaction.query_row("SELECT capture_id, effect_state, ciphertext_digest, ciphertext_bytes, manifest_digest, manifest_entry_count, file_count, payload_bytes FROM payload_artifacts WHERE artifact_id = ?1", [artifact_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?))).optional()?;
        let (
            capture_id,
            state,
            previous_cipher,
            previous_size,
            previous_manifest,
            previous_count,
            previous_files,
            previous_bytes,
        ) = prior.ok_or(StateError::EffectConflict)?;
        if state == "abandoned" {
            return Err(StateError::EffectConflict);
        }
        if state == "sealed" {
            if previous_cipher.as_deref() != Some(seal.ciphertext_digest.as_str())
                || previous_size.as_deref() != Some(cipher_bytes.as_str())
                || previous_manifest.as_deref() != Some(seal.manifest_digest.as_str())
                || previous_count.as_deref() != Some(manifest_count.as_str())
                || previous_files.as_deref() != Some(file_count.as_str())
                || previous_bytes.as_deref() != Some(payload_bytes.as_str())
            {
                return Err(StateError::IdempotencyConflict);
            }
        } else if state == "prepared" {
            let capture: Option<PayloadCaptureRow> = transaction.query_row("SELECT c.manifest_digest, c.manifest_entry_count, c.manifest_artifact_id, c.payload_artifact_id, m.effect_state, m.manifest_digest, m.manifest_entry_count FROM captures c LEFT JOIN manifest_artifacts m ON m.artifact_id = c.manifest_artifact_id AND m.capture_id = c.capture_id WHERE c.capture_id = ?1", [&capture_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))).optional()?;
            let (
                digest,
                count,
                manifest_id,
                payload_id,
                manifest_state,
                artifact_digest,
                artifact_count,
            ) = capture.ok_or(StateError::EffectConflict)?;
            if manifest_id.is_none() || manifest_state.as_deref() != Some("sealed") {
                return Err(StateError::EffectConflict);
            }
            if digest.as_deref() != Some(seal.manifest_digest.as_str())
                || count.as_deref() != Some(manifest_count.as_str())
                || artifact_digest.as_deref() != Some(seal.manifest_digest.as_str())
                || artifact_count.as_deref() != Some(manifest_count.as_str())
                || payload_id.as_deref().is_some_and(|id| id != artifact_id)
            {
                return Err(StateError::IdempotencyConflict);
            }
            transaction.execute("UPDATE captures SET payload_artifact_id = ?1, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE capture_id = ?2", params![artifact_id, capture_id])?;
            transaction.execute("UPDATE payload_artifacts SET effect_state = 'sealed', ciphertext_digest = ?1, ciphertext_bytes = ?2, manifest_digest = ?3, manifest_entry_count = ?4, file_count = ?5, payload_bytes = ?6, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE artifact_id = ?7 AND effect_state = 'prepared'", params![seal.ciphertext_digest, cipher_bytes, seal.manifest_digest, manifest_count, file_count, payload_bytes, artifact_id])?;
        } else {
            return Err(StateError::EffectConflict);
        }
        transaction.commit()?;
        self.get_payload_artifact(artifact_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn abandon_payload_artifact(
        &mut self,
        artifact_id: &str,
    ) -> Result<PayloadArtifactRecord, StateError> {
        if !valid_identifier_text(artifact_id) {
            return Err(StateError::InvalidInput);
        }
        let changed = self.connection.execute("UPDATE payload_artifacts SET effect_state = 'abandoned', system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE artifact_id = ?1 AND effect_state = 'prepared'", [artifact_id])?;
        if changed != 1 {
            return Err(StateError::EffectConflict);
        }
        self.get_payload_artifact(artifact_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn prepare_restore(
        &mut self,
        binding: &RestoreBinding,
    ) -> Result<RestoreRecord, StateError> {
        validate_restore_binding(binding)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<RestorePrior> = transaction.query_row("SELECT capture_id, payload_artifact_id, target_endpoint_id, target_identity, relative_name, effect_state FROM restore_intents WHERE restore_id = ?1", [&binding.restore_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).optional()?;
        if let Some((capture, payload, endpoint, identity, name, state)) = prior {
            if capture != binding.capture_id
                || payload != binding.payload_artifact_id
                || endpoint != binding.target_endpoint_id
                || identity != binding.target_identity
                || name != binding.relative_name
            {
                return Err(StateError::IdempotencyConflict);
            }
            if state == "abandoned" {
                return Err(StateError::EffectConflict);
            }
        } else {
            let reserved: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM restore_intents WHERE (target_endpoint_id = ?1 OR target_identity = ?2) AND relative_name = ?3 AND effect_state IN ('prepared', 'staging', 'verified', 'published'))", params![binding.target_endpoint_id, binding.target_identity, binding.relative_name], |row| row.get(0))?;
            if reserved {
                return Err(StateError::EffectConflict);
            }
            let snapshot: Option<RestoreSnapshot> = transaction.query_row("SELECT p.manifest_digest, p.ciphertext_digest, p.manifest_entry_count, p.file_count, p.payload_bytes FROM captures c JOIN payload_artifacts p ON p.artifact_id = c.payload_artifact_id AND p.capture_id = c.capture_id JOIN manifest_artifacts m ON m.artifact_id = c.manifest_artifact_id AND m.capture_id = c.capture_id WHERE c.capture_id = ?1 AND p.artifact_id = ?2 AND p.effect_state = 'sealed' AND m.effect_state = 'sealed' AND c.manifest_digest = p.manifest_digest AND c.manifest_digest = m.manifest_digest AND c.manifest_entry_count = p.manifest_entry_count AND c.manifest_entry_count = m.manifest_entry_count", params![binding.capture_id, binding.payload_artifact_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional()?;
            let (digest, cipher, count, files, bytes) =
                snapshot.ok_or(StateError::EffectConflict)?;
            transaction.execute("INSERT INTO restore_intents (restore_id, capture_id, payload_artifact_id, target_endpoint_id, target_identity, relative_name, effect_state, manifest_digest, payload_ciphertext_digest, manifest_entry_count, file_count, payload_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared', ?7, ?8, ?9, ?10, ?11)", params![binding.restore_id, binding.capture_id, binding.payload_artifact_id, binding.target_endpoint_id, binding.target_identity, binding.relative_name, digest, cipher, count, files, bytes])?;
        }
        transaction.commit()?;
        self.get_restore(&binding.restore_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn get_restore(&self, restore_id: &str) -> Result<Option<RestoreRecord>, StateError> {
        if !valid_restore_id(restore_id) {
            return Err(StateError::InvalidInput);
        }
        self.connection.query_row("SELECT restore_id, capture_id, payload_artifact_id, target_endpoint_id, target_identity, relative_name, effect_state, manifest_digest, payload_ciphertext_digest, manifest_entry_count, file_count, payload_bytes, staging_identity FROM restore_intents WHERE restore_id = ?1", [restore_id], |row| Ok(RestoreRecord { binding: RestoreBinding { restore_id: row.get(0)?, capture_id: row.get(1)?, payload_artifact_id: row.get(2)?, target_endpoint_id: row.get(3)?, target_identity: row.get(4)?, relative_name: row.get(5)? }, effect_state: row.get(6)?, manifest_digest: row.get(7)?, payload_ciphertext_digest: row.get(8)?, manifest_entry_count: row.get(9)?, file_count: row.get(10)?, payload_bytes: row.get(11)?, staging_identity: row.get(12)? })).optional().map_err(StateError::from)
    }

    pub fn list_pending_restores(
        &self,
        after_restore_id: &str,
        limit: u32,
    ) -> Result<Vec<RestoreRecord>, StateError> {
        if !(1..=1000).contains(&limit) || after_restore_id.len() > 128 {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT restore_id FROM restore_intents WHERE effect_state IN ('prepared', 'staging', 'verified') AND restore_id > ?1 ORDER BY restore_id LIMIT ?2")?;
        let rows = statement.query_map(params![after_restore_id, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(self.get_restore(&row?)?.ok_or(StateError::EffectConflict)?);
        }
        Ok(records)
    }

    pub fn mark_restore_staging(
        &mut self,
        restore_id: &str,
        identity: &str,
    ) -> Result<RestoreRecord, StateError> {
        if !valid_restore_id(restore_id) || !valid_identifier_text(identity) {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT effect_state, staging_identity FROM restore_intents WHERE restore_id = ?1",
                [restore_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (state, existing) = prior.ok_or(StateError::EffectConflict)?;
        match state.as_str() {
            "prepared" => {
                transaction.execute("UPDATE restore_intents SET effect_state = 'staging', staging_identity = ?1, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE restore_id = ?2", params![identity, restore_id])?;
            }
            "staging" if existing.as_deref() == Some(identity) => {}
            "staging" => return Err(StateError::IdempotencyConflict),
            _ => return Err(StateError::EffectConflict),
        }
        transaction.commit()?;
        self.get_restore(restore_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn mark_restore_verified(&mut self, restore_id: &str) -> Result<RestoreRecord, StateError> {
        if !valid_restore_id(restore_id) {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = transaction
            .query_row(
                "SELECT effect_state FROM restore_intents WHERE restore_id = ?1",
                [restore_id],
                |row| row.get(0),
            )
            .optional()?;
        match state.as_deref() {
            Some("staging") => {
                transaction.execute("UPDATE restore_intents SET effect_state = 'verified', system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE restore_id = ?1", [restore_id])?;
            }
            Some("verified") => {}
            _ => return Err(StateError::EffectConflict),
        }
        transaction.commit()?;
        self.get_restore(restore_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn mark_restore_published(
        &mut self,
        restore_id: &str,
        identity: &str,
    ) -> Result<RestoreRecord, StateError> {
        if !valid_restore_id(restore_id) || !valid_identifier_text(identity) {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT effect_state, staging_identity FROM restore_intents WHERE restore_id = ?1",
                [restore_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (state, existing) = prior.ok_or(StateError::EffectConflict)?;
        if !matches!(state.as_str(), "verified" | "published") {
            return Err(StateError::EffectConflict);
        }
        if existing.as_deref() != Some(identity) {
            return Err(StateError::IdempotencyConflict);
        }
        if state == "verified" {
            transaction.execute("UPDATE restore_intents SET effect_state = 'published', system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE restore_id = ?1", [restore_id])?;
        }
        transaction.commit()?;
        self.get_restore(restore_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn abandon_restore(&mut self, restore_id: &str) -> Result<RestoreRecord, StateError> {
        if !valid_restore_id(restore_id) {
            return Err(StateError::InvalidInput);
        }
        let changed = self.connection.execute("UPDATE restore_intents SET effect_state = 'abandoned', system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE restore_id = ?1 AND effect_state IN ('prepared', 'staging')", [restore_id])?;
        if changed != 1 {
            return Err(StateError::EffectConflict);
        }
        self.get_restore(restore_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn prepare_archive_stage(
        &mut self,
        binding: &ArchiveStageBinding,
    ) -> Result<ArchiveStageRecord, StateError> {
        if !valid_archive_id(&binding.stage_id)
            || !valid_identifier_text(&binding.capture_id)
            || !valid_identifier_text(&binding.payload_artifact_id)
            || !valid_identifier_text(&binding.storage_endpoint_id)
            || !valid_identifier_text(&binding.storage_identity)
            || !valid_identifier_text(&binding.key_ref)
        {
            return Err(StateError::InvalidInput);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String, String, String, String)> = transaction.query_row(
            "SELECT capture_id, payload_artifact_id, storage_endpoint_id, storage_identity, key_ref, effect_state FROM archive_stages WHERE stage_id = ?1",
            [&binding.stage_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).optional()?;

        if let Some((capture, payload, endpoint, identity, key_ref, state)) = existing {
            if capture != binding.capture_id
                || payload != binding.payload_artifact_id
                || endpoint != binding.storage_endpoint_id
                || identity != binding.storage_identity
                || key_ref != binding.key_ref
            {
                return Err(StateError::IdempotencyConflict);
            }
            if state == "abandoned" {
                return Err(StateError::EffectConflict);
            }
        } else {
            let snapshot: Option<RestoreSnapshot> = transaction.query_row(
                "SELECT p.manifest_digest, p.ciphertext_digest, p.manifest_entry_count, p.file_count, p.payload_bytes FROM captures c JOIN payload_artifacts p ON p.artifact_id = c.payload_artifact_id AND p.capture_id = c.capture_id JOIN manifest_artifacts m ON m.artifact_id = c.manifest_artifact_id AND m.capture_id = c.capture_id WHERE c.capture_id = ?1 AND p.artifact_id = ?2 AND p.effect_state = 'sealed' AND m.effect_state = 'sealed' AND c.manifest_digest = p.manifest_digest AND c.manifest_digest = m.manifest_digest AND c.manifest_entry_count = p.manifest_entry_count AND c.manifest_entry_count = m.manifest_entry_count",
                params![binding.capture_id, binding.payload_artifact_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            ).optional()?;
            let (digest, cipher, entries, files, bytes) =
                snapshot.ok_or(StateError::EffectConflict)?;
            if parse_archive_counter(&files)? > 10_000
                || parse_archive_counter(&files)? > parse_archive_counter(&entries)?
            {
                return Err(StateError::InvalidInput);
            }
            parse_archive_counter(&bytes)?;
            transaction.execute(
                "INSERT INTO archive_stages (stage_id, capture_id, payload_artifact_id, storage_endpoint_id, storage_identity, key_ref, effect_state, manifest_digest, manifest_entry_count, payload_ciphertext_digest, file_count, payload_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared', ?7, ?8, ?9, ?10, ?11)",
                params![binding.stage_id, binding.capture_id, binding.payload_artifact_id, binding.storage_endpoint_id, binding.storage_identity, binding.key_ref, digest, entries, cipher, files, bytes],
            )?;
        }
        transaction.commit()?;
        self.get_archive_stage(&binding.stage_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn get_archive_stage(
        &self,
        stage_id: &str,
    ) -> Result<Option<ArchiveStageRecord>, StateError> {
        if !valid_archive_id(stage_id) {
            return Err(StateError::InvalidInput);
        }
        self.connection.query_row(
            "SELECT stage_id, capture_id, payload_artifact_id, storage_endpoint_id, storage_identity, key_ref, effect_state, manifest_digest, manifest_entry_count, payload_ciphertext_digest, file_count, payload_bytes, catalog_ciphertext_digest, catalog_ciphertext_bytes, catalog_identity FROM archive_stages WHERE stage_id = ?1",
            [stage_id],
            |row| Ok(ArchiveStageRecord {
                binding: ArchiveStageBinding {stage_id: row.get(0)?, capture_id: row.get(1)?, payload_artifact_id: row.get(2)?, storage_endpoint_id: row.get(3)?, storage_identity: row.get(4)?, key_ref: row.get(5)?},
                effect_state: row.get(6)?, manifest_digest: row.get(7)?, manifest_entry_count: row.get(8)?, payload_ciphertext_digest: row.get(9)?, file_count: row.get(10)?, payload_bytes: row.get(11)?, catalog_ciphertext_digest: row.get(12)?, catalog_ciphertext_bytes: row.get(13)?, catalog_identity: row.get(14)?,
            }),
        ).optional().map_err(StateError::from)
    }

    pub fn get_archive_file(
        &self,
        stage_id: &str,
        file_id: &str,
    ) -> Result<Option<ArchiveFileRecord>, StateError> {
        if !valid_archive_id(stage_id) || !valid_archive_id(file_id) {
            return Err(StateError::InvalidInput);
        }
        self.connection.query_row(
            "SELECT stage_id, file_id, header_digest, plaintext_bytes, effect_state, ciphertext_digest, ciphertext_bytes, identity FROM archive_files WHERE stage_id = ?1 AND file_id = ?2",
            params![stage_id, file_id],
            |row| Ok(ArchiveFileRecord {stage_id: row.get(0)?, file_id: row.get(1)?, header_digest: row.get(2)?, plaintext_bytes: row.get(3)?, effect_state: row.get(4)?, ciphertext_digest: row.get(5)?, ciphertext_bytes: row.get(6)?, identity: row.get(7)?}),
        ).optional().map_err(StateError::from)
    }

    pub fn list_archive_files(
        &self,
        stage_id: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<ArchiveFileRecord>, StateError> {
        if !valid_archive_id(stage_id)
            || (!after.is_empty() && !valid_archive_id(after))
            || !(1..=1000).contains(&limit)
        {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT file_id FROM archive_files WHERE stage_id = ?1 AND file_id > ?2 ORDER BY file_id LIMIT ?3")?;
        let rows = statement.query_map(params![stage_id, after, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut files = Vec::new();
        for row in rows {
            files.push(
                self.get_archive_file(stage_id, &row?)?
                    .ok_or(StateError::EffectConflict)?,
            );
        }
        Ok(files)
    }

    pub fn prepare_archive_file(
        &self,
        stage_id: &str,
        file_id: &str,
        header_digest: &str,
        plaintext_bytes: u64,
    ) -> Result<ArchiveFileRecord, StateError> {
        if !valid_archive_id(stage_id)
            || !valid_archive_id(file_id)
            || !valid_digest_text(header_digest)
        {
            return Err(StateError::InvalidInput);
        }
        let transaction =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let stage: Option<(String, String, String, String, String)> = transaction.query_row(
            "SELECT effect_state, file_count, payload_bytes, prepared_count, prepared_bytes FROM archive_stages WHERE stage_id = ?1",
            [stage_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        let (state, file_count, payload_bytes, count, bytes) =
            stage.ok_or(StateError::EffectConflict)?;
        if state != "prepared" {
            return Err(StateError::EffectConflict);
        }
        let existing: Option<(String, String)> = transaction.query_row(
            "SELECT header_digest, plaintext_bytes FROM archive_files WHERE stage_id = ?1 AND file_id = ?2", params![stage_id, file_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some((digest, size)) = existing {
            if digest != header_digest || size != plaintext_bytes.to_string() {
                return Err(StateError::IdempotencyConflict);
            }
        } else {
            let count = parse_archive_counter(&count)?
                .checked_add(1)
                .ok_or(StateError::InvalidInput)?;
            let bytes = parse_archive_counter(&bytes)?
                .checked_add(plaintext_bytes)
                .ok_or(StateError::InvalidInput)?;
            if count > 10_000
                || count > parse_archive_counter(&file_count)?
                || bytes > parse_archive_counter(&payload_bytes)?
            {
                return Err(StateError::InvalidInput);
            }
            transaction.execute("INSERT INTO archive_files (stage_id, file_id, header_digest, plaintext_bytes, effect_state) VALUES (?1, ?2, ?3, ?4, 'prepared')", params![stage_id, file_id, header_digest, plaintext_bytes.to_string()])?;
            transaction.execute("UPDATE archive_stages SET prepared_count = ?1, prepared_bytes = ?2 WHERE stage_id = ?3", params![count.to_string(), bytes.to_string(), stage_id])?;
        }
        transaction.commit()?;
        self.get_archive_file(stage_id, file_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn seal_archive_file(
        &self,
        stage_id: &str,
        file_id: &str,
        ciphertext_digest: &str,
        ciphertext_bytes: u64,
        identity: &str,
    ) -> Result<ArchiveFileRecord, StateError> {
        if !valid_archive_id(stage_id)
            || !valid_archive_id(file_id)
            || !valid_digest_text(ciphertext_digest)
            || ciphertext_bytes < 60
            || !valid_identifier_text(identity)
        {
            return Err(StateError::InvalidInput);
        }
        let transaction =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let parent: Option<(String, String, String)> = transaction.query_row("SELECT effect_state, sealed_count, sealed_bytes FROM archive_stages WHERE stage_id = ?1", [stage_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?;
        let (parent_state, count, bytes) = parent.ok_or(StateError::EffectConflict)?;
        let file: Option<ArchiveFileSealRow> = transaction.query_row("SELECT effect_state, plaintext_bytes, ciphertext_digest, ciphertext_bytes, identity FROM archive_files WHERE stage_id = ?1 AND file_id = ?2", params![stage_id, file_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional()?;
        let (state, plaintext, previous_digest, previous_bytes, previous_identity) =
            file.ok_or(StateError::EffectConflict)?;
        if state == "sealed" && parent_state != "abandoned" {
            if previous_digest.as_deref() != Some(ciphertext_digest)
                || previous_bytes.as_deref() != Some(ciphertext_bytes.to_string().as_str())
                || previous_identity.as_deref() != Some(identity)
            {
                return Err(StateError::IdempotencyConflict);
            }
        } else if state == "prepared" && parent_state == "prepared" {
            let count = parse_archive_counter(&count)?
                .checked_add(1)
                .ok_or(StateError::InvalidInput)?;
            let bytes = parse_archive_counter(&bytes)?
                .checked_add(parse_archive_counter(&plaintext)?)
                .ok_or(StateError::InvalidInput)?;
            transaction.execute("UPDATE archive_files SET effect_state = 'sealed', ciphertext_digest = ?1, ciphertext_bytes = ?2, identity = ?3 WHERE stage_id = ?4 AND file_id = ?5", params![ciphertext_digest, ciphertext_bytes.to_string(), identity, stage_id, file_id])?;
            transaction.execute("UPDATE archive_stages SET sealed_count = ?1, sealed_bytes = ?2 WHERE stage_id = ?3", params![count.to_string(), bytes.to_string(), stage_id])?;
        } else {
            return Err(StateError::EffectConflict);
        }
        transaction.commit()?;
        self.get_archive_file(stage_id, file_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn seal_archive_stage(
        &mut self,
        stage_id: &str,
        catalog_digest: &str,
        catalog_bytes: u64,
        catalog_identity: &str,
    ) -> Result<ArchiveStageRecord, StateError> {
        if !valid_archive_id(stage_id)
            || !valid_digest_text(catalog_digest)
            || catalog_bytes < 60
            || !valid_identifier_text(catalog_identity)
        {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<ArchiveStageSealRow> = transaction.query_row(
            "SELECT effect_state, file_count, payload_bytes, prepared_count, prepared_bytes, sealed_count, sealed_bytes, catalog_ciphertext_digest, catalog_ciphertext_bytes, catalog_identity FROM archive_stages WHERE stage_id = ?1", [stage_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
        ).optional()?;
        let (
            state,
            files,
            bytes,
            prepared_count,
            prepared_bytes,
            sealed_count,
            sealed_bytes,
            previous_digest,
            previous_bytes,
            previous_identity,
        ) = prior.ok_or(StateError::EffectConflict)?;
        if state == "sealed" {
            if previous_digest.as_deref() != Some(catalog_digest)
                || previous_bytes.as_deref() != Some(catalog_bytes.to_string().as_str())
                || previous_identity.as_deref() != Some(catalog_identity)
            {
                return Err(StateError::IdempotencyConflict);
            }
        } else if state == "prepared" {
            if files != prepared_count
                || files != sealed_count
                || bytes != prepared_bytes
                || bytes != sealed_bytes
            {
                return Err(StateError::EffectConflict);
            }
            {
                let mut statement = transaction.prepare(
                    "SELECT effect_state, plaintext_bytes FROM archive_files WHERE stage_id = ?1",
                )?;
                let mut rows = statement.query([stage_id])?;
                let mut actual_count = 0u64;
                let mut actual_bytes = 0u64;
                while let Some(row) = rows.next()? {
                    let file_state: String = row.get(0)?;
                    let size: String = row.get(1)?;
                    actual_count = actual_count
                        .checked_add(1)
                        .ok_or(StateError::InvalidInput)?;
                    actual_bytes = actual_bytes
                        .checked_add(parse_archive_counter(&size)?)
                        .ok_or(StateError::InvalidInput)?;
                    if file_state != "sealed" || actual_count > 10_000 {
                        return Err(StateError::EffectConflict);
                    }
                }
                if actual_count != parse_archive_counter(&files)?
                    || actual_bytes != parse_archive_counter(&bytes)?
                {
                    return Err(StateError::EffectConflict);
                }
            }
            transaction.execute("UPDATE archive_stages SET effect_state = 'sealed', catalog_ciphertext_digest = ?1, catalog_ciphertext_bytes = ?2, catalog_identity = ?3, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE stage_id = ?4", params![catalog_digest, catalog_bytes.to_string(), catalog_identity, stage_id])?;
        } else {
            return Err(StateError::EffectConflict);
        }
        transaction.commit()?;
        self.get_archive_stage(stage_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn abandon_archive_stage(
        &mut self,
        stage_id: &str,
    ) -> Result<ArchiveStageRecord, StateError> {
        if !valid_archive_id(stage_id) {
            return Err(StateError::InvalidInput);
        }
        let changed = self.connection.execute("UPDATE archive_stages SET effect_state = 'abandoned', system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE stage_id = ?1 AND effect_state = 'prepared'", [stage_id])?;
        if changed != 1 {
            return Err(StateError::EffectConflict);
        }
        self.get_archive_stage(stage_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn prepare_native_run(
        &mut self,
        binding: &NativeRunBinding,
    ) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(&binding.run_id)
            || !valid_archive_id(&binding.stage_id)
            || !valid_identifier_text(&binding.storage_endpoint_id)
            || !valid_identifier_text(&binding.storage_identity)
            || !valid_identifier_text(&binding.repository_key_ref)
            || binding.relative_name != format!("native_{}", binding.run_id)
        {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(prior) = read_native_run(&transaction, &binding.run_id)? {
            if prior.binding != *binding {
                return Err(StateError::IdempotencyConflict);
            }
            if prior.effect_state == "abandoned" {
                return Err(StateError::EffectConflict);
            }
        } else {
            let reserved: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM native_runs WHERE (storage_endpoint_id = ?1 OR storage_identity = ?2) AND relative_name = ?3 AND effect_state != 'abandoned')", params![binding.storage_endpoint_id, binding.storage_identity, binding.relative_name], |row| row.get(0))?;
            if reserved {
                return Err(StateError::EffectConflict);
            }
            let snapshot: Option<(String, String, String, String, String, String, String)> = transaction.query_row(
                "SELECT s.capture_id, s.manifest_digest, s.manifest_entry_count, s.file_count, s.payload_bytes, s.catalog_ciphertext_digest, s.key_ref FROM archive_stages s JOIN captures c ON c.capture_id = s.capture_id JOIN payload_artifacts p ON p.artifact_id = s.payload_artifact_id AND p.capture_id = s.capture_id JOIN manifest_artifacts m ON m.artifact_id = c.manifest_artifact_id AND m.capture_id = c.capture_id WHERE s.stage_id = ?1 AND s.effect_state = 'sealed' AND s.catalog_ciphertext_digest IS NOT NULL AND s.catalog_ciphertext_bytes IS NOT NULL AND s.catalog_identity IS NOT NULL AND c.payload_artifact_id = p.artifact_id AND p.effect_state = 'sealed' AND m.effect_state = 'sealed' AND c.manifest_digest = s.manifest_digest AND c.manifest_digest = p.manifest_digest AND c.manifest_digest = m.manifest_digest AND c.manifest_entry_count = s.manifest_entry_count AND c.manifest_entry_count = p.manifest_entry_count AND c.manifest_entry_count = m.manifest_entry_count AND s.payload_ciphertext_digest = p.ciphertext_digest AND s.file_count = p.file_count AND s.payload_bytes = p.payload_bytes",
                [&binding.stage_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            ).optional()?;
            let (capture, digest, entries, files, bytes, catalog, key_ref) =
                snapshot.ok_or(StateError::EffectConflict)?;
            if !valid_digest_text(&digest)
                || !valid_digest_text(&catalog)
                || parse_archive_counter(&files)? > parse_archive_counter(&entries)?
            {
                return Err(StateError::InvalidInput);
            }
            parse_archive_counter(&bytes)?;
            transaction.execute("INSERT INTO native_runs (run_id, stage_id, storage_endpoint_id, storage_identity, relative_name, repository_key_ref, capture_id, manifest_digest, manifest_entry_count, file_count, payload_bytes, source_catalog_digest, source_key_ref, effect_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'prepared')", params![binding.run_id, binding.stage_id, binding.storage_endpoint_id, binding.storage_identity, binding.relative_name, binding.repository_key_ref, capture, digest, entries, files, bytes, catalog, key_ref])?;
        }
        transaction.commit()?;
        self.get_native_run(&binding.run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn get_native_run(&self, run_id: &str) -> Result<Option<NativeRunRecord>, StateError> {
        if !valid_archive_id(run_id) {
            return Err(StateError::InvalidInput);
        }
        read_native_run(&self.connection, run_id)
    }

    pub fn list_pending_native_runs(
        &self,
        after: &str,
        limit: u32,
    ) -> Result<Vec<NativeRunRecord>, StateError> {
        if (!after.is_empty() && !valid_archive_id(after)) || !(1..=1000).contains(&limit) {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT run_id FROM native_runs WHERE effect_state NOT IN ('verified', 'abandoned') AND run_id > ?1 ORDER BY run_id LIMIT ?2")?;
        let rows = statement.query_map(params![after, limit], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(
                self.get_native_run(&row?)?
                    .ok_or(StateError::EffectConflict)?,
            );
        }
        Ok(result)
    }

    pub fn mark_native_staging(
        &mut self,
        run_id: &str,
        identity: &str,
    ) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(run_id) || !valid_identifier_text(identity) {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior = read_native_run(&transaction, run_id)?.ok_or(StateError::EffectConflict)?;
        match prior.effect_state.as_str() {
            "prepared" => {
                transaction.execute("UPDATE native_runs SET effect_state = 'staging', container_identity = ?1 WHERE run_id = ?2", params![identity, run_id])?;
            }
            "staging" if prior.container_identity.as_deref() == Some(identity) => {}
            "staging" => return Err(StateError::IdempotencyConflict),
            _ => return Err(StateError::EffectConflict),
        }
        transaction.commit()?;
        self.get_native_run(run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn mark_native_ready(
        &mut self,
        run_id: &str,
        repository_identity: &str,
        owner_lock_identity: &str,
        scratch_identity: &str,
    ) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(run_id)
            || ![repository_identity, owner_lock_identity, scratch_identity]
                .iter()
                .all(|value| valid_identifier_text(value))
        {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior = read_native_run(&transaction, run_id)?.ok_or(StateError::EffectConflict)?;
        if prior.effect_state == "staging" {
            transaction.execute("UPDATE native_runs SET effect_state = 'ready', repository_identity = ?1, owner_lock_identity = ?2, scratch_identity = ?3 WHERE run_id = ?4", params![repository_identity, owner_lock_identity, scratch_identity, run_id])?;
        } else if matches!(
            prior.effect_state.as_str(),
            "ready" | "running" | "unknown" | "verified"
        ) {
            if prior.repository_identity.as_deref() != Some(repository_identity)
                || prior.owner_lock_identity.as_deref() != Some(owner_lock_identity)
                || prior.scratch_identity.as_deref() != Some(scratch_identity)
            {
                return Err(StateError::IdempotencyConflict);
            }
        } else {
            return Err(StateError::EffectConflict);
        }
        transaction.commit()?;
        self.get_native_run(run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn start_native_run(
        &mut self,
        run_id: &str,
        operation: &str,
    ) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(run_id) || !matches!(operation, "create" | "verify") {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior = read_native_run(&transaction, run_id)?.ok_or(StateError::EffectConflict)?;
        if operation == "create" {
            if prior.effect_state != "ready" || prior.creation_attempts != 0 {
                return Err(StateError::EffectConflict);
            }
            transaction.execute("UPDATE native_runs SET effect_state = 'running', active_operation = 'create', creation_attempts = 1 WHERE run_id = ?1", [run_id])?;
        } else {
            if !matches!(prior.effect_state.as_str(), "unknown" | "verified")
                || prior.verification_failures >= 3
            {
                return Err(StateError::EffectConflict);
            }
            let attempts = prior
                .verification_attempts
                .checked_add(1)
                .ok_or(StateError::InvalidInput)?;
            transaction.execute("UPDATE native_runs SET effect_state = 'running', active_operation = 'verify', verification_attempts = ?1 WHERE run_id = ?2", params![attempts.to_string(), run_id])?;
        }
        transaction.commit()?;
        self.get_native_run(run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn mark_native_unknown(&mut self, run_id: &str) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(run_id) {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior = read_native_run(&transaction, run_id)?.ok_or(StateError::EffectConflict)?;
        match prior.effect_state.as_str() {
            "running" => {
                let failures = if prior.active_operation.as_deref() == Some("verify") {
                    prior
                        .verification_failures
                        .checked_add(1)
                        .ok_or(StateError::InvalidInput)?
                } else {
                    prior.verification_failures
                };
                if failures > 3 {
                    return Err(StateError::InvalidInput);
                }
                transaction.execute("UPDATE native_runs SET effect_state = 'unknown', active_operation = NULL, verification_failures = ?1 WHERE run_id = ?2", params![failures, run_id])?;
            }
            "unknown" => {}
            _ => return Err(StateError::EffectConflict),
        }
        transaction.commit()?;
        self.get_native_run(run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn seal_native_run(
        &mut self,
        run_id: &str,
        snapshot_id: &str,
        digest: &str,
        entries: u64,
        files: u64,
        bytes: u64,
    ) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(run_id)
            || snapshot_id.len() != 64
            || !snapshot_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !valid_digest_text(digest)
        {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior = read_native_run(&transaction, run_id)?.ok_or(StateError::EffectConflict)?;
        if prior.manifest_digest != digest
            || prior.manifest_entry_count != entries.to_string()
            || prior.file_count != files.to_string()
            || prior.payload_bytes != bytes.to_string()
            || prior
                .native_snapshot_id
                .as_deref()
                .is_some_and(|value| value != snapshot_id)
        {
            return Err(StateError::IdempotencyConflict);
        }
        if prior.effect_state == "running" {
            transaction.execute("UPDATE native_runs SET effect_state = 'verified', native_snapshot_id = ?1, active_operation = NULL, verification_failures = 0 WHERE run_id = ?2", params![snapshot_id, run_id])?;
        } else if prior.effect_state != "verified"
            || prior.native_snapshot_id.as_deref() != Some(snapshot_id)
        {
            return Err(StateError::EffectConflict);
        }
        transaction.commit()?;
        self.get_native_run(run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn abandon_native_run(&mut self, run_id: &str) -> Result<NativeRunRecord, StateError> {
        if !valid_archive_id(run_id) {
            return Err(StateError::InvalidInput);
        }
        let changed = self.connection.execute("UPDATE native_runs SET effect_state = 'abandoned', active_operation = NULL WHERE run_id = ?1 AND effect_state IN ('prepared', 'staging', 'ready', 'unknown')", [run_id])?;
        if changed != 1 {
            return Err(StateError::EffectConflict);
        }
        self.get_native_run(run_id)?
            .ok_or(StateError::EffectConflict)
    }

    pub fn require_staging_quota_inventory(&mut self) -> Result<(), StateError> {
        self.connection.execute(
            "UPDATE staging_quota_metadata SET inventory_complete = 0 WHERE singleton = 1",
            [],
        )?;
        Ok(())
    }

    pub fn is_staging_quota_inventory_complete(&self) -> Result<bool, StateError> {
        self.connection
            .query_row(
                "SELECT inventory_complete FROM staging_quota_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(StateError::from)
    }

    pub fn has_staging_quota_storage(&self, identity: &str) -> Result<bool, StateError> {
        let mut components = identity.split(':');
        if components.next() != Some("unix")
            || components
                .next()
                .is_none_or(|value| parse_archive_counter(value).is_err())
            || components
                .next()
                .is_none_or(|value| parse_archive_counter(value).is_err())
            || components.next().is_some()
        {
            return Err(StateError::InvalidInput);
        }
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM staging_quota WHERE storage_identity = ?1)",
                [identity],
                |row| row.get(0),
            )
            .map_err(StateError::from)
    }

    pub fn get_staging_quota(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<StagingQuotaRecord>, StateError> {
        if !valid_staging_kind(kind) || !valid_identifier_text(id) {
            return Err(StateError::InvalidInput);
        }
        read_staging_quota(&self.connection, kind, id)
    }

    pub fn list_staging_quota(
        &self,
        after_kind: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<StagingQuotaRecord>, StateError> {
        if !(1..=1000).contains(&limit)
            || ((!after_kind.is_empty() || !after_id.is_empty())
                && (!valid_staging_kind(after_kind) || !valid_identifier_text(after_id)))
        {
            return Err(StateError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT object_kind, object_id FROM staging_quota WHERE (object_kind, object_id) > (?1, ?2) ORDER BY object_kind, object_id LIMIT ?3")?;
        let rows = statement.query_map(params![after_kind, after_id, limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (kind, id) = row?;
            result.push(
                self.get_staging_quota(&kind, &id)?
                    .ok_or(StateError::EffectConflict)?,
            );
        }
        Ok(result)
    }

    pub fn get_staging_quota_usage(&self) -> Result<u64, StateError> {
        get_staging_totals(&self.connection, None).map(|value| value.0)
    }

    pub fn reserve_staging_quota(
        &mut self,
        binding: &StagingQuotaBinding,
        capacity_bytes: u64,
        available_bytes: u64,
    ) -> Result<StagingQuotaRecord, StateError> {
        self.insert_staging_quota(binding, capacity_bytes, available_bytes, false)
    }

    /// Records externally verified legacy ownership while the inventory gate remains closed.
    pub fn record_staging_quota_inventory(
        &mut self,
        binding: &StagingQuotaBinding,
        capacity_bytes: u64,
        available_bytes: u64,
    ) -> Result<StagingQuotaRecord, StateError> {
        self.insert_staging_quota(binding, capacity_bytes, available_bytes, true)
    }

    fn insert_staging_quota(
        &mut self,
        binding: &StagingQuotaBinding,
        capacity_bytes: u64,
        available_bytes: u64,
        is_inventory: bool,
    ) -> Result<StagingQuotaRecord, StateError> {
        validate_staging_quota(binding)?;
        if capacity_bytes == 0 || available_bytes > capacity_bytes {
            return Err(StateError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inventory_complete: bool = transaction.query_row(
            "SELECT inventory_complete FROM staging_quota_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let existing = read_staging_quota(&transaction, &binding.object_kind, &binding.object_id)?;
        if existing
            .as_ref()
            .is_some_and(|record| record.binding != *binding)
        {
            return Err(StateError::IdempotencyConflict);
        }
        if !is_inventory && !inventory_complete {
            return Err(StateError::InventoryRequired);
        }
        if is_inventory && inventory_complete && existing.is_none() {
            return Err(StateError::EffectConflict);
        }
        let (endpoint, identity) =
            get_staging_owner(&transaction, &binding.object_kind, &binding.object_id)?
                .ok_or(StateError::EffectConflict)?;
        if endpoint != binding.storage_endpoint_id || identity != binding.storage_identity {
            return Err(StateError::IdempotencyConflict);
        }
        let (total, count) = get_staging_totals(&transaction, None)?;
        if existing.is_none() && count >= MAX_STAGING_OBJECTS {
            return Err(StateError::QuotaExceeded);
        }
        let additional = if existing.is_some() {
            0
        } else {
            binding.max_bytes
        };
        let new_total = total
            .checked_add(additional)
            .ok_or(StateError::QuotaExceeded)?;
        if !is_inventory {
            if new_total > MAX_STAGING_BYTES {
                return Err(StateError::QuotaExceeded);
            }
            let (volume_total, _) =
                get_staging_totals(&transaction, Some(&binding.volume_identity))?;
            let volume_total = volume_total
                .checked_add(additional)
                .ok_or(StateError::QuotaExceeded)?;
            let reserve = MIN_FREE_BYTES.max(capacity_bytes.div_ceil(20));
            if volume_total
                .checked_add(reserve)
                .is_none_or(|required| required > available_bytes)
            {
                return Err(StateError::QuotaExceeded);
            }
        }
        if let Some(existing) = existing {
            transaction.commit()?;
            return Ok(existing);
        }
        transaction.execute("INSERT INTO staging_quota (object_kind, object_id, storage_endpoint_id, storage_identity, volume_identity, max_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![binding.object_kind, binding.object_id, binding.storage_endpoint_id, binding.storage_identity, binding.volume_identity, i64::try_from(binding.max_bytes).map_err(|_| StateError::InvalidInput)?])?;
        transaction.commit()?;
        Ok(StagingQuotaRecord {
            binding: binding.clone(),
        })
    }

    /// The caller must verify physical inventory and unknown files before opening this gate.
    pub fn mark_staging_quota_inventory_complete(&mut self) -> Result<(), StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let missing: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM manifest_artifacts m WHERE NOT EXISTS (SELECT 1 FROM staging_quota q WHERE q.object_kind = 'manifest' AND q.object_id = m.artifact_id AND q.storage_endpoint_id = m.storage_endpoint_id AND q.storage_identity = m.storage_identity)) OR EXISTS(SELECT 1 FROM payload_artifacts p WHERE NOT EXISTS (SELECT 1 FROM staging_quota q WHERE q.object_kind = 'payload' AND q.object_id = p.artifact_id AND q.storage_endpoint_id = p.storage_endpoint_id AND q.storage_identity = p.storage_identity)) OR EXISTS(SELECT 1 FROM archive_stages a WHERE NOT EXISTS (SELECT 1 FROM staging_quota q WHERE q.object_kind = 'archive_stage' AND q.object_id = a.stage_id AND q.storage_endpoint_id = a.storage_endpoint_id AND q.storage_identity = a.storage_identity)) OR EXISTS(SELECT 1 FROM native_runs n WHERE NOT EXISTS (SELECT 1 FROM staging_quota q WHERE q.object_kind = 'native_run' AND q.object_id = n.run_id AND q.storage_endpoint_id = n.storage_endpoint_id AND q.storage_identity = n.storage_identity))",
            [], |row| row.get(0),
        )?;
        if missing {
            return Err(StateError::InventoryRequired);
        }
        {
            let mut statement = transaction
                .prepare("SELECT object_kind, object_id, max_bytes FROM staging_quota")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let kind: String = row.get(0)?;
                let id: String = row.get(1)?;
                let charged =
                    u64::try_from(row.get::<_, i64>(2)?).map_err(|_| StateError::InvalidInput)?;
                if get_staging_persisted_bytes(&transaction, &kind, &id)? > charged {
                    return Err(StateError::InventoryRequired);
                }
            }
        }
        transaction.execute(
            "UPDATE staging_quota_metadata SET inventory_complete = 1 WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn bind_publication(&mut self, binding: &Value) -> Result<PublicationRecord, StateError> {
        validate_publication_binding(binding)?;
        let key = binding.get("commit_key").ok_or(StateError::InvalidInput)?;
        let key_text = serde_jcs::to_string(key)?;
        let binding_text = serde_jcs::to_string(binding)?;
        let mut hasher = Sha256::new();
        hasher.update(b"relic/publication/payload/v1\0");
        hasher.update(binding_text.as_bytes());
        let payload_hash = format!(
            "sha256:{}",
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture: Option<(String, String, String, String, String, Option<String>)> = transaction.query_row(
            "SELECT authority_id, job_id, occurrence_id, source_view_id, consistency, manifest_digest FROM captures WHERE capture_id = ?1",
            [binding["capture_id"].as_str().ok_or(StateError::InvalidInput)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).optional()?;
        let (authority, job, occurrence, view, consistency, manifest) =
            capture.ok_or(StateError::EffectConflict)?;
        if key["authority_id"] != authority
            || key["job_id"] != job
            || key["occurrence_id"] != occurrence
            || binding["source_view_id"] != view
            || binding["consistency"] != consistency
            || manifest.as_deref() != binding["manifest_digest"].as_str()
        {
            return Err(StateError::IdempotencyConflict);
        }
        let prior: Option<String> = transaction
            .query_row(
                "SELECT binding FROM publication_intents WHERE commit_key = ?1",
                [&key_text],
                |row| row.get(0),
            )
            .optional()?;

        if prior.is_some_and(|value| value != binding_text) {
            return Err(StateError::IdempotencyConflict);
        }

        transaction.execute("INSERT OR IGNORE INTO publication_intents (commit_key, payload_hash, binding, effect_state) VALUES (?1, ?2, ?3, 'prepared')", params![key_text, payload_hash, binding_text])?;
        transaction.commit()?;

        self.get_publication(key)?.ok_or(StateError::EffectConflict)
    }

    pub fn get_publication(&self, key: &Value) -> Result<Option<PublicationRecord>, StateError> {
        let key_text = serde_jcs::to_string(key)?;
        let row: Option<PublicationRow> = self.connection.query_row(
            "SELECT payload_hash, binding, effect_state, native_result_id, receipt FROM publication_intents WHERE commit_key = ?1",
            [&key_text],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;

        row.map(
            |(payload_hash, binding, effect_state, native_result_id, receipt)| {
                Ok(PublicationRecord {
                    commit_key: key.clone(),
                    payload_hash,
                    binding: serde_json::from_str(&binding)?,
                    effect_state,
                    native_result_id,
                    receipt: receipt
                        .map(|text| serde_json::from_str(&text))
                        .transpose()?,
                })
            },
        )
        .transpose()
    }

    pub fn list_recoverable(
        &self,
        after_key: &str,
        limit: u32,
    ) -> Result<Vec<PublicationRecord>, StateError> {
        if !(1..=1_000).contains(&limit) || after_key.len() > 1024 {
            return Err(StateError::InvalidInput);
        }

        let mut statement = self.connection.prepare("SELECT commit_key FROM publication_intents WHERE effect_state IN ('admitted', 'unknown', 'published') AND commit_key > ?1 ORDER BY commit_key LIMIT ?2")?;
        let keys = statement.query_map(params![after_key, limit], |row| row.get::<_, String>(0))?;
        let mut records = Vec::new();

        for key in keys {
            let key: Value = serde_json::from_str(&key?)?;
            records.push(
                self.get_publication(&key)?
                    .ok_or(StateError::EffectConflict)?,
            );
        }

        Ok(records)
    }

    pub fn advance_publication(
        &mut self,
        key: &Value,
        expected: &str,
        next: &str,
        native_result_id: Option<&str>,
    ) -> Result<(), StateError> {
        let valid = matches!(
            (expected, next),
            ("prepared", "admitted")
                | ("admitted", "published")
                | ("admitted", "unknown")
                | ("unknown", "published")
        );

        if !valid
            || (next == "published"
                && !native_result_id
                    .is_some_and(|value| is_identifier(&Value::String(value.to_owned()))))
            || (next != "published" && native_result_id.is_some())
        {
            return Err(StateError::EffectConflict);
        }

        let gateway_bound: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_admissions WHERE commit_key = ?1)",
            [serde_jcs::to_string(key)?],
            |row| row.get(0),
        )?;
        if gateway_bound {
            return Err(StateError::EffectConflict);
        }

        let changed = self.connection.execute("UPDATE publication_intents SET effect_state = ?1, native_result_id = ?2, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE commit_key = ?3 AND effect_state = ?4 AND NOT EXISTS (SELECT 1 FROM gateway_admissions WHERE commit_key = ?3)", params![next, native_result_id, serde_jcs::to_string(key)?, expected])?;

        if changed != 1 {
            return Err(StateError::EffectConflict);
        }

        Ok(())
    }

    pub fn record_receipt(&mut self, receipt: &Value) -> Result<Value, StateError> {
        crate::contracts::validate_record(receipt).map_err(|_| StateError::InvalidInput)?;
        let key = serde_jcs::to_string(&receipt["commit_key"])?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let gateway_bound: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_admissions WHERE commit_key = ?1)",
            [&key],
            |row| row.get(0),
        )?;
        if gateway_bound {
            return Err(StateError::EffectConflict);
        }
        let previous: Option<PublicationRow> = transaction.query_row(
            "SELECT payload_hash, binding, effect_state, native_result_id, receipt FROM publication_intents WHERE commit_key = ?1",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        let (payload_hash, binding_text, effect_state, native_result, prior_receipt) =
            previous.ok_or(StateError::EffectConflict)?;

        let binding: Value = serde_json::from_str(&binding_text)?;
        let fields = [
            "capture_id",
            "commit_key",
            "consistency",
            "destination_config_revision",
            "manifest_digest",
            "policy_digest",
            "source_view_id",
        ];

        if fields
            .iter()
            .any(|field| receipt[*field] != binding[*field])
            || receipt["payload_hash"] != payload_hash
            || receipt["native_result_id"].as_str() != native_result.as_deref()
        {
            return Err(StateError::IdempotencyConflict);
        }

        if let Some(text) = prior_receipt {
            return Ok(serde_json::from_str(&text)?);
        }

        if effect_state != "published" {
            return Err(StateError::EffectConflict);
        }

        transaction.execute(
            "UPDATE publication_intents SET effect_state = 'verified', receipt = ?1, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE commit_key = ?2 AND effect_state = 'published'",
            params![serde_json::to_string(receipt)?, key],
        )?;
        transaction.execute(
            "INSERT INTO events (event_type, subject_id) VALUES ('publication_verified', ?1)",
            [receipt["commit_key"]["job_id"]
                .as_str()
                .ok_or(StateError::InvalidInput)?],
        )?;
        transaction.commit()?;

        Ok(receipt.clone())
    }
}

fn validate_publication_binding(binding: &Value) -> Result<(), StateError> {
    let object = binding.as_object().ok_or(StateError::InvalidInput)?;
    let fields = [
        "capture_id",
        "commit_key",
        "consistency",
        "destination_config_revision",
        "manifest_digest",
        "policy_digest",
        "source_view_id",
    ];

    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(StateError::InvalidInput);
    }

    let key = binding["commit_key"]
        .as_object()
        .ok_or(StateError::InvalidInput)?;
    let key_fields = ["authority_id", "job_id", "occurrence_id", "destination_id"];

    if key.len() != key_fields.len()
        || key_fields
            .iter()
            .any(|field| !key.get(*field).is_some_and(is_identifier))
        || !is_identifier(&binding["capture_id"])
        || !is_identifier(&binding["source_view_id"])
        || !matches!(
            binding["consistency"].as_str(),
            Some("application_consistent" | "crash_consistent" | "best_effort")
        )
        || !is_digest(&binding["manifest_digest"])
        || !is_digest(&binding["policy_digest"])
    {
        return Err(StateError::InvalidInput);
    }

    let revision = binding["destination_config_revision"]
        .as_str()
        .ok_or(StateError::InvalidInput)?;

    if revision.is_empty()
        || (revision.len() > 1 && revision.starts_with('0'))
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
        || revision.parse::<u64>().is_err()
    {
        return Err(StateError::InvalidInput);
    }

    Ok(())
}

fn is_identifier(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        let mut bytes = text.bytes();
        !text.is_empty()
            && text.len() <= 128
            && bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes.all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
    })
}

fn is_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 71
            && text.starts_with("sha256:")
            && text[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn validate_capture_binding(binding: &CaptureBinding) -> Result<(), StateError> {
    let ids = [
        &binding.authority_id,
        &binding.job_id,
        &binding.occurrence_id,
        &binding.capture_id,
        &binding.source_view_id,
    ];
    if ids
        .iter()
        .any(|id| !is_identifier(&Value::String((*id).clone())))
        || !matches!(
            binding.consistency.as_str(),
            "application_consistent" | "crash_consistent" | "best_effort"
        )
        || !is_digest(&Value::String(binding.source_selection_digest.clone()))
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn valid_identifier_text(text: &str) -> bool {
    let mut bytes = text.bytes();
    !text.is_empty()
        && text.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_digest_text(text: &str) -> bool {
    text.len() == 71
        && text.starts_with("sha256:")
        && text.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn validate_artifact_binding(binding: &ManifestArtifactBinding) -> Result<(), StateError> {
    if [
        &binding.artifact_id,
        &binding.capture_id,
        &binding.storage_endpoint_id,
        &binding.storage_identity,
        &binding.key_ref,
    ]
    .iter()
    .any(|value| !valid_identifier_text(value))
        || binding.artifact_id.contains(':')
        || binding.relative_name.len() > 144
        || binding.relative_name != format!("artifact_{}.sealed", binding.artifact_id)
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}

fn validate_payload_binding(binding: &PayloadArtifactBinding) -> Result<(), StateError> {
    if [
        &binding.artifact_id,
        &binding.capture_id,
        &binding.storage_endpoint_id,
        &binding.storage_identity,
        &binding.key_ref,
    ]
    .iter()
    .any(|value| !valid_identifier_text(value))
        || binding.artifact_id.contains(':')
        || binding.relative_name.len() > 143
        || binding.relative_name != format!("payload_{}.sealed", binding.artifact_id)
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}

fn valid_restore_id(value: &str) -> bool {
    valid_identifier_text(value) && !value.contains(':')
}

fn validate_restore_binding(binding: &RestoreBinding) -> Result<(), StateError> {
    let name = &binding.relative_name;
    if !valid_restore_id(&binding.restore_id)
        || !valid_identifier_text(&binding.capture_id)
        || !valid_restore_id(&binding.payload_artifact_id)
        || !valid_identifier_text(&binding.target_endpoint_id)
        || !valid_identifier_text(&binding.target_identity)
        || name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.starts_with(".restore_")
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}

fn valid_archive_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn parse_archive_counter(value: &str) -> Result<u64, StateError> {
    let number = value.parse::<u64>().map_err(|_| StateError::InvalidInput)?;
    if value != number.to_string() {
        return Err(StateError::InvalidInput);
    }
    Ok(number)
}

fn validate_readonly_state_file(path: &Path) -> Result<fs::Metadata, StateError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(StateError::InsecureDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
        let owner = unsafe { libc::geteuid() };
        if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1 {
            return Err(StateError::InsecureDirectory);
        }
    }
    Ok(metadata)
}

fn read_native_run(
    connection: &Connection,
    run_id: &str,
) -> Result<Option<NativeRunRecord>, StateError> {
    let record: Option<(NativeRunRecord, String)> = connection.query_row(
        "SELECT run_id, stage_id, storage_endpoint_id, storage_identity, relative_name, repository_key_ref, capture_id, manifest_digest, manifest_entry_count, file_count, payload_bytes, source_catalog_digest, source_key_ref, effect_state, container_identity, repository_identity, owner_lock_identity, scratch_identity, native_snapshot_id, active_operation, creation_attempts, verification_attempts, verification_failures FROM native_runs WHERE run_id = ?1",
        [run_id], |row| Ok((NativeRunRecord {
            binding: NativeRunBinding { run_id: row.get(0)?, stage_id: row.get(1)?, storage_endpoint_id: row.get(2)?, storage_identity: row.get(3)?, relative_name: row.get(4)?, repository_key_ref: row.get(5)? },
            capture_id: row.get(6)?, manifest_digest: row.get(7)?, manifest_entry_count: row.get(8)?, file_count: row.get(9)?, payload_bytes: row.get(10)?, source_catalog_digest: row.get(11)?, source_key_ref: row.get(12)?, effect_state: row.get(13)?, container_identity: row.get(14)?, repository_identity: row.get(15)?, owner_lock_identity: row.get(16)?, scratch_identity: row.get(17)?, native_snapshot_id: row.get(18)?, active_operation: row.get(19)?, creation_attempts: row.get(20)?, verification_attempts: 0, verification_failures: row.get(22)?,
        }, row.get(21)?)),
    ).optional()?;
    record
        .map(|(mut value, attempts)| {
            value.verification_attempts = parse_archive_counter(&attempts)?;
            Ok(value)
        })
        .transpose()
}

fn valid_staging_kind(kind: &str) -> bool {
    matches!(
        kind,
        "manifest" | "payload" | "archive_stage" | "native_run"
    )
}

fn validate_staging_quota(binding: &StagingQuotaBinding) -> Result<(), StateError> {
    if !valid_staging_kind(&binding.object_kind)
        || !valid_identifier_text(&binding.object_id)
        || !valid_identifier_text(&binding.storage_endpoint_id)
        || binding.max_bytes == 0
        || binding.max_bytes > i64::MAX as u64
        || (matches!(binding.object_kind.as_str(), "archive_stage" | "native_run")
            && !valid_archive_id(&binding.object_id))
    {
        return Err(StateError::InvalidInput);
    }
    let mut parts = binding.storage_identity.split(':');
    let prefix = parts.next();
    let device = parts.next().ok_or(StateError::InvalidInput)?;
    let inode = parts.next().ok_or(StateError::InvalidInput)?;
    if prefix != Some("unix")
        || parts.next().is_some()
        || parse_archive_counter(device).is_err()
        || parse_archive_counter(inode).is_err()
        || binding.volume_identity != format!("unix:{device}")
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}

fn get_staging_owner(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<(String, String)>, StateError> {
    let query = match kind {
        "manifest" => {
            "SELECT storage_endpoint_id, storage_identity FROM manifest_artifacts WHERE artifact_id = ?1"
        }
        "payload" => {
            "SELECT storage_endpoint_id, storage_identity FROM payload_artifacts WHERE artifact_id = ?1"
        }
        "archive_stage" => {
            "SELECT storage_endpoint_id, storage_identity FROM archive_stages WHERE stage_id = ?1"
        }
        "native_run" => {
            "SELECT storage_endpoint_id, storage_identity FROM native_runs WHERE run_id = ?1"
        }
        _ => return Err(StateError::InvalidInput),
    };
    connection
        .query_row(query, [id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()
        .map_err(StateError::from)
}

// Journal sizes are decimal text; sum in Rust with checked arithmetic.
fn get_staging_persisted_bytes(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<u64, StateError> {
    let query = match kind {
        "manifest" => "SELECT ciphertext_bytes FROM manifest_artifacts WHERE artifact_id = ?1",
        "payload" => "SELECT ciphertext_bytes FROM payload_artifacts WHERE artifact_id = ?1",
        "archive_stage" => {
            "SELECT catalog_ciphertext_bytes FROM archive_stages WHERE stage_id = ?1"
        }
        "native_run" => return Ok(0),
        _ => return Err(StateError::InvalidInput),
    };
    let value: Option<String> = connection.query_row(query, [id], |row| row.get(0))?;
    let mut total = value
        .as_deref()
        .map(parse_archive_counter)
        .transpose()?
        .unwrap_or(0);
    if kind == "archive_stage" {
        let mut statement = connection.prepare("SELECT ciphertext_bytes FROM archive_files WHERE stage_id = ?1 AND ciphertext_bytes IS NOT NULL")?;
        let rows = statement.query_map([id], |row| row.get::<_, String>(0))?;
        for row in rows {
            total = total
                .checked_add(parse_archive_counter(&row?)?)
                .ok_or(StateError::QuotaExceeded)?;
        }
    }
    Ok(total)
}

fn read_staging_quota(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<StagingQuotaRecord>, StateError> {
    connection.query_row(
        "SELECT object_kind, object_id, storage_endpoint_id, storage_identity, volume_identity, max_bytes FROM staging_quota WHERE object_kind = ?1 AND object_id = ?2",
        params![kind, id],
        |row| {
            let maximum_bytes: i64 = row.get(5)?;
            let maximum_bytes = u64::try_from(maximum_bytes)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, maximum_bytes))?;
            Ok(StagingQuotaRecord {
                binding: StagingQuotaBinding {
                    object_kind: row.get(0)?,
                    object_id: row.get(1)?,
                    storage_endpoint_id: row.get(2)?,
                    storage_identity: row.get(3)?,
                    volume_identity: row.get(4)?,
                    max_bytes: maximum_bytes,
                },
            })
        },
    ).optional().map_err(StateError::from)
}

fn get_staging_totals(
    connection: &Connection,
    volume: Option<&str>,
) -> Result<(u64, u64), StateError> {
    let mut statement = connection.prepare(
        "SELECT max_bytes FROM staging_quota WHERE (?1 IS NULL OR volume_identity = ?1)",
    )?;
    let rows = statement.query_map([volume], |row| row.get::<_, i64>(0))?;
    let mut total = 0u64;
    let mut count = 0u64;
    for row in rows {
        count = count.checked_add(1).ok_or(StateError::QuotaExceeded)?;
        if count > MAX_STAGING_OBJECTS {
            return Err(StateError::QuotaExceeded);
        }
        let bytes = u64::try_from(row?).map_err(|_| StateError::InvalidInput)?;
        total = total.checked_add(bytes).ok_or(StateError::QuotaExceeded)?;
    }
    Ok((total, count))
}
