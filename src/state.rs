use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
    connection: Connection,
}

impl StateStore {
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

        let deadline = Instant::now() + Duration::from_secs(5);

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

        if version > 5 {
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

        let changed = self.connection.execute("UPDATE publication_intents SET effect_state = ?1, native_result_id = ?2, system_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE commit_key = ?3 AND effect_state = ?4", params![next, native_result_id, serde_jcs::to_string(key)?, expected])?;

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
