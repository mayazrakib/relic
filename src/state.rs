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

type PublicationRow = (String, String, String, Option<String>, Option<String>);

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

        match version {
            0 => transaction
                .execute_batch(include_str!("../database/migrations/00001_initialize.sql"))?,
            1 => {}
            _ => return Err(StateError::UnsupportedVersion),
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
