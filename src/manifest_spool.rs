use std::fmt;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OpenFlags, params};

use crate::manifest::{ManifestEntry, ManifestError, ManifestHeader, ManifestValidator};

const PAGE_BYTES: u64 = 4096;
const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct SpoolLimits {
    pub max_entries: u64,
    pub max_frame_bytes: usize,
    pub max_spool_bytes: u64,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum SpoolError {
    INVALID_LIMITS,
    INSECURE_DIRECTORY,
    ENTRY_LIMIT,
    FRAME_LIMIT,
    DUPLICATE,
    POISONED,
    IO(io::Error),
    DATABASE(rusqlite::Error),
    JSON(serde_json::Error),
    MANIFEST(ManifestError),
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::INVALID_LIMITS => write!(formatter, "invalid spool limits"),
            Self::INSECURE_DIRECTORY => write!(
                formatter,
                "spool directory is not private and owner controlled"
            ),
            Self::ENTRY_LIMIT => write!(formatter, "manifest entry limit reached"),
            Self::FRAME_LIMIT => write!(formatter, "manifest frame limit reached"),
            Self::DUPLICATE => write!(formatter, "duplicate manifest path"),
            Self::POISONED => write!(formatter, "spool failed and must be discarded"),
            Self::IO(error) => write!(formatter, "spool I/O: {error}"),
            Self::DATABASE(error) => write!(formatter, "spool database: {error}"),
            Self::JSON(error) => write!(formatter, "spool encoding: {error}"),
            Self::MANIFEST(error) => write!(formatter, "spool manifest: {error}"),
        }
    }
}

impl std::error::Error for SpoolError {}

impl From<io::Error> for SpoolError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<rusqlite::Error> for SpoolError {
    fn from(error: rusqlite::Error) -> Self {
        Self::DATABASE(error)
    }
}

impl From<serde_json::Error> for SpoolError {
    fn from(error: serde_json::Error) -> Self {
        Self::JSON(error)
    }
}

impl From<ManifestError> for SpoolError {
    fn from(error: ManifestError) -> Self {
        Self::MANIFEST(error)
    }
}

pub struct ManifestSpool {
    connection: Connection,
    limits: SpoolLimits,
    count: u64,
    is_poisoned: bool,
}

impl ManifestSpool {
    pub fn create(path: &Path, limits: SpoolLimits) -> Result<Self, SpoolError> {
        let max_pages = limits.max_spool_bytes / PAGE_BYTES;
        if limits.max_entries == 0
            || limits.max_frame_bytes == 0
            || limits.max_frame_bytes > MAX_FRAME_BYTES
            || !(2..=u32::MAX as u64).contains(&max_pages)
        {
            return Err(SpoolError::INVALID_LIMITS);
        }

        let max_pages = i64::try_from(max_pages).map_err(|_| SpoolError::INVALID_LIMITS)?;
        let name = path.file_name().ok_or(SpoolError::INSECURE_DIRECTORY)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = std::fs::canonicalize(parent)?;
        let metadata = std::fs::metadata(&parent)?;

        if !metadata.is_dir() {
            return Err(SpoolError::INSECURE_DIRECTORY);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
            let effective_user = unsafe { libc::geteuid() };

            if metadata.uid() != effective_user || metadata.mode() & 0o077 != 0 {
                return Err(SpoolError::INSECURE_DIRECTORY);
            }
        }

        let path = parent.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }

        let file = options.open(&path)?;
        drop(file);
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags)?;
        connection.pragma_update(None, "page_size", PAGE_BYTES as i64)?;
        connection.pragma_update(None, "journal_mode", "OFF")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "cache_size", -256)?;
        let actual_page_bytes: i64 =
            connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let actual_max_pages: i64 =
            connection
                .pragma_update_and_check(None, "max_page_count", max_pages, |row| row.get(0))?;

        if actual_page_bytes != PAGE_BYTES as i64 || !(2..=max_pages).contains(&actual_max_pages) {
            return Err(SpoolError::INVALID_LIMITS);
        }

        connection.execute_batch(
            "CREATE TABLE entries (sort_key BLOB PRIMARY KEY, frame BLOB NOT NULL) WITHOUT ROWID;",
        )?;

        Ok(Self {
            connection,
            limits,
            count: 0,
            is_poisoned: false,
        })
    }

    pub fn add_entry(&mut self, entry: &ManifestEntry) -> Result<(), SpoolError> {
        if self.is_poisoned {
            return Err(SpoolError::POISONED);
        }
        if self.count >= self.limits.max_entries {
            return Err(SpoolError::ENTRY_LIMIT);
        }

        let header = ManifestHeader {
            schema_version: 1,
            capture_id: "spool_validation".into(),
            entry_count: "1".into(),
        };
        let mut validator = ManifestValidator::new(&header)?;
        validator.add_entry(entry)?;
        validator.finish()?;
        let frame = serde_jcs::to_vec(entry)?;
        if frame.len() > self.limits.max_frame_bytes {
            return Err(SpoolError::FRAME_LIMIT);
        }

        let key = encode_sort_key(entry)?;
        let result = self.connection.execute(
            "INSERT INTO entries (sort_key, frame) VALUES (?1, ?2)",
            params![key, frame],
        );

        match result {
            Ok(_) => self.count += 1,
            Err(rusqlite::Error::SqliteFailure(ref error, _))
                if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY =>
            {
                return Err(SpoolError::DUPLICATE);
            }
            Err(error) => {
                self.is_poisoned = true;
                return Err(SpoolError::DATABASE(error));
            }
        }

        Ok(())
    }

    pub fn finish(&self, capture_id: &str) -> Result<String, SpoolError> {
        if self.is_poisoned {
            return Err(SpoolError::POISONED);
        }

        let header = ManifestHeader {
            schema_version: 1,
            capture_id: capture_id.to_owned(),
            entry_count: self.count.to_string(),
        };
        let mut validator = ManifestValidator::new(&header)?;
        let mut statement = self
            .connection
            .prepare("SELECT frame FROM entries ORDER BY sort_key")?;
        let mut rows = statement.query([])?;

        while let Some(row) = rows.next()? {
            let frame: Vec<u8> = row.get(0)?;
            let entry: ManifestEntry = serde_json::from_slice(&frame)?;
            validator.add_entry(&entry)?;
        }

        Ok(validator.finish()?)
    }

    pub fn visit_sorted<F>(&self, mut visit: F) -> Result<(), SpoolError>
    where
        F: FnMut(&ManifestEntry) -> Result<(), SpoolError>,
    {
        if self.is_poisoned {
            return Err(SpoolError::POISONED);
        }

        let mut statement = self
            .connection
            .prepare("SELECT frame FROM entries ORDER BY sort_key")?;
        let mut rows = statement.query([])?;

        while let Some(row) = rows.next()? {
            let frame: Vec<u8> = row.get(0)?;
            let entry: ManifestEntry = serde_json::from_slice(&frame)?;
            visit(&entry)?;
        }

        Ok(())
    }

    pub fn get_entry_count(&self) -> u64 {
        self.count
    }
}

fn encode_sort_key(entry: &ManifestEntry) -> Result<Vec<u8>, SpoolError> {
    let mut key = entry.source_id.as_bytes().to_vec();
    key.push(0);

    for component in &entry.path {
        let bytes = URL_SAFE_NO_PAD
            .decode(component)
            .map_err(|_| SpoolError::MANIFEST(ManifestError::INVALID("invalid path encoding")))?;
        for byte in bytes {
            key.push(1);
            key.push(byte);
        }
        key.push(0);
    }

    Ok(key)
}
