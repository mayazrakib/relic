use std::fmt;
use std::io;

use crate::resources::ResourceError;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum SortError {
    UNSUPPORTED,
    INVALID,
    LIMIT,
    DUPLICATE,
    RESOURCE(ResourceError),
    IO(io::Error),
    ENCRYPTED(crate::encrypted_spool::SpoolError),
    MANIFEST(crate::manifest::ManifestError),
}

impl fmt::Display for SortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UNSUPPORTED => "encrypted manifest sorting is unavailable on this platform",
            Self::INVALID => "invalid encrypted manifest sort",
            Self::LIMIT => "encrypted manifest sort capacity unavailable",
            Self::DUPLICATE => "duplicate logical manifest entry",
            Self::RESOURCE(_) => "encrypted manifest sort resource guard stopped the operation",
            Self::IO(_) => "encrypted manifest sort I/O failed",
            Self::ENCRYPTED(_) => "encrypted manifest run authentication or encryption failed",
            Self::MANIFEST(_) => "logical manifest validation failed",
        })
    }
}

impl std::error::Error for SortError {}

#[derive(Clone, Copy, Debug)]
pub struct SortLimits {
    pub max_entries: u64,
    pub max_frame_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_chunk_entries: usize,
    pub max_runs: usize,
    pub max_fan_in: usize,
    pub max_cipher_bytes: u64,
    pub max_memory_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SortUsage {
    pub entry_count: u64,
    pub run_count: usize,
    pub run_ids_allocated: u64,
    pub merges_completed: u64,
    pub reserved_ciphertext_bytes: u64,
    pub peak_reserved_ciphertext_bytes: u64,
    pub total_reserved_ciphertext_bytes: u64,
}

#[cfg(unix)]
#[path = "encrypted_manifest_sort/unix.rs"]
mod platform;

#[cfg(unix)]
pub use platform::EncryptedManifestSort;

#[cfg(not(unix))]
pub struct EncryptedManifestSort;

#[cfg(not(unix))]
impl EncryptedManifestSort {
    pub fn get_usage(&self) -> SortUsage {
        SortUsage::default()
    }

    pub fn create(
        _directory: &std::path::Path,
        _key: &zeroize::Zeroizing<[u8; 32]>,
        _limits: SortLimits,
        _guard: &crate::resources::StageGuard,
    ) -> Result<Self, SortError> {
        Err(SortError::UNSUPPORTED)
    }
    pub fn add_entry(&mut self, _entry: &crate::manifest::ManifestEntry) -> Result<(), SortError> {
        Err(SortError::UNSUPPORTED)
    }
    pub fn visit_sorted<F>(&mut self, _capture_id: &str, _visit: F) -> Result<String, SortError>
    where
        F: FnMut(&crate::manifest::ManifestEntry) -> Result<(), SortError>,
    {
        Err(SortError::UNSUPPORTED)
    }
}
