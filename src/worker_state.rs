//! Restricted file grants for a worker's read-only SQLite connection.
use std::path::{Path, PathBuf};

use crate::state::{StateError, StateStore};

/// Return the actual database and existing SQLite sidecars after private-file checks.
/// The caller must retain its StateStore and exclude replacement of the validated files
/// until the worker has opened them; path grants do not pin their inodes.
#[cfg(unix)]
pub fn get_readonly_state_paths(
    state: &StateStore,
    configured_dir: &Path,
) -> Result<Vec<PathBuf>, StateError> {
    use std::os::unix::fs::MetadataExt;

    let configured = std::fs::symlink_metadata(configured_dir)?;
    if !configured.is_dir() || configured.file_type().is_symlink() {
        return Err(StateError::InsecureDirectory);
    }
    let directory = std::fs::canonicalize(configured_dir)?;
    let canonical = std::fs::metadata(&directory)?;
    // SAFETY: geteuid has no memory safety preconditions.
    let owner = unsafe { libc::geteuid() };
    if configured.dev() != canonical.dev()
        || configured.ino() != canonical.ino()
        || configured.uid() != owner
        || configured.mode() & 0o077 != 0
    {
        return Err(StateError::InsecureDirectory);
    }
    let actual = state.connection.path().ok_or(StateError::InvalidInput)?;
    let database = std::fs::canonicalize(actual)?;
    if database.parent() != Some(directory.as_path())
        || database.file_name() != Some(std::ffi::OsStr::new("state.sqlite3"))
    {
        return Err(StateError::InsecureDirectory);
    }
    let mut paths = Vec::with_capacity(3);
    for (index, name) in ["state.sqlite3", "state.sqlite3-wal", "state.sqlite3-shm"]
        .iter()
        .enumerate()
    {
        let path = directory.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if index != 0 && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(StateError::InsecureDirectory);
        }
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(not(unix))]
pub fn get_readonly_state_paths(
    _state: &StateStore,
    _configured_dir: &Path,
) -> Result<Vec<PathBuf>, StateError> {
    Err(StateError::UnsupportedVersion)
}
