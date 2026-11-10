#![cfg(target_os = "linux")]

use relic::local_endpoint::{FileIdentity, LocalEndpoint, get_physical_scope_observation};
use relic::state::StateStore;
use relic::worker_state::get_readonly_state_paths;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

#[test]
fn grants_only_private_state_files_and_metadata_endpoint_has_no_read_access() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("state");
    let state = StateStore::open(&path).unwrap();
    std::fs::write(path.join("auth_token"), b"private").unwrap();
    let paths = get_readonly_state_paths(&state, &path).unwrap();
    assert!(paths.iter().any(|entry| entry.ends_with("state.sqlite3")));
    assert!(paths.iter().all(|entry| matches!(
        entry.file_name().unwrap().to_str().unwrap(),
        "state.sqlite3" | "state.sqlite3-wal" | "state.sqlite3-shm"
    )));
    let metadata = std::fs::metadata(&path).unwrap();
    let endpoint = LocalEndpoint::resolve_metadata(
        &path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();
    // SAFETY: F_GETFL does not mutate the live descriptor.
    let flags = unsafe { libc::fcntl(endpoint.directory().as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0 && flags & libc::O_PATH != 0);
    get_physical_scope_observation(&endpoint).unwrap();
    let other = root.path().join("other");
    std::fs::create_dir(&other).unwrap();
    assert!(get_readonly_state_paths(&state, &other).is_err());
}

#[test]
fn rejects_symlink_sidecar_and_foreign_directory_alias() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("state");
    let state = StateStore::open(&path).unwrap();
    let alias = root.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(get_readonly_state_paths(&state, &alias).is_err());
    let shm = path.join("state.sqlite3-shm");
    std::fs::remove_file(&shm).unwrap();
    symlink(path.join("state.sqlite3"), &shm).unwrap();
    assert!(get_readonly_state_paths(&state, &path).is_err());
}

#[test]
#[ignore = "requires delegated Linux cgroup guard with Landlock"]
fn grants_database_files_without_granting_other_state_files() {
    use relic::resources::StageGuard;
    use relic::worker_runtime::{WorkerLimits, execute_worker};
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = root.path().join("state");
    let state = StateStore::open(&state_dir).unwrap();
    let secret = state_dir.join("auth_token");
    std::fs::write(&secret, b"private").unwrap();
    let paths = get_readonly_state_paths(&state, &state_dir).unwrap();
    let scripts = root.path().join("scripts");
    std::fs::create_dir(&scripts).unwrap();
    let script = scripts.join("worker.py");
    let code = format!(
        "#!/usr/bin/python3\nfrom pathlib import Path\nassert Path({:?}).read_bytes().startswith(b'SQLite format 3')\ntry:\n    Path({:?}).read_bytes()\n    raise RuntimeError('ungranted state file readable')\nexcept PermissionError:\n    pass\nprint('restricted')\n",
        state_dir.join("state.sqlite3").to_str().unwrap(),
        secret.to_str().unwrap()
    );
    std::fs::write(&script, code).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let limits = WorkerLimits {
        memory_max_bytes: 32 * 1024 * 1024,
        memory_high_bytes: 24 * 1024 * 1024,
        max_tasks: 16,
        max_open_files: 32,
        max_runtime: Duration::from_secs(5),
        max_output_bytes: 4096,
    };
    let output = execute_worker(&script, b"", &paths, &[], limits, &StageGuard::default()).unwrap();
    assert_eq!(output.stdout, b"restricted\n");
}
