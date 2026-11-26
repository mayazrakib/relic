#![cfg(target_os = "linux")]
use relic::resources::StageGuard;
use relic::worker_runtime::{WorkerLimits, execute_worker_recorded, quiesce_recorded_worker};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn get_limits() -> WorkerLimits {
    WorkerLimits {
        memory_max_bytes: 32 * 1024 * 1024,
        memory_high_bytes: 24 * 1024 * 1024,
        max_tasks: 16,
        max_open_files: 32,
        max_runtime: Duration::from_secs(15),
        max_output_bytes: 4096,
    }
}
fn create_script(root: &Path, code: &str) -> PathBuf {
    let path = root.join("worker.py");
    fs::write(&path, format!("#!/usr/bin/python3\n{code}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn get_scope_path(group: &str) -> PathBuf {
    Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'))
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn quiescing_recorded_scope_before_fork_prevents_delayed_launch() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let marker = directory.path().join("marker");
    let script = create_script(
        directory.path(),
        &format!(
            "from pathlib import Path\nPath({:?}).write_text('ran')",
            marker.to_str().unwrap()
        ),
    );
    let root = directory.path().to_path_buf();
    let (identity_tx, identity_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        execute_worker_recorded(
            &script,
            b"",
            &[],
            &[root],
            get_limits(),
            &StageGuard::default(),
            |identity| {
                identity_tx.send(identity.clone()).unwrap();
                resume_rx.recv().unwrap();
                Ok(())
            },
        )
    });
    let identity = identity_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let path = get_scope_path(&identity.group_path);
    assert!(path.exists());
    assert!(quiesce_recorded_worker(&identity, &StageGuard::default()).unwrap());
    assert!(!path.exists());
    let mut recreated_parent = identity.clone();
    recreated_parent.parent_inode = recreated_parent.parent_inode.saturating_add(1);
    assert!(quiesce_recorded_worker(&recreated_parent, &StageGuard::default()).unwrap());
    resume_tx.send(()).unwrap();
    assert!(thread.join().unwrap().is_err());
    assert!(!marker.exists());
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn live_worker_is_killed_only_for_matching_recorded_scope() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let marker = directory.path().join("marker");
    let script = create_script(
        directory.path(),
        &format!(
            "from pathlib import Path\nimport time\nPath({:?}).write_text('started')\ntime.sleep(30)",
            marker.to_str().unwrap()
        ),
    );
    let root = directory.path().to_path_buf();
    let (identity_tx, identity_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        execute_worker_recorded(
            &script,
            b"",
            &[],
            &[root],
            get_limits(),
            &StageGuard::default(),
            |identity| {
                identity_tx.send(identity.clone()).unwrap();
                Ok(())
            },
        )
    });
    let identity = identity_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists());
    let path = get_scope_path(&identity.group_path);
    let mut foreign = identity.clone();
    foreign.parent_inode = foreign.parent_inode.saturating_add(1);
    assert!(quiesce_recorded_worker(&foreign, &StageGuard::default()).is_err());
    assert!(path.exists());
    foreign = identity.clone();
    foreign.cgroup_namespace_inode = foreign.cgroup_namespace_inode.saturating_add(1);
    assert!(quiesce_recorded_worker(&foreign, &StageGuard::default()).is_err());
    foreign = identity.clone();
    foreign.host_id = format!("sha256:{}", "0".repeat(64));
    foreign.boot_id = "00000000-0000-0000-0000-000000000000".into();
    assert!(quiesce_recorded_worker(&foreign, &StageGuard::default()).is_err());
    assert!(path.exists());
    assert!(quiesce_recorded_worker(&identity, &StageGuard::default()).unwrap());
    assert!(!path.exists());
    assert!(thread.join().unwrap().is_err());
}
