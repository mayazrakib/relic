#![cfg(target_os = "linux")]

use relic::physical_registry::{PhysicalRegistryError, acquire_capacity_guard, register_roots};
use relic::resources::StageGuard;
use relic::state::StateStore;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn capacity_guard_excludes_other_handles_until_drop() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let guard = StageGuard::default();
    register_roots(&mut state, &[], &guard).unwrap();
    let held = acquire_capacity_guard(&state, &guard).unwrap();
    let other_path = path.clone();
    let result = std::thread::spawn(move || {
        let other = StateStore::open(&other_path).unwrap();
        matches!(
            acquire_capacity_guard(&other, &StageGuard::default()),
            Err(PhysicalRegistryError::BUSY)
        )
    })
    .join()
    .unwrap();
    assert!(result);
    held.check(&state, &guard).unwrap();
    drop(held);
    let other = StateStore::open(&path).unwrap();
    acquire_capacity_guard(&other, &guard)
        .unwrap()
        .check(&other, &guard)
        .unwrap();
}

#[test]
fn replaced_coordinator_cannot_validate_or_be_reacquired() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let guard = StageGuard::default();
    register_roots(&mut state, &[], &guard).unwrap();
    let held = acquire_capacity_guard(&state, &guard).unwrap();
    let other_state = StateStore::open(&root.path().join("other-state")).unwrap();
    assert!(held.check(&other_state, &guard).is_err());
    let lock = path.join(".physical-registry.lock");
    fs::rename(&lock, path.join("old-coordinator")).unwrap();
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(held.check(&state, &guard).is_err());
    assert!(acquire_capacity_guard(&state, &guard).is_err());
    drop(held);
    assert!(acquire_capacity_guard(&state, &guard).is_err());
    assert!(path.join("old-coordinator").exists());
}
