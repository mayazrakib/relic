use relic::state::{CaptureBinding, StateError, StateStore};
use serde_json::json;

fn prepare_capture(store: &mut StateStore, binding: &serde_json::Value) {
    let key = &binding["commit_key"];
    let capture = CaptureBinding {
        authority_id: key["authority_id"].as_str().unwrap().into(),
        job_id: key["job_id"].as_str().unwrap().into(),
        occurrence_id: key["occurrence_id"].as_str().unwrap().into(),
        capture_id: binding["capture_id"].as_str().unwrap().into(),
        source_view_id: binding["source_view_id"].as_str().unwrap().into(),
        consistency: binding["consistency"].as_str().unwrap().into(),
        source_selection_digest: binding["policy_digest"].as_str().unwrap().into(),
    };
    store.bind_capture(&capture).unwrap();
    store
        .freeze_capture_manifest(
            &capture.capture_id,
            binding["manifest_digest"].as_str().unwrap(),
            1,
        )
        .unwrap();
}

#[cfg(unix)]
#[test]
fn accepts_a_trusted_ancestor_alias_but_rejects_final_directory_symlink() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let actual_parent = directory.path().join("actual");
    std::fs::create_dir(&actual_parent).unwrap();
    let alias = directory.path().join("alias");
    symlink(&actual_parent, &alias).unwrap();
    let store = StateStore::open(&alias.join("state")).unwrap();
    assert!(store.check_integrity().unwrap());
    drop(store);
    symlink(
        actual_parent.join("state"),
        directory.path().join("final_alias"),
    )
    .unwrap();
    assert!(matches!(
        StateStore::open(&directory.path().join("final_alias")),
        Err(StateError::InsecureDirectory)
    ));
}

#[test]
fn persists_revisioned_jobs_and_rejects_stale_updates() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    assert!(store.check_integrity().unwrap());
    store
        .put_job(&json!({"job_id":"documents","revision":1}), None)
        .unwrap();
    assert!(matches!(
        store.put_job(&json!({"job_id":"documents","revision":2}), None),
        Err(StateError::RevisionConflict)
    ));
    store
        .put_job(&json!({"job_id":"documents","revision":2}), Some(1))
        .unwrap();
    drop(store);
    let reopened = StateStore::open(&directory.path().join("state")).unwrap();
    assert_eq!(reopened.get_job("documents").unwrap().unwrap().revision, 2);
    assert_eq!(reopened.list_jobs("", 10).unwrap().len(), 1);
}

#[test]
fn binds_intent_once_and_retains_uncertainty_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    let binding: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/publication.json")).unwrap();
    prepare_capture(&mut store, &binding);
    let record = store.bind_publication(&binding).unwrap();
    assert_eq!(record.effect_state, "prepared");
    assert_eq!(
        store.bind_publication(&binding).unwrap().payload_hash,
        record.payload_hash
    );
    let mut changed = binding.clone();
    changed["source_view_id"] = json!("changed");
    assert!(matches!(
        store.bind_publication(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    store
        .advance_publication(&binding["commit_key"], "prepared", "admitted", None)
        .unwrap();
    store
        .advance_publication(&binding["commit_key"], "admitted", "unknown", None)
        .unwrap();
    drop(store);
    let mut reopened = StateStore::open(&directory.path().join("state")).unwrap();
    assert_eq!(
        reopened
            .get_publication(&binding["commit_key"])
            .unwrap()
            .unwrap()
            .effect_state,
        "unknown"
    );
    assert!(matches!(
        reopened.advance_publication(&binding["commit_key"], "unknown", "admitted", None),
        Err(StateError::EffectConflict)
    ));
    reopened
        .advance_publication(
            &binding["commit_key"],
            "unknown",
            "published",
            Some("snapshot_1"),
        )
        .unwrap();
}

#[cfg(unix)]
#[test]
fn refuses_shared_state_directory() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        StateStore::open(directory.path()),
        Err(StateError::InsecureDirectory)
    ));
}

#[test]
fn persists_one_receipt_and_never_overwrites_it_on_retry() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    let binding: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/publication.json")).unwrap();
    let receipt: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/receipt.json")).unwrap();
    prepare_capture(&mut store, &binding);
    store.bind_publication(&binding).unwrap();
    assert!(matches!(
        store.record_receipt(&receipt),
        Err(StateError::IdempotencyConflict) | Err(StateError::EffectConflict)
    ));
    store
        .advance_publication(&binding["commit_key"], "prepared", "admitted", None)
        .unwrap();
    store
        .advance_publication(
            &binding["commit_key"],
            "admitted",
            "published",
            receipt["native_result_id"].as_str(),
        )
        .unwrap();
    assert_eq!(store.record_receipt(&receipt).unwrap(), receipt);
    let mut retry = receipt.clone();
    retry["committed_at"] = json!("2026-11-10T00:05:00Z");
    assert_eq!(store.record_receipt(&retry).unwrap(), receipt);
    drop(store);
    let reopened = StateStore::open(&directory.path().join("state")).unwrap();
    assert_eq!(
        reopened
            .get_publication(&binding["commit_key"])
            .unwrap()
            .unwrap()
            .receipt,
        Some(receipt)
    );
}

#[test]
fn job_request_key_is_durable_and_rejects_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let definition = json!({"job_id":"documents","revision":1});
    let mut store = StateStore::open(&path).unwrap();
    store
        .put_job_idempotent(&definition, None, "request")
        .unwrap();
    drop(store);
    let mut store = StateStore::open(&path).unwrap();
    assert_eq!(
        store
            .put_job_idempotent(&definition, None, "request")
            .unwrap()
            .revision,
        1
    );
    assert!(matches!(
        store.put_job_idempotent(&json!({"job_id":"other","revision":1}), None, "request"),
        Err(StateError::IdempotencyConflict)
    ));
}

#[test]
fn rejects_invalid_publication_and_lists_recovery_in_pages() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    let binding: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/publication.json")).unwrap();
    let mut invalid = binding.clone();
    invalid["unexpected"] = json!(true);
    assert!(matches!(
        store.bind_publication(&invalid),
        Err(StateError::InvalidInput)
    ));
    invalid = binding.clone();
    invalid["policy_digest"] = json!("bad");
    assert!(matches!(
        store.bind_publication(&invalid),
        Err(StateError::InvalidInput)
    ));
    prepare_capture(&mut store, &binding);
    let mut other = binding.clone();
    other["commit_key"]["destination_id"] = json!("second");
    for value in [&binding, &other] {
        store.bind_publication(value).unwrap();
        store
            .advance_publication(&value["commit_key"], "prepared", "admitted", None)
            .unwrap();
    }
    let first = store.list_recoverable("", 1).unwrap();
    assert_eq!(first.len(), 1);
    let cursor = serde_jcs::to_string(&first[0].commit_key).unwrap();
    let second = store.list_recoverable(&cursor, 1).unwrap();
    assert_eq!(second.len(), 1);
    assert_ne!(first[0].commit_key, second[0].commit_key);
    assert!(store.list_recoverable("", 0).is_err());
}

#[test]
fn concurrent_initialization_rechecks_schema_version() {
    use std::sync::{Arc, Barrier};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let barrier = Arc::new(Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let barrier = barrier.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                barrier.wait();
                StateStore::open(&path).map(|store| store.check_integrity().unwrap())
            })
        })
        .collect();
    for worker in workers {
        assert!(worker.join().unwrap().unwrap());
    }
}

#[cfg(unix)]
#[test]
fn rejects_shared_symlink_and_hardlinked_database() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, b"").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let database = state.join("state.sqlite3");
    symlink(&target, &database).unwrap();
    assert!(StateStore::open(&state).is_err());
    std::fs::remove_file(&database).unwrap();
    std::fs::hard_link(&target, &database).unwrap();
    assert!(matches!(
        StateStore::open(&state),
        Err(StateError::InsecureDirectory)
    ));
    std::fs::remove_file(&database).unwrap();
    std::fs::write(&database, b"").unwrap();
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        StateStore::open(&state),
        Err(StateError::InsecureDirectory)
    ));
}
