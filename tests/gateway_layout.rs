use relic::gateway_state::GatewayResourceBinding;
use relic::state::{StateError, StateStore};

fn get_binding(id: &str, inode: u64) -> GatewayResourceBinding {
    GatewayResourceBinding {
        resource_id: id.into(),
        authority_id: "authority".into(),
        storage_endpoint_id: format!("endpoint_{id}"),
        storage_identity: format!("unix:1:{inode}"),
        repository_key_ref: "key".into(),
    }
}

#[test]
fn binds_layout_once_and_initialization_unknown_never_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    store
        .prepare_gateway_resource(&get_binding("resource", 10))
        .unwrap();
    let intent = store.prepare_gateway_layout("resource").unwrap();
    assert_eq!(intent.effect_state, "prepared");
    assert_eq!(store.prepare_gateway_layout("resource").unwrap(), intent);
    assert!(store.bind_gateway_scratch("resource", "unix:1:12").is_err());
    assert!(store.bind_gateway_owner("resource", "unix:2:11").is_err());
    assert!(store.bind_gateway_owner("resource", "unix:1:10").is_err());
    store.bind_gateway_owner("resource", "unix:1:11").unwrap();
    assert!(matches!(
        store.bind_gateway_owner("resource", "unix:1:15"),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(store.bind_gateway_scratch("resource", "unix:1:11").is_err());
    store.bind_gateway_scratch("resource", "unix:1:12").unwrap();
    assert_eq!(
        store.seal_gateway_layout("resource").unwrap().effect_state,
        "ready"
    );
    assert!(
        store
            .start_gateway_initialization("resource", 1, 2)
            .is_err()
    );
    let started = store
        .start_gateway_initialization("resource", 1, 1)
        .unwrap();
    assert_eq!(started.initialization_attempts, 1);
    assert_eq!(started.initialization_epoch, Some(1));
    let unknown = store
        .mark_gateway_initialization_unknown("resource", 1, 1)
        .unwrap();
    assert_eq!(
        store
            .mark_gateway_initialization_unknown("resource", 1, 1)
            .unwrap(),
        unknown
    );
    assert!(
        store
            .start_gateway_initialization("resource", 1, 1)
            .is_err()
    );
    drop(store);
    let mut store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.get_gateway_layout("resource").unwrap().unwrap(),
        unknown
    );
    assert!(
        store
            .complete_gateway_initialization("resource", 1, 2, &"a".repeat(64))
            .is_err()
    );
    assert!(
        store
            .complete_gateway_initialization("resource", 1, 1, "ABC")
            .is_err()
    );
    let result = store
        .complete_gateway_initialization("resource", 1, 1, &"a".repeat(64))
        .unwrap();
    assert_eq!(result.effect_state, "initialized");
    let resource = store.get_gateway_resource("resource").unwrap().unwrap();
    assert_eq!(resource.effect_state, "ready");
    assert_eq!(
        resource.repository_id.as_deref(),
        Some("a".repeat(64).as_str())
    );
    assert_eq!(
        store
            .complete_gateway_initialization("resource", 1, 1, &"a".repeat(64))
            .unwrap(),
        result
    );
    assert!(matches!(
        store.complete_gateway_initialization("resource", 1, 1, &"b".repeat(64)),
        Err(StateError::IdempotencyConflict)
    ));
    assert_eq!(
        store.bind_gateway_owner("resource", "unix:1:11").unwrap(),
        result
    );
    assert_eq!(store.seal_gateway_layout("resource").unwrap(), result);
}

#[test]
fn never_adopts_legacy_ready_resource() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    store
        .prepare_gateway_resource(&get_binding("legacy", 20))
        .unwrap();
    drop(store);
    let connection =
        rusqlite::Connection::open(directory.path().join("state/state.sqlite3")).unwrap();
    connection.execute("UPDATE gateway_resources SET effect_state='ready', repository_id='legacy_repo' WHERE resource_id='legacy'", []).unwrap();
    drop(connection);
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    assert!(store.prepare_gateway_layout("legacy").is_err());
    assert!(store.get_gateway_layout("legacy").unwrap().is_none());
}

#[test]
fn migration_from_nine_retains_existing_resource() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    let binding = get_binding("resource", 30);
    store.prepare_gateway_resource(&binding).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    let key = r#"{"authority_id":"authority","destination_id":"destination","job_id":"job","occurrence_id":"occurrence"}"#;
    let admission = serde_json::json!({"resource_id":"resource","admission_id":"old_admission","commit_key":serde_json::from_str::<serde_json::Value>(key).unwrap(),"payload_hash":"sha256:abc","native_run_id":"run","native_snapshot_id":"snapshot","capture_id":"capture","manifest_digest":"sha256:abc","owner":"owner","effective_policy":{}}).to_string();
    connection.execute("INSERT INTO publication_intents(commit_key,payload_hash,binding,effect_state) VALUES(?1,'sha256:abc','{}','unknown')", [key]).unwrap();
    connection.execute("INSERT INTO gateway_admissions(admission_id,resource_id,commit_key,binding,receiver_epoch,fence_generation,request_type,admission_decision) VALUES('old_admission','resource',?1,?2,'1','1','publication','accepted')", rusqlite::params![key,admission]).unwrap();
    connection.execute("INSERT INTO gateway_executions(admission_id,ordinal,resource_id,receiver_epoch,fence_generation,effect_state) VALUES('old_admission',1,'resource','1','1','unknown')", []).unwrap();
    connection
        .execute_batch("DROP TABLE gateway_layouts; ALTER TABLE gateway_executions DROP COLUMN worker_identity; PRAGMA user_version = 9;")
        .unwrap();
    drop(connection);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store
            .get_gateway_resource("resource")
            .unwrap()
            .unwrap()
            .binding,
        binding
    );
    assert!(store.get_gateway_layout("resource").unwrap().is_none());
    assert_eq!(
        store
            .get_gateway_admission("old_admission")
            .unwrap()
            .unwrap()
            .receiver_epoch,
        1
    );
    assert_eq!(
        store.list_gateway_executions("old_admission").unwrap()[0].effect_state,
        "unknown"
    );
}

fn create_ready_layout(store: &mut StateStore, id: &str, inode: u64) {
    store
        .prepare_gateway_resource(&get_binding(id, inode))
        .unwrap();
    store.prepare_gateway_layout(id).unwrap();
    store
        .bind_gateway_owner(id, &format!("unix:1:{}", inode + 1))
        .unwrap();
    store
        .bind_gateway_scratch(id, &format!("unix:1:{}", inode + 2))
        .unwrap();
    store.seal_gateway_layout(id).unwrap();
}

fn get_worker_identity() -> relic::worker_identity::WorkerIdentity {
    relic::worker_identity::WorkerIdentity {
        host_id: format!("sha256:{}", "a".repeat(64)),
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        cgroup_namespace_inode: 123,
        group_path: format!("/scope/worker_{}", "a".repeat(32)),
        group_inode: 456,
        parent_path: "/scope".into(),
        parent_inode: 789,
    }
}

#[test]
fn initializer_scope_binding_is_immutable_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_ready_layout(&mut store, "resource", 40);
    let identity = get_worker_identity();
    assert!(
        store
            .bind_gateway_initialization_worker("resource", 1, 1, &identity)
            .is_err()
    );
    store
        .start_gateway_initialization("resource", 1, 1)
        .unwrap();
    assert!(
        store
            .bind_gateway_initialization_worker("resource", 1, 2, &identity)
            .is_err()
    );
    let record = store
        .bind_gateway_initialization_worker("resource", 1, 1, &identity)
        .unwrap();
    assert_eq!(record.launch_protocol, 1);
    assert_eq!(record.containment.as_ref(), Some(&identity));
    assert_eq!(
        store
            .bind_gateway_initialization_worker("resource", 1, 1, &identity)
            .unwrap(),
        record
    );
    let mut changed = identity.clone();
    changed.group_inode += 1;
    assert!(matches!(
        store.bind_gateway_initialization_worker("resource", 1, 1, &changed),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(
        store
            .revoke_unbound_gateway_initialization("resource", 1, 1)
            .is_err()
    );
    drop(store);
    let mut store = StateStore::open(&path).unwrap();
    assert_eq!(
        store
            .get_gateway_layout("resource")
            .unwrap()
            .unwrap()
            .containment
            .as_ref(),
        Some(&identity)
    );
    store
        .mark_gateway_initialization_unknown("resource", 1, 1)
        .unwrap();
    assert!(
        store
            .bind_gateway_initialization_worker("resource", 1, 1, &identity)
            .is_err()
    );
    assert_eq!(
        store
            .get_gateway_layout("resource")
            .unwrap()
            .unwrap()
            .containment
            .as_ref(),
        Some(&identity)
    );
}

#[test]
fn revoking_unbound_initialization_prevents_late_before_fork_binding() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_ready_layout(&mut store, "resource", 50);
    store
        .start_gateway_initialization("resource", 1, 1)
        .unwrap();
    let revoked = store
        .revoke_unbound_gateway_initialization("resource", 1, 1)
        .unwrap();
    assert_eq!(revoked.effect_state, "unknown");
    assert!(revoked.containment.is_none());
    assert!(
        store
            .bind_gateway_initialization_worker("resource", 1, 1, &get_worker_identity())
            .is_err()
    );
    assert!(
        store
            .start_gateway_initialization("resource", 1, 1)
            .is_err()
    );
    assert!(
        store
            .get_gateway_layout("resource")
            .unwrap()
            .unwrap()
            .containment
            .is_none()
    );
}

#[test]
fn completion_preserves_blocked_resource_until_new_fence() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_ready_layout(&mut store, "resource", 60);
    store
        .start_gateway_initialization("resource", 1, 1)
        .unwrap();
    store
        .bind_gateway_initialization_worker("resource", 1, 1, &get_worker_identity())
        .unwrap();
    store.block_gateway_resource("resource", 1, 1).unwrap();
    store
        .mark_gateway_initialization_unknown("resource", 1, 1)
        .unwrap();
    let repository_id = "a".repeat(64);
    let layout = store
        .complete_gateway_initialization("resource", 1, 1, &repository_id)
        .unwrap();
    assert_eq!(layout.effect_state, "initialized");
    let blocked = store.get_gateway_resource("resource").unwrap().unwrap();
    assert_eq!(blocked.effect_state, "blocked");
    assert_eq!(
        blocked.repository_id.as_deref(),
        Some(repository_id.as_str())
    );
    assert!(store.install_gateway_fence("resource", 1, 1, 1, 1).is_err());
    let ready = store.install_gateway_fence("resource", 1, 1, 2, 2).unwrap();
    assert_eq!(ready.effect_state, "ready");
    assert_eq!((ready.receiver_epoch, ready.fence_generation), (2, 2));
    assert_eq!(ready.repository_id.as_deref(), Some(repository_id.as_str()));
}
