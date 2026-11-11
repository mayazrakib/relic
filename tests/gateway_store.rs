#![cfg(all(target_os = "linux", feature = "embedded-archive"))]
use relic::gateway_state::GatewayResourceBinding;
use relic::gateway_store::{GatewayExecutionContext, GatewayStoreError, LocalGatewayStore};
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::resources::{ResourceClass, ResourcePool, StageGuard};
use relic::state::StateStore;
use relic::worker_runtime::WorkerLimits;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

struct Fixture {
    directory: tempfile::TempDir,
    state: StateStore,
    store: LocalGatewayStore,
    binding: GatewayResourceBinding,
}
fn get_endpoint(path: &Path) -> LocalEndpoint {
    let metadata = fs::metadata(path).unwrap();
    LocalEndpoint::resolve(
        path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap()
}
fn create_fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().join("target");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let state = StateStore::open(&directory.path().join("state")).unwrap();
    let endpoint = get_endpoint(&root);
    let store = LocalGatewayStore::new(endpoint, &root, "endpoint").unwrap();
    let binding = GatewayResourceBinding {
        resource_id: "resource".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: store.storage_identity().into(),
        repository_key_ref: "target_key".into(),
    };
    Fixture {
        directory,
        state,
        store,
        binding,
    }
}
fn get_limits() -> WorkerLimits {
    WorkerLimits {
        memory_max_bytes: 192 * 1024 * 1024,
        memory_high_bytes: 144 * 1024 * 1024,
        max_tasks: 16,
        max_open_files: 64,
        max_runtime: Duration::from_secs(60),
        max_output_bytes: 16388,
    }
}
#[test]
fn creates_private_layout_and_replays_immutable_identities() {
    let mut fixture = create_fixture();
    let guard = StageGuard::default();
    let layout = fixture
        .store
        .prepare(&mut fixture.state, &fixture.binding, &guard)
        .unwrap();
    assert_eq!(layout.effect_state, "ready");
    let root = fixture.directory.path().join("target");
    for name in [".relic-owner.lock", ".relic-coordinator.lock"] {
        let metadata = fs::symlink_metadata(root.join(name)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), 0);
    }
    let scratch = fs::symlink_metadata(root.join(".relic-scratch")).unwrap();
    assert!(scratch.is_dir());
    assert_eq!(scratch.mode() & 0o7777, 0o700);
    assert_eq!(
        fixture
            .store
            .prepare(&mut fixture.state, &fixture.binding, &guard)
            .unwrap(),
        layout
    );
    let lock = File::open(root.join(".relic-owner.lock")).unwrap();
    lock.try_lock().unwrap();
    assert!(matches!(
        fixture
            .store
            .prepare(&mut fixture.state, &fixture.binding, &guard),
        Err(GatewayStoreError::BUSY)
    ));
}

#[test]
fn gateway_preparation_respects_registered_physical_roots() {
    use relic::physical_registry::{PhysicalRootClaim, PhysicalRootKind, register_roots};

    let mut fixture = create_fixture();
    let guard = StageGuard::default();
    let layout = fixture
        .store
        .prepare(&mut fixture.state, &fixture.binding, &guard)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .prepare(&mut fixture.state, &fixture.binding, &guard)
            .unwrap(),
        layout
    );

    let staging = fixture.directory.path().join("staging");
    fs::create_dir(&staging).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
    let staging_endpoint = get_endpoint(&staging);
    register_roots(
        &mut fixture.state,
        &[PhysicalRootClaim {
            kind: PhysicalRootKind::STAGING,
            owner_id: "staging_endpoint",
            endpoint: &staging_endpoint,
        }],
        &guard,
    )
    .unwrap();

    let nested = fixture.directory.path().join("target/nested");
    let staging_nested = staging.join("nested");
    for path in [&nested, &staging_nested] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state_path = fixture.directory.path().join("state");
    for (id, path) in [
        ("nested_gateway", &nested),
        ("state_gateway", &state_path),
        ("staging_gateway", &staging_nested),
    ] {
        let store = LocalGatewayStore::new(get_endpoint(path), path, "endpoint").unwrap();
        let binding = GatewayResourceBinding {
            resource_id: id.into(),
            authority_id: "authority".into(),
            storage_endpoint_id: "endpoint".into(),
            storage_identity: store.storage_identity().into(),
            repository_key_ref: "target_key".into(),
        };
        assert!(store.prepare(&mut fixture.state, &binding, &guard).is_err());
        assert!(fixture.state.get_gateway_resource(id).unwrap().is_none());
        assert!(!path.join(".relic-owner.lock").exists());
        assert!(!path.join("config").exists());
    }

    let sibling = fixture.directory.path().join("sibling");
    fs::create_dir(&sibling).unwrap();
    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o700)).unwrap();
    let store = LocalGatewayStore::new(get_endpoint(&sibling), &sibling, "endpoint").unwrap();
    let binding = GatewayResourceBinding {
        resource_id: "sibling".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "endpoint".into(),
        storage_identity: store.storage_identity().into(),
        repository_key_ref: "target_key".into(),
    };
    assert_eq!(
        store
            .prepare(&mut fixture.state, &binding, &guard)
            .unwrap()
            .effect_state,
        "ready"
    );
}

#[test]
fn foreign_files_and_replaced_layout_are_preserved_and_rejected() {
    let mut fixture = create_fixture();
    let guard = StageGuard::default();
    let root = fixture.directory.path().join("target");
    let foreign = root.join("foreign");
    fs::write(&foreign, b"preserved").unwrap();
    assert!(
        fixture
            .store
            .prepare(&mut fixture.state, &fixture.binding, &guard)
            .is_err()
    );
    assert_eq!(fs::read(&foreign).unwrap(), b"preserved");
    fs::remove_file(&foreign).unwrap();
    fixture
        .store
        .prepare(&mut fixture.state, &fixture.binding, &guard)
        .unwrap();
    let owner = root.join(".relic-owner.lock");
    fs::rename(&owner, root.join("old_owner")).unwrap();
    fs::write(&owner, b"").unwrap();
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        fixture
            .store
            .prepare(&mut fixture.state, &fixture.binding, &guard)
            .is_err()
    );
    assert!(root.join("old_owner").exists());
    fs::remove_file(&owner).unwrap();
    fs::rename(root.join("old_owner"), &owner).unwrap();
    let scratch = root.join(".relic-scratch");
    fs::rename(&scratch, root.join("old_scratch")).unwrap();
    fs::create_dir(&scratch).unwrap();
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        fixture
            .store
            .prepare(&mut fixture.state, &fixture.binding, &guard)
            .is_err()
    );
    assert!(root.join("old_scratch").exists());
}

#[test]
fn wrong_key_and_cancellation_do_not_record_initialization_attempts() {
    let mut fixture = create_fixture();
    let guard = StageGuard::default();
    fixture
        .store
        .prepare(&mut fixture.state, &fixture.binding, &guard)
        .unwrap();
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let job = pool.admit_job("job", &guard).unwrap();
    let state_dir = fixture.directory.path().join("state");
    let context = GatewayExecutionContext {
        executable: Path::new("/does-not-exist"),
        state_dir: &state_dir,
        target_key_ref: "wrong",
        target_password: "test-only-password",
        repository_max_bytes: 32 * 1024 * 1024,
        worker_limits: get_limits(),
        job: &job,
        guard: &guard,
    };
    assert!(matches!(
        fixture
            .store
            .initialize(&mut fixture.state, "resource", &context),
        Err(GatewayStoreError::WRONG_KEY_REFERENCE)
    ));
    guard.cancellation.cancel();
    assert!(
        fixture
            .store
            .initialize(&mut fixture.state, "resource", &context)
            .is_err()
    );
    assert_eq!(
        fixture
            .state
            .get_gateway_layout("resource")
            .unwrap()
            .unwrap()
            .initialization_attempts,
        0
    );
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard with Landlock"]
fn initializes_and_recovers_completed_native_repository_after_store_restart() {
    let Fixture {
        directory,
        mut state,
        store,
        binding,
    } = create_fixture();
    let guard = StageGuard::default();
    store.prepare(&mut state, &binding, &guard).unwrap();
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let job = pool.admit_job("job", &guard).unwrap();
    let state_dir = directory.path().join("state");
    let executable = Path::new(env!("CARGO_BIN_EXE_relic-gateway-worker"));
    let context = GatewayExecutionContext {
        executable,
        state_dir: &state_dir,
        target_key_ref: "target_key",
        target_password: "test-only-password",
        repository_max_bytes: 32 * 1024 * 1024,
        worker_limits: get_limits(),
        job: &job,
        guard: &guard,
    };
    let resource = store.initialize(&mut state, "resource", &context).unwrap();
    assert_eq!(resource.effect_state, "ready");
    assert_eq!(state.get_total_held_destination_growth().unwrap(), 0);
    let repository_id = resource.repository_id.clone().unwrap();
    assert_eq!(repository_id.len(), 64);
    assert!(
        repository_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let layout = state.get_gateway_layout("resource").unwrap().unwrap();
    assert_eq!(layout.initialization_attempts, 1);
    assert!(layout.containment.is_some());
    assert_eq!(
        store.initialize(&mut state, "resource", &context).unwrap(),
        resource
    );
    assert_eq!(
        state
            .get_gateway_layout("resource")
            .unwrap()
            .unwrap()
            .initialization_attempts,
        1
    );
    drop(store);
    drop(state);
    let connection = rusqlite::Connection::open(state_dir.join("state.sqlite3")).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE; UPDATE gateway_resources SET effect_state='prepared',repository_id=NULL WHERE resource_id='resource'; UPDATE gateway_layouts SET effect_state='unknown' WHERE resource_id='resource'; UPDATE destination_growth SET effect_state='held' WHERE operation_kind='initialization' AND operation_id='resource'; COMMIT;").unwrap();
    drop(connection);
    let mut state = StateStore::open(&state_dir).unwrap();
    let root = directory.path().join("target");
    let store = LocalGatewayStore::new(get_endpoint(&root), &root, "endpoint").unwrap();
    let recovered = store
        .reconcile_initialization(&mut state, "resource", &context)
        .unwrap();
    assert_eq!(recovered.effect_state, "ready");
    assert_eq!(state.get_total_held_destination_growth().unwrap(), 0);
    assert_eq!(
        recovered.repository_id.as_deref(),
        Some(repository_id.as_str())
    );
    let recovered_layout = state.get_gateway_layout("resource").unwrap().unwrap();
    assert_eq!(recovered_layout.initialization_attempts, 1);
    assert!(recovered_layout.containment.is_some());
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard with Landlock"]
fn recovery_quiesces_recorded_orphan_before_probing_owner_lock() {
    use relic::physical_registry::{PhysicalRootClaim, PhysicalRootKind, register_roots};
    use relic::worker_runtime::execute_worker_recorded;
    use std::sync::mpsc;
    use std::time::Instant;

    let Fixture {
        directory,
        mut state,
        store,
        binding,
    } = create_fixture();
    let guard = StageGuard::default();
    store.prepare(&mut state, &binding, &guard).unwrap();
    let executable = fs::canonicalize(env!("CARGO_BIN_EXE_relic-gateway-worker")).unwrap();
    let executable_endpoint = get_endpoint(executable.parent().unwrap());
    register_roots(
        &mut state,
        &[PhysicalRootClaim {
            kind: PhysicalRootKind::EXECUTABLE,
            owner_id: "gateway_worker_binary",
            endpoint: &executable_endpoint,
        }],
        &guard,
    )
    .unwrap();
    let scratch = get_endpoint(&directory.path().join("target/.relic-scratch"));
    relic::staging_quota::reserve_owned_staging_quota(
        &mut state,
        &scratch,
        &relic::staging_quota::StagingQuotaBinding {
            object_kind: "gateway_scratch".into(),
            object_id: "resource".into(),
            storage_endpoint_id: binding.storage_endpoint_id.clone(),
            storage_identity: format!(
                "unix:{}:{}",
                scratch.identity().device,
                scratch.identity().inode
            ),
            volume_identity: format!("unix:{}", scratch.identity().device),
            max_bytes: 8 * 1024 * 1024,
        },
    )
    .unwrap();
    drop(scratch);
    let growth = relic::volume_budget::GrowthBinding {
        operation_kind: "initialization".into(),
        operation_id: "resource".into(),
        ordinal: 0,
        resource_id: "resource".into(),
        storage_identity: binding.storage_identity.clone(),
        volume_identity: format!(
            "unix:{}",
            fs::metadata(directory.path().join("target")).unwrap().dev()
        ),
        receiver_epoch: 1,
        fence_generation: 1,
        max_bytes: 32 * 1024 * 1024,
    };
    state
        .start_gateway_initialization_with_growth(
            "resource",
            1,
            1,
            &growth,
            16 * 1024 * 1024 * 1024,
            16 * 1024 * 1024 * 1024,
        )
        .unwrap();
    let target = directory.path().join("target");
    let state_dir = directory.path().join("state");
    let markers = directory.path().join("markers");
    fs::create_dir(&markers).unwrap();
    fs::set_permissions(&markers, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = markers.join("locked");
    let script = directory.path().join("orphan.py");
    fs::write(&script, format!("#!/usr/bin/python3\nimport fcntl,time\nf=open({:?},'r')\nfcntl.flock(f,fcntl.LOCK_EX)\nopen({:?},'w').write('locked')\ntime.sleep(30)\n", target.join(".relic-owner.lock").to_str().unwrap(), marker.to_str().unwrap())).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let (bound_tx, bound_rx) = mpsc::channel();
    let child_state = state_dir.clone();
    let child_target = target.clone();
    let child_markers = markers.clone();
    let worker = std::thread::spawn(move || {
        let limits = WorkerLimits {
            memory_max_bytes: 32 * 1024 * 1024,
            memory_high_bytes: 24 * 1024 * 1024,
            max_tasks: 16,
            max_open_files: 32,
            max_runtime: Duration::from_secs(30),
            max_output_bytes: 4096,
        };
        execute_worker_recorded(
            &script,
            b"",
            &[],
            &[child_target, child_markers],
            limits,
            &StageGuard::default(),
            |identity| {
                let mut callback_state = StateStore::open(&child_state).unwrap();
                callback_state
                    .bind_gateway_initialization_worker("resource", 1, 1, identity)
                    .unwrap();
                bound_tx.send(()).unwrap();
                Ok(())
            },
        )
    });
    bound_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists());
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let job = pool.admit_job("job", &guard).unwrap();
    let context = GatewayExecutionContext {
        executable: Path::new(env!("CARGO_BIN_EXE_relic-gateway-worker")),
        state_dir: &state_dir,
        target_key_ref: "target_key",
        target_password: "test-only-password",
        repository_max_bytes: 32 * 1024 * 1024,
        worker_limits: get_limits(),
        job: &job,
        guard: &guard,
    };
    // The orphan made no repository; inspection fails closed after quiescing it.
    let result = store.reconcile_initialization(&mut state, "resource", &context);
    assert!(matches!(result, Err(GatewayStoreError::OUTCOME_UNKNOWN)));
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        growth.max_bytes
    );
    let recorded = state
        .get_gateway_layout("resource")
        .unwrap()
        .unwrap()
        .containment
        .unwrap();
    assert!(
        !Path::new("/sys/fs/cgroup")
            .join(recorded.group_path.trim_start_matches('/'))
            .exists()
    );
    assert!(worker.join().unwrap().is_err());
    assert_eq!(
        state
            .get_gateway_layout("resource")
            .unwrap()
            .unwrap()
            .effect_state,
        "unknown"
    );
    let owner = File::open(target.join(".relic-owner.lock")).unwrap();
    owner.try_lock().unwrap();
}
