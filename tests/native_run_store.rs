#![cfg(all(feature = "embedded-archive", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use relic::archive_disk::ArchiveDiskLimits;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::native_run_store::{NativeRunError, NativeRunExecution, NativeRunStore};
use relic::resources::{ResourceClass, ResourcePool, StageGuard};
use relic::state::{
    ArchiveStageBinding, CaptureBinding, ManifestArtifactBinding, NativeRunBinding,
    PayloadArtifactBinding, PayloadArtifactSeal, StateStore,
};
use relic::worker_runtime::WorkerLimits;
use zeroize::Zeroizing;

fn get_digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn get_stage(id: &str) -> ArchiveStageBinding {
    ArchiveStageBinding {
        stage_id: id.into(),
        capture_id: "capture".into(),
        payload_artifact_id: "payload".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity: "unix:1:2".into(),
        key_ref: "key".into(),
    }
}

fn create_capture(store: &mut StateStore) {
    store
        .bind_capture(&CaptureBinding {
            authority_id: "authority".into(),
            job_id: "job".into(),
            occurrence_id: "occurrence".into(),
            capture_id: "capture".into(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: get_digest('a'),
        })
        .unwrap();
}

fn create_sealed_capture(store: &mut StateStore) {
    create_capture(store);
    let manifest = ManifestArtifactBinding {
        artifact_id: "manifest".into(),
        capture_id: "capture".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity: "unix:1:2".into(),
        relative_name: "artifact_manifest.sealed".into(),
        key_ref: "key".into(),
    };
    store.prepare_manifest_artifact(&manifest).unwrap();
    store
        .seal_manifest_artifact("manifest", &get_digest('b'), 100, &get_digest('c'), 5)
        .unwrap();
    let payload = PayloadArtifactBinding {
        artifact_id: "payload".into(),
        capture_id: "capture".into(),
        storage_endpoint_id: "storage".into(),
        storage_identity: "unix:1:2".into(),
        relative_name: "payload_payload.sealed".into(),
        key_ref: "key".into(),
    };
    store.prepare_payload_artifact(&payload).unwrap();
    store
        .seal_payload_artifact(
            "payload",
            &PayloadArtifactSeal {
                ciphertext_digest: get_digest('d'),
                ciphertext_bytes: 100,
                manifest_digest: get_digest('c'),
                manifest_entry_count: 5,
                file_count: 2,
                payload_bytes: 42,
            },
        )
        .unwrap();
}

fn create_sealed_stage(store: &mut StateStore) {
    create_sealed_capture(store);
    store.prepare_archive_stage(&get_stage("stage_1")).unwrap();
    store
        .prepare_archive_file("stage_1", "file_1", &get_digest('e'), 40)
        .unwrap();
    store
        .prepare_archive_file("stage_1", "file_2", &get_digest('f'), 2)
        .unwrap();
    store
        .seal_archive_file("stage_1", "file_1", &get_digest('1'), 100, "inode_1")
        .unwrap();
    store
        .seal_archive_file("stage_1", "file_2", &get_digest('2'), 100, "inode_2")
        .unwrap();
    store
        .seal_archive_stage("stage_1", &get_digest('3'), 100, "catalog_inode")
        .unwrap();
}

fn create_store(path: &Path) -> NativeRunStore {
    let metadata = fs::metadata(path).unwrap();
    let endpoint = LocalEndpoint::resolve(
        path,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .unwrap();
    NativeRunStore::new(endpoint, path, "native_endpoint").unwrap()
}

fn get_binding(store: &NativeRunStore, id: &str) -> NativeRunBinding {
    NativeRunBinding {
        run_id: id.into(),
        stage_id: "stage_1".into(),
        storage_endpoint_id: "native_endpoint".into(),
        storage_identity: store.storage_identity().into(),
        relative_name: format!("native_{id}"),
        repository_key_ref: "repository_key".into(),
    }
}

fn get_private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn get_identity(path: &Path) -> String {
    let metadata = fs::metadata(path).unwrap();
    format!("unix:{}:{}", metadata.dev(), metadata.ino())
}

#[test]
fn prepares_private_layout_and_replays_without_replacing_it() {
    let directory = get_private_directory();
    let root = fs::canonicalize(directory.path()).unwrap();
    let native = root.join("native");
    fs::create_dir(&native).unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    let mut state = StateStore::open(&root.join("state")).unwrap();
    create_sealed_stage(&mut state);
    let store = create_store(&native);
    let binding = get_binding(&store, "run_1");
    let result = store
        .prepare(&mut state, &binding, &StageGuard::default())
        .unwrap();
    assert_eq!(result.effect_state, "ready");
    let container = native.join("native_run_1");
    assert_eq!(
        result.container_identity.as_deref(),
        Some(get_identity(&container).as_str())
    );
    assert_eq!(
        result.repository_identity.as_deref(),
        Some(get_identity(&container.join("repository")).as_str())
    );
    assert_eq!(
        result.scratch_identity.as_deref(),
        Some(get_identity(&container.join("scratch")).as_str())
    );
    assert_eq!(
        result.owner_lock_identity.as_deref(),
        Some(get_identity(&container.join("owner.lock")).as_str())
    );
    assert_eq!(fs::metadata(&container).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(
        fs::metadata(container.join("owner.lock")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        store
            .prepare(&mut state, &binding, &StageGuard::default())
            .unwrap(),
        result
    );
    let mut changed = binding;
    changed.repository_key_ref = "different_key".into();
    assert!(
        store
            .prepare(&mut state, &changed, &StageGuard::default())
            .is_err()
    );
    changed.repository_key_ref = "repository_key".into();
    changed.storage_identity = "unix:999:999".into();
    assert!(
        store
            .prepare(&mut state, &changed, &StageGuard::default())
            .is_err()
    );
    assert_eq!(get_identity(&container), result.container_identity.unwrap());
}

#[test]
fn preserves_unknown_preexisting_container_and_rejects_unsealed_source() {
    let directory = get_private_directory();
    let root = fs::canonicalize(directory.path()).unwrap();
    let native = root.join("native");
    fs::create_dir(&native).unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    let mut state = StateStore::open(&root.join("state")).unwrap();
    create_sealed_capture(&mut state);
    state.prepare_archive_stage(&get_stage("stage_1")).unwrap();
    let store = create_store(&native);
    let binding = get_binding(&store, "run_1");
    assert!(matches!(
        store.prepare(&mut state, &binding, &StageGuard::default()),
        Err(NativeRunError::STATE)
    ));
    assert!(state.get_native_run("run_1").unwrap().is_none());
    state
        .prepare_archive_file("stage_1", "file_1", &get_digest('e'), 40)
        .unwrap();
    state
        .prepare_archive_file("stage_1", "file_2", &get_digest('f'), 2)
        .unwrap();
    state
        .seal_archive_file("stage_1", "file_1", &get_digest('1'), 100, "inode_1")
        .unwrap();
    state
        .seal_archive_file("stage_1", "file_2", &get_digest('2'), 100, "inode_2")
        .unwrap();
    state
        .seal_archive_stage("stage_1", &get_digest('3'), 100, "catalog_inode")
        .unwrap();
    let foreign = native.join("native_run_1");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("sentinel"), b"preserve").unwrap();
    assert!(matches!(
        store.prepare(&mut state, &binding, &StageGuard::default()),
        Err(NativeRunError::RECONCILIATION_REQUIRED)
    ));
    assert_eq!(fs::read(foreign.join("sentinel")).unwrap(), b"preserve");
    assert_eq!(
        state.get_native_run("run_1").unwrap().unwrap().effect_state,
        "prepared"
    );
}

#[test]
fn rejects_replaced_owner_and_extra_layout_entries() {
    for scenario in ["owner", "extra", "repository"] {
        let directory = get_private_directory();
        let root = fs::canonicalize(directory.path()).unwrap();
        let native = root.join("native");
        fs::create_dir(&native).unwrap();
        fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = StateStore::open(&root.join("state")).unwrap();
        create_sealed_stage(&mut state);
        let store = create_store(&native);
        let binding = get_binding(&store, "run_1");
        store
            .prepare(&mut state, &binding, &StageGuard::default())
            .unwrap();
        let container = native.join("native_run_1");
        match scenario {
            "owner" => {
                let original = container.join("owner.lock");
                fs::rename(&original, native.join("retained_lock")).unwrap();
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(original)
                    .unwrap();
            }
            "extra" => {
                fs::write(container.join("unexpected"), b"keep").unwrap();
            }
            "repository" => {
                let original = container.join("repository");
                fs::rename(&original, native.join("retained_repository")).unwrap();
                fs::create_dir(&original).unwrap();
                fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            store
                .prepare(&mut state, &binding, &StageGuard::default())
                .is_err()
        );
        assert_eq!(
            state.get_native_run("run_1").unwrap().unwrap().effect_state,
            "ready"
        );
        if scenario == "extra" {
            assert_eq!(fs::read(container.join("unexpected")).unwrap(), b"keep");
        }
    }
}

#[test]
fn reconciles_recorded_staging_without_running_a_worker() {
    let directory = get_private_directory();
    let root = fs::canonicalize(directory.path()).unwrap();
    let native = root.join("native");
    fs::create_dir(&native).unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = root.join("state");
    let mut state = StateStore::open(&state_path).unwrap();
    create_sealed_stage(&mut state);
    let store = create_store(&native);
    let binding = get_binding(&store, "run_1");
    state.prepare_native_run(&binding).unwrap();
    let metadata = fs::metadata(&native).unwrap();
    state
        .reserve_staging_quota(
            &relic::staging_quota::StagingQuotaBinding {
                object_kind: "native_run".into(),
                object_id: "run_1".into(),
                storage_endpoint_id: binding.storage_endpoint_id.clone(),
                storage_identity: binding.storage_identity.clone(),
                volume_identity: format!("unix:{}", metadata.dev()),
                max_bytes: 24 * 1024 * 1024 + 84,
            },
            16 * 1024 * 1024 * 1024,
            16 * 1024 * 1024 * 1024,
        )
        .unwrap();
    let container = native.join("native_run_1");
    fs::create_dir(&container).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    state
        .mark_native_staging("run_1", &get_identity(&container))
        .unwrap();
    let guard = StageGuard::default();
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let job = pool.admit_job("job", &guard).unwrap();
    let key = Zeroizing::new([7u8; 32]);
    let execution = NativeRunExecution {
        executable: Path::new("/nonexistent-worker"),
        state_dir: &state_path,
        archive_dir: &root,
        source_key_ref: "key",
        source_key: &key,
        repository_key_ref: "repository_key",
        repository_password: "test-only-password",
        source_limits: ArchiveDiskLimits {
            max_entries: 10,
            max_file_bytes: 1024,
            max_ciphertext_bytes: 4096,
            max_catalog_bytes: 4096,
        },
        worker_limits: WorkerLimits {
            memory_max_bytes: 128 * 1024 * 1024,
            memory_high_bytes: 64 * 1024 * 1024,
            max_tasks: 16,
            max_open_files: 32,
            max_runtime: Duration::from_secs(5),
            max_output_bytes: 4096,
        },
        job: &job,
        guard: &guard,
    };
    let record = store.reconcile(&mut state, "run_1", &execution).unwrap();
    assert_eq!(record.effect_state, "ready");
    assert_eq!(record.creation_attempts, 0);
    assert!(container.join("repository").is_dir());
    assert!(container.join("scratch").is_dir());
    assert!(container.join("owner.lock").is_file());
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard with Landlock"]
fn retains_fence_and_budget_until_unreaped_worker_is_proved_stopped() {
    use std::time::Instant;

    let directory = get_private_directory();
    let root = fs::canonicalize(directory.path()).unwrap();
    let native = root.join("native");
    fs::create_dir(&native).unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = root.join("state");
    let mut state = StateStore::open(&state_path).unwrap();
    create_sealed_stage(&mut state);
    let store = create_store(&native);
    let other_store = create_store(&native);
    let binding = get_binding(&store, "run_1");
    store
        .prepare(&mut state, &binding, &StageGuard::default())
        .unwrap();
    let script = root.join("worker.py");
    fs::write(&script, "#!/usr/bin/python3\nimport json,sys,time\nfrom pathlib import Path\nraw=sys.stdin.buffer.read()\nassert len(raw)>=4 and int.from_bytes(raw[:4],'big')==len(raw)-4\nrequest=json.loads(raw[4:])\nmember=next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))\n(Path(request['scratch_dir'])/'membership').write_text(member)\ntime.sleep(15)\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = native.join("native_run_1/scratch/membership");
    let observer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(member) = fs::read_to_string(&marker) {
                let control = Path::new("/sys/fs/cgroup")
                    .join(member.trim().trim_start_matches('/'))
                    .join("cgroup.kill");
                assert!(
                    control
                        .parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("worker_")
                );
                fs::set_permissions(&control, fs::Permissions::from_mode(0o000)).unwrap();
                return control;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not report its membership"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let guard = StageGuard::default();
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let job = pool.admit_job("job", &guard).unwrap();
    let key = Zeroizing::new([7u8; 32]);
    let execution = NativeRunExecution {
        executable: &script,
        state_dir: &state_path,
        archive_dir: &root,
        source_key_ref: "key",
        source_key: &key,
        repository_key_ref: "repository_key",
        repository_password: "test-only-password",
        source_limits: ArchiveDiskLimits {
            max_entries: 10,
            max_file_bytes: 1024,
            max_ciphertext_bytes: 4096,
            max_catalog_bytes: 4096,
        },
        worker_limits: WorkerLimits {
            memory_max_bytes: 32 * 1024 * 1024,
            memory_high_bytes: 24 * 1024 * 1024,
            max_tasks: 16,
            max_open_files: 32,
            max_runtime: Duration::from_secs(1),
            max_output_bytes: 4096,
        },
        job: &job,
        guard: &guard,
    };
    let result = store.execute(&mut state, "run_1", &execution);
    let control = observer.join().unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(result, Err(NativeRunError::OUTCOME_UNKNOWN)));
    assert_eq!(
        state.get_native_run("run_1").unwrap().unwrap().effect_state,
        "unknown"
    );
    let held = pool.usage().unwrap().0;
    assert_eq!(held.jobs, 1);
    assert_eq!(held.data_bytes, 32 * 1024 * 1024);
    assert!(held.spool_bytes > 0);
    assert!(matches!(
        other_store.prepare(&mut state, &binding, &guard),
        Err(NativeRunError::BUSY)
    ));
    assert!(store.reap_pending("run_1", &guard).unwrap());
    assert_eq!(pool.usage().unwrap().0.data_bytes, 0);
    assert_eq!(pool.usage().unwrap().0.spool_bytes, 0);
    assert_eq!(
        other_store
            .prepare(&mut state, &binding, &guard)
            .unwrap()
            .effect_state,
        "unknown"
    );
}
