use relic::gateway_state::{GatewayAdmissionBinding, GatewayResourceBinding};
use relic::state::{
    ArchiveStageBinding, CaptureBinding, ManifestArtifactBinding, NativeRunBinding,
    PayloadArtifactBinding, PayloadArtifactSeal, StateError, StateStore,
};
use serde_json::json;

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

fn get_run(id: &str) -> NativeRunBinding {
    NativeRunBinding {
        run_id: id.into(),
        stage_id: "stage_1".into(),
        storage_endpoint_id: "native_endpoint".into(),
        storage_identity: "unix:1:3".into(),
        relative_name: format!("native_{id}"),
        repository_key_ref: "repository_key".into(),
    }
}

#[test]
fn authority_and_execution_history_are_bound() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_stage(&mut store);
    store.prepare_native_run(&get_run("run_1")).unwrap();
    store.mark_native_staging("run_1", "container").unwrap();
    store
        .mark_native_ready("run_1", "repository", "lock", "scratch")
        .unwrap();
    store.start_native_run("run_1", "create").unwrap();
    store
        .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 42)
        .unwrap();
    let key = json!({"authority_id":"authority","job_id":"job","occurrence_id":"occurrence","destination_id":"destination"});
    let mut policy: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    policy["job"]["job_id"] = json!("job");
    policy["job"]["verification"]["publication"] = json!("data_verified");
    policy["destination"]["destination_id"] = json!("destination");
    policy["destination"]["repository_id"] = json!("repository_id");
    policy["verification"] = json!("data_verified");
    let policy_digest = relic::identity::hash_domain("relic/effective-policy/v1", &policy).unwrap();
    let publication=store.bind_publication(&json!({"commit_key":key,"capture_id":"capture","consistency":"best_effort","destination_config_revision":"1","manifest_digest":get_digest('c'),"policy_digest":policy_digest,"source_view_id":"view"})).unwrap();
    let resource = GatewayResourceBinding {
        resource_id: "resource".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "target".into(),
        storage_identity: "unix:1:9".into(),
        repository_key_ref: "key".into(),
    };
    assert_eq!(
        store
            .prepare_gateway_resource(&resource)
            .unwrap()
            .receiver_epoch,
        1
    );
    store
        .ready_gateway_resource("resource", 1, 1, "repository_id")
        .unwrap();
    let binding = GatewayAdmissionBinding {
        resource_id: "resource".into(),
        admission_id: "admission".into(),
        commit_key: key,
        payload_hash: publication.payload_hash,
        native_run_id: "run_1".into(),
        native_snapshot_id: "a".repeat(64),
        capture_id: "capture".into(),
        manifest_digest: get_digest('c'),
        owner: "owner".into(),
        effective_policy: policy.clone(),
    };
    assert!(store.admit_gateway_publication(&binding, 1, 2).is_err());
    let mut bad_preimage = binding.clone();
    bad_preimage.effective_policy["job"]["name"] = json!("different policy");
    assert!(matches!(
        store.admit_gateway_publication(&bad_preimage, 1, 1),
        Err(StateError::IdempotencyConflict)
    ));
    let admitted = store.admit_gateway_publication(&binding, 1, 1).unwrap();
    assert_eq!(
        store.admit_gateway_publication(&binding, 1, 1).unwrap(),
        admitted
    );
    let mut tampered = binding.clone();
    tampered.effective_policy["verification"] = json!("metadata_verified");
    assert!(store.admit_gateway_publication(&tampered, 1, 1).is_err());
    let mut other_admission = binding.clone();
    other_admission.admission_id = "other_admission".into();
    assert!(matches!(
        store.admit_gateway_publication(&other_admission, 1, 1),
        Err(StateError::IdempotencyConflict)
    ));
    let mut altered = binding.clone();
    altered.payload_hash = get_digest('f');
    assert!(matches!(
        store.admit_gateway_publication(&altered, 1, 1),
        Err(StateError::IdempotencyConflict)
    ));
    let first = store.start_gateway_execution("admission", 1, 1).unwrap();
    store
        .transition_gateway_execution("admission", first.ordinal, 1, 1, "unknown", None)
        .unwrap();
    assert!(store.start_gateway_execution("admission", 1, 1).is_err());
    store.block_gateway_resource("resource", 1, 1).unwrap();
    assert!(store.install_gateway_fence("resource", 1, 1, 2, 2).is_err());
    store
        .transition_gateway_execution("admission", first.ordinal, 1, 1, "proven_unpublished", None)
        .unwrap();
    assert_eq!(
        store
            .install_gateway_fence("resource", 1, 1, 2, 2)
            .unwrap()
            .effect_state,
        "ready"
    );
    let preserved = store.get_gateway_admission("admission").unwrap().unwrap();
    assert_eq!(
        (preserved.receiver_epoch, preserved.fence_generation),
        (1, 1)
    );
    assert_eq!(preserved.request_type, "publication");
    assert_eq!(preserved.admission_decision, "accepted");
    for ordinal in 2..=3 {
        let item = store.start_gateway_execution("admission", 2, 2).unwrap();
        assert_eq!((item.receiver_epoch, item.fence_generation), (2, 2));
        assert_eq!(item.ordinal, ordinal);
        store
            .transition_gateway_execution("admission", ordinal, 2, 2, "proven_unpublished", None)
            .unwrap();
    }
    assert!(store.start_gateway_execution("admission", 2, 2).is_err());
    assert_eq!(store.list_gateway_executions("admission").unwrap().len(), 3);
    assert_eq!(
        store.list_gateway_pending("resource", "", 1).unwrap().len(),
        1
    );
    assert!(store.list_gateway_pending("resource", "", 1001).is_err());
    assert!(store.admit_gateway_publication(&binding, 1, 1).is_err());
}

#[test]
fn receipt_correlates_all_gateway_and_publication_identities() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_stage(&mut store);
    store.prepare_native_run(&get_run("run_1")).unwrap();
    store.mark_native_staging("run_1", "container").unwrap();
    store
        .mark_native_ready("run_1", "repository", "lock", "scratch")
        .unwrap();
    store.start_native_run("run_1", "create").unwrap();
    store
        .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 42)
        .unwrap();
    let key = json!({"authority_id":"authority","job_id":"job","occurrence_id":"occurrence","destination_id":"destination"});
    let mut policy: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    policy["job"]["job_id"] = json!("job");
    policy["job"]["verification"]["publication"] = json!("data_verified");
    policy["destination"]["destination_id"] = json!("destination");
    policy["destination"]["repository_id"] = json!("repository_id");
    policy["verification"] = json!("data_verified");
    let policy_digest = relic::identity::hash_domain("relic/effective-policy/v1", &policy).unwrap();
    let publication=store.bind_publication(&json!({"commit_key":key,"capture_id":"capture","consistency":"best_effort","destination_config_revision":"1","manifest_digest":get_digest('c'),"policy_digest":policy_digest,"source_view_id":"view"})).unwrap();
    let resource = GatewayResourceBinding {
        resource_id: "resource".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "target".into(),
        storage_identity: "unix:1:9".into(),
        repository_key_ref: "key".into(),
    };
    assert_eq!(
        store
            .prepare_gateway_resource(&resource)
            .unwrap()
            .receiver_epoch,
        1
    );
    store
        .ready_gateway_resource("resource", 1, 1, "repository_id")
        .unwrap();
    let binding = GatewayAdmissionBinding {
        resource_id: "resource".into(),
        admission_id: "admission".into(),
        commit_key: key,
        payload_hash: publication.payload_hash,
        native_run_id: "run_1".into(),
        native_snapshot_id: "a".repeat(64),
        capture_id: "capture".into(),
        manifest_digest: get_digest('c'),
        owner: "owner".into(),
        effective_policy: policy.clone(),
    };
    store.admit_gateway_publication(&binding, 1, 1).unwrap();
    store.start_gateway_execution("admission", 1, 1).unwrap();
    store
        .transition_gateway_execution(
            "admission",
            1,
            1,
            1,
            "published_unverified",
            Some("snapshot"),
        )
        .unwrap();
    let receipt = json!({"record_version":1,"commit_key":binding.commit_key,"payload_hash":binding.payload_hash,"manifest_digest":get_digest('c'),"policy_digest":policy_digest,"destination_config_revision":"1","source_view_id":"view","capture_id":"capture","consistency":"best_effort","resource_id":"resource","receiver_epoch":"1","fence_generation":"1","admission_id":"admission","repository_id":"repository_id","native_result_id":"snapshot","durability":"durable","verification":"data_verified","committed_at":"2026-01-01T00:00:00Z"});
    let mut weaker = receipt.clone();
    weaker["verification"] = json!("metadata_verified");
    assert!(
        store
            .record_gateway_receipt("admission", 1, 1, 1, &weaker)
            .is_err()
    );
    let mut changed = receipt.clone();
    changed["repository_id"] = json!("other");
    assert!(
        store
            .record_gateway_receipt("admission", 1, 1, 1, &changed)
            .is_err()
    );
    for (field, value) in [
        ("native_result_id", json!("wrong_snapshot")),
        ("fence_generation", json!("2")),
        ("admission_id", json!("other_admission")),
        ("policy_digest", json!(get_digest('f'))),
    ] {
        let mut changed = receipt.clone();
        changed[field] = value;
        assert!(
            store
                .record_gateway_receipt("admission", 1, 1, 1, &changed)
                .is_err()
        );
        let publication = store.get_publication(&binding.commit_key).unwrap().unwrap();
        assert_eq!(publication.effect_state, "published");
        assert!(publication.receipt.is_none());
        assert_eq!(
            store.list_gateway_executions("admission").unwrap()[0].effect_state,
            "published_unverified"
        );
    }
    assert!(store.record_receipt(&receipt).is_err());
    assert_eq!(
        store
            .record_gateway_receipt("admission", 1, 1, 1, &receipt)
            .unwrap(),
        receipt
    );
    assert_eq!(
        store
            .record_gateway_receipt("admission", 1, 1, 1, &receipt)
            .unwrap(),
        receipt
    );
    assert_eq!(
        store.list_gateway_executions("admission").unwrap()[0].effect_state,
        "verified"
    );
}

#[test]
fn separate_connections_serialize_competing_admissions_and_executions() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_stage(&mut store);
    store.prepare_native_run(&get_run("run_1")).unwrap();
    store.mark_native_staging("run_1", "container").unwrap();
    store
        .mark_native_ready("run_1", "repository", "lock", "scratch")
        .unwrap();
    store.start_native_run("run_1", "create").unwrap();
    store
        .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 42)
        .unwrap();
    let key = json!({"authority_id":"authority","job_id":"job","occurrence_id":"occurrence","destination_id":"destination"});
    let mut policy: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    policy["job"]["job_id"] = json!("job");
    policy["job"]["verification"]["publication"] = json!("data_verified");
    policy["destination"]["destination_id"] = json!("destination");
    policy["destination"]["repository_id"] = json!("repository_id");
    policy["verification"] = json!("data_verified");
    let policy_digest = relic::identity::hash_domain("relic/effective-policy/v1", &policy).unwrap();
    let publication=store.bind_publication(&json!({"commit_key":key,"capture_id":"capture","consistency":"best_effort","destination_config_revision":"1","manifest_digest":get_digest('c'),"policy_digest":policy_digest,"source_view_id":"view"})).unwrap();
    let resource = GatewayResourceBinding {
        resource_id: "resource".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "target".into(),
        storage_identity: "unix:1:9".into(),
        repository_key_ref: "key".into(),
    };
    assert_eq!(
        store
            .prepare_gateway_resource(&resource)
            .unwrap()
            .receiver_epoch,
        1
    );
    store
        .ready_gateway_resource("resource", 1, 1, "repository_id")
        .unwrap();
    let binding = GatewayAdmissionBinding {
        resource_id: "resource".into(),
        admission_id: "admission".into(),
        commit_key: key,
        payload_hash: publication.payload_hash,
        native_run_id: "run_1".into(),
        native_snapshot_id: "a".repeat(64),
        capture_id: "capture".into(),
        manifest_digest: get_digest('c'),
        owner: "owner".into(),
        effective_policy: policy.clone(),
    };
    let path = directory.path().join("state");
    drop(store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for id in ["first", "second"] {
        let mut candidate = binding.clone();
        candidate.admission_id = id.into();
        let path = path.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut connection = StateStore::open(&path).unwrap();
            barrier.wait();
            let accepted = connection
                .admit_gateway_publication(&candidate, 1, 1)
                .is_ok();
            let started = accepted && connection.start_gateway_execution(id, 1, 1).is_ok();
            (accepted, started)
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|value| value.0).count(), 1);
    assert_eq!(outcomes.iter().filter(|value| value.1).count(), 1);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store
            .list_gateway_pending("resource", "", 10)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn replication_cannot_admit_matching_metadata_only_policy() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&directory.path().join("state")).unwrap();
    create_sealed_stage(&mut store);
    store.prepare_native_run(&get_run("run_1")).unwrap();
    store.mark_native_staging("run_1", "container").unwrap();
    store
        .mark_native_ready("run_1", "repository", "lock", "scratch")
        .unwrap();
    store.start_native_run("run_1", "create").unwrap();
    store
        .seal_native_run("run_1", &"a".repeat(64), &get_digest('c'), 5, 2, 42)
        .unwrap();
    let key = json!({"authority_id":"authority","job_id":"job","occurrence_id":"occurrence","destination_id":"destination"});
    let mut policy: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    policy["job"]["job_id"] = json!("job");
    policy["job"]["verification"]["publication"] = json!("metadata_verified");
    policy["job"]["method"] = json!("replicate");
    policy["destination"]["destination_id"] = json!("destination");
    policy["destination"]["repository_id"] = json!("repository_id");
    policy["verification"] = json!("metadata_verified");
    let policy_digest = relic::identity::hash_domain("relic/effective-policy/v1", &policy).unwrap();
    let publication=store.bind_publication(&json!({"commit_key":key,"capture_id":"capture","consistency":"best_effort","destination_config_revision":"1","manifest_digest":get_digest('c'),"policy_digest":policy_digest,"source_view_id":"view"})).unwrap();
    let resource = GatewayResourceBinding {
        resource_id: "resource".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "target".into(),
        storage_identity: "unix:1:9".into(),
        repository_key_ref: "key".into(),
    };
    assert_eq!(
        store
            .prepare_gateway_resource(&resource)
            .unwrap()
            .receiver_epoch,
        1
    );
    store
        .ready_gateway_resource("resource", 1, 1, "repository_id")
        .unwrap();
    let binding = GatewayAdmissionBinding {
        resource_id: "resource".into(),
        admission_id: "admission".into(),
        commit_key: key,
        payload_hash: publication.payload_hash,
        native_run_id: "run_1".into(),
        native_snapshot_id: "a".repeat(64),
        capture_id: "capture".into(),
        manifest_digest: get_digest('c'),
        owner: "owner".into(),
        effective_policy: policy.clone(),
    };
    assert!(matches!(
        store.admit_gateway_publication(&binding, 1, 1),
        Err(StateError::InvalidInput)
    ));
    assert!(store.get_gateway_admission("admission").unwrap().is_none());
    assert_eq!(
        store
            .get_publication(&binding.commit_key)
            .unwrap()
            .unwrap()
            .effect_state,
        "prepared"
    );
}

#[test]
fn schema_eight_migration_preserves_existing_capture() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut store = StateStore::open(&path).unwrap();
    create_capture(&mut store);
    drop(store);
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    connection.execute_batch("DROP TABLE gateway_layouts; DROP TABLE gateway_executions; DROP TABLE gateway_admissions; DROP TABLE gateway_resources; ALTER TABLE native_runs DROP COLUMN worker_identity; ALTER TABLE native_runs DROP COLUMN operation_token; ALTER TABLE native_runs DROP COLUMN scope_protocol; PRAGMA user_version = 8;").unwrap();
    drop(connection);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store
            .get_capture("capture")
            .unwrap()
            .unwrap()
            .binding
            .job_id,
        "job"
    );
    assert!(store.get_gateway_resource("resource").unwrap().is_none());
}
