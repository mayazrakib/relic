#![cfg(unix)]

use std::fs::{File, OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use relic::identity::hash_domain;
use relic::manifest::{ManifestEntry, verify_file_content};
use relic::manifest_artifact::{seal_manifest, verify_sealed_manifest};
use relic::manifest_spool::{ManifestSpool, SpoolLimits};
use relic::resources::{Demand, ResourceClass, ResourcePool, StageGuard};
use relic::state::{CaptureBinding, StateError, StateStore};
use serde_json::Value;
use zeroize::Zeroizing;

#[test]
fn authenticated_manifest_precedes_durable_publication_binding() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temporary.path(), Permissions::from_mode(0o700)).unwrap();
    let pool = ResourcePool::new(ResourceClass::LOW, 2);
    let guard = StageGuard::default();
    let control = pool.reserve_control(8 * 1024 * 1024, &guard).unwrap();
    let job = pool.admit_job("job_1", &guard).unwrap();
    let stage = job
        .reserve_stage(
            None,
            Demand {
                data_bytes: 8 * 1024 * 1024,
                cache_bytes: 256 * 1024,
                spool_bytes: 2 * 1024 * 1024,
                open_files: 4,
                cpu_workers: 1,
                streams: 1,
                ..Demand::default()
            },
            &guard,
        )
        .unwrap();
    let state_path = temporary.path().join("state");
    let mut store = StateStore::open(&state_path).unwrap();
    let publication: Value =
        serde_json::from_str(include_str!("../fixtures/contracts/publication.json")).unwrap();
    let policy: Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    let binding = CaptureBinding {
        authority_id: publication["commit_key"]["authority_id"]
            .as_str()
            .unwrap()
            .into(),
        job_id: publication["commit_key"]["job_id"].as_str().unwrap().into(),
        occurrence_id: publication["commit_key"]["occurrence_id"]
            .as_str()
            .unwrap()
            .into(),
        capture_id: publication["capture_id"].as_str().unwrap().into(),
        source_view_id: publication["source_view_id"].as_str().unwrap().into(),
        consistency: publication["consistency"].as_str().unwrap().into(),
        source_selection_digest: hash_domain(
            "relic/source-selection/v1",
            &policy["source_bindings"],
        )
        .unwrap(),
    };
    store.bind_capture(&binding).unwrap();
    assert!(matches!(
        store.bind_publication(&publication),
        Err(StateError::IdempotencyConflict)
    ));
    let mut spool = ManifestSpool::create(
        &temporary.path().join("ordering.sqlite"),
        SpoolLimits {
            max_entries: 10,
            max_frame_bytes: 1024 * 1024,
            max_spool_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let entry: ManifestEntry =
        serde_json::from_str(include_str!("../fixtures/contracts/manifest_entry.json")).unwrap();
    verify_file_content(&entry, &mut &b""[..]).unwrap();
    spool.add_entry(&entry).unwrap();
    let artifact_path = temporary.path().join("capture.encrypted");
    let mut artifact_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&artifact_path)
        .unwrap();
    let key = Zeroizing::new([19_u8; 32]);
    let limits = relic::encrypted_spool::SpoolLimits {
        plaintext_bytes: 1024 * 1024,
        ciphertext_bytes: 2 * 1024 * 1024,
    };
    let sealed = seal_manifest(&spool, &binding, &mut artifact_file, &key, limits, &guard).unwrap();
    artifact_file.sync_all().unwrap();
    File::open(temporary.path()).unwrap().sync_all().unwrap();
    drop(artifact_file);
    let verified = verify_sealed_manifest(
        &mut File::open(&artifact_path).unwrap(),
        &binding,
        &key,
        limits,
        &guard,
        &sealed.digest,
    )
    .unwrap();
    assert_eq!(verified, sealed);
    assert_eq!(verified.digest, publication["manifest_digest"]);
    store
        .freeze_capture_manifest(&binding.capture_id, &verified.digest, verified.entry_count)
        .unwrap();
    let intent = store.bind_publication(&publication).unwrap();
    assert_eq!(intent.effect_state, "prepared");
    drop(store);
    let mut reopened = StateStore::open(&state_path).unwrap();
    assert_eq!(
        reopened
            .bind_publication(&publication)
            .unwrap()
            .payload_hash,
        intent.payload_hash
    );
    drop(reopened);
    drop(spool);
    std::fs::remove_file(artifact_path).unwrap();
    std::fs::remove_file(temporary.path().join("ordering.sqlite")).unwrap();
    drop(job);
    assert_eq!(pool.usage().unwrap().0.jobs, 1);
    drop(stage);
    drop(control);
    assert_eq!(pool.usage().unwrap(), (Demand::default(), 0));
}
