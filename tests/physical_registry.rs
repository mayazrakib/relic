#![cfg(target_os = "linux")]
use relic::gateway_state::GatewayResourceBinding;
use relic::local_endpoint::{FileIdentity, LocalEndpoint};
use relic::physical_registry::{
    PhysicalRegistryError, PhysicalRootClaim, PhysicalRootKind, check_registered_access,
    check_registered_roots, complete_inventory, register_roots, seed_inventory_roots,
};
use relic::resources::StageGuard;
use relic::state::{CaptureBinding, ManifestArtifactBinding, StateStore};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

fn create_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
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
fn create_fixture() -> (tempfile::TempDir, PathBuf, StateStore) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("state");
    let state = StateStore::open(&path).unwrap();
    (root, path, state)
}

#[test]
fn scoped_access_checks_registered_owner_and_staging_ancestry() {
    let (root, _, mut state) = create_fixture();
    let staging = root.path().join("staging");
    let other = root.path().join("other");
    let sibling = root.path().join("sibling");
    for path in [&staging, &other, &sibling] {
        create_directory(path);
    }
    let child = staging.join("child");
    create_directory(&child);
    let staging_endpoint = get_endpoint(&staging);
    let child_endpoint = get_endpoint(&child);
    let other_endpoint = get_endpoint(&other);
    let sibling_endpoint = get_endpoint(&sibling);
    let guard = StageGuard::default();
    register_roots(
        &mut state,
        &[
            PhysicalRootClaim {
                kind: PhysicalRootKind::STAGING,
                owner_id: "staging",
                endpoint: &staging_endpoint,
            },
            PhysicalRootClaim {
                kind: PhysicalRootKind::GATEWAY,
                owner_id: "gateway",
                endpoint: &other_endpoint,
            },
        ],
        &guard,
    )
    .unwrap();
    check_registered_access(
        &state,
        PhysicalRootKind::STAGING,
        "staging",
        &staging_endpoint,
        &guard,
    )
    .unwrap();
    check_registered_access(
        &state,
        PhysicalRootKind::STAGING,
        "staging",
        &child_endpoint,
        &guard,
    )
    .unwrap();
    assert!(
        check_registered_access(
            &state,
            PhysicalRootKind::STAGING,
            "wrong_owner",
            &staging_endpoint,
            &guard
        )
        .is_err()
    );
    assert!(
        check_registered_access(
            &state,
            PhysicalRootKind::STAGING,
            "staging",
            &sibling_endpoint,
            &guard
        )
        .is_err()
    );
    assert!(
        check_registered_access(
            &state,
            PhysicalRootKind::GATEWAY,
            "unregistered",
            &sibling_endpoint,
            &guard
        )
        .is_err()
    );

    fs::rename(&other, root.path().join("moved_other")).unwrap();
    check_registered_access(
        &state,
        PhysicalRootKind::STAGING,
        "staging",
        &child_endpoint,
        &guard,
    )
    .unwrap();
    assert!(register_roots(&mut state, &[], &guard).is_err());

    fs::rename(&staging, root.path().join("moved_staging")).unwrap();
    create_directory(&staging);
    let replacement = get_endpoint(&staging);
    assert!(
        check_registered_access(
            &state,
            PhysicalRootKind::STAGING,
            "staging",
            &replacement,
            &guard
        )
        .is_err()
    );
    assert!(
        check_registered_access(
            &state,
            PhysicalRootKind::STAGING,
            "staging",
            &staging_endpoint,
            &guard
        )
        .is_err()
    );
}

#[test]
fn read_only_checks_require_registration_and_preserve_registry() {
    let (root, path, mut state) = create_fixture();
    let directory = root.path().join("gateway");
    create_directory(&directory);
    let endpoint = get_endpoint(&directory);
    let guard = StageGuard::default();
    let claim = || PhysicalRootClaim {
        kind: PhysicalRootKind::GATEWAY,
        owner_id: "gateway",
        endpoint: &endpoint,
    };
    assert!(check_registered_roots(&state, &[claim()], &guard).is_err());
    assert!(!path.join(".physical-registry.lock").exists());
    register_roots(&mut state, &[claim()], &guard).unwrap();
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    let before: (i64, i64) = db
        .query_row(
            "SELECT generation,(SELECT count(*) FROM physical_roots) FROM physical_registry_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let readonly = StateStore::open_readonly(&path).unwrap();
    check_registered_roots(&readonly, &[claim()], &guard).unwrap();
    let missing = PhysicalRootClaim {
        kind: PhysicalRootKind::GATEWAY,
        owner_id: "other",
        endpoint: &endpoint,
    };
    assert!(check_registered_roots(&readonly, &[missing], &guard).is_err());
    let after: (i64, i64) = db
        .query_row(
            "SELECT generation,(SELECT count(*) FROM physical_roots) FROM physical_registry_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, after);
    db.execute("UPDATE physical_registry_meta SET inventory_complete=0", [])
        .unwrap();
    assert!(matches!(
        check_registered_roots(&readonly, &[claim()], &guard),
        Err(PhysicalRegistryError::INVENTORY_REQUIRED)
    ));
    fs::rename(&directory, root.path().join("old_gateway")).unwrap();
    create_directory(&directory);
    db.execute("UPDATE physical_registry_meta SET inventory_complete=1", [])
        .unwrap();
    assert!(check_registered_roots(&readonly, &[claim()], &guard).is_err());
}

#[test]
fn registration_enforces_overlap_replay_owner_and_sharing() {
    let (root, _, mut state) = create_fixture();
    let a = root.path().join("a");
    let child = a.join("child");
    let b = root.path().join("b");
    create_directory(&a);
    create_directory(&child);
    create_directory(&b);
    let a = get_endpoint(&a);
    let child = get_endpoint(&child);
    let b = get_endpoint(&b);
    let guard = StageGuard::default();
    let first = register_roots(
        &mut state,
        &[PhysicalRootClaim {
            kind: PhysicalRootKind::STAGING,
            owner_id: "store_a",
            endpoint: &a,
        }],
        &guard,
    )
    .unwrap();
    assert_eq!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::STAGING,
                owner_id: "store_a",
                endpoint: &a
            }],
            &guard
        )
        .unwrap(),
        first
    );
    assert!(matches!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::STAGING,
                owner_id: "store_a",
                endpoint: &b
            }],
            &guard
        ),
        Err(PhysicalRegistryError::CONFLICT)
    ));
    assert!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::STAGING,
                owner_id: "store_b",
                endpoint: &a
            }],
            &guard
        )
        .is_ok()
    );
    assert!(matches!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::GATEWAY,
                owner_id: "gateway",
                endpoint: &child
            }],
            &guard
        ),
        Err(PhysicalRegistryError::CONFLICT)
    ));
    assert!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::GATEWAY,
                owner_id: "gateway",
                endpoint: &b
            }],
            &guard
        )
        .is_ok()
    );
}

#[test]
fn read_only_roots_can_overlap_but_not_a_writer() {
    let (root, _, mut state) = create_fixture();
    let parent = root.path().join("source");
    let child = parent.join("child");
    create_directory(&parent);
    create_directory(&child);
    let parent = get_endpoint(&parent);
    let child = get_endpoint(&child);
    let guard = StageGuard::default();
    register_roots(
        &mut state,
        &[
            PhysicalRootClaim {
                kind: PhysicalRootKind::SOURCE,
                owner_id: "job",
                endpoint: &parent,
            },
            PhysicalRootClaim {
                kind: PhysicalRootKind::EXECUTABLE,
                owner_id: "worker",
                endpoint: &child,
            },
        ],
        &guard,
    )
    .unwrap();
    assert!(matches!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::RESTORE,
                owner_id: "restore",
                endpoint: &child
            }],
            &guard
        ),
        Err(PhysicalRegistryError::CONFLICT)
    ));
}

#[test]
fn simultaneous_controllers_cannot_register_nested_writers() {
    let (root, path, state) = create_fixture();
    let parent = root.path().join("parent");
    let child = parent.join("child");
    create_directory(&parent);
    create_directory(&child);
    drop(state);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (index, target) in [(0, parent), (1, child)] {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut state = StateStore::open(&path).unwrap();
            let endpoint = get_endpoint(&target);
            let owner = format!("gateway_{index}");
            barrier.wait();
            register_roots(
                &mut state,
                &[PhysicalRootClaim {
                    kind: PhysicalRootKind::GATEWAY,
                    owner_id: &owner,
                    endpoint: &endpoint,
                }],
                &StageGuard::default(),
            )
            .is_ok()
        }));
    }
    barrier.wait();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|success| *success)
            .count(),
        1
    );
}

#[test]
fn detects_replaced_root_and_generation_overflow() {
    let (root, path, mut state) = create_fixture();
    let a = root.path().join("a");
    let b = root.path().join("b");
    create_directory(&a);
    create_directory(&b);
    let endpoint = get_endpoint(&a);
    let guard = StageGuard::default();
    register_roots(
        &mut state,
        &[PhysicalRootClaim {
            kind: PhysicalRootKind::GATEWAY,
            owner_id: "gateway",
            endpoint: &endpoint,
        }],
        &guard,
    )
    .unwrap();
    fs::rename(&a, root.path().join("old_a")).unwrap();
    create_directory(&a);
    let b = get_endpoint(&b);
    assert!(matches!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::SOURCE,
                owner_id: "source",
                endpoint: &b
            }],
            &guard
        ),
        Err(PhysicalRegistryError::DRIFT)
    ));
    drop(state);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE physical_registry_meta SET generation=9223372036854775807",
        [],
    )
    .unwrap();
    drop(db);
    fs::remove_dir(&a).unwrap();
    fs::rename(root.path().join("old_a"), &a).unwrap();
    let mut state = StateStore::open(&path).unwrap();
    assert!(matches!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::SOURCE,
                owner_id: "source",
                endpoint: &b
            }],
            &guard
        ),
        Err(PhysicalRegistryError::LIMIT)
    ));
}

#[test]
fn stale_boot_or_namespace_evidence_fails_closed() {
    for field in ["boot_id", "mount_namespace_inode"] {
        let (root, path, mut state) = create_fixture();
        let a = root.path().join("a");
        let b = root.path().join("b");
        create_directory(&a);
        create_directory(&b);
        let a = get_endpoint(&a);
        let b = get_endpoint(&b);
        let guard = StageGuard::default();
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::GATEWAY,
                owner_id: "gateway",
                endpoint: &a,
            }],
            &guard,
        )
        .unwrap();
        drop(state);
        let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
        let value = if field == "boot_id" {
            serde_json::json!("00000000-0000-0000-0000-000000000000")
        } else {
            serde_json::json!(1)
        };
        let text: String = db
            .query_row(
                "SELECT observation FROM physical_roots WHERE kind='gateway'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut observation: serde_json::Value = serde_json::from_str(&text).unwrap();
        observation[field] = value;
        db.execute(
            "UPDATE physical_roots SET observation=?1 WHERE kind='gateway'",
            [observation.to_string()],
        )
        .unwrap();
        drop(db);
        let mut state = StateStore::open(&path).unwrap();
        assert!(matches!(
            register_roots(
                &mut state,
                &[PhysicalRootClaim {
                    kind: PhysicalRootKind::SOURCE,
                    owner_id: "source",
                    endpoint: &b
                }],
                &guard
            ),
            Err(PhysicalRegistryError::DRIFT)
        ));
    }
}

#[test]
fn legacy_inventory_requires_coverage_of_all_existing_owned_roots() {
    let (root, path, mut state) = create_fixture();
    let gateway_path = root.path().join("gateway");
    let artifacts_path = root.path().join("artifacts");
    create_directory(&gateway_path);
    create_directory(&artifacts_path);
    let gateway = get_endpoint(&gateway_path);
    let artifacts = get_endpoint(&artifacts_path);
    let gateway_binding = GatewayResourceBinding {
        resource_id: "gateway".into(),
        authority_id: "authority".into(),
        storage_endpoint_id: "gateway_endpoint".into(),
        storage_identity: format!(
            "unix:{}:{}",
            gateway.identity().device,
            gateway.identity().inode
        ),
        repository_key_ref: "key".into(),
    };
    state.prepare_gateway_resource(&gateway_binding).unwrap();
    state
        .bind_capture(&CaptureBinding {
            authority_id: "authority".into(),
            job_id: "job".into(),
            occurrence_id: "occurrence".into(),
            capture_id: "capture".into(),
            source_view_id: "view".into(),
            consistency: "best_effort".into(),
            source_selection_digest: format!("sha256:{}", "a".repeat(64)),
        })
        .unwrap();
    state
        .prepare_manifest_artifact(&ManifestArtifactBinding {
            artifact_id: "manifest".into(),
            capture_id: "capture".into(),
            storage_endpoint_id: "artifacts".into(),
            storage_identity: format!(
                "unix:{}:{}",
                artifacts.identity().device,
                artifacts.identity().inode
            ),
            relative_name: "artifact_manifest.sealed".into(),
            key_ref: "key".into(),
        })
        .unwrap();
    drop(state);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch(
        "DROP TABLE physical_roots; DROP TABLE physical_registry_meta; PRAGMA user_version=12;",
    )
    .unwrap();
    drop(db);
    let mut state = StateStore::open(&path).unwrap();
    let guard = StageGuard::default();
    assert!(matches!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::GATEWAY,
                owner_id: "gateway",
                endpoint: &gateway
            }],
            &guard
        ),
        Err(PhysicalRegistryError::INVENTORY_REQUIRED)
    ));
    seed_inventory_roots(
        &mut state,
        &[PhysicalRootClaim {
            kind: PhysicalRootKind::GATEWAY,
            owner_id: "gateway",
            endpoint: &gateway,
        }],
        &guard,
    )
    .unwrap();
    assert!(matches!(
        complete_inventory(&mut state, &guard),
        Err(PhysicalRegistryError::INVENTORY_REQUIRED)
    ));
    seed_inventory_roots(
        &mut state,
        &[PhysicalRootClaim {
            kind: PhysicalRootKind::STAGING,
            owner_id: "artifacts",
            endpoint: &artifacts,
        }],
        &guard,
    )
    .unwrap();
    complete_inventory(&mut state, &guard).unwrap();
    assert!(
        register_roots(
            &mut state,
            &[PhysicalRootClaim {
                kind: PhysicalRootKind::GATEWAY,
                owner_id: "gateway",
                endpoint: &gateway
            }],
            &guard
        )
        .is_ok()
    );
}
