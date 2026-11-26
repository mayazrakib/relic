use relic::gateway_state::GatewayResourceBinding;
use relic::state::{StateError, StateStore};
use relic::volume_budget::{GrowthBinding, MAX_GROWTH_BYTES};

const RESERVE: u64 = 512 * 1024 * 1024;
const CAPACITY: u64 = 8 * 1024 * 1024 * 1024;

fn create_ready_layout(state: &mut StateStore, id: &str, device: u64, inode: u64) -> GrowthBinding {
    let identity = format!("unix:{device}:{inode}");
    state
        .prepare_gateway_resource(&GatewayResourceBinding {
            resource_id: id.into(),
            authority_id: "authority".into(),
            storage_endpoint_id: format!("endpoint_{id}"),
            storage_identity: identity.clone(),
            repository_key_ref: "key".into(),
        })
        .unwrap();
    state.prepare_gateway_layout(id).unwrap();
    state
        .bind_gateway_owner(id, &format!("unix:{device}:{}", inode + 1))
        .unwrap();
    state
        .bind_gateway_scratch(id, &format!("unix:{device}:{}", inode + 2))
        .unwrap();
    state.seal_gateway_layout(id).unwrap();
    GrowthBinding {
        operation_kind: "initialization".into(),
        operation_id: id.into(),
        ordinal: 0,
        resource_id: id.into(),
        storage_identity: identity,
        volume_identity: format!("unix:{device}"),
        receiver_epoch: 1,
        fence_generation: 1,
        max_bytes: 1024,
    }
}

#[test]
fn initialization_reservation_is_atomic_retained_and_released_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let binding = create_ready_layout(&mut state, "one", 1, 10);
    assert!(matches!(
        state.start_gateway_initialization_with_growth(
            "one",
            1,
            1,
            &binding,
            CAPACITY,
            RESERVE + binding.max_bytes - 1
        ),
        Err(StateError::QuotaExceeded)
    ));
    let layout = state.get_gateway_layout("one").unwrap().unwrap();
    assert_eq!(layout.effect_state, "ready");
    assert_eq!(layout.initialization_attempts, 0);
    assert!(
        state
            .get_destination_growth("initialization", "one", 0)
            .unwrap()
            .is_none()
    );
    state
        .start_gateway_initialization_with_growth(
            "one",
            1,
            1,
            &binding,
            CAPACITY,
            RESERVE + binding.max_bytes,
        )
        .unwrap();
    state
        .mark_gateway_initialization_unknown("one", 1, 1)
        .unwrap();
    drop(state);
    let mut state = StateStore::open(&path).unwrap();
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        binding.max_bytes
    );
    let mut changed = binding.clone();
    changed.max_bytes += 1;
    assert!(
        state
            .complete_gateway_initialization_with_growth("one", 1, 1, &"a".repeat(64), &changed)
            .is_err()
    );
    assert_eq!(
        state
            .get_gateway_layout("one")
            .unwrap()
            .unwrap()
            .effect_state,
        "unknown"
    );
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        binding.max_bytes
    );
    let result = state
        .complete_gateway_initialization_with_growth("one", 1, 1, &"a".repeat(64), &binding)
        .unwrap();
    assert_eq!(result.effect_state, "initialized");
    assert_eq!(state.get_total_held_destination_growth().unwrap(), 0);
    assert_eq!(
        state
            .get_destination_growth("initialization", "one", 0)
            .unwrap()
            .unwrap()
            .effect_state,
        "released"
    );
    assert_eq!(
        state
            .complete_gateway_initialization_with_growth("one", 1, 1, &"a".repeat(64), &binding)
            .unwrap(),
        result
    );
    assert!(
        state
            .complete_gateway_initialization_with_growth("one", 1, 1, &"b".repeat(64), &binding)
            .is_err()
    );
}

#[test]
fn raw_completion_does_not_release_growth_hold() {
    let directory = tempfile::tempdir().unwrap();
    let mut state = StateStore::open(&directory.path().join("state")).unwrap();
    let binding = create_ready_layout(&mut state, "one", 1, 10);
    state
        .start_gateway_initialization_with_growth("one", 1, 1, &binding, CAPACITY, CAPACITY)
        .unwrap();
    state
        .complete_gateway_initialization("one", 1, 1, &"a".repeat(64))
        .unwrap();
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        binding.max_bytes
    );
    state
        .complete_gateway_initialization_with_growth("one", 1, 1, &"a".repeat(64), &binding)
        .unwrap();
    assert_eq!(state.get_total_held_destination_growth().unwrap(), 0);
}

#[test]
fn node_wide_totals_include_distinct_observed_devices() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let first = create_ready_layout(&mut state, "one", 1, 10);
    let second = create_ready_layout(&mut state, "two", 2, 20);
    // Ledger-only arithmetic fixture: this row does not claim producer validation.
    let connection = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    connection.execute("INSERT INTO staging_quota(object_kind,object_id,storage_endpoint_id,storage_identity,volume_identity,max_bytes) VALUES('manifest','synthetic','endpoint','unix:3:30','unix:3',4096)", []).unwrap();
    state
        .start_gateway_initialization_with_growth(
            "one",
            1,
            1,
            &first,
            CAPACITY,
            RESERVE + 4096 + first.max_bytes,
        )
        .unwrap();
    assert!(matches!(
        state.start_gateway_initialization_with_growth(
            "two",
            1,
            1,
            &second,
            CAPACITY,
            RESERVE + 4096 + first.max_bytes + second.max_bytes - 1
        ),
        Err(StateError::QuotaExceeded)
    ));
    assert_eq!(
        state
            .get_gateway_layout("two")
            .unwrap()
            .unwrap()
            .effect_state,
        "ready"
    );
    state
        .start_gateway_initialization_with_growth(
            "two",
            1,
            1,
            &second,
            CAPACITY,
            RESERVE + 4096 + first.max_bytes + second.max_bytes,
        )
        .unwrap();
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        first.max_bytes + second.max_bytes
    );
}

#[test]
fn concurrent_initializations_cannot_share_one_growth_allowance() {
    // Journal-level race with fixed capacity evidence; controller lock behavior is tested separately.
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let first = create_ready_layout(&mut state, "race_one", 1, 10);
    let second = create_ready_layout(&mut state, "race_two", 2, 20);
    let budget = first.max_bytes;
    assert_eq!(budget, second.max_bytes);
    drop(state);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let mut starts = Vec::new();
    let mut threads = Vec::new();
    for binding in [first, second] {
        let (start_tx, start_rx) = mpsc::channel();
        starts.push(start_tx);
        let path = path.clone();
        let ready = ready_tx.clone();
        let result = result_tx.clone();
        threads.push(std::thread::spawn(move || {
            let mut state = StateStore::open(&path).unwrap();
            ready.send(()).unwrap();
            start_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let outcome = state.start_gateway_initialization_with_growth(
                &binding.resource_id,
                1,
                1,
                &binding,
                CAPACITY,
                RESERVE + budget,
            );
            let status = match outcome {
                Ok(_) => "started",
                Err(StateError::QuotaExceeded) => "quota",
                Err(_) => "unexpected",
            };
            result.send((binding.resource_id, status)).unwrap();
        }));
    }
    for _ in 0..2 {
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    for start in starts {
        start.send(()).unwrap();
    }
    let outcomes = [
        result_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        result_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
    ];
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, status)| *status == "started")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, status)| *status == "quota")
            .count(),
        1
    );
    let state = StateStore::open(&path).unwrap();
    assert_eq!(state.get_total_held_destination_growth().unwrap(), budget);
    for (id, status) in outcomes {
        let layout = state.get_gateway_layout(&id).unwrap().unwrap();
        let hold = state
            .get_destination_growth("initialization", &id, 0)
            .unwrap();
        if status == "started" {
            assert_eq!(layout.effect_state, "initializing");
            assert_eq!(hold.unwrap().effect_state, "held");
        } else {
            assert_eq!(layout.effect_state, "ready");
            assert!(hold.is_none());
        }
    }
}

#[test]
fn rejects_excessive_limits_and_overflowing_capacity_calculation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let mut binding = create_ready_layout(&mut state, "one", 1, 10);
    binding.max_bytes = MAX_GROWTH_BYTES + 1;
    assert!(
        state
            .start_gateway_initialization_with_growth("one", 1, 1, &binding, CAPACITY, CAPACITY)
            .is_err()
    );
    binding.max_bytes = 1;
    // Ledger-only rows exercise checked sums, not physical staging admission.
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch("INSERT INTO staging_quota VALUES('manifest','a','endpoint','unix:3:30','unix:3',9223372036854775807); INSERT INTO staging_quota VALUES('manifest','b','endpoint','unix:4:40','unix:4',9223372036854775807);").unwrap();
    assert!(matches!(
        state.start_gateway_initialization_with_growth("one", 1, 1, &binding, u64::MAX, u64::MAX),
        Err(StateError::QuotaExceeded)
    ));
    assert_eq!(
        state
            .get_gateway_layout("one")
            .unwrap()
            .unwrap()
            .effect_state,
        "ready"
    );
}

#[test]
fn migrating_unresolved_legacy_operation_closes_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    create_ready_layout(&mut state, "old", 1, 10);
    state.start_gateway_initialization("old", 1, 1).unwrap();
    state
        .mark_gateway_initialization_unknown("old", 1, 1)
        .unwrap();
    drop(state);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE destination_growth; DROP TABLE destination_growth_metadata; PRAGMA user_version=13;").unwrap();
    drop(db);
    let mut state = StateStore::open(&path).unwrap();
    assert!(!state.is_destination_growth_inventory_complete().unwrap());
    let binding = create_ready_layout(&mut state, "new", 2, 20);
    assert!(matches!(
        state.start_gateway_initialization_with_growth("new", 1, 1, &binding, CAPACITY, CAPACITY),
        Err(StateError::InventoryRequired)
    ));
    assert_eq!(
        state
            .get_gateway_layout("new")
            .unwrap()
            .unwrap()
            .effect_state,
        "ready"
    );
}

#[test]
fn legacy_inventory_requires_every_obligation_and_preserves_charges() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let mut state = StateStore::open(&path).unwrap();
    let first = create_ready_layout(&mut state, "old_one", 1, 10);
    let second = create_ready_layout(&mut state, "old_two", 2, 20);
    for id in ["old_one", "old_two"] {
        state.start_gateway_initialization(id, 1, 1).unwrap();
        state.mark_gateway_initialization_unknown(id, 1, 1).unwrap();
    }
    drop(state);
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE destination_growth; DROP TABLE destination_growth_metadata; PRAGMA user_version=13;").unwrap();
    drop(db);
    let mut state = StateStore::open(&path).unwrap();
    assert!(!state.is_destination_growth_inventory_complete().unwrap());
    assert!(matches!(
        state.complete_destination_growth_inventory(),
        Err(StateError::InventoryRequired)
    ));
    let recorded = state.record_destination_growth_inventory(&first).unwrap();
    assert_eq!(recorded.effect_state, "held");
    assert_eq!(
        state.record_destination_growth_inventory(&first).unwrap(),
        recorded
    );
    let mut changed = first.clone();
    changed.max_bytes += 1;
    assert!(matches!(
        state.record_destination_growth_inventory(&changed),
        Err(StateError::IdempotencyConflict)
    ));
    assert!(matches!(
        state.complete_destination_growth_inventory(),
        Err(StateError::InventoryRequired)
    ));
    assert!(!state.is_destination_growth_inventory_complete().unwrap());
    state.record_destination_growth_inventory(&second).unwrap();
    state.complete_destination_growth_inventory().unwrap();
    assert!(state.is_destination_growth_inventory_complete().unwrap());
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        first.max_bytes + second.max_bytes
    );
    drop(state);
    let state = StateStore::open(&path).unwrap();
    assert!(state.is_destination_growth_inventory_complete().unwrap());
    assert_eq!(
        state.get_total_held_destination_growth().unwrap(),
        first.max_bytes + second.max_bytes
    );
    for id in ["old_one", "old_two"] {
        assert_eq!(
            state
                .get_destination_growth("initialization", id, 0)
                .unwrap()
                .unwrap()
                .effect_state,
            "held"
        );
    }
}
