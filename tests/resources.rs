use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use relic::resources::{
    Demand, ResourceClass, ResourceError, ResourcePool, SharedBuffer, StageGuard,
};

fn guard() -> StageGuard {
    StageGuard::default()
}

#[test]
fn admission_is_atomic_and_releases_every_counter() {
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let demand = Demand {
        data_bytes: 1024,
        spool_bytes: 2048,
        open_files: 1,
        cpu_workers: 1,
        streams: 1,
        jobs: 1,
        ..Demand::default()
    };
    let reservation = pool
        .reserve("job", Some("endpoint"), demand, &guard())
        .unwrap();
    assert_eq!(pool.usage().unwrap().0, demand);
    let invalid = Demand {
        streams: 5,
        ..Demand::default()
    };
    assert!(matches!(
        pool.reserve("job", Some("endpoint"), invalid, &guard()),
        Err(ResourceError::EXHAUSTED)
    ));
    assert_eq!(pool.usage().unwrap().0, demand);
    drop(reservation);
    assert_eq!(pool.usage().unwrap(), (Demand::default(), 0));
}

#[test]
fn endpoint_limits_preserve_other_endpoint_and_control_capacity() {
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let endpoint_limit = pool.caps().endpoint;
    let slow = pool
        .reserve(
            "job_1",
            Some("slow"),
            Demand {
                data_bytes: endpoint_limit.data_bytes,
                streams: endpoint_limit.streams,
                ..Demand::default()
            },
            &guard(),
        )
        .unwrap();
    assert!(matches!(
        pool.reserve(
            "job_1",
            Some("slow"),
            Demand {
                streams: 1,
                ..Demand::default()
            },
            &guard()
        ),
        Err(ResourceError::EXHAUSTED)
    ));
    let fast = pool
        .reserve(
            "job_2",
            Some("fast"),
            Demand {
                streams: 1,
                data_bytes: 1,
                ..Demand::default()
            },
            &guard(),
        )
        .unwrap();
    let control = pool
        .reserve_control(pool.caps().control_bytes, &guard())
        .unwrap();
    assert!(matches!(
        pool.reserve_control(1, &guard()),
        Err(ResourceError::EXHAUSTED)
    ));
    drop((slow, fast, control));
    assert_eq!(pool.usage().unwrap(), (Demand::default(), 0));
}

#[test]
fn low_profile_and_caps_only_reduce_limits() {
    let balanced = ResourcePool::new(ResourceClass::BALANCED, 8).caps();
    let low = ResourcePool::new(ResourceClass::LOW, 8).caps();
    assert_eq!(low.global.data_bytes * 2, balanced.global.data_bytes);
    assert_eq!(low.global.cache_bytes * 2, balanced.global.cache_bytes);
    assert_eq!(low.global.jobs, 1);
    assert_eq!(low.global.cpu_workers, 2);
    let mut requested = balanced;
    requested.global.data_bytes = u64::MAX;
    requested.endpoint.streams = 2;
    let capped = ResourcePool::with_caps(ResourceClass::BALANCED, 8, requested).caps();
    assert_eq!(capped.global.data_bytes, balanced.global.data_bytes);
    assert_eq!(capped.endpoint.streams, 2);
}

#[test]
fn shared_buffer_is_charged_until_last_owner_drops() {
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let buffer = SharedBuffer::new(&pool, "job", Some("endpoint"), 1024, &guard()).unwrap();
    let copy = buffer.clone();
    assert_eq!(buffer.as_slice().len(), 1024);
    drop(buffer);
    assert_eq!(pool.usage().unwrap().0.data_bytes, 1024);
    drop(copy);
    assert_eq!(pool.usage().unwrap().0.data_bytes, 0);
    assert!(matches!(
        SharedBuffer::new(&pool, "job", None, 8 * 1024 * 1024 + 1, &guard()),
        Err(ResourceError::INVALID_REQUEST)
    ));
}

#[test]
fn cancellation_deadline_and_overflow_fail_without_charging() {
    let pool = ResourcePool::new(ResourceClass::BALANCED, 8);
    let canceled = guard();
    canceled.cancellation.cancel();
    assert!(matches!(
        pool.reserve(
            "job",
            None,
            Demand {
                streams: 1,
                ..Demand::default()
            },
            &canceled
        ),
        Err(ResourceError::CANCELED)
    ));
    let expired = StageGuard {
        deadline: Some(Instant::now() - Duration::from_secs(1)),
        ..guard()
    };
    assert!(matches!(
        pool.reserve_control(1, &expired),
        Err(ResourceError::DEADLINE_EXCEEDED)
    ));
    let held = pool
        .reserve(
            "job",
            None,
            Demand {
                data_bytes: 1,
                ..Demand::default()
            },
            &guard(),
        )
        .unwrap();
    assert!(matches!(
        pool.reserve(
            "job",
            None,
            Demand {
                data_bytes: u64::MAX,
                ..Demand::default()
            },
            &guard()
        ),
        Err(ResourceError::OVERFLOW)
    ));
    assert_eq!(pool.usage().unwrap().0.data_bytes, 1);
    drop(held);
}

#[test]
fn concurrent_admission_never_oversubscribes() {
    let pool = ResourcePool::new(ResourceClass::LOW, 2);
    let start = Arc::new(Barrier::new(3));
    let finish = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for job in ["job_1", "job_2"] {
        let pool = pool.clone();
        let start = start.clone();
        let finish = finish.clone();
        threads.push(std::thread::spawn(move || {
            start.wait();
            let result = pool.reserve(
                job,
                None,
                Demand {
                    jobs: 1,
                    ..Demand::default()
                },
                &guard(),
            );
            finish.wait();
            result.is_ok()
        }));
    }
    start.wait();
    finish.wait();
    let successes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|is_success| *is_success)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(pool.usage().unwrap().0, Demand::default());
}

#[test]
fn releases_interleaved_reservations_without_losing_shared_identity() {
    let pool = ResourcePool::new(ResourceClass::BALANCED, 4);
    let first = pool
        .reserve(
            "job",
            Some("first"),
            Demand {
                streams: 1,
                ..Demand::default()
            },
            &guard(),
        )
        .unwrap();
    let second = pool
        .reserve(
            "job",
            Some("second"),
            Demand {
                streams: 1,
                ..Demand::default()
            },
            &guard(),
        )
        .unwrap();
    let third = pool
        .reserve(
            "other",
            Some("first"),
            Demand {
                streams: 1,
                ..Demand::default()
            },
            &guard(),
        )
        .unwrap();
    drop(first);
    assert_eq!(pool.usage().unwrap().0.streams, 2);
    drop(second);
    assert_eq!(pool.usage().unwrap().0.streams, 1);
    drop(third);
    assert_eq!(pool.usage().unwrap().0, Demand::default());
}
