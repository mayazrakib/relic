#![cfg(feature = "embedded-archive")]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use bytes::Bytes;
use relic::archive_backend::ArchiveBudgetBackend;
use relic::resources::StageGuard;
use rustic_core::{
    BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend,
};

#[derive(Default)]
struct TestBackend {
    writes: AtomicU64,
    creates: AtomicU64,
    removes: AtomicU64,
    should_fail: AtomicBool,
}

impl ReadBackend for TestBackend {
    fn location(&self) -> String {
        "private-location".to_owned()
    }
    fn list_with_size(&self, _tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        Ok(Vec::new())
    }
    fn read_full(&self, _tpe: FileType, _id: &Id) -> RusticResult<Bytes> {
        Ok(Bytes::from_static(b"readable"))
    }
    fn read_partial(
        &self,
        _tpe: FileType,
        _id: &Id,
        _cacheable: bool,
        _offset: u32,
        _length: u32,
    ) -> RusticResult<Bytes> {
        Ok(Bytes::from_static(b"readable"))
    }
    fn warmup_path(&self, _tpe: FileType, _id: &Id) -> String {
        "path".into()
    }
}

impl WriteBackend for TestBackend {
    fn create(&self) -> RusticResult<()> {
        self.creates.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn write_bytes(
        &self,
        _tpe: FileType,
        _id: &Id,
        _cacheable: bool,
        _content: BytesList,
    ) -> RusticResult<()> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        if self.should_fail.load(Ordering::Acquire) {
            return Err(RusticError::new(
                ErrorKind::InputOutput,
                "secret backend detail",
            ));
        }
        Ok(())
    }

    fn remove(&self, _tpe: FileType, _id: &Id, _cacheable: bool) -> RusticResult<()> {
        self.removes.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[test]
fn admits_exact_budget_and_rejects_excess_before_native_write() {
    let inner = Arc::new(TestBackend::default());
    let backend = ArchiveBudgetBackend::new(inner.clone(), 5, true, StageGuard::default()).unwrap();
    let mut chunks = BytesList::from(Bytes::from_static(b"ab"));
    chunks.add(Bytes::from_static(b"cde"));
    backend.create().unwrap();
    backend
        .write_bytes(FileType::Pack, &Id::default(), false, chunks)
        .unwrap();
    assert_eq!(backend.get_written_bytes(), 5);
    assert!(
        backend
            .write_bytes(FileType::Pack, &Id::default(), false, vec![1].into())
            .is_err()
    );
    assert_eq!(inner.writes.load(Ordering::Acquire), 1);
    assert_eq!(backend.get_written_bytes(), 5);
    assert!(backend.create().is_err());
    assert_eq!(inner.creates.load(Ordering::Acquire), 1);
}

#[test]
fn failed_native_write_stays_charged_and_blocks_later_mutations() {
    let inner = Arc::new(TestBackend::default());
    inner.should_fail.store(true, Ordering::Release);
    let backend =
        ArchiveBudgetBackend::new(inner.clone(), 100, true, StageGuard::default()).unwrap();
    let error = backend
        .write_bytes(FileType::Pack, &Id::default(), false, vec![1, 2, 3].into())
        .unwrap_err();
    assert!(!error.to_string().contains("secret backend detail"));
    assert_eq!(backend.get_written_bytes(), 3);
    inner.should_fail.store(false, Ordering::Release);
    assert!(
        backend
            .write_bytes(FileType::Pack, &Id::default(), false, vec![4].into())
            .is_err()
    );
    assert!(backend.create().is_err());
    assert_eq!(inner.writes.load(Ordering::Acquire), 1);
    assert_eq!(
        backend.read_full(FileType::Pack, &Id::default()).unwrap(),
        Bytes::from_static(b"readable")
    );
}

#[test]
fn readonly_backend_never_delegates_mutation_or_warmup() {
    let inner = Arc::new(TestBackend::default());
    let backend =
        ArchiveBudgetBackend::new(inner.clone(), 10, false, StageGuard::default()).unwrap();
    assert!(backend.create().is_err());
    assert!(
        backend
            .write_bytes(FileType::Pack, &Id::default(), false, vec![1].into())
            .is_err()
    );
    assert!(
        backend
            .remove(FileType::Pack, &Id::default(), false)
            .is_err()
    );
    assert!(backend.warm_up(FileType::Pack, &Id::default()).is_err());
    assert_eq!(inner.creates.load(Ordering::Acquire), 0);
    assert_eq!(inner.writes.load(Ordering::Acquire), 0);
    assert_eq!(inner.removes.load(Ordering::Acquire), 0);
    assert_eq!(backend.get_written_bytes(), 0);
}

#[test]
fn parallel_writers_never_exceed_budget() {
    let inner = Arc::new(TestBackend::default());
    let backend =
        Arc::new(ArchiveBudgetBackend::new(inner.clone(), 8, true, StageGuard::default()).unwrap());
    let barrier = Arc::new(Barrier::new(17));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let backend = backend.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            backend
                .write_bytes(FileType::Pack, &Id::default(), false, vec![1].into())
                .is_ok()
        }));
    }
    barrier.wait();
    let accepted = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|success| *success)
        .count();
    assert_eq!(accepted, 8);
    assert_eq!(backend.get_written_bytes(), 8);
    assert_eq!(inner.writes.load(Ordering::Acquire), 8);
}

#[test]
fn rejects_invalid_limits_and_bounds_write_count() {
    let inner = Arc::new(TestBackend::default());
    assert!(ArchiveBudgetBackend::new(inner.clone(), 0, true, StageGuard::default()).is_err());
    assert!(
        ArchiveBudgetBackend::new(
            inner.clone(),
            512 * 1024 * 1024 + 1,
            true,
            StageGuard::default()
        )
        .is_err()
    );
    let backend = ArchiveBudgetBackend::new(inner.clone(), 1, true, StageGuard::default()).unwrap();
    for _ in 0..10_000 {
        backend
            .write_bytes(
                FileType::Pack,
                &Id::default(),
                false,
                Vec::<u8>::new().into(),
            )
            .unwrap();
    }
    assert!(
        backend
            .write_bytes(
                FileType::Pack,
                &Id::default(),
                false,
                Vec::<u8>::new().into()
            )
            .is_err()
    );
    assert_eq!(inner.writes.load(Ordering::Acquire), 10_000);
}
