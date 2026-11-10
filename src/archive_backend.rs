use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustic_core::{
    BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend,
};

use crate::resources::StageGuard;

const MAX_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_WRITES: u64 = 10_000;

fn get_backend_error() -> Box<RusticError> {
    RusticError::new(ErrorKind::InputOutput, "Archive backend operation failed")
}

pub struct ArchiveBudgetBackend {
    inner: Arc<dyn WriteBackend>,
    maximum_bytes: u64,
    can_write: bool,
    guard: StageGuard,
    written_bytes: AtomicU64,
    write_count: AtomicU64,
    is_failed: AtomicBool,
    mutation_lock: Mutex<()>,
}

impl ArchiveBudgetBackend {
    pub fn new(
        inner: Arc<dyn WriteBackend>,
        max_bytes: u64,
        can_write: bool,
        guard: StageGuard,
    ) -> RusticResult<Self> {
        if max_bytes == 0 || max_bytes > MAX_BUDGET_BYTES {
            return Err(get_backend_error());
        }
        Ok(Self {
            inner,
            maximum_bytes: max_bytes,
            can_write,
            guard,
            written_bytes: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            is_failed: AtomicBool::new(false),
            mutation_lock: Mutex::new(()),
        })
    }

    pub fn get_written_bytes(&self) -> u64 {
        self.written_bytes.load(Ordering::Acquire)
    }

    fn check_read(&self) -> RusticResult<()> {
        self.guard.check().map_err(|_| get_backend_error())
    }

    fn check_mutation(&self) -> RusticResult<()> {
        if !self.can_write || self.is_failed.load(Ordering::Acquire) || self.guard.check().is_err()
        {
            return Err(get_backend_error());
        }
        Ok(())
    }

    fn fail_mutations(&self) -> Box<RusticError> {
        self.is_failed.store(true, Ordering::Release);
        get_backend_error()
    }
}

impl ReadBackend for ArchiveBudgetBackend {
    fn location(&self) -> String {
        "bounded archive backend".to_owned()
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        self.check_read()?;
        self.inner
            .list_with_size(tpe)
            .map_err(|_| get_backend_error())
    }

    fn list(&self, tpe: FileType) -> RusticResult<Vec<Id>> {
        self.check_read()?;
        self.inner.list(tpe).map_err(|_| get_backend_error())
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        self.check_read()?;
        self.inner
            .read_full(tpe, id)
            .map_err(|_| get_backend_error())
    }

    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<Bytes> {
        self.check_read()?;
        self.inner
            .read_partial(tpe, id, cacheable, offset, length)
            .map_err(|_| get_backend_error())
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        if self.check_read().is_err() {
            return String::new();
        }
        self.inner.warmup_path(tpe, id)
    }

    fn needs_warm_up(&self) -> bool {
        false
    }

    fn warm_up(&self, _tpe: FileType, _id: &Id) -> RusticResult<()> {
        Err(get_backend_error())
    }
}

impl WriteBackend for ArchiveBudgetBackend {
    fn create(&self) -> RusticResult<()> {
        let _lock = self
            .mutation_lock
            .lock()
            .map_err(|_| self.fail_mutations())?;
        self.check_mutation()?;
        self.inner.create().map_err(|_| self.fail_mutations())
    }

    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        cacheable: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        let _lock = self
            .mutation_lock
            .lock()
            .map_err(|_| self.fail_mutations())?;
        self.check_mutation()?;
        let length = content
            .slice()
            .iter()
            .try_fold(0u64, |total, bytes| {
                u64::try_from(bytes.len())
                    .ok()
                    .and_then(|size| total.checked_add(size))
            })
            .ok_or_else(|| self.fail_mutations())?;
        self.write_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1).filter(|next| *next <= MAX_WRITES)
            })
            .map_err(|_| self.fail_mutations())?;
        self.written_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                total
                    .checked_add(length)
                    .filter(|next| *next <= self.maximum_bytes)
            })
            .map_err(|_| self.fail_mutations())?;
        self.guard.check().map_err(|_| self.fail_mutations())?;
        self.inner
            .write_bytes(tpe, id, cacheable, content)
            .map_err(|_| self.fail_mutations())
    }

    fn remove(&self, _tpe: FileType, _id: &Id, _cacheable: bool) -> RusticResult<()> {
        Err(get_backend_error())
    }
}
