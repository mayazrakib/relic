use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MIB: u64 = 1024 * 1024;
const MAX_IDENTITIES: usize = 1024;
const MAX_ID_BYTES: usize = 128;
const MAX_TRANSFER_BUFFER: u64 = 8 * MIB;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Demand {
    pub data_bytes: u64,
    pub cache_bytes: u64,
    pub spool_bytes: u64,
    pub open_files: u64,
    pub cpu_workers: u64,
    pub streams: u64,
    pub jobs: u64,
}

impl Demand {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            data_bytes: self.data_bytes.checked_add(other.data_bytes)?,
            cache_bytes: self.cache_bytes.checked_add(other.cache_bytes)?,
            spool_bytes: self.spool_bytes.checked_add(other.spool_bytes)?,
            open_files: self.open_files.checked_add(other.open_files)?,
            cpu_workers: self.cpu_workers.checked_add(other.cpu_workers)?,
            streams: self.streams.checked_add(other.streams)?,
            jobs: self.jobs.checked_add(other.jobs)?,
        })
    }

    fn subtract(self, other: Self) -> Self {
        Self {
            data_bytes: self.data_bytes - other.data_bytes,
            cache_bytes: self.cache_bytes - other.cache_bytes,
            spool_bytes: self.spool_bytes - other.spool_bytes,
            open_files: self.open_files - other.open_files,
            cpu_workers: self.cpu_workers - other.cpu_workers,
            streams: self.streams - other.streams,
            jobs: self.jobs - other.jobs,
        }
    }

    fn fits(self, cap: Self) -> bool {
        self.data_bytes <= cap.data_bytes
            && self.cache_bytes <= cap.cache_bytes
            && self.spool_bytes <= cap.spool_bytes
            && self.open_files <= cap.open_files
            && self.cpu_workers <= cap.cpu_workers
            && self.streams <= cap.streams
            && self.jobs <= cap.jobs
    }

    fn intersect(self, other: Self) -> Self {
        Self {
            data_bytes: self.data_bytes.min(other.data_bytes),
            cache_bytes: self.cache_bytes.min(other.cache_bytes),
            spool_bytes: self.spool_bytes.min(other.spool_bytes),
            open_files: self.open_files.min(other.open_files),
            cpu_workers: self.cpu_workers.min(other.cpu_workers),
            streams: self.streams.min(other.streams),
            jobs: self.jobs.min(other.jobs),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceClass {
    BALANCED,
    LOW,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceCaps {
    pub global: Demand,
    pub job: Demand,
    pub endpoint: Demand,
    pub control_bytes: u64,
}

impl ResourceCaps {
    pub fn for_class(class: ResourceClass, available_parallelism: usize) -> Self {
        let workers = available_parallelism.saturating_sub(1).clamp(1, 4) as u64;
        let low = class == ResourceClass::LOW;
        let global = Demand {
            data_bytes: if low { 128 * MIB } else { 256 * MIB },
            cache_bytes: if low { 32 * MIB } else { 64 * MIB },
            spool_bytes: 1024 * MIB,
            open_files: 64,
            cpu_workers: if low { workers.min(2) } else { workers },
            streams: 16,
            jobs: if low { 1 } else { 2 },
        };
        let mut job = global;
        job.jobs = 1;
        let mut endpoint = global;
        endpoint.streams = 4;
        endpoint.data_bytes = 16 * MIB;
        endpoint.cache_bytes = global.cache_bytes / 2;
        endpoint.spool_bytes = global.spool_bytes / 2;
        endpoint.open_files = global.open_files / 2;
        endpoint.cpu_workers = (global.cpu_workers / 2).max(1);
        endpoint.jobs = 1;

        Self {
            global,
            job,
            endpoint,
            control_bytes: 32 * MIB,
        }
    }

    fn intersect(self, other: Self) -> Self {
        Self {
            global: self.global.intersect(other.global),
            job: self.job.intersect(other.job),
            endpoint: self.endpoint.intersect(other.endpoint),
            control_bytes: self.control_bytes.min(other.control_bytes),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceError {
    INVALID_REQUEST,
    EXHAUSTED,
    OVERFLOW,
    CANCELED,
    DEADLINE_EXCEEDED,
    ALLOCATION_FAILED,
    STATE_UNAVAILABLE,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID_REQUEST => "invalid resource request",
            Self::EXHAUSTED => "resource capacity exhausted",
            Self::OVERFLOW => "resource accounting overflow",
            Self::CANCELED => "operation canceled",
            Self::DEADLINE_EXCEEDED => "operation deadline exceeded",
            Self::ALLOCATION_FAILED => "buffer allocation failed",
            Self::STATE_UNAVAILABLE => "resource accounting unavailable",
        })
    }
}

impl std::error::Error for ResourceError {}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Default)]
pub struct StageGuard {
    pub cancellation: CancellationToken,
    pub deadline: Option<Instant>,
}

impl StageGuard {
    pub fn check(&self) -> Result<(), ResourceError> {
        if self.cancellation.is_canceled() {
            return Err(ResourceError::CANCELED);
        }

        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ResourceError::DEADLINE_EXCEEDED);
        }

        Ok(())
    }
}

#[derive(Default)]
struct Accounting {
    global: Demand,
    jobs: HashMap<String, Demand>,
    endpoints: HashMap<String, Demand>,
    control_bytes: u64,
}

struct PoolInner {
    caps: ResourceCaps,
    accounting: Mutex<Accounting>,
}

#[derive(Clone)]
pub struct ResourcePool(Arc<PoolInner>);

impl ResourcePool {
    pub fn new(class: ResourceClass, available_parallelism: usize) -> Self {
        Self::from_caps(ResourceCaps::for_class(class, available_parallelism))
    }

    pub fn with_caps(
        class: ResourceClass,
        available_parallelism: usize,
        caps: ResourceCaps,
    ) -> Self {
        Self::from_caps(ResourceCaps::for_class(class, available_parallelism).intersect(caps))
    }

    fn from_caps(caps: ResourceCaps) -> Self {
        Self(Arc::new(PoolInner {
            caps,
            accounting: Mutex::new(Accounting::default()),
        }))
    }

    pub fn caps(&self) -> ResourceCaps {
        self.0.caps
    }

    pub fn usage(&self) -> Result<(Demand, u64), ResourceError> {
        let state = self
            .0
            .accounting
            .lock()
            .map_err(|_| ResourceError::STATE_UNAVAILABLE)?;
        Ok((state.global, state.control_bytes))
    }

    pub fn reserve(
        &self,
        job_id: &str,
        endpoint_id: Option<&str>,
        demand: Demand,
        guard: &StageGuard,
    ) -> Result<Reservation, ResourceError> {
        guard.check()?;

        if !valid_id(job_id)
            || endpoint_id.is_some_and(|id| !valid_id(id))
            || demand == Demand::default()
        {
            return Err(ResourceError::INVALID_REQUEST);
        }

        let mut state = self
            .0
            .accounting
            .lock()
            .map_err(|_| ResourceError::STATE_UNAVAILABLE)?;
        guard.check()?;

        if (!state.jobs.contains_key(job_id) && state.jobs.len() >= MAX_IDENTITIES)
            || endpoint_id.is_some_and(|id| {
                !state.endpoints.contains_key(id) && state.endpoints.len() >= MAX_IDENTITIES
            })
        {
            return Err(ResourceError::EXHAUSTED);
        }

        let global = state
            .global
            .checked_add(demand)
            .ok_or(ResourceError::OVERFLOW)?;

        let job = state
            .jobs
            .get(job_id)
            .copied()
            .unwrap_or_default()
            .checked_add(demand)
            .ok_or(ResourceError::OVERFLOW)?;

        let endpoint = endpoint_id
            .map(|id| {
                state
                    .endpoints
                    .get(id)
                    .copied()
                    .unwrap_or_default()
                    .checked_add(demand)
                    .ok_or(ResourceError::OVERFLOW)
            })
            .transpose()?;

        if !global.fits(self.0.caps.global)
            || !job.fits(self.0.caps.job)
            || endpoint.is_some_and(|value| !value.fits(self.0.caps.endpoint))
        {
            return Err(ResourceError::EXHAUSTED);
        }
        state.global = global;
        state.jobs.insert(job_id.to_owned(), job);
        if let (Some(id), Some(value)) = (endpoint_id, endpoint) {
            state.endpoints.insert(id.to_owned(), value);
        }

        Ok(Reservation {
            pool: self.0.clone(),
            job_id: job_id.to_owned(),
            endpoint_id: endpoint_id.map(str::to_owned),
            demand,
        })
    }

    pub fn reserve_control(
        &self,
        bytes: u64,
        guard: &StageGuard,
    ) -> Result<ControlReservation, ResourceError> {
        guard.check()?;

        if bytes == 0 {
            return Err(ResourceError::INVALID_REQUEST);
        }

        let mut state = self
            .0
            .accounting
            .lock()
            .map_err(|_| ResourceError::STATE_UNAVAILABLE)?;
        guard.check()?;

        let total = state
            .control_bytes
            .checked_add(bytes)
            .ok_or(ResourceError::OVERFLOW)?;

        if total > self.0.caps.control_bytes {
            return Err(ResourceError::EXHAUSTED);
        }
        state.control_bytes = total;
        Ok(ControlReservation {
            pool: self.0.clone(),
            bytes,
        })
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_BYTES
}

pub struct Reservation {
    pool: Arc<PoolInner>,
    job_id: String,
    endpoint_id: Option<String>,
    demand: Demand,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .accounting
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.global = state.global.subtract(self.demand);
        let job = state
            .jobs
            .get_mut(&self.job_id)
            .expect("live job reservation");
        *job = job.subtract(self.demand);
        if *job == Demand::default() {
            state.jobs.remove(&self.job_id);
        }

        if let Some(id) = &self.endpoint_id {
            let endpoint = state
                .endpoints
                .get_mut(id)
                .expect("live endpoint reservation");
            *endpoint = endpoint.subtract(self.demand);
            if *endpoint == Demand::default() {
                state.endpoints.remove(id);
            }
        }
    }
}

pub struct ControlReservation {
    pool: Arc<PoolInner>,
    bytes: u64,
}

impl Drop for ControlReservation {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .accounting
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.control_bytes -= self.bytes;
    }
}

#[derive(Clone)]
pub struct SharedBuffer(Arc<BufferInner>);

struct BufferInner {
    data: Vec<u8>,
    _reservation: Reservation,
}

impl SharedBuffer {
    pub fn new(
        pool: &ResourcePool,
        job_id: &str,
        endpoint_id: Option<&str>,
        size: u64,
        guard: &StageGuard,
    ) -> Result<Self, ResourceError> {
        if size == 0 || size > MAX_TRANSFER_BUFFER {
            return Err(ResourceError::INVALID_REQUEST);
        }

        let size_usize = usize::try_from(size).map_err(|_| ResourceError::OVERFLOW)?;

        let reservation = pool.reserve(
            job_id,
            endpoint_id,
            Demand {
                data_bytes: size,
                ..Demand::default()
            },
            guard,
        )?;

        let mut data = Vec::new();
        data.try_reserve_exact(size_usize)
            .map_err(|_| ResourceError::ALLOCATION_FAILED)?;
        data.resize(size_usize, 0);
        guard.check()?;
        Ok(Self(Arc::new(BufferInner {
            data,
            _reservation: reservation,
        })))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0.data
    }
}
