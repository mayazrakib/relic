//! Pinned local root registry. Callers must exclude external writers and mount
//! changes across admission and effects; observations are not authority proof.
use crate::local_endpoint::{
    EndpointError, FileIdentity, LocalEndpoint, PhysicalScopeObservation,
    compare_physical_scope_observations, get_physical_scope_observation,
    validate_physical_scope_observation,
};
use crate::resources::StageGuard;
use crate::state::StateStore;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_ROOTS: u64 = 4096;
const MAX_CLAIMS: usize = 8;
const PAGE_SIZE: u32 = 8;
const MAX_SECONDS: u64 = 5;

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalRootKind {
    STATE,
    EXECUTABLE,
    STAGING,
    SOURCE,
    GATEWAY,
    RESTORE,
}
impl PhysicalRootKind {
    fn get_name(self) -> &'static str {
        match self {
            Self::STATE => "state",
            Self::EXECUTABLE => "executable",
            Self::STAGING => "staging",
            Self::SOURCE => "source",
            Self::GATEWAY => "gateway",
            Self::RESTORE => "restore",
        }
    }
    fn parse(value: &str) -> Result<Self, PhysicalRegistryError> {
        match value {
            "state" => Ok(Self::STATE),
            "executable" => Ok(Self::EXECUTABLE),
            "staging" => Ok(Self::STAGING),
            "source" => Ok(Self::SOURCE),
            "gateway" => Ok(Self::GATEWAY),
            "restore" => Ok(Self::RESTORE),
            _ => Err(PhysicalRegistryError::STATE),
        }
    }
    fn is_read_only(self) -> bool {
        matches!(self, Self::EXECUTABLE | Self::SOURCE)
    }
}
pub struct PhysicalRootClaim<'a> {
    pub kind: PhysicalRootKind,
    pub owner_id: &'a str,
    pub endpoint: &'a LocalEndpoint,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalRootRecord {
    pub root_id: String,
    pub kind: PhysicalRootKind,
    pub owner_id: String,
    pub observation: PhysicalScopeObservation,
}
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum PhysicalRegistryError {
    INVALID,
    STORAGE,
    STATE,
    BUSY,
    CONFLICT,
    INVENTORY_REQUIRED,
    DRIFT,
    RESOURCE,
    LIMIT,
}
impl fmt::Display for PhysicalRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::INVALID => "invalid physical root claim",
            Self::STORAGE => "physical registry storage failed",
            Self::STATE => "physical registry journal failed",
            Self::BUSY => "physical registry is busy",
            Self::CONFLICT => "physical root overlaps or conflicts",
            Self::INVENTORY_REQUIRED => "physical root inventory is incomplete",
            Self::DRIFT => "physical root observation changed",
            Self::RESOURCE => "physical registry deadline or cancellation",
            Self::LIMIT => "physical registry bound exceeded",
        })
    }
}
impl std::error::Error for PhysicalRegistryError {}
fn check_guard(guard: &StageGuard, deadline: Instant) -> Result<(), PhysicalRegistryError> {
    guard.check().map_err(|_| PhysicalRegistryError::RESOURCE)?;
    if Instant::now() >= deadline {
        return Err(PhysicalRegistryError::RESOURCE);
    }
    Ok(())
}
fn get_identity_text(value: FileIdentity) -> String {
    format!("unix:{}:{}", value.device, value.inode)
}
fn check_private(file: &File, is_directory: bool) -> Result<(), PhysicalRegistryError> {
    let m = file
        .metadata()
        .map_err(|_| PhysicalRegistryError::STORAGE)?; // SAFETY: geteuid reads only process identity.
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if is_directory { 0o700 } else { 0o600 }
        || if is_directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1 || m.len() != 0
        }
    {
        return Err(PhysicalRegistryError::STORAGE);
    }
    Ok(())
}
fn open_lock(parent: &File, can_create: bool) -> Result<File, PhysicalRegistryError> {
    if can_create {
        // SAFETY: single fixed component, exclusive creation and no-follow.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c".physical-registry.lock".as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: fd is newly owned.
            let file = unsafe { File::from_raw_fd(fd) };
            check_private(&file, false)?;
            file.sync_all()
                .map_err(|_| PhysicalRegistryError::STORAGE)?;
            parent
                .sync_all()
                .map_err(|_| PhysicalRegistryError::STORAGE)?;
            return Ok(file);
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(PhysicalRegistryError::STORAGE);
        }
    }
    // SAFETY: O_PATH pins without opening a possible special file.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".physical-registry.lock".as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(PhysicalRegistryError::STORAGE);
    } // SAFETY: fresh fd is uniquely owned.
    let pin = unsafe { File::from_raw_fd(fd) };
    check_private(&pin, false)?;
    let file = File::open(format!("/proc/thread-self/fd/{}", pin.as_raw_fd()))
        .map_err(|_| PhysicalRegistryError::STORAGE)?;
    if get_identity_text(get_file_identity(&file)?) != get_identity_text(get_file_identity(&pin)?) {
        return Err(PhysicalRegistryError::STORAGE);
    }
    Ok(file)
}
fn get_file_identity(file: &File) -> Result<FileIdentity, PhysicalRegistryError> {
    let m = file
        .metadata()
        .map_err(|_| PhysicalRegistryError::STORAGE)?;
    Ok(FileIdentity {
        device: m.dev(),
        inode: m.ino(),
    })
}
fn check_lock_slot(parent: &File, lock: &File) -> Result<(), PhysicalRegistryError> {
    let current = open_lock(parent, false)?;
    if get_file_identity(lock)? != get_file_identity(&current)? {
        return Err(PhysicalRegistryError::DRIFT);
    }
    Ok(())
}
fn get_state_endpoint(state: &StateStore) -> Result<LocalEndpoint, PhysicalRegistryError> {
    let path = state
        .connection
        .path()
        .ok_or(PhysicalRegistryError::STATE)?;
    let path = fs::canonicalize(path).map_err(|_| PhysicalRegistryError::STORAGE)?;
    let parent = path.parent().ok_or(PhysicalRegistryError::STATE)?;
    let metadata = fs::metadata(parent).map_err(|_| PhysicalRegistryError::STORAGE)?;
    let endpoint = LocalEndpoint::resolve(
        parent,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )
    .map_err(|_| PhysicalRegistryError::STORAGE)?;
    check_private(endpoint.directory(), true)?;
    Ok(endpoint)
}
fn get_root_id(
    kind: PhysicalRootKind,
    owner: &str,
    observation: &PhysicalScopeObservation,
) -> Result<String, PhysicalRegistryError> {
    crate::identity::hash_domain(
        "relic/physical-root/v1",
        &(
            kind.get_name(),
            owner,
            observation.device,
            observation.inode,
        ),
    )
    .map_err(|_| PhysicalRegistryError::INVALID)
}
fn read_page(
    tx: &Transaction<'_>,
    after: &str,
) -> Result<Vec<PhysicalRootRecord>, PhysicalRegistryError> {
    let mut statement=tx.prepare("SELECT root_id,kind,owner_id,CASE WHEN length(CAST(observation AS BLOB)) <= 262144 THEN observation ELSE NULL END,physical_identity FROM physical_roots WHERE root_id>?1 ORDER BY root_id LIMIT ?2").map_err(|_|PhysicalRegistryError::STATE)?;
    let rows = statement
        .query_map(params![after, PAGE_SIZE], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| PhysicalRegistryError::STATE)?;
    let mut result = Vec::new();
    for row in rows {
        let (root_id, kind, owner_id, text, physical_identity) =
            row.map_err(|_| PhysicalRegistryError::STATE)?;
        let text = text.ok_or(PhysicalRegistryError::LIMIT)?;
        let observation: PhysicalScopeObservation =
            serde_json::from_str(&text).map_err(|_| PhysicalRegistryError::STATE)?;
        validate_physical_scope_observation(&observation)
            .map_err(|_| PhysicalRegistryError::DRIFT)?;
        let kind = PhysicalRootKind::parse(&kind)?;
        if !crate::state::valid_identifier_text(&owner_id)
            || (kind == PhysicalRootKind::STATE && owner_id != "node")
            || physical_identity
                != get_identity_text(FileIdentity {
                    device: observation.device,
                    inode: observation.inode,
                })
            || root_id != get_root_id(kind, &owner_id, &observation)?
        {
            return Err(PhysicalRegistryError::DRIFT);
        }
        result.push(PhysicalRootRecord {
            root_id,
            kind,
            owner_id,
            observation,
        });
    }
    Ok(result)
}
fn get_fresh_record(
    record: &PhysicalRootRecord,
    anchor: &PhysicalScopeObservation,
) -> Result<PhysicalScopeObservation, PhysicalRegistryError> {
    let path = URL_SAFE_NO_PAD
        .decode(&record.observation.path_base64url)
        .map_err(|_| PhysicalRegistryError::DRIFT)?;
    let path = PathBuf::from(std::ffi::OsString::from_vec(path));
    let endpoint = LocalEndpoint::resolve(
        &path,
        FileIdentity {
            device: record.observation.device,
            inode: record.observation.inode,
        },
    )
    .map_err(|_| PhysicalRegistryError::DRIFT)?;
    if !record.kind.is_read_only() {
        check_private(endpoint.directory(), true)?;
    }
    let fresh =
        get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?;
    let mut prior = record.observation.clone();
    prior.mountinfo_sha256 = fresh.mountinfo_sha256.clone();
    if prior != fresh || ensure_same_snapshot(&fresh, anchor).is_err() {
        return Err(PhysicalRegistryError::DRIFT);
    }
    Ok(fresh)
}
fn check_overlap(
    left_kind: PhysicalRootKind,
    left: &PhysicalScopeObservation,
    right_kind: PhysicalRootKind,
    right: &PhysicalScopeObservation,
) -> Result<(), PhysicalRegistryError> {
    if left_kind.is_read_only() && right_kind.is_read_only() {
        return Ok(());
    }
    let same = left.device == right.device && left.inode == right.inode;
    if same && left_kind == PhysicalRootKind::STAGING && right_kind == PhysicalRootKind::STAGING {
        return Ok(());
    }
    match compare_physical_scope_observations(left, right) {
        Ok(()) => Ok(()),
        Err(EndpointError::OVERLAP) => Err(PhysicalRegistryError::CONFLICT),
        Err(_) => Err(PhysicalRegistryError::DRIFT),
    }
}
fn get_lock(
    state_endpoint: &LocalEndpoint,
    stored: Option<&str>,
) -> Result<File, PhysicalRegistryError> {
    let file = open_lock(state_endpoint.directory(), stored.is_none())?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(PhysicalRegistryError::BUSY),
        Err(_) => return Err(PhysicalRegistryError::STORAGE),
    }
    check_lock_slot(state_endpoint.directory(), &file)?;
    Ok(file)
}
fn get_stored_coordinator(
    connection: &Connection,
) -> Result<Option<String>, PhysicalRegistryError> {
    connection
        .query_row(
            "SELECT coordinator_identity FROM physical_registry_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| PhysicalRegistryError::STATE)
}
fn ensure_same_snapshot(
    observation: &PhysicalScopeObservation,
    anchor: &PhysicalScopeObservation,
) -> Result<(), PhysicalRegistryError> {
    if observation.mountinfo_sha256 != anchor.mountinfo_sha256
        || observation.boot_id != anchor.boot_id
        || observation.mount_namespace_inode != anchor.mount_namespace_inode
    {
        return Err(PhysicalRegistryError::DRIFT);
    }
    Ok(())
}
fn validate_claim(claim: &PhysicalRootClaim<'_>) -> Result<(), PhysicalRegistryError> {
    if !crate::state::valid_identifier_text(claim.owner_id)
        || (claim.kind == PhysicalRootKind::STATE && claim.owner_id != "node")
    {
        return Err(PhysicalRegistryError::INVALID);
    }
    if !claim.kind.is_read_only() {
        check_private(claim.endpoint.directory(), true)?;
    }
    Ok(())
}
fn read_meta(
    connection: &Connection,
) -> Result<(i64, bool, Option<String>), PhysicalRegistryError> {
    connection.query_row("SELECT generation,inventory_complete,coordinator_identity FROM physical_registry_meta WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(|_| PhysicalRegistryError::STATE)
}

fn compare_claims(
    left: &PhysicalRootRecord,
    right: &PhysicalRootRecord,
) -> Result<(), PhysicalRegistryError> {
    if left.kind == right.kind
        && left.owner_id == right.owner_id
        && left.kind != PhysicalRootKind::SOURCE
        && left.root_id != right.root_id
    {
        return Err(PhysicalRegistryError::CONFLICT);
    }
    if left.root_id == right.root_id {
        if left != right {
            return Err(PhysicalRegistryError::CONFLICT);
        }
        return Ok(());
    }
    check_overlap(left.kind, &left.observation, right.kind, &right.observation)
}

fn register_internal(
    state: &mut StateStore,
    claims: &[PhysicalRootClaim<'_>],
    guard: &StageGuard,
    is_inventory: bool,
) -> Result<Vec<PhysicalRootRecord>, PhysicalRegistryError> {
    if claims.len() > MAX_CLAIMS {
        return Err(PhysicalRegistryError::LIMIT);
    }
    for claim in claims {
        validate_claim(claim)?;
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(MAX_SECONDS))
        .ok_or(PhysicalRegistryError::RESOURCE)?;
    check_guard(guard, deadline)?;
    let endpoint = get_state_endpoint(state)?;
    let coordinator = get_lock(
        &endpoint,
        get_stored_coordinator(&state.connection)?.as_deref(),
    )?;
    let coordinator_id = get_identity_text(get_file_identity(&coordinator)?);
    // WAL read snapshot permits unrelated authoritative writes during slow filesystem I/O.
    let snapshot = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| PhysicalRegistryError::STATE)?;
    let (generation, ready, saved_coordinator) = read_meta(&snapshot)?;
    if saved_coordinator
        .as_ref()
        .is_some_and(|value| value != &coordinator_id)
    {
        return Err(PhysicalRegistryError::DRIFT);
    }
    if !is_inventory && !ready {
        return Err(PhysicalRegistryError::INVENTORY_REQUIRED);
    }
    if is_inventory && ready {
        return Err(PhysicalRegistryError::INVALID);
    }
    let state_observation =
        get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?;
    let mut candidates = vec![PhysicalRootRecord {
        root_id: get_root_id(PhysicalRootKind::STATE, "node", &state_observation)?,
        kind: PhysicalRootKind::STATE,
        owner_id: "node".into(),
        observation: state_observation.clone(),
    }];
    for claim in claims {
        check_guard(guard, deadline)?;
        let observation = get_physical_scope_observation(claim.endpoint)
            .map_err(|_| PhysicalRegistryError::DRIFT)?;
        ensure_same_snapshot(&observation, &state_observation)?;
        candidates.push(PhysicalRootRecord {
            root_id: get_root_id(claim.kind, claim.owner_id, &observation)?,
            kind: claim.kind,
            owner_id: claim.owner_id.into(),
            observation,
        });
    }
    for (index, left) in candidates.iter().enumerate() {
        for right in &candidates[index + 1..] {
            compare_claims(left, right)?;
        }
    }
    let mut replay = vec![None; candidates.len()];
    let mut after = String::new();
    let mut count = 0u64;
    loop {
        let page = read_page(&snapshot, &after)?;
        if page.is_empty() {
            break;
        }
        for prior in &page {
            check_guard(guard, deadline)?;
            count = count.checked_add(1).ok_or(PhysicalRegistryError::LIMIT)?;
            if count > MAX_ROOTS {
                return Err(PhysicalRegistryError::LIMIT);
            }
            let fresh = get_fresh_record(prior, &state_observation)?;
            let current = PhysicalRootRecord {
                observation: fresh,
                ..prior.clone()
            };
            for (index, candidate) in candidates.iter().enumerate() {
                compare_claims(&current, candidate)?;
                if prior.root_id == candidate.root_id {
                    replay[index] = Some(prior.clone());
                }
            }
        }
        after = page
            .last()
            .ok_or(PhysicalRegistryError::STATE)?
            .root_id
            .clone();
    }
    for (claim, candidate) in claims.iter().zip(candidates.iter().skip(1)) {
        check_guard(guard, deadline)?;
        if get_physical_scope_observation(claim.endpoint)
            .map_err(|_| PhysicalRegistryError::DRIFT)?
            != candidate.observation
        {
            return Err(PhysicalRegistryError::DRIFT);
        }
    }
    if get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?
        != state_observation
    {
        return Err(PhysicalRegistryError::DRIFT);
    }
    check_lock_slot(endpoint.directory(), &coordinator)?;
    check_guard(guard, deadline)?;
    snapshot
        .commit()
        .map_err(|_| PhysicalRegistryError::STATE)?;
    let tx = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PhysicalRegistryError::STATE)?;
    if read_meta(&tx)? != (generation, ready, saved_coordinator.clone()) {
        return Err(PhysicalRegistryError::DRIFT);
    }
    let mut inserted = std::collections::BTreeSet::new();
    let mut result = Vec::with_capacity(claims.len());
    for (index, candidate) in candidates.iter().enumerate() {
        if replay[index].is_none() && inserted.insert(candidate.root_id.clone()) {
            count = count.checked_add(1).ok_or(PhysicalRegistryError::LIMIT)?;
            if count > MAX_ROOTS {
                return Err(PhysicalRegistryError::LIMIT);
            }
            let text = serde_json::to_string(&candidate.observation)
                .map_err(|_| PhysicalRegistryError::STATE)?;
            if text.len() > 256 * 1024 {
                return Err(PhysicalRegistryError::LIMIT);
            }
            tx.execute("INSERT INTO physical_roots(root_id,kind,owner_id,physical_identity,observation) VALUES(?1,?2,?3,?4,?5)", params![candidate.root_id,candidate.kind.get_name(),candidate.owner_id,get_identity_text(FileIdentity { device:candidate.observation.device, inode:candidate.observation.inode }),text]).map_err(|_|PhysicalRegistryError::STATE)?;
        }
        if index > 0 {
            result.push(replay[index].clone().unwrap_or_else(|| candidate.clone()));
        }
    }
    if !inserted.is_empty() || saved_coordinator.is_none() {
        let next = generation
            .checked_add(1)
            .ok_or(PhysicalRegistryError::LIMIT)?;
        let changed = tx.execute("UPDATE physical_registry_meta SET generation=?1,coordinator_identity=?2 WHERE singleton=1 AND generation=?3", params![next,coordinator_id,generation]).map_err(|_|PhysicalRegistryError::STATE)?;
        if changed != 1 {
            return Err(PhysicalRegistryError::DRIFT);
        }
    }
    tx.commit().map_err(|_| PhysicalRegistryError::STATE)?;
    Ok(result)
}
/// Check existing root authorizations without creating registry metadata or changing the journal.
///
/// This requires the same external namespace-mutation exclusion as registration; it is not
/// an authorization RPC or a substitute for retaining the caller's pinned endpoints.
pub fn check_registered_roots(
    state: &StateStore,
    claims: &[PhysicalRootClaim<'_>],
    guard: &StageGuard,
) -> Result<(), PhysicalRegistryError> {
    if claims.len() > MAX_CLAIMS {
        return Err(PhysicalRegistryError::LIMIT);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(MAX_SECONDS))
        .ok_or(PhysicalRegistryError::RESOURCE)?;
    check_guard(guard, deadline)?;
    for claim in claims {
        validate_claim(claim)?;
    }
    let initial = read_meta(&state.connection)?;
    if !initial.1 {
        return Err(PhysicalRegistryError::INVENTORY_REQUIRED);
    }
    let saved = initial
        .2
        .as_deref()
        .ok_or(PhysicalRegistryError::CONFLICT)?;
    let endpoint = get_state_endpoint(state)?;
    let coordinator = get_lock(&endpoint, Some(saved))?;
    if get_identity_text(get_file_identity(&coordinator)?) != saved {
        return Err(PhysicalRegistryError::DRIFT);
    }
    let snapshot = state
        .connection
        .unchecked_transaction()
        .map_err(|_| PhysicalRegistryError::STATE)?;
    if read_meta(&snapshot)? != initial {
        return Err(PhysicalRegistryError::DRIFT);
    }
    let anchor =
        get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?;
    let mut candidates = vec![PhysicalRootRecord {
        root_id: get_root_id(PhysicalRootKind::STATE, "node", &anchor)?,
        kind: PhysicalRootKind::STATE,
        owner_id: "node".into(),
        observation: anchor.clone(),
    }];
    for claim in claims {
        check_guard(guard, deadline)?;
        let observation = get_physical_scope_observation(claim.endpoint)
            .map_err(|_| PhysicalRegistryError::DRIFT)?;
        ensure_same_snapshot(&observation, &anchor)?;
        candidates.push(PhysicalRootRecord {
            root_id: get_root_id(claim.kind, claim.owner_id, &observation)?,
            kind: claim.kind,
            owner_id: claim.owner_id.into(),
            observation,
        });
    }
    for (index, left) in candidates.iter().enumerate() {
        for right in &candidates[index + 1..] {
            compare_claims(left, right)?;
        }
    }
    let mut found = vec![false; candidates.len()];
    let mut after = String::new();
    let mut count = 0u64;
    loop {
        let page = read_page(&snapshot, &after)?;
        if page.is_empty() {
            break;
        }
        for prior in &page {
            check_guard(guard, deadline)?;
            count = count.checked_add(1).ok_or(PhysicalRegistryError::LIMIT)?;
            if count > MAX_ROOTS {
                return Err(PhysicalRegistryError::LIMIT);
            }
            let current = PhysicalRootRecord {
                observation: get_fresh_record(prior, &anchor)?,
                ..prior.clone()
            };
            for (index, candidate) in candidates.iter().enumerate() {
                compare_claims(&current, candidate)?;
                if current.root_id == candidate.root_id {
                    found[index] = true;
                }
            }
        }
        after = page
            .last()
            .ok_or(PhysicalRegistryError::STATE)?
            .root_id
            .clone();
    }
    if found.iter().any(|found| !found) {
        return Err(PhysicalRegistryError::CONFLICT);
    }
    for (claim, candidate) in claims.iter().zip(candidates.iter().skip(1)) {
        check_guard(guard, deadline)?;
        if get_physical_scope_observation(claim.endpoint)
            .map_err(|_| PhysicalRegistryError::DRIFT)?
            != candidate.observation
        {
            return Err(PhysicalRegistryError::DRIFT);
        }
    }
    if get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?
        != anchor
    {
        return Err(PhysicalRegistryError::DRIFT);
    }
    check_lock_slot(endpoint.directory(), &coordinator)?;
    check_guard(guard, deadline)?;
    snapshot
        .commit()
        .map_err(|_| PhysicalRegistryError::STATE)?;
    if read_meta(&state.connection)? != initial {
        return Err(PhysicalRegistryError::DRIFT);
    }
    Ok(())
}

/// Validate one worker's already-admitted scope without reading other roots or
/// acquiring the controller's registry lock. The controller revalidates the full
/// registry before admission; registrations are immutable and never deleted here.
pub fn check_registered_access(
    state: &StateStore,
    kind: PhysicalRootKind,
    owner_id: &str,
    endpoint: &LocalEndpoint,
    guard: &StageGuard,
) -> Result<(), PhysicalRegistryError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(MAX_SECONDS))
        .ok_or(PhysicalRegistryError::RESOURCE)?;
    check_guard(guard, deadline)?;
    let fresh =
        get_physical_scope_observation(endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?;
    let snapshot = state
        .connection
        .unchecked_transaction()
        .map_err(|_| PhysicalRegistryError::STATE)?;
    let (_, ready, coordinator) = read_meta(&snapshot)?;
    if !ready || coordinator.is_none() {
        return Err(PhysicalRegistryError::INVENTORY_REQUIRED);
    }
    let mut after = String::new();
    let mut count = 0u64;
    let mut found = false;
    loop {
        let page = read_page(&snapshot, &after)?;
        if page.is_empty() {
            break;
        }
        for record in &page {
            check_guard(guard, deadline)?;
            count = count.checked_add(1).ok_or(PhysicalRegistryError::LIMIT)?;
            if count > MAX_ROOTS {
                return Err(PhysicalRegistryError::LIMIT);
            }
            if record.kind != kind || record.owner_id != owner_id {
                continue;
            }
            let saved = &record.observation;
            let same = saved.device == fresh.device && saved.inode == fresh.inode;
            if kind == PhysicalRootKind::SOURCE && !same {
                continue;
            }
            let descendant = kind == PhysicalRootKind::STAGING
                && fresh.ancestor_identities.contains(&FileIdentity {
                    device: saved.device,
                    inode: saved.inode,
                })
                && fresh
                    .origin_components_base64url
                    .starts_with(&saved.origin_components_base64url);
            if (!same && !descendant)
                || saved.device != fresh.device
                || saved.boot_id != fresh.boot_id
                || saved.mount_namespace_inode != fresh.mount_namespace_inode
                || saved.fs_type != fresh.fs_type
                || (same && saved.origin_components_base64url != fresh.origin_components_base64url)
            {
                return Err(PhysicalRegistryError::DRIFT);
            }
            found = true;
        }
        after = page
            .last()
            .ok_or(PhysicalRegistryError::STATE)?
            .root_id
            .clone();
    }
    if !found {
        return Err(PhysicalRegistryError::CONFLICT);
    }
    if get_physical_scope_observation(endpoint).map_err(|_| PhysicalRegistryError::DRIFT)? != fresh
    {
        return Err(PhysicalRegistryError::DRIFT);
    }
    snapshot
        .commit()
        .map_err(|_| PhysicalRegistryError::STATE)?;
    Ok(())
}

/// Register fresh physical roots when the legacy inventory is complete.
pub fn register_roots(
    state: &mut StateStore,
    claims: &[PhysicalRootClaim<'_>],
    guard: &StageGuard,
) -> Result<Vec<PhysicalRootRecord>, PhysicalRegistryError> {
    register_internal(state, claims, guard, false)
}
/// Seed caller-verified existing roots while the legacy inventory gate is closed.
pub fn seed_inventory_roots(
    state: &mut StateStore,
    claims: &[PhysicalRootClaim<'_>],
    guard: &StageGuard,
) -> Result<Vec<PhysicalRootRecord>, PhysicalRegistryError> {
    register_internal(state, claims, guard, true)
}

fn check_coverage(tx: &Transaction<'_>) -> Result<(), PhysicalRegistryError> {
    for query in [
        "SELECT count(*) FROM (SELECT 1 FROM manifest_artifacts LIMIT 10001)",
        "SELECT count(*) FROM (SELECT 1 FROM payload_artifacts LIMIT 10001)",
        "SELECT count(*) FROM (SELECT 1 FROM archive_stages LIMIT 10001)",
        "SELECT count(*) FROM (SELECT 1 FROM native_runs LIMIT 10001)",
        "SELECT count(*) FROM (SELECT 1 FROM restore_intents LIMIT 10001)",
        "SELECT count(*) FROM (SELECT 1 FROM gateway_resources LIMIT 10001)",
    ] {
        let count: u32 = tx
            .query_row(query, [], |row| row.get(0))
            .map_err(|_| PhysicalRegistryError::STATE)?;
        if count > 10_000 {
            return Err(PhysicalRegistryError::LIMIT);
        }
    }
    let missing: bool = tx.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM physical_roots WHERE kind='state' AND owner_id='node')
        OR EXISTS (SELECT 1 FROM manifest_artifacts a WHERE NOT EXISTS (SELECT 1 FROM physical_roots r WHERE r.kind='staging' AND r.owner_id=a.storage_endpoint_id AND r.physical_identity=a.storage_identity))
        OR EXISTS (SELECT 1 FROM payload_artifacts a WHERE NOT EXISTS (SELECT 1 FROM physical_roots r WHERE r.kind='staging' AND r.owner_id=a.storage_endpoint_id AND r.physical_identity=a.storage_identity))
        OR EXISTS (SELECT 1 FROM archive_stages a WHERE NOT EXISTS (SELECT 1 FROM physical_roots r WHERE r.kind='staging' AND r.owner_id=a.storage_endpoint_id AND r.physical_identity=a.storage_identity))
        OR EXISTS (SELECT 1 FROM native_runs a WHERE NOT EXISTS (SELECT 1 FROM physical_roots r WHERE r.kind='staging' AND r.owner_id=a.storage_endpoint_id AND r.physical_identity=a.storage_identity))
        OR EXISTS (SELECT 1 FROM restore_intents a WHERE NOT EXISTS (SELECT 1 FROM physical_roots r WHERE r.kind='restore' AND r.owner_id=a.target_endpoint_id AND r.physical_identity=a.target_identity))
        OR EXISTS (SELECT 1 FROM gateway_resources a WHERE NOT EXISTS (SELECT 1 FROM physical_roots r WHERE r.kind='gateway' AND r.owner_id=a.resource_id AND r.physical_identity=a.storage_identity))",
        [], |row| row.get(0),
    ).map_err(|_| PhysicalRegistryError::STATE)?;
    if missing {
        return Err(PhysicalRegistryError::INVENTORY_REQUIRED);
    }
    Ok(())
}

/// Opens the gate only after recorded owned roots are covered and freshly observed.
/// Source-view lifecycle and a complete startup object inventory remain separate gates.
pub fn complete_inventory(
    state: &mut StateStore,
    guard: &StageGuard,
) -> Result<(), PhysicalRegistryError> {
    let (_, ready, _) = read_meta(&state.connection)?;
    if ready {
        register_roots(state, &[], guard)?;
    } else {
        seed_inventory_roots(state, &[], guard)?;
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(MAX_SECONDS))
        .ok_or(PhysicalRegistryError::RESOURCE)?;
    check_guard(guard, deadline)?;
    let endpoint = get_state_endpoint(state)?;
    let coordinator = get_lock(
        &endpoint,
        get_stored_coordinator(&state.connection)?.as_deref(),
    )?;
    let coordinator_id = get_identity_text(get_file_identity(&coordinator)?);
    let snapshot = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| PhysicalRegistryError::STATE)?;
    let (generation, ready, saved_coordinator) = read_meta(&snapshot)?;
    if saved_coordinator.as_deref() != Some(coordinator_id.as_str()) {
        return Err(PhysicalRegistryError::DRIFT);
    }
    let anchor =
        get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?;
    let mut after = String::new();
    let mut count = 0u64;
    loop {
        let page = read_page(&snapshot, &after)?;
        if page.is_empty() {
            break;
        }
        for record in &page {
            check_guard(guard, deadline)?;
            count = count.checked_add(1).ok_or(PhysicalRegistryError::LIMIT)?;
            if count > MAX_ROOTS {
                return Err(PhysicalRegistryError::LIMIT);
            }
            get_fresh_record(record, &anchor)?;
        }
        after = page
            .last()
            .ok_or(PhysicalRegistryError::STATE)?
            .root_id
            .clone();
    }
    if get_physical_scope_observation(&endpoint).map_err(|_| PhysicalRegistryError::DRIFT)?
        != anchor
    {
        return Err(PhysicalRegistryError::DRIFT);
    }
    check_lock_slot(endpoint.directory(), &coordinator)?;
    check_guard(guard, deadline)?;
    snapshot
        .commit()
        .map_err(|_| PhysicalRegistryError::STATE)?;
    let tx = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PhysicalRegistryError::STATE)?;
    if read_meta(&tx)? != (generation, ready, saved_coordinator) {
        return Err(PhysicalRegistryError::DRIFT);
    }
    check_coverage(&tx)?;
    if !ready {
        let next = generation
            .checked_add(1)
            .ok_or(PhysicalRegistryError::LIMIT)?;
        let changed = tx.execute("UPDATE physical_registry_meta SET inventory_complete=1,generation=?1 WHERE singleton=1 AND generation=?2 AND inventory_complete=0",params![next,generation]).map_err(|_|PhysicalRegistryError::STATE)?;
        if changed != 1 {
            return Err(PhysicalRegistryError::DRIFT);
        }
    }
    tx.commit().map_err(|_| PhysicalRegistryError::STATE)
}

// One node-wide pinned lock deliberately serializes all local volumes.
pub struct CapacityGuard {
    endpoint: LocalEndpoint,
    coordinator: File,
    coordinator_identity: String,
    deadline: Instant,
}

impl CapacityGuard {
    pub fn check(
        &self,
        state: &StateStore,
        guard: &StageGuard,
    ) -> Result<(), PhysicalRegistryError> {
        check_guard(guard, self.deadline)?;
        let (_, ready, saved) = read_meta(&state.connection)?;
        if !ready || saved.as_deref() != Some(self.coordinator_identity.as_str()) {
            return Err(PhysicalRegistryError::INVENTORY_REQUIRED);
        }
        let current_state = get_state_endpoint(state)?;
        if current_state.identity() != self.endpoint.identity()
            || get_identity_text(get_file_identity(&self.coordinator)?) != self.coordinator_identity
        {
            return Err(PhysicalRegistryError::DRIFT);
        }
        check_lock_slot(self.endpoint.directory(), &self.coordinator)?;
        check_guard(guard, self.deadline)
    }
}

pub fn acquire_capacity_guard(
    state: &StateStore,
    guard: &StageGuard,
) -> Result<CapacityGuard, PhysicalRegistryError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(MAX_SECONDS))
        .ok_or(PhysicalRegistryError::RESOURCE)?;
    check_guard(guard, deadline)?;
    let (_, ready, saved) = read_meta(&state.connection)?;
    let saved = saved.ok_or(PhysicalRegistryError::INVENTORY_REQUIRED)?;
    if !ready {
        return Err(PhysicalRegistryError::INVENTORY_REQUIRED);
    }
    let endpoint = get_state_endpoint(state)?;
    let coordinator = get_lock(&endpoint, Some(&saved))?;
    if get_identity_text(get_file_identity(&coordinator)?) != saved {
        return Err(PhysicalRegistryError::DRIFT);
    }
    check_registered_access(state, PhysicalRootKind::STATE, "node", &endpoint, guard)?;
    let result = CapacityGuard {
        endpoint,
        coordinator,
        coordinator_identity: saved,
        deadline,
    };
    result.check(state, guard)?;
    Ok(result)
}
