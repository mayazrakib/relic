//! Conservative node-wide destination growth journal. OS coordination is supplied by callers.
//!
//! The caller must hold the shared node-wide coordinator across fresh statvfs,
//! this transaction, and commit. Start and reserve, or final transition and release,
//! must be performed in the same immediate transaction. The caller supplies physical
//! quiescence and authenticated verification/absence proof before release.
//! All local staging and growth holds are charged against each admission's fresh
//! free-space sample. Device identity is an observation, not a capacity domain.
use crate::state::{StateError, StateStore};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub const MAX_GROWTH_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_GROWTH_RECORDS: u64 = 10_000;
const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrowthBinding {
    pub operation_kind: String,
    pub operation_id: String,
    pub ordinal: u32,
    pub resource_id: String,
    pub storage_identity: String,
    pub volume_identity: String,
    pub receiver_epoch: u64,
    pub fence_generation: u64,
    pub max_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrowthRecord {
    pub binding: GrowthBinding,
    pub effect_state: String,
}

fn is_canonical_number(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|c| c.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

fn validate_binding(binding: &GrowthBinding) -> Result<(), StateError> {
    let device = binding
        .volume_identity
        .strip_prefix("unix:")
        .ok_or(StateError::InvalidInput)?;
    let storage = binding
        .storage_identity
        .strip_prefix("unix:")
        .ok_or(StateError::InvalidInput)?;
    let (storage_device, inode) = storage.split_once(':').ok_or(StateError::InvalidInput)?;
    if !is_canonical_number(device)
        || device != storage_device
        || !is_canonical_number(inode)
        || !crate::state::valid_identifier_text(&binding.resource_id)
        || !crate::state::valid_identifier_text(&binding.operation_id)
        || binding.receiver_epoch == 0
        || binding.fence_generation == 0
        || !(1..=MAX_GROWTH_BYTES).contains(&binding.max_bytes)
        || !match binding.operation_kind.as_str() {
            "initialization" => binding.ordinal == 0 && binding.operation_id == binding.resource_id,
            "copy" => (1..=3).contains(&binding.ordinal),
            _ => false,
        }
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}

fn read_growth(
    connection: &Connection,
    kind: &str,
    id: &str,
    ordinal: u32,
) -> Result<Option<GrowthRecord>, StateError> {
    let row = connection.query_row(
        "SELECT resource_id,storage_identity,volume_identity,receiver_epoch,fence_generation,max_bytes,effect_state FROM destination_growth WHERE operation_kind=?1 AND operation_id=?2 AND ordinal=?3",
        params![kind,id,ordinal],
        |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,String>(6)?)),
    ).optional()?;
    row.map(
        |(
            resource_id,
            storage_identity,
            volume_identity,
            epoch,
            fence,
            max_bytes,
            effect_state,
        )| {
            if !is_canonical_number(&epoch) || !is_canonical_number(&fence) {
                return Err(StateError::EffectConflict);
            }
            let binding = GrowthBinding {
                operation_kind: kind.into(),
                operation_id: id.into(),
                ordinal,
                resource_id,
                storage_identity,
                volume_identity,
                receiver_epoch: epoch.parse().map_err(|_| StateError::EffectConflict)?,
                fence_generation: fence.parse().map_err(|_| StateError::EffectConflict)?,
                max_bytes: u64::try_from(max_bytes).map_err(|_| StateError::EffectConflict)?,
            };
            validate_binding(&binding)?;
            if effect_state != "held" && effect_state != "released" {
                return Err(StateError::EffectConflict);
            }
            Ok(GrowthRecord {
                binding,
                effect_state,
            })
        },
    )
    .transpose()
}

fn get_sum(connection: &Connection, sql: &str, volume: Option<&str>) -> Result<u64, StateError> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(volume))?;
    let mut sum = 0u64;
    let mut count = 0u64;
    while let Some(row) = rows.next()? {
        count = count.checked_add(1).ok_or(StateError::QuotaExceeded)?;
        if count > MAX_GROWTH_RECORDS {
            return Err(StateError::QuotaExceeded);
        }
        let value: i64 = row.get(0)?;
        let value = u64::try_from(value).map_err(|_| StateError::EffectConflict)?;
        sum = sum.checked_add(value).ok_or(StateError::QuotaExceeded)?;
    }
    Ok(sum)
}

/// Read the node-wide held growth in the caller's staging transaction.
pub(crate) fn get_total_held_growth(connection: &Connection) -> Result<u64, StateError> {
    get_sum(
        connection,
        "SELECT max_bytes FROM destination_growth WHERE effect_state='held'",
        None,
    )
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy)]
enum JournalCheck {
    START,
    RELEASE,
    INVENTORY,
}

fn check_journal(
    tx: &Transaction<'_>,
    binding: &GrowthBinding,
    mode: JournalCheck,
) -> Result<(), StateError> {
    let mode = match mode {
        JournalCheck::START => 0,
        JournalCheck::RELEASE => 1,
        JournalCheck::INVENTORY => 2,
    };
    let matches: bool = if binding.operation_kind == "initialization" {
        tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_resources r JOIN gateway_layouts l USING(resource_id) WHERE r.resource_id=?1 AND r.storage_identity=?2 AND r.receiver_epoch=?3 AND r.fence_generation=?4 AND l.initialization_epoch=?3 AND l.initialization_fence=?4 AND l.initialization_attempts=1 AND ((?5=0 AND l.effect_state='initializing') OR (?5=1 AND l.effect_state='initialized') OR (?5=2 AND l.effect_state IN ('initializing','unknown'))))", params![binding.resource_id,binding.storage_identity,binding.receiver_epoch.to_string(),binding.fence_generation.to_string(),mode], |r|r.get(0))?
    } else {
        tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_resources r JOIN gateway_executions e USING(resource_id) JOIN gateway_admissions a USING(admission_id) WHERE r.resource_id=?1 AND r.storage_identity=?2 AND r.receiver_epoch=?3 AND r.fence_generation=?4 AND e.receiver_epoch=?3 AND e.fence_generation=?4 AND e.admission_id=?5 AND e.ordinal=?6 AND a.resource_id=r.resource_id AND ((?7=0 AND e.effect_state='active') OR (?7=1 AND e.effect_state IN ('verified','proven_unpublished')) OR (?7=2 AND e.effect_state IN ('active','unknown','published_unverified'))))",params![binding.resource_id,binding.storage_identity,binding.receiver_epoch.to_string(),binding.fence_generation.to_string(),binding.operation_id,binding.ordinal,mode],|r|r.get(0))?
    };
    if !matches {
        return Err(StateError::EffectConflict);
    }
    Ok(())
}

impl StateStore {
    pub fn get_destination_growth(
        &self,
        kind: &str,
        id: &str,
        ordinal: u32,
    ) -> Result<Option<GrowthRecord>, StateError> {
        read_growth(&self.connection, kind, id, ordinal)
    }
    pub fn is_destination_growth_inventory_complete(&self) -> Result<bool, StateError> {
        Ok(self.connection.query_row(
            "SELECT inventory_complete FROM destination_growth_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }
    /// Informational only; per-device totals are not independent capacity domains.
    pub fn get_held_destination_growth(&self, volume: &str) -> Result<u64, StateError> {
        get_sum(
            &self.connection,
            "SELECT max_bytes FROM destination_growth WHERE volume_identity=?1 AND effect_state='held'",
            Some(volume),
        )
    }

    /// All node-wide held growth; staging admission must include this amount.
    pub fn get_total_held_destination_growth(&self) -> Result<u64, StateError> {
        get_total_held_growth(&self.connection)
    }

    /// Trusted inventory only. Caller validates the pinned root and a conservative
    /// bound on the old accepted worker, under the common capacity coordinator.
    /// This records an existing obligation; it does not admit a new native effect.
    pub fn record_destination_growth_inventory(
        &mut self,
        binding: &GrowthBinding,
    ) -> Result<GrowthRecord, StateError> {
        validate_binding(binding)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ready: bool = tx.query_row(
            "SELECT inventory_complete FROM destination_growth_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if ready {
            return Err(StateError::EffectConflict);
        }
        check_journal(&tx, binding, JournalCheck::INVENTORY)?;
        if let Some(saved) = read_growth(
            &tx,
            &binding.operation_kind,
            &binding.operation_id,
            binding.ordinal,
        )? {
            if saved.binding != *binding || saved.effect_state != "held" {
                return Err(StateError::IdempotencyConflict);
            }
            tx.commit()?;
            return Ok(saved);
        }
        let count: i64 =
            tx.query_row("SELECT count(*) FROM destination_growth", [], |r| r.get(0))?;
        if count < 0 || count as u64 >= MAX_GROWTH_RECORDS {
            return Err(StateError::QuotaExceeded);
        }
        tx.execute("INSERT INTO destination_growth(operation_kind,operation_id,ordinal,resource_id,storage_identity,volume_identity,receiver_epoch,fence_generation,max_bytes,effect_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'held')", params![binding.operation_kind,binding.operation_id,binding.ordinal,binding.resource_id,binding.storage_identity,binding.volume_identity,binding.receiver_epoch.to_string(),binding.fence_generation.to_string(),binding.max_bytes as i64])?;
        tx.commit()?;
        Ok(GrowthRecord {
            binding: binding.clone(),
            effect_state: "held".into(),
        })
    }

    /// Trusted inventory completion never drops or releases an existing charge.
    /// Root identity and quiescence proof remain the controller's responsibility.
    pub fn complete_destination_growth_inventory(&mut self) -> Result<(), StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let staging_ready: bool = tx.query_row(
            "SELECT inventory_complete FROM staging_quota_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if !staging_ready {
            return Err(StateError::InventoryRequired);
        }
        let count: i64 =
            tx.query_row("SELECT count(*) FROM destination_growth", [], |r| r.get(0))?;
        if count < 0 || count as u64 > MAX_GROWTH_RECORDS {
            return Err(StateError::QuotaExceeded);
        }
        {
            let mut statement = tx.prepare("SELECT operation_kind,operation_id,ordinal FROM destination_growth ORDER BY operation_kind,operation_id,ordinal")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let kind: String = row.get(0)?;
                let id: String = row.get(1)?;
                let ordinal: u32 = row.get(2)?;
                read_growth(&tx, &kind, &id, ordinal)?.ok_or(StateError::EffectConflict)?;
            }
        }
        let missing_init: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_layouts l JOIN gateway_resources r USING(resource_id) WHERE l.effect_state IN ('initializing','unknown') AND NOT EXISTS(SELECT 1 FROM destination_growth g WHERE g.operation_kind='initialization' AND g.operation_id=l.resource_id AND g.ordinal=0 AND g.resource_id=r.resource_id AND g.storage_identity=r.storage_identity AND g.receiver_epoch=l.initialization_epoch AND g.fence_generation=l.initialization_fence AND g.effect_state='held'))", [], |r| r.get(0))?;
        let missing_copy: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_executions e JOIN gateway_resources r USING(resource_id) WHERE e.effect_state IN ('active','unknown','published_unverified') AND NOT EXISTS(SELECT 1 FROM destination_growth g WHERE g.operation_kind='copy' AND g.operation_id=e.admission_id AND g.ordinal=e.ordinal AND g.resource_id=r.resource_id AND g.storage_identity=r.storage_identity AND g.receiver_epoch=e.receiver_epoch AND g.fence_generation=e.fence_generation AND g.effect_state='held'))", [], |r| r.get(0))?;
        if missing_init || missing_copy {
            return Err(StateError::InventoryRequired);
        }
        get_total_held_growth(&tx)?;
        tx.execute(
            "UPDATE destination_growth_metadata SET inventory_complete=1 WHERE singleton=1",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// Called after the journal start in the same transaction, before worker launch.
pub(crate) fn reserve_growth_in_transaction(
    tx: &Transaction<'_>,
    binding: &GrowthBinding,
    capacity: u64,
    available: u64,
) -> Result<GrowthRecord, StateError> {
    validate_binding(binding)?;
    if capacity == 0 || available > capacity {
        return Err(StateError::InvalidInput);
    }
    let ready: bool = tx.query_row(
        "SELECT inventory_complete FROM destination_growth_metadata WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let staging_ready: bool = tx.query_row(
        "SELECT inventory_complete FROM staging_quota_metadata WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if !ready || !staging_ready {
        return Err(StateError::InventoryRequired);
    }
    check_journal(tx, binding, JournalCheck::START)?;
    let previous = read_growth(
        tx,
        &binding.operation_kind,
        &binding.operation_id,
        binding.ordinal,
    )?;
    if previous
        .as_ref()
        .is_some_and(|r| r.binding != *binding || r.effect_state != "held")
    {
        return Err(StateError::IdempotencyConflict);
    }
    let count: i64 = tx.query_row("SELECT count(*) FROM destination_growth", [], |r| r.get(0))?;
    if previous.is_none() && (count < 0 || count as u64 >= MAX_GROWTH_RECORDS) {
        return Err(StateError::QuotaExceeded);
    }
    let staging = get_sum(tx, "SELECT max_bytes FROM staging_quota", None)?;
    let growth = get_total_held_growth(tx)?;
    let additional = if previous.is_some() {
        0
    } else {
        binding.max_bytes
    };
    let required = staging
        .checked_add(growth)
        .and_then(|v| v.checked_add(additional))
        .and_then(|v| v.checked_add(MIN_FREE_BYTES.max(capacity.div_ceil(20))))
        .ok_or(StateError::QuotaExceeded)?;
    if required > available {
        return Err(StateError::QuotaExceeded);
    }
    if let Some(record) = previous {
        return Ok(record);
    }
    tx.execute("INSERT INTO destination_growth(operation_kind,operation_id,ordinal,resource_id,storage_identity,volume_identity,receiver_epoch,fence_generation,max_bytes,effect_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'held')",params![binding.operation_kind,binding.operation_id,binding.ordinal,binding.resource_id,binding.storage_identity,binding.volume_identity,binding.receiver_epoch.to_string(),binding.fence_generation.to_string(),binding.max_bytes as i64])?;
    Ok(GrowthRecord {
        binding: binding.clone(),
        effect_state: "held".into(),
    })
}

/// Called only after physical quiescence and verified/negative journal transition.
pub(crate) fn release_growth_in_transaction(
    tx: &Transaction<'_>,
    binding: &GrowthBinding,
) -> Result<(), StateError> {
    validate_binding(binding)?;
    check_journal(tx, binding, JournalCheck::RELEASE)?;
    let record = read_growth(
        tx,
        &binding.operation_kind,
        &binding.operation_id,
        binding.ordinal,
    )?
    .ok_or(StateError::EffectConflict)?;
    if record.binding != *binding {
        return Err(StateError::IdempotencyConflict);
    }
    if record.effect_state == "released" {
        return Ok(());
    }
    let changed = tx.execute("UPDATE destination_growth SET effect_state='released' WHERE operation_kind=?1 AND operation_id=?2 AND ordinal=?3 AND effect_state='held'",params![binding.operation_kind,binding.operation_id,binding.ordinal])?;
    if changed != 1 {
        return Err(StateError::EffectConflict);
    }
    Ok(())
}
