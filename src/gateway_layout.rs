//! Durable intent for a gateway's fixed private layout and one initialization.
//! Callers must independently establish physical identity and effect evidence.
use crate::gateway_state::GatewayResourceBinding;
use crate::state::{StateError, StateStore, valid_identifier_text};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayLayoutRecord {
    pub resource_id: String,
    pub owner_identity: Option<String>,
    pub scratch_identity: Option<String>,
    pub effect_state: String,
    pub initialization_attempts: u32,
    pub initialization_epoch: Option<u64>,
    pub initialization_fence: Option<u64>,
    pub launch_protocol: u32,
    pub containment: Option<crate::worker_identity::WorkerIdentity>,
}

fn parse_counter(value: &str) -> Result<u64, StateError> {
    let number = value.parse::<u64>().map_err(|_| StateError::InvalidInput)?;
    if number == 0 || number.to_string() != value {
        return Err(StateError::InvalidInput);
    }
    Ok(number)
}
fn parse_identity(value: &str) -> Result<(u64, u64), StateError> {
    let mut parts = value.split(':');
    if parts.next() != Some("unix") {
        return Err(StateError::InvalidInput);
    }
    let parse = |s: Option<&str>| -> Result<u64, StateError> {
        let s = s.ok_or(StateError::InvalidInput)?;
        let n = s.parse::<u64>().map_err(|_| StateError::InvalidInput)?;
        if n.to_string() != s {
            return Err(StateError::InvalidInput);
        }
        Ok(n)
    };
    let device = parse(parts.next())?;
    let inode = parse(parts.next())?;
    if parts.next().is_some() {
        return Err(StateError::InvalidInput);
    }
    Ok((device, inode))
}
fn read_layout(
    connection: &Connection,
    id: &str,
) -> Result<Option<GatewayLayoutRecord>, StateError> {
    type Row = (
        Option<String>,
        Option<String>,
        String,
        u32,
        Option<String>,
        Option<String>,
        u32,
        Option<String>,
    );
    let row: Option<Row> = connection.query_row("SELECT owner_identity,scratch_identity,effect_state,initialization_attempts,initialization_epoch,initialization_fence,launch_protocol,containment FROM gateway_layouts WHERE resource_id=?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?))).optional()?;
    row.map(
        |(
            owner_identity,
            scratch_identity,
            effect_state,
            initialization_attempts,
            epoch,
            fence,
            launch_protocol,
            containment,
        )| {
            Ok(GatewayLayoutRecord {
                resource_id: id.into(),
                owner_identity,
                scratch_identity,
                effect_state,
                initialization_attempts,
                initialization_epoch: epoch.as_deref().map(parse_counter).transpose()?,
                initialization_fence: fence.as_deref().map(parse_counter).transpose()?,
                launch_protocol,
                containment: containment
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?,
            })
        },
    )
    .transpose()
}
struct Resource {
    binding: GatewayResourceBinding,
    epoch: u64,
    fence: u64,
    state: String,
    repository_id: Option<String>,
}
fn read_resource(connection: &Connection, id: &str) -> Result<Resource, StateError> {
    let row:Option<(String,String,String,String,Option<String>)> = connection.query_row("SELECT binding,receiver_epoch,fence_generation,effect_state,repository_id FROM gateway_resources WHERE resource_id=?1",[id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional()?;
    let (binding, epoch, fence, state, repository_id) = row.ok_or(StateError::EffectConflict)?;
    Ok(Resource {
        binding: serde_json::from_str(&binding)?,
        epoch: parse_counter(&epoch)?,
        fence: parse_counter(&fence)?,
        state,
        repository_id,
    })
}
fn check_authority(resource: &Resource, epoch: u64, fence: u64) -> Result<(), StateError> {
    if epoch == 0 || fence == 0 || epoch != resource.epoch || fence != resource.fence {
        return Err(StateError::EffectConflict);
    }
    Ok(())
}
impl StateStore {
    pub fn get_gateway_layout(&self, id: &str) -> Result<Option<GatewayLayoutRecord>, StateError> {
        if !valid_identifier_text(id) {
            return Err(StateError::InvalidInput);
        }
        read_layout(&self.connection, id)
    }
    pub fn prepare_gateway_layout(&mut self, id: &str) -> Result<GatewayLayoutRecord, StateError> {
        if !valid_identifier_text(id) {
            return Err(StateError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        if let Some(record) = read_layout(&tx, id)? {
            tx.commit()?;
            return Ok(record);
        }
        if resource.state != "prepared" || resource.repository_id.is_some() {
            return Err(StateError::EffectConflict);
        }
        tx.execute(
            "INSERT INTO gateway_layouts(resource_id,effect_state) VALUES(?1,'prepared')",
            [id],
        )?;
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn bind_gateway_owner(
        &mut self,
        id: &str,
        identity: &str,
    ) -> Result<GatewayLayoutRecord, StateError> {
        self.bind_gateway_layout_identity(id, identity, false)
    }
    pub fn bind_gateway_scratch(
        &mut self,
        id: &str,
        identity: &str,
    ) -> Result<GatewayLayoutRecord, StateError> {
        self.bind_gateway_layout_identity(id, identity, true)
    }
    fn bind_gateway_layout_identity(
        &mut self,
        id: &str,
        identity: &str,
        is_scratch: bool,
    ) -> Result<GatewayLayoutRecord, StateError> {
        let physical = parse_identity(identity)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        let root = parse_identity(&resource.binding.storage_identity)?;
        if physical.0 != root.0 || physical == root {
            return Err(StateError::InvalidInput);
        }
        let previous = if is_scratch {
            &record.scratch_identity
        } else {
            &record.owner_identity
        };
        if let Some(previous) = previous {
            if previous != identity {
                return Err(StateError::IdempotencyConflict);
            }
            tx.commit()?;
            return Ok(record);
        }
        if resource.state != "prepared" || record.effect_state != "prepared" {
            return Err(StateError::EffectConflict);
        }
        if is_scratch {
            let owner = record
                .owner_identity
                .as_deref()
                .ok_or(StateError::EffectConflict)?;
            if parse_identity(owner)? == physical {
                return Err(StateError::InvalidInput);
            }
            tx.execute(
                "UPDATE gateway_layouts SET scratch_identity=?1 WHERE resource_id=?2",
                params![identity, id],
            )?;
        } else {
            tx.execute(
                "UPDATE gateway_layouts SET owner_identity=?1 WHERE resource_id=?2",
                params![identity, id],
            )?;
        }
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn seal_gateway_layout(&mut self, id: &str) -> Result<GatewayLayoutRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        if record.effect_state != "prepared" {
            tx.commit()?;
            return Ok(record);
        }
        if resource.state != "prepared"
            || record.owner_identity.is_none()
            || record.scratch_identity.is_none()
        {
            return Err(StateError::EffectConflict);
        }
        tx.execute(
            "UPDATE gateway_layouts SET effect_state='ready' WHERE resource_id=?1",
            [id],
        )?;
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    /// Record the only allowed initialization before any SDK effect.
    pub fn start_gateway_initialization(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
    ) -> Result<GatewayLayoutRecord, StateError> {
        self.start_gateway_initialization_inner(id, epoch, fence, None)
    }
    /// The caller holds the node coordinator across the capacity sample and commit.
    pub fn start_gateway_initialization_with_growth(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        binding: &crate::volume_budget::GrowthBinding,
        capacity: u64,
        available: u64,
    ) -> Result<GatewayLayoutRecord, StateError> {
        self.start_gateway_initialization_inner(
            id,
            epoch,
            fence,
            Some((binding, capacity, available)),
        )
    }
    fn start_gateway_initialization_inner(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        growth: Option<(&crate::volume_budget::GrowthBinding, u64, u64)>,
    ) -> Result<GatewayLayoutRecord, StateError> {
        if let Some((binding, _, _)) = growth
            && (binding.operation_kind != "initialization"
                || binding.operation_id != id
                || binding.resource_id != id
                || binding.ordinal != 0
                || binding.receiver_epoch != epoch
                || binding.fence_generation != fence)
        {
            return Err(StateError::IdempotencyConflict);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        check_authority(&resource, epoch, fence)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        if resource.state != "prepared"
            || resource.repository_id.is_some()
            || record.effect_state != "ready"
            || record.initialization_attempts != 0
        {
            return Err(StateError::EffectConflict);
        }
        tx.execute("UPDATE gateway_layouts SET effect_state='initializing',initialization_attempts=1,launch_protocol=1,initialization_epoch=?1,initialization_fence=?2 WHERE resource_id=?3",params![epoch.to_string(),fence.to_string(),id])?;
        if let Some((binding, capacity, available)) = growth {
            crate::volume_budget::reserve_growth_in_transaction(&tx, binding, capacity, available)?;
        }
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    /// Persist the kernel scope before the runtime may fork a mutating initializer.
    pub fn bind_gateway_initialization_worker(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        identity: &crate::worker_identity::WorkerIdentity,
    ) -> Result<GatewayLayoutRecord, StateError> {
        let encoded = serde_json::to_string(identity)?;
        if encoded.len() > 16384 {
            return Err(StateError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        check_authority(&resource, epoch, fence)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        if record.effect_state != "initializing"
            || record.launch_protocol != 1
            || record.initialization_epoch != Some(epoch)
            || record.initialization_fence != Some(fence)
        {
            return Err(StateError::EffectConflict);
        }
        if let Some(previous) = &record.containment {
            if previous != identity {
                return Err(StateError::IdempotencyConflict);
            }
        } else {
            tx.execute(
                "UPDATE gateway_layouts SET containment=?1 WHERE resource_id=?2",
                params![encoded, id],
            )?;
        }
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }

    /// Revocation serializes against the pre-fork binding callback; an unbound launch can no longer start.
    pub fn revoke_unbound_gateway_initialization(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
    ) -> Result<GatewayLayoutRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        check_authority(&resource, epoch, fence)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        if record.launch_protocol != 1
            || record.containment.is_some()
            || record.initialization_epoch != Some(epoch)
            || record.initialization_fence != Some(fence)
            || !matches!(record.effect_state.as_str(), "initializing" | "unknown")
        {
            return Err(StateError::EffectConflict);
        }
        tx.execute(
            "UPDATE gateway_layouts SET effect_state='unknown' WHERE resource_id=?1",
            [id],
        )?;
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn mark_gateway_initialization_unknown(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
    ) -> Result<GatewayLayoutRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        check_authority(&resource, epoch, fence)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        if !matches!(resource.state.as_str(), "prepared" | "blocked")
            || record.initialization_epoch != Some(epoch)
            || record.initialization_fence != Some(fence)
        {
            return Err(StateError::EffectConflict);
        }
        if record.effect_state == "unknown" {
            tx.commit()?;
            return Ok(record);
        }
        if record.effect_state != "initializing" {
            return Err(StateError::EffectConflict);
        }
        tx.execute(
            "UPDATE gateway_layouts SET effect_state='unknown' WHERE resource_id=?1",
            [id],
        )?;
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    /// Caller must authenticate the native repository and establish its durability.
    pub fn complete_gateway_initialization(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        repository_id: &str,
    ) -> Result<GatewayLayoutRecord, StateError> {
        self.complete_gateway_initialization_inner(id, epoch, fence, repository_id, None)
    }
    /// The caller holds the node coordinator and has proved the mutating scope quiescent.
    pub fn complete_gateway_initialization_with_growth(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        repository_id: &str,
        binding: &crate::volume_budget::GrowthBinding,
    ) -> Result<GatewayLayoutRecord, StateError> {
        self.complete_gateway_initialization_inner(id, epoch, fence, repository_id, Some(binding))
    }
    fn complete_gateway_initialization_inner(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        repository_id: &str,
        growth: Option<&crate::volume_budget::GrowthBinding>,
    ) -> Result<GatewayLayoutRecord, StateError> {
        if let Some(binding) = growth
            && (binding.operation_kind != "initialization"
                || binding.operation_id != id
                || binding.resource_id != id
                || binding.ordinal != 0
                || binding.receiver_epoch != epoch
                || binding.fence_generation != fence)
        {
            return Err(StateError::IdempotencyConflict);
        }
        if repository_id.len() != 64
            || !repository_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StateError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let resource = read_resource(&tx, id)?;
        check_authority(&resource, epoch, fence)?;
        let record = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        if record.initialization_epoch != Some(epoch) || record.initialization_fence != Some(fence)
        {
            return Err(StateError::EffectConflict);
        }
        if record.effect_state == "initialized" {
            if !matches!(resource.state.as_str(), "ready" | "blocked")
                || resource.repository_id.as_deref() != Some(repository_id)
            {
                return Err(StateError::IdempotencyConflict);
            }
            if let Some(binding) = growth {
                crate::volume_budget::release_growth_in_transaction(&tx, binding)?;
            }
            tx.commit()?;
            return Ok(record);
        }
        if !matches!(resource.state.as_str(), "prepared" | "blocked")
            || resource.repository_id.is_some()
            || !matches!(record.effect_state.as_str(), "initializing" | "unknown")
        {
            return Err(StateError::EffectConflict);
        }
        let changed=tx.execute("UPDATE gateway_resources SET effect_state=CASE WHEN effect_state='blocked' THEN 'blocked' ELSE 'ready' END,repository_id=?1 WHERE resource_id=?2 AND effect_state IN ('prepared','blocked') AND repository_id IS NULL",params![repository_id,id])?;
        if changed != 1 {
            return Err(StateError::EffectConflict);
        }
        tx.execute(
            "UPDATE gateway_layouts SET effect_state='initialized' WHERE resource_id=?1",
            [id],
        )?;
        if let Some(binding) = growth {
            crate::volume_budget::release_growth_in_transaction(&tx, binding)?;
        }
        let result = read_layout(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
}
