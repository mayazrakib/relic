//! Trusted journal for one local publication authority. Physical exclusion and
//! native verification are obligations of its caller; this module performs no IO.
use crate::state::{StateError, StateStore, valid_identifier_text};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayResourceBinding {
    pub resource_id: String,
    pub authority_id: String,
    pub storage_endpoint_id: String,
    pub storage_identity: String,
    pub repository_key_ref: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayResourceRecord {
    pub binding: GatewayResourceBinding,
    pub receiver_epoch: u64,
    pub fence_generation: u64,
    pub effect_state: String,
    pub repository_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAdmissionBinding {
    pub resource_id: String,
    pub admission_id: String,
    pub commit_key: Value,
    pub payload_hash: String,
    pub native_run_id: String,
    pub native_snapshot_id: String,
    pub capture_id: String,
    pub manifest_digest: String,
    pub owner: String,
    pub effective_policy: Value,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayAdmissionRecord {
    pub binding: GatewayAdmissionBinding,
    pub receiver_epoch: u64,
    pub fence_generation: u64,
    pub request_type: String,
    pub admission_decision: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayExecutionRecord {
    pub admission_id: String,
    pub ordinal: u32,
    pub resource_id: String,
    pub receiver_epoch: u64,
    pub fence_generation: u64,
    pub effect_state: String,
    pub native_result_id: Option<String>,
}
fn is_identifier(value: &str) -> bool {
    valid_identifier_text(value)
}
fn parse_counter(value: &str) -> Result<u64, StateError> {
    let result = value.parse::<u64>().map_err(|_| StateError::InvalidInput)?;
    if result == 0 || result.to_string() != value {
        return Err(StateError::InvalidInput);
    }
    Ok(result)
}
fn encode_canonical(value: &impl Serialize) -> Result<String, StateError> {
    serde_jcs::to_string(value).map_err(|_| StateError::InvalidInput)
}
fn check_epoch(record: &GatewayResourceRecord, epoch: u64, fence: u64) -> Result<(), StateError> {
    if epoch == 0
        || fence == 0
        || record.receiver_epoch != epoch
        || record.fence_generation != fence
    {
        return Err(StateError::EffectConflict);
    }
    Ok(())
}
fn read_resource(
    connection: &rusqlite::Connection,
    id: &str,
) -> Result<Option<GatewayResourceRecord>, StateError> {
    let row: Option<(String,String,String,String,Option<String>)> = connection.query_row("SELECT binding,receiver_epoch,fence_generation,effect_state,repository_id FROM gateway_resources WHERE resource_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    row.map(|(binding, epoch, fence, effect_state, repository_id)| {
        Ok(GatewayResourceRecord {
            binding: serde_json::from_str(&binding)?,
            receiver_epoch: parse_counter(&epoch)?,
            fence_generation: parse_counter(&fence)?,
            effect_state,
            repository_id,
        })
    })
    .transpose()
}
fn read_admission(
    connection: &rusqlite::Connection,
    id: &str,
) -> Result<Option<GatewayAdmissionRecord>, StateError> {
    let row: Option<(String, String, String, String, String)> = connection.query_row(
        "SELECT binding,receiver_epoch,fence_generation,request_type,admission_decision FROM gateway_admissions WHERE admission_id=?1",
        [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional()?;
    row.map(
        |(binding, epoch, fence, request_type, admission_decision)| {
            if request_type != "publication" || admission_decision != "accepted" {
                return Err(StateError::InvalidInput);
            }
            Ok(GatewayAdmissionRecord {
                binding: serde_json::from_str(&binding)?,
                receiver_epoch: parse_counter(&epoch)?,
                fence_generation: parse_counter(&fence)?,
                request_type,
                admission_decision,
            })
        },
    )
    .transpose()
}
fn read_execution(
    connection: &rusqlite::Connection,
    id: &str,
    ordinal: u32,
) -> Result<Option<GatewayExecutionRecord>, StateError> {
    let row: Option<(String,String,String,String,Option<String>)> = connection.query_row("SELECT resource_id,receiver_epoch,fence_generation,effect_state,native_result_id FROM gateway_executions WHERE admission_id=?1 AND ordinal=?2", params![id,ordinal], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    row.map(
        |(resource_id, epoch, fence, effect_state, native_result_id)| {
            Ok(GatewayExecutionRecord {
                admission_id: id.into(),
                ordinal,
                resource_id,
                receiver_epoch: parse_counter(&epoch)?,
                fence_generation: parse_counter(&fence)?,
                effect_state,
                native_result_id,
            })
        },
    )
    .transpose()
}
impl StateStore {
    pub fn get_gateway_resource(
        &self,
        id: &str,
    ) -> Result<Option<GatewayResourceRecord>, StateError> {
        read_resource(&self.connection, id)
    }
    pub fn prepare_gateway_resource(
        &mut self,
        binding: &GatewayResourceBinding,
    ) -> Result<GatewayResourceRecord, StateError> {
        if ![
            &binding.resource_id,
            &binding.authority_id,
            &binding.storage_endpoint_id,
            &binding.repository_key_ref,
        ]
        .into_iter()
        .all(|v| is_identifier(v))
        {
            return Err(StateError::InvalidInput);
        }
        let mut parts = binding.storage_identity.split(':');
        if parts.next() != Some("unix")
            || parts
                .next()
                .is_none_or(|v| v.parse::<u64>().ok().is_none_or(|n| n.to_string() != v))
            || parts
                .next()
                .is_none_or(|v| v.parse::<u64>().ok().is_none_or(|n| n.to_string() != v))
            || parts.next().is_some()
        {
            return Err(StateError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(old) = read_resource(&tx, &binding.resource_id)? {
            if old.binding != *binding {
                return Err(StateError::IdempotencyConflict);
            }
            tx.commit()?;
            return Ok(old);
        }
        tx.execute("INSERT INTO gateway_resources(resource_id,storage_identity,binding,receiver_epoch,fence_generation,effect_state) VALUES(?1,?2,?3,'1','1','prepared')",params![binding.resource_id,binding.storage_identity,encode_canonical(binding)?])?;
        let result = read_resource(&tx, &binding.resource_id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn ready_gateway_resource(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        repository_id: &str,
    ) -> Result<GatewayResourceRecord, StateError> {
        if !is_identifier(repository_id) {
            return Err(StateError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_resource(&tx, id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&old, epoch, fence)?;
        if old.effect_state == "ready" {
            if old.repository_id.as_deref() != Some(repository_id) {
                return Err(StateError::IdempotencyConflict);
            }
        } else if old.effect_state == "prepared" {
            tx.execute("UPDATE gateway_resources SET effect_state='ready',repository_id=?1 WHERE resource_id=?2",params![repository_id,id])?;
        } else {
            return Err(StateError::EffectConflict);
        }
        let result = read_resource(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn block_gateway_resource(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
    ) -> Result<GatewayResourceRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = read_resource(&tx, id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&record, epoch, fence)?;
        tx.execute(
            "UPDATE gateway_resources SET effect_state='blocked' WHERE resource_id=?1",
            [id],
        )?;
        let result = read_resource(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    /// Caller must establish exclusion before advancing authority.
    pub fn install_gateway_fence(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
        new_epoch: u64,
        new_fence: u64,
    ) -> Result<GatewayResourceRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_resource(&tx, id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&old, epoch, fence)?;
        if new_epoch < epoch
            || new_fence <= fence
            || !matches!(old.effect_state.as_str(), "ready" | "blocked")
            || old.repository_id.is_none()
        {
            return Err(StateError::EffectConflict);
        }
        let unresolved:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_executions WHERE resource_id=?1 AND effect_state IN ('active','unknown','published_unverified'))",[id],|r|r.get(0))?;
        if unresolved {
            return Err(StateError::EffectConflict);
        }
        tx.execute("UPDATE gateway_resources SET receiver_epoch=?1,fence_generation=?2,effect_state='ready' WHERE resource_id=?3",params![new_epoch.to_string(),new_fence.to_string(),id])?;
        let result = read_resource(&tx, id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn get_gateway_admission(
        &self,
        id: &str,
    ) -> Result<Option<GatewayAdmissionRecord>, StateError> {
        read_admission(&self.connection, id)
    }
    pub fn admit_gateway_publication(
        &mut self,
        binding: &GatewayAdmissionBinding,
        epoch: u64,
        fence: u64,
    ) -> Result<GatewayAdmissionRecord, StateError> {
        if ![
            &binding.resource_id,
            &binding.admission_id,
            &binding.native_run_id,
            &binding.native_snapshot_id,
            &binding.capture_id,
            &binding.owner,
        ]
        .into_iter()
        .all(|v| is_identifier(v))
        {
            return Err(StateError::InvalidInput);
        }
        let policy = binding
            .effective_policy
            .as_object()
            .ok_or(StateError::InvalidInput)?;
        let fields = [
            "job",
            "destination",
            "source_bindings",
            "secret_refs",
            "security_policy_revision",
            "verification",
        ];
        if policy.len() != fields.len()
            || fields.iter().any(|field| !policy.contains_key(*field))
            || !matches!(
                binding.effective_policy["verification"].as_str(),
                Some("metadata_verified" | "data_verified")
            )
            || binding.effective_policy["job"]["verification"]["publication"]
                != binding.effective_policy["verification"]
            || !matches!(
                binding.effective_policy["job"]["method"].as_str(),
                Some("archive" | "replicate")
            )
            || (binding.effective_policy["job"]["method"] == "replicate"
                && binding.effective_policy["verification"] != "data_verified")
            || binding.effective_policy["job"]["job_id"] != binding.commit_key["job_id"]
            || binding.effective_policy["destination"]["destination_id"]
                != binding.commit_key["destination_id"]
            || !binding.effective_policy["source_bindings"].is_array()
            || !binding.effective_policy["secret_refs"].is_array()
            || encode_canonical(&binding.effective_policy)?.len() > 64 * 1024
        {
            return Err(StateError::InvalidInput);
        }
        let key = encode_canonical(&binding.commit_key)?;
        let encoded = encode_canonical(binding)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let res = read_resource(&tx, &binding.resource_id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&res, epoch, fence)?;
        if res.effect_state != "ready"
            || binding.commit_key["authority_id"] != res.binding.authority_id
            || binding.effective_policy["destination"]["repository_id"].as_str()
                != res.repository_id.as_deref()
        {
            return Err(StateError::EffectConflict);
        }
        let prior:Option<(String,String)>=tx.query_row("SELECT admission_id,binding FROM gateway_admissions WHERE admission_id=?1 OR commit_key=?2",params![binding.admission_id,key],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((id, old)) = prior {
            if id != binding.admission_id || old != encoded {
                return Err(StateError::IdempotencyConflict);
            }
            let result = read_admission(&tx, &id)?.ok_or(StateError::EffectConflict)?;
            tx.commit()?;
            return Ok(result);
        }
        let occupied:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_executions WHERE resource_id=?1 AND effect_state IN ('active','unknown','published_unverified'))",[&binding.resource_id],|r|r.get(0))?;
        if occupied {
            return Err(StateError::EffectConflict);
        }
        let pubrow:Option<(String,String,String)>=tx.query_row("SELECT payload_hash,binding,effect_state FROM publication_intents WHERE commit_key=?1",[&key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (hash, publication, state) = pubrow.ok_or(StateError::EffectConflict)?;
        let publication: Value = serde_json::from_str(&publication)?;
        let policy_digest =
            crate::identity::hash_domain("relic/effective-policy/v1", &binding.effective_policy)
                .map_err(|_| StateError::InvalidInput)?;
        if publication["policy_digest"] != policy_digest
            || hash != binding.payload_hash
            || publication["capture_id"] != binding.capture_id
            || publication["manifest_digest"] != binding.manifest_digest
        {
            return Err(StateError::IdempotencyConflict);
        }
        if state != "prepared" {
            return Err(StateError::EffectConflict);
        }
        let run:Option<(String,String,String,Option<String>)>=tx.query_row("SELECT effect_state,capture_id,manifest_digest,native_snapshot_id FROM native_runs WHERE run_id=?1",[&binding.native_run_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if run
            != Some((
                "verified".into(),
                binding.capture_id.clone(),
                binding.manifest_digest.clone(),
                Some(binding.native_snapshot_id.clone()),
            ))
        {
            return Err(StateError::EffectConflict);
        }
        tx.execute("INSERT INTO gateway_admissions(admission_id,resource_id,commit_key,binding,receiver_epoch,fence_generation,request_type,admission_decision) VALUES(?1,?2,?3,?4,?5,?6,'publication','accepted')",params![binding.admission_id,binding.resource_id,key,encoded,epoch.to_string(),fence.to_string()])?;
        tx.execute("UPDATE publication_intents SET effect_state='admitted' WHERE commit_key=?1 AND effect_state='prepared'",[key])?;
        let result =
            read_admission(&tx, &binding.admission_id)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn start_gateway_execution(
        &mut self,
        id: &str,
        epoch: u64,
        fence: u64,
    ) -> Result<GatewayExecutionRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let item = read_admission(&tx, id)?.ok_or(StateError::EffectConflict)?;
        let res =
            read_resource(&tx, &item.binding.resource_id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&res, epoch, fence)?;
        if res.effect_state != "ready" {
            return Err(StateError::EffectConflict);
        }
        let occupied:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM gateway_executions WHERE resource_id=?1 AND effect_state IN ('active','unknown','published_unverified'))",[&item.binding.resource_id],|r|r.get(0))?;
        if occupied {
            return Err(StateError::EffectConflict);
        }
        let last:Option<(u32,String)>=tx.query_row("SELECT ordinal,effect_state FROM gateway_executions WHERE admission_id=?1 ORDER BY ordinal DESC LIMIT 1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let ordinal = match last {
            None => 1,
            Some((n, state)) if state == "proven_unpublished" && n < 3 => n + 1,
            _ => return Err(StateError::EffectConflict),
        };
        tx.execute("INSERT INTO gateway_executions(admission_id,ordinal,resource_id,receiver_epoch,fence_generation,effect_state) VALUES(?1,?2,?3,?4,?5,'active')",params![id,ordinal,item.binding.resource_id,epoch.to_string(),fence.to_string()])?;
        let result = read_execution(&tx, id, ordinal)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    /// Caller supplies independently established native result or proof of no effect.
    pub fn transition_gateway_execution(
        &mut self,
        id: &str,
        ordinal: u32,
        epoch: u64,
        fence: u64,
        next: &str,
        native: Option<&str>,
    ) -> Result<GatewayExecutionRecord, StateError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_execution(&tx, id, ordinal)?.ok_or(StateError::EffectConflict)?;
        let res = read_resource(&tx, &old.resource_id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&res, epoch, fence)?;
        if !matches!(
            (old.effect_state.as_str(), next),
            ("active", "unknown")
                | ("active", "published_unverified")
                | ("active", "proven_unpublished")
                | ("unknown", "published_unverified")
                | ("unknown", "proven_unpublished")
        ) {
            return Err(StateError::EffectConflict);
        }
        if (next == "published_unverified") != native.is_some()
            || native.is_some_and(|v| !is_identifier(v))
        {
            return Err(StateError::InvalidInput);
        }
        tx.execute("UPDATE gateway_executions SET effect_state=?1,native_result_id=?2 WHERE admission_id=?3 AND ordinal=?4",params![next,native,id,ordinal])?;
        let key = encode_canonical(
            &read_admission(&tx, id)?
                .ok_or(StateError::EffectConflict)?
                .binding
                .commit_key,
        )?;
        if next == "unknown" {
            tx.execute("UPDATE publication_intents SET effect_state='unknown' WHERE commit_key=?1 AND effect_state='admitted'",[&key])?;
        }
        if next == "published_unverified" {
            tx.execute("UPDATE publication_intents SET effect_state='published',native_result_id=?1 WHERE commit_key=?2 AND effect_state IN ('admitted','unknown')",params![native,key])?;
        }
        let result = read_execution(&tx, id, ordinal)?.ok_or(StateError::EffectConflict)?;
        tx.commit()?;
        Ok(result)
    }
    /// Only a caller that has verified the native repository and snapshot may submit this receipt.
    pub fn record_gateway_receipt(
        &mut self,
        id: &str,
        ordinal: u32,
        epoch: u64,
        fence: u64,
        receipt: &Value,
    ) -> Result<Value, StateError> {
        crate::contracts::validate_record(receipt).map_err(|_| StateError::InvalidInput)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_execution(&tx, id, ordinal)?.ok_or(StateError::EffectConflict)?;
        let item = read_admission(&tx, id)?.ok_or(StateError::EffectConflict)?;
        let res = read_resource(&tx, &old.resource_id)?.ok_or(StateError::EffectConflict)?;
        check_epoch(&res, epoch, fence)?;
        if old.effect_state == "verified" {
            let existing: Option<String> = tx.query_row(
                "SELECT receipt FROM publication_intents WHERE commit_key=?1 AND effect_state='verified'",
                [encode_canonical(&item.binding.commit_key)?], |row| row.get(0),
            ).optional()?.flatten();
            let existing: Value =
                serde_json::from_str(existing.as_deref().ok_or(StateError::EffectConflict)?)?;
            if existing != *receipt {
                return Err(StateError::IdempotencyConflict);
            }
            tx.commit()?;
            return Ok(existing);
        }
        if old.effect_state != "published_unverified"
            || receipt["resource_id"] != old.resource_id
            || receipt["admission_id"] != id
            || receipt["receiver_epoch"]
                .as_str()
                .map(parse_counter)
                .transpose()?
                != Some(old.receiver_epoch)
            || receipt["fence_generation"]
                .as_str()
                .map(parse_counter)
                .transpose()?
                != Some(old.fence_generation)
            || receipt["repository_id"] != res.repository_id.as_deref().unwrap_or("")
            || receipt["native_result_id"].as_str() != old.native_result_id.as_deref()
            || receipt["commit_key"] != item.binding.commit_key
            || receipt["payload_hash"] != item.binding.payload_hash
            || (item.binding.effective_policy["verification"] == "data_verified"
                && receipt["verification"] == "metadata_verified")
        {
            return Err(StateError::IdempotencyConflict);
        }
        let key = encode_canonical(&item.binding.commit_key)?;
        let (binding,state,native):(String,String,Option<String>)=tx.query_row("SELECT binding,effect_state,native_result_id FROM publication_intents WHERE commit_key=?1",[&key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let binding: Value = serde_json::from_str(&binding)?;
        if state != "published"
            || native != old.native_result_id
            || [
                "capture_id",
                "commit_key",
                "consistency",
                "destination_config_revision",
                "manifest_digest",
                "policy_digest",
                "source_view_id",
            ]
            .iter()
            .any(|field| receipt[*field] != binding[*field])
        {
            return Err(StateError::IdempotencyConflict);
        }
        tx.execute(
            "UPDATE publication_intents SET effect_state='verified',receipt=?1 WHERE commit_key=?2",
            params![serde_json::to_string(receipt)?, key],
        )?;
        tx.execute("UPDATE gateway_executions SET effect_state='verified' WHERE admission_id=?1 AND ordinal=?2",params![id,ordinal])?;
        tx.commit()?;
        Ok(receipt.clone())
    }
    pub fn list_gateway_executions(
        &self,
        id: &str,
    ) -> Result<Vec<GatewayExecutionRecord>, StateError> {
        let mut result = Vec::new();
        for ordinal in 1..=3 {
            if let Some(row) = read_execution(&self.connection, id, ordinal)? {
                result.push(row);
            }
        }
        Ok(result)
    }
    pub fn list_gateway_pending(
        &self,
        resource_id: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<GatewayAdmissionRecord>, StateError> {
        if !(1..=1000).contains(&limit)
            || !is_identifier(resource_id)
            || (!after.is_empty() && !is_identifier(after))
        {
            return Err(StateError::InvalidInput);
        }
        let mut statement=self.connection.prepare("SELECT a.admission_id FROM gateway_admissions a JOIN publication_intents p ON p.commit_key=a.commit_key WHERE a.resource_id=?1 AND a.admission_id>?2 AND p.effect_state!='verified' ORDER BY a.admission_id LIMIT ?3")?;
        let rows = statement.query_map(params![resource_id, after, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut result = Vec::new();
        for row in rows {
            result
                .push(read_admission(&self.connection, &row?)?.ok_or(StateError::EffectConflict)?);
        }
        Ok(result)
    }
}
