//! Local publication control. This restricted profile remains unavailable to enabled jobs.
use super::*;
use crate::gateway_state::{
    GatewayAdmissionBinding, GatewayAdmissionRecord, GatewayExecutionRecord,
};
use crate::staging_quota::{StagingQuotaBinding, reserve_owned_staging_quota};
use serde_json::{Value, json};

pub struct GatewayPublicationSource<'a> {
    pub repository_dir: &'a Path,
    pub repository_key_ref: &'a str,
    pub repository_password: &'a str,
}

impl LocalGatewayStore {
    fn get_verified_receipt(
        &self,
        state: &StateStore,
        admission_id: &str,
        expected: Option<&GatewayAdmissionBinding>,
    ) -> Result<Option<Value>, GatewayStoreError> {
        let Some(admission) = state
            .get_gateway_admission(admission_id)
            .map_err(|_| GatewayStoreError::STATE)?
        else {
            return Ok(None);
        };
        if expected.is_some_and(|binding| *binding != admission.binding) {
            return Err(GatewayStoreError::STATE);
        }
        let resource = state
            .get_gateway_resource(&admission.binding.resource_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        if resource.binding.storage_endpoint_id != self.endpoint_id
            || resource.binding.storage_identity != self.identity
        {
            return Err(GatewayStoreError::STORAGE);
        }
        if !state
            .list_gateway_executions(admission_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .last()
            .is_some_and(|last| last.effect_state == "verified")
        {
            return Ok(None);
        }
        state
            .get_publication(&admission.binding.commit_key)
            .map_err(|_| GatewayStoreError::STATE)?
            .and_then(|publication| publication.receipt)
            .map(Some)
            .ok_or(GatewayStoreError::STATE)
    }

    fn reserve_scratch(
        &self,
        state: &mut StateStore,
        resource: &GatewayResourceRecord,
        layout: &GatewayLayoutRecord,
    ) -> Result<(), GatewayStoreError> {
        let scratch = resolve_endpoint(&self.root.join(".relic-scratch"))?;
        let identity = scratch.identity();
        if layout.scratch_identity.as_deref()
            != Some(format!("unix:{}:{}", identity.device, identity.inode).as_str())
        {
            return Err(GatewayStoreError::STORAGE);
        }
        reserve_owned_staging_quota(
            state,
            &scratch,
            &StagingQuotaBinding {
                object_kind: "gateway_scratch".into(),
                object_id: resource.binding.resource_id.clone(),
                storage_endpoint_id: self.endpoint_id.clone(),
                storage_identity: format!("unix:{}:{}", identity.device, identity.inode),
                volume_identity: format!("unix:{}", identity.device),
                max_bytes: SCRATCH_BYTES,
            },
        )
        .map_err(|_| GatewayStoreError::CAPACITY)?;
        Ok(())
    }

    fn check_source(
        &self,
        state: &StateStore,
        admission: &GatewayAdmissionBinding,
        source: &GatewayPublicationSource<'_>,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<(), GatewayStoreError> {
        let run = state
            .get_native_run(&admission.native_run_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        if source.repository_key_ref != run.binding.repository_key_ref {
            return Err(GatewayStoreError::WRONG_KEY_REFERENCE);
        }
        if source.repository_password.is_empty()
            || source.repository_password.len() > 4096
            || source.repository_dir.file_name().and_then(|v| v.to_str()) != Some("repository")
            || run.effect_state != "verified"
            || run.capture_id != admission.capture_id
            || run.manifest_digest != admission.manifest_digest
            || run.native_snapshot_id.as_deref() != Some(admission.native_snapshot_id.as_str())
        {
            return Err(GatewayStoreError::INVALID);
        }
        let parent = resolve_endpoint(
            source
                .repository_dir
                .parent()
                .ok_or(GatewayStoreError::INVALID)?,
        )?;
        let repository = resolve_endpoint(source.repository_dir)?;
        let parent_identity = parent.identity();
        let repository_identity = repository.identity();
        if run.container_identity.as_deref()
            != Some(format!("unix:{}:{}", parent_identity.device, parent_identity.inode).as_str())
            || run.repository_identity.as_deref()
                != Some(
                    format!(
                        "unix:{}:{}",
                        repository_identity.device, repository_identity.inode
                    )
                    .as_str(),
                )
        {
            return Err(GatewayStoreError::STORAGE);
        }
        let state_endpoint = resolve_endpoint(context.state_dir)?;
        get_disjoint_scope_evidence(&[&self.endpoint, &parent, &state_endpoint])
            .map_err(|_| GatewayStoreError::STORAGE)?;
        let owner = open_lock(parent.directory(), c"owner.lock", false)?;
        if run.owner_lock_identity.as_deref() != Some(get_identity(&owner)?.as_str()) {
            return Err(GatewayStoreError::STORAGE);
        }
        acquire_file_lock(&owner)?;
        check_slot(
            parent.directory(),
            c"owner.lock",
            &get_identity(&owner)?,
            false,
        )?;
        Ok(())
    }

    pub fn publish(
        &self,
        state: &mut StateStore,
        binding: &GatewayAdmissionBinding,
        source: &GatewayPublicationSource<'_>,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<Value, GatewayStoreError> {
        if let Some(receipt) =
            self.get_verified_receipt(state, &binding.admission_id, Some(binding))?
        {
            // Replay acknowledges the recorded effect; it does not claim current repository health.
            return Ok(receipt);
        }
        let id = &binding.resource_id;
        if !self.reap_pending(id, context.guard)? {
            return Err(GatewayStoreError::BUSY);
        }
        let resource = state
            .get_gateway_resource(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        self.validate_execution(state, &resource, context)?;
        let coordinator = self.acquire_coordinator(false)?;
        let layout = state
            .get_gateway_layout(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        if layout.effect_state != "initialized" || resource.effect_state != "ready" {
            return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
        }
        let (owner, _scratch) = self.open_bound_layout(&layout)?;
        acquire_file_lock(&owner)?;
        if state
            .get_gateway_admission(&binding.admission_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .is_some_and(|old| old.binding == *binding)
            && state
                .list_gateway_executions(&binding.admission_id)
                .map_err(|_| GatewayStoreError::STATE)?
                .last()
                .is_some_and(|last| last.effect_state == "verified")
        {
            return state
                .get_publication(&binding.commit_key)
                .map_err(|_| GatewayStoreError::STATE)?
                .and_then(|p| p.receipt)
                .ok_or(GatewayStoreError::STATE);
        }
        self.check_source(state, binding, source, context)?;
        self.check_capacity(context)?;
        self.reserve_scratch(state, &resource, &layout)?;
        let admission = state
            .admit_gateway_publication(binding, resource.receiver_epoch, resource.fence_generation)
            .map_err(|_| GatewayStoreError::STATE)?;
        let previous = state
            .list_gateway_executions(&binding.admission_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .pop();
        if let Some(previous) = previous {
            if previous.effect_state == "verified" {
                return state
                    .get_publication(&binding.commit_key)
                    .map_err(|_| GatewayStoreError::STATE)?
                    .and_then(|p| p.receipt)
                    .ok_or(GatewayStoreError::STATE);
            }
            if previous.effect_state != "proven_unpublished" {
                return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
            }
        }
        self.check_coordinator(&coordinator)?;
        context
            .guard
            .check()
            .map_err(|_| GatewayStoreError::RESOURCE)?;
        let execution = state
            .start_gateway_execution(
                &binding.admission_id,
                resource.receiver_epoch,
                resource.fence_generation,
            )
            .map_err(|_| GatewayStoreError::STATE)?;
        drop(owner);
        self.run_publication(
            state,
            &resource,
            &layout,
            &admission,
            &execution,
            Some(source),
            context,
            &coordinator,
        )?
        .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)
    }

    /// None means a fully authenticated census proved no snapshot for this execution.
    pub fn reconcile_publication(
        &self,
        state: &mut StateStore,
        admission_id: &str,
        context: &GatewayExecutionContext<'_>,
    ) -> Result<Option<Value>, GatewayStoreError> {
        if let Some(receipt) = self.get_verified_receipt(state, admission_id, None)? {
            return Ok(Some(receipt));
        }
        let admission = state
            .get_gateway_admission(admission_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        let id = &admission.binding.resource_id;
        if !self.reap_pending(id, context.guard)? {
            return Err(GatewayStoreError::BUSY);
        }
        let resource = state
            .get_gateway_resource(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        self.validate_execution(state, &resource, context)?;
        let coordinator = self.acquire_coordinator(false)?;
        let layout = state
            .get_gateway_layout(id)
            .map_err(|_| GatewayStoreError::STATE)?
            .ok_or(GatewayStoreError::STATE)?;
        self.open_bound_layout(&layout)?;
        if layout.effect_state != "initialized" {
            return Err(GatewayStoreError::RECONCILIATION_REQUIRED);
        }
        let mut execution = state
            .list_gateway_executions(admission_id)
            .map_err(|_| GatewayStoreError::STATE)?
            .pop()
            .ok_or(GatewayStoreError::STATE)?;
        if execution.effect_state == "verified" {
            return state
                .get_publication(&admission.binding.commit_key)
                .map_err(|_| GatewayStoreError::STATE)?
                .and_then(|p| p.receipt)
                .map(Some)
                .ok_or(GatewayStoreError::STATE);
        }
        if execution.effect_state == "proven_unpublished" {
            return Ok(None);
        }
        if execution.effect_state == "active" {
            execution = state
                .transition_gateway_execution(
                    admission_id,
                    execution.ordinal,
                    resource.receiver_epoch,
                    resource.fence_generation,
                    "unknown",
                    None,
                )
                .map_err(|_| GatewayStoreError::STATE)?;
        }
        for identity in [
            &execution.worker_identity,
            &execution.verification_worker_identity,
        ]
        .into_iter()
        .flatten()
        {
            if !quiesce_recorded_worker(identity, context.guard)
                .map_err(|_| GatewayStoreError::RECONCILIATION_REQUIRED)?
            {
                return Err(GatewayStoreError::BUSY);
            }
        }
        let (owner, _scratch) = self.open_bound_layout(&layout)?;
        acquire_file_lock(&owner)?;
        self.reserve_scratch(state, &resource, &layout)?;
        self.check_coordinator(&coordinator)?;
        execution = state
            .start_gateway_verification(
                admission_id,
                execution.ordinal,
                resource.receiver_epoch,
                resource.fence_generation,
            )
            .map_err(|_| GatewayStoreError::RECONCILIATION_REQUIRED)?;
        drop(owner);
        self.run_publication(
            state,
            &resource,
            &layout,
            &admission,
            &execution,
            None,
            context,
            &coordinator,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_publication(
        &self,
        state: &mut StateStore,
        resource: &GatewayResourceRecord,
        layout: &GatewayLayoutRecord,
        admission: &GatewayAdmissionRecord,
        execution: &GatewayExecutionRecord,
        source: Option<&GatewayPublicationSource<'_>>,
        context: &GatewayExecutionContext<'_>,
        coordinator: &File,
    ) -> Result<Option<Value>, GatewayStoreError> {
        let outcome = (|| {
            let mut reservation = Some(
                context
                    .job
                    .reserve_stage(
                        None,
                        Demand {
                            data_bytes: MEMORY_BYTES,
                            spool_bytes: SCRATCH_BYTES,
                            open_files: 64,
                            cpu_workers: 1,
                            streams: 4,
                            ..Demand::default()
                        },
                        context.guard,
                    )
                    .map_err(|_| GatewayStoreError::RESOURCE)?,
            );
            let request = GatewayWorkerRequest {
                protocol_version: 1,
                operation: if source.is_some() {
                    GatewayWorkerOperation::COPY
                } else {
                    GatewayWorkerOperation::VERIFY
                },
                state_dir: context.state_dir.to_path_buf(),
                target_dir: self.root.clone(),
                target_identity: get_worker_identity(&self.identity)?,
                owner_identity: get_worker_identity(
                    layout
                        .owner_identity
                        .as_deref()
                        .ok_or(GatewayStoreError::STATE)?,
                )?,
                scratch_identity: get_worker_identity(
                    layout
                        .scratch_identity
                        .as_deref()
                        .ok_or(GatewayStoreError::STATE)?,
                )?,
                resource_id: resource.binding.resource_id.clone(),
                receiver_epoch: resource.receiver_epoch,
                fence_generation: resource.fence_generation,
                admission_id: Some(admission.binding.admission_id.clone()),
                execution_ordinal: Some(execution.ordinal),
                source_repository_dir: source.map(|s| s.repository_dir.to_path_buf()),
                source_password: source.map(|s| s.repository_password.into()),
                source_key_ref: source.map(|s| s.repository_key_ref.into()),
                target_password: context.target_password.into(),
                target_key_ref: context.target_key_ref.into(),
                repository_max_bytes: context.repository_max_bytes,
                memory_max_bytes: context.worker_limits.memory_max_bytes,
                timeout_seconds: context.worker_limits.max_runtime.as_secs().clamp(1, 900),
            };
            let body = Zeroizing::new(
                serde_json::to_vec(&request).map_err(|_| GatewayStoreError::INVALID)?,
            );
            if body.len() > 65536 {
                return Err(GatewayStoreError::INVALID);
            }
            let mut input = Zeroizing::new((body.len() as u32).to_be_bytes().to_vec());
            input.extend_from_slice(&body);
            let mut reads = vec![context.state_dir.to_path_buf(), self.root.clone()];
            if let Some(source) = source {
                reads.push(
                    source
                        .repository_dir
                        .parent()
                        .ok_or(GatewayStoreError::INVALID)?
                        .to_path_buf(),
                );
            }
            let writes = vec![if source.is_some() {
                self.root.clone()
            } else {
                self.root.join(".relic-scratch")
            }];
            let mut pending_lock = Some(
                coordinator
                    .try_clone()
                    .map_err(|_| GatewayStoreError::STORAGE)?,
            );
            let output = execute_worker_recorded(
                context.executable,
                &input,
                &reads,
                &writes,
                context.worker_limits,
                context.guard,
                |identity| {
                    if source.is_some() {
                        state.bind_gateway_execution_worker(
                            &admission.binding.admission_id,
                            execution.ordinal,
                            resource.receiver_epoch,
                            resource.fence_generation,
                            identity,
                        )
                    } else {
                        state.bind_gateway_verification_worker(
                            &admission.binding.admission_id,
                            execution.ordinal,
                            resource.receiver_epoch,
                            resource.fence_generation,
                            execution.verify_attempts,
                            identity,
                        )
                    }
                    .map_err(|_| WorkerError::INVALID)?;
                    Ok(())
                },
            )
            .map_err(|error| {
                if let WorkerError::OUTCOME_UNKNOWN(mut stop) = error
                    && let Some(worker) = stop.recovery.take()
                {
                    let pending = PendingGateway {
                        worker,
                        reservation: reservation.take(),
                        coordinator: pending_lock.take(),
                    };
                    match self.pending.lock() {
                        Ok(mut entries) => {
                            entries.insert(resource.binding.resource_id.clone(), pending);
                        }
                        Err(_) => drop(pending),
                    }
                }
                GatewayStoreError::OUTCOME_UNKNOWN
            })?;
            let stdout = Zeroizing::new(output.stdout);
            if stdout.len() < 4 {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            let size = u32::from_be_bytes(
                stdout[..4]
                    .try_into()
                    .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?,
            ) as usize;
            if size > 16384 || size != stdout.len() - 4 {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            let value = crate::config::parse_json_bytes(&stdout[4..])
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            let report: GatewayWorkerReport =
                serde_json::from_value(value).map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            self.check_coordinator(coordinator)?;
            let (owner, _scratch) = self.open_bound_layout(layout)?;
            acquire_file_lock(&owner)?;
            context
                .guard
                .check()
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            if report.protocol_version != 1
                || report.resource_id != resource.binding.resource_id
                || report.admission_id.as_deref() != Some(admission.binding.admission_id.as_str())
                || report.execution_ordinal != Some(execution.ordinal)
                || report.receiver_epoch != execution.receiver_epoch
                || report.fence_generation != execution.fence_generation
                || Some(report.repository_id.as_str()) != resource.repository_id.as_deref()
                || report.repository_bytes > context.repository_max_bytes
            {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            if report.native_snapshot_id.is_none() {
                if source.is_some()
                    || execution.native_result_id.is_some()
                    || report.manifest_digest.is_some()
                    || report.entry_count != 0
                    || report.file_count != 0
                    || report.payload_bytes != 0
                {
                    return Err(GatewayStoreError::OUTCOME_UNKNOWN);
                }
                state
                    .transition_gateway_execution(
                        &admission.binding.admission_id,
                        execution.ordinal,
                        resource.receiver_epoch,
                        resource.fence_generation,
                        "proven_unpublished",
                        None,
                    )
                    .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
                return Ok(None);
            }
            let native = report
                .native_snapshot_id
                .as_deref()
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?;
            let run = state
                .get_native_run(&admission.binding.native_run_id)
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?;
            if native.len() != 64
                || !native
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || report.manifest_digest.as_deref()
                    != Some(admission.binding.manifest_digest.as_str())
                || report.entry_count.to_string() != run.manifest_entry_count
                || report.file_count.to_string() != run.file_count
                || report.payload_bytes.to_string() != run.payload_bytes
                || execution
                    .native_result_id
                    .as_deref()
                    .is_some_and(|old| old != native)
            {
                return Err(GatewayStoreError::OUTCOME_UNKNOWN);
            }
            if execution.effect_state != "published_unverified" {
                state
                    .transition_gateway_execution(
                        &admission.binding.admission_id,
                        execution.ordinal,
                        resource.receiver_epoch,
                        resource.fence_generation,
                        "published_unverified",
                        Some(native),
                    )
                    .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            }
            let publication = state
                .get_publication(&admission.binding.commit_key)
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?;
            let mut receipt = publication.binding;
            let fields = receipt
                .as_object_mut()
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?;
            fields.extend(json!({"record_version":1,"payload_hash":admission.binding.payload_hash,
                "resource_id":resource.binding.resource_id,"admission_id":admission.binding.admission_id,
                "receiver_epoch":execution.receiver_epoch.to_string(),"fence_generation":execution.fence_generation.to_string(),
                "repository_id":report.repository_id,"native_result_id":native,"durability":"durable",
                "verification":"data_verified","committed_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs,true)
            }).as_object().ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?.clone());
            state
                .record_gateway_receipt(
                    &admission.binding.admission_id,
                    execution.ordinal,
                    resource.receiver_epoch,
                    resource.fence_generation,
                    &receipt,
                )
                .map(Some)
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)
        })();
        if outcome.is_err() {
            let current = state
                .list_gateway_executions(&admission.binding.admission_id)
                .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?
                .into_iter()
                .find(|v| v.ordinal == execution.ordinal)
                .ok_or(GatewayStoreError::OUTCOME_UNKNOWN)?;
            if current.effect_state == "active" {
                state
                    .transition_gateway_execution(
                        &admission.binding.admission_id,
                        execution.ordinal,
                        resource.receiver_epoch,
                        resource.fence_generation,
                        "unknown",
                        None,
                    )
                    .map_err(|_| GatewayStoreError::OUTCOME_UNKNOWN)?;
            }
        }
        outcome
    }
}
