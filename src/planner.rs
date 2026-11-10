use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Value, json};

use crate::config;
use crate::identity::{DestinationId, EndpointId, JobId, NodeId, hash_domain};
use crate::resources::{Demand, ResourceCaps, ResourceClass};

const MAX_INPUT_BYTES: usize = 1_048_576;
const MAX_METADATA_ITEMS: usize = 64;
const MAX_SCOPE_COMPONENTS: usize = 128;
const MAX_IDENT_BYTES: usize = 128;
const MIN_FREE_RESERVE: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ScopeEvidence {
    pub domain: String,
    pub components: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct GrantEvidence {
    pub node_id: NodeId,
    pub endpoint_id: EndpointId,
    pub can_read: bool,
    pub can_write: bool,
    pub is_revoked: bool,
}

#[derive(Clone, Debug)]
pub struct EndpointEvidence {
    pub alias: EndpointId,
    pub identity: EndpointId,
    pub expected_revision: u32,
    pub observed_revision: u32,
    pub grant: GrantEvidence,
    pub scope: ScopeEvidence,
    pub methods: BTreeSet<String>,
    pub metadata: BTreeSet<String>,
    pub consistency: BTreeSet<String>,
    pub verification: BTreeSet<String>,
    pub can_enforce_budget: bool,
    pub minimum_memory_bytes: u64,
    pub minimum_spool_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceId(pub String);

#[derive(Clone, Debug)]
pub struct SourceEvidence {
    pub source_id: SourceId,
    pub endpoint: EndpointEvidence,
    pub resolved_snapshot_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DestinationEvidence {
    pub destination_id: DestinationId,
    pub endpoint: EndpointEvidence,
}

#[derive(Clone, Debug)]
pub struct PreflightEvidence {
    pub node_id: NodeId,
    pub job_id: JobId,
    pub expected_job_revision: u32,
    pub sources: Vec<SourceEvidence>,
    pub destinations: Vec<DestinationEvidence>,
    pub required_metadata: BTreeSet<String>,
    pub secret_refs: Vec<String>,
    pub are_secrets_resolved: bool,
    pub security_policy_revision: u64,
    pub requested_budget: Demand,
    pub hard_budget: Demand,
    pub available_parallelism: usize,
    pub spool_available_bytes: u64,
    pub spool_capacity_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct DestinationPolicy {
    pub destination_id: DestinationId,
    pub binding: Value,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub struct ExecutionPlan {
    pub job_id: JobId,
    pub revision: u32,
    pub destination_policies: Vec<DestinationPolicy>,
    pub resolved_snapshots: Vec<(SourceId, String)>,
    pub requested_budget: Demand,
    pub job: Value,
    pub evidence: PreflightEvidence,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    INVALID_INPUT,
    REVISION_CONFLICT,
    GRANT_DENIED,
    UNSUPPORTED_CAPABILITY,
    OVERLAP,
    RESOURCE_EXHAUSTED,
    IDENTITY_ERROR,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID_INPUT => "invalid preflight input",
            Self::REVISION_CONFLICT => "definition or endpoint revision changed",
            Self::GRANT_DENIED => "endpoint grant is missing or revoked",
            Self::UNSUPPORTED_CAPABILITY => "required capability is unavailable",
            Self::OVERLAP => "source and destination scopes overlap",
            Self::RESOURCE_EXHAUSTED => "requested resources exceed available capacity",
            Self::IDENTITY_ERROR => "policy digest could not be produced",
        })
    }
}

impl std::error::Error for PlanError {}

fn is_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= MAX_IDENT_BYTES
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_scope_valid(scope: &ScopeEvidence) -> bool {
    is_id(&scope.domain)
        && scope.components.len() <= MAX_SCOPE_COMPONENTS
        && scope.components.iter().all(|component| {
            !component.is_empty()
                && component.len() <= 4096
                && component != "."
                && component != ".."
                && !component.contains('/')
                && !component.contains('\0')
        })
}

fn does_overlap(left: &ScopeEvidence, right: &ScopeEvidence) -> bool {
    left.domain == right.domain
        && (left.components.starts_with(&right.components)
            || right.components.starts_with(&left.components))
}

fn fits_budget(value: Demand, cap: Demand) -> bool {
    value.data_bytes <= cap.data_bytes
        && value.cache_bytes <= cap.cache_bytes
        && value.spool_bytes <= cap.spool_bytes
        && value.open_files <= cap.open_files
        && value.cpu_workers <= cap.cpu_workers
        && value.streams <= cap.streams
        && value.jobs <= cap.jobs
}

fn check_endpoint(
    endpoint: &EndpointEvidence,
    alias: &str,
    node: &NodeId,
    is_source: bool,
    method: &str,
    metadata: &BTreeSet<String>,
) -> Result<(), PlanError> {
    if !is_id(&endpoint.alias.0)
        || !is_id(&endpoint.identity.0)
        || endpoint.alias.0 != alias
        || !is_scope_valid(&endpoint.scope)
        || endpoint.expected_revision == 0
        || endpoint.observed_revision == 0
        || endpoint.methods.len() > MAX_METADATA_ITEMS
        || endpoint.metadata.len() > MAX_METADATA_ITEMS
        || endpoint.consistency.len() > MAX_METADATA_ITEMS
        || endpoint.verification.len() > MAX_METADATA_ITEMS
    {
        return Err(PlanError::INVALID_INPUT);
    }
    if endpoint.expected_revision != endpoint.observed_revision {
        return Err(PlanError::REVISION_CONFLICT);
    }
    if endpoint.grant.is_revoked
        || endpoint.grant.node_id != *node
        || endpoint.grant.endpoint_id != endpoint.identity
        || (is_source && !endpoint.grant.can_read)
        || (!is_source && !endpoint.grant.can_write)
    {
        return Err(PlanError::GRANT_DENIED);
    }
    if !endpoint.methods.contains(method)
        || !metadata.is_subset(&endpoint.metadata)
        || !endpoint.can_enforce_budget
    {
        return Err(PlanError::UNSUPPORTED_CAPABILITY);
    }
    Ok(())
}

pub fn plan_job(job: &Value, evidence: &PreflightEvidence) -> Result<ExecutionPlan, PlanError> {
    let encoded = serde_json::to_vec(job).map_err(|_| PlanError::INVALID_INPUT)?;
    if encoded.len() > MAX_INPUT_BYTES
        || config::normalize_job(job).map_err(|_| PlanError::INVALID_INPUT)? != *job
        || !is_id(&evidence.node_id.0)
        || !is_id(&evidence.job_id.0)
        || evidence.required_metadata.len() > MAX_METADATA_ITEMS
        || evidence.secret_refs.len() > MAX_METADATA_ITEMS
        || evidence.security_policy_revision == 0
        || evidence.sources.len() > 128
        || evidence.destinations.len() > 128
    {
        return Err(PlanError::INVALID_INPUT);
    }
    if job["job_id"] != evidence.job_id.0
        || job["revision"].as_u64() != Some(u64::from(evidence.expected_job_revision))
    {
        return Err(PlanError::REVISION_CONFLICT);
    }
    if !evidence.are_secrets_resolved || evidence.secret_refs.iter().any(|value| !is_id(value)) {
        return Err(PlanError::GRANT_DENIED);
    }
    if job["security"]["policy_revision"]
        .as_u64()
        .is_some_and(|revision| revision != evidence.security_policy_revision)
    {
        return Err(PlanError::REVISION_CONFLICT);
    }
    let mut evidence_bytes = 0usize;
    for endpoint in evidence
        .sources
        .iter()
        .map(|item| &item.endpoint)
        .chain(evidence.destinations.iter().map(|item| &item.endpoint))
    {
        for part in std::iter::once(&endpoint.scope.domain)
            .chain(endpoint.scope.components.iter())
            .chain(endpoint.methods.iter())
            .chain(endpoint.metadata.iter())
            .chain(endpoint.consistency.iter())
            .chain(endpoint.verification.iter())
        {
            evidence_bytes = evidence_bytes
                .checked_add(part.len())
                .ok_or(PlanError::INVALID_INPUT)?;
            if evidence_bytes > MAX_INPUT_BYTES || part.len() > 4096 {
                return Err(PlanError::INVALID_INPUT);
            }
        }
    }
    if evidence.required_metadata.iter().any(|item| !is_id(item)) {
        return Err(PlanError::INVALID_INPUT);
    }
    let mut secrets = evidence.secret_refs.clone();
    secrets.sort();
    if secrets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PlanError::INVALID_INPUT);
    }
    if let Some(reference) = job["security"]["credential_ref"].as_str()
        && secrets.binary_search(&reference.to_owned()).is_err()
    {
        return Err(PlanError::GRANT_DENIED);
    }
    let reserve = MIN_FREE_RESERVE.max(evidence.spool_capacity_bytes.div_ceil(20));
    let budget = evidence.requested_budget;
    let resources = &job["resources"];
    if evidence.available_parallelism == 0 {
        return Err(PlanError::INVALID_INPUT);
    }
    let class = match resources["class"].as_str().unwrap_or("balanced") {
        "balanced" => ResourceClass::BALANCED,
        "low" => ResourceClass::LOW,
        "throughput" => return Err(PlanError::UNSUPPORTED_CAPABILITY),
        _ => return Err(PlanError::INVALID_INPUT),
    };
    let class_caps = ResourceCaps::for_class(class, evidence.available_parallelism);
    if !fits_budget(budget, class_caps.global) || !fits_budget(budget, class_caps.job) {
        return Err(PlanError::RESOURCE_EXHAUSTED);
    }
    for endpoint in evidence
        .sources
        .iter()
        .map(|item| &item.endpoint)
        .chain(evidence.destinations.iter().map(|item| &item.endpoint))
    {
        if endpoint.minimum_memory_bytes == 0
            || endpoint.minimum_memory_bytes > budget.data_bytes
            || endpoint.minimum_spool_bytes > budget.spool_bytes
            || endpoint.minimum_spool_bytes > class_caps.endpoint.spool_bytes
        {
            return Err(PlanError::RESOURCE_EXHAUSTED);
        }
    }
    let memory = budget
        .data_bytes
        .checked_add(budget.cache_bytes)
        .ok_or(PlanError::RESOURCE_EXHAUSTED)?;
    if budget.data_bytes == 0
        || budget.open_files == 0
        || budget.cpu_workers == 0
        || budget.streams == 0
        || budget.jobs == 0
        || resources["memory_bytes"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|cap| memory > cap)
        || resources["cache_bytes"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|cap| budget.cache_bytes > cap)
        || resources["spool_bytes"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|cap| budget.spool_bytes > cap)
        || resources["workers"]
            .as_u64()
            .is_some_and(|cap| budget.cpu_workers > cap)
        || resources["open_files"]
            .as_u64()
            .is_some_and(|cap| budget.open_files > cap)
        || resources["endpoint_streams"]
            .as_u64()
            .is_some_and(|cap| budget.streams > cap)
        || resources["active_jobs"]
            .as_u64()
            .is_some_and(|cap| budget.jobs > cap)
    {
        return Err(PlanError::RESOURCE_EXHAUSTED);
    }
    if !fits_budget(evidence.requested_budget, evidence.hard_budget)
        || evidence.spool_available_bytes > evidence.spool_capacity_bytes
        || evidence
            .requested_budget
            .spool_bytes
            .checked_add(reserve)
            .is_none_or(|required| required > evidence.spool_available_bytes)
    {
        return Err(PlanError::RESOURCE_EXHAUSTED);
    }
    let sources = job["sources"].as_array().ok_or(PlanError::INVALID_INPUT)?;
    let destinations = job["destinations"]
        .as_array()
        .ok_or(PlanError::INVALID_INPUT)?;
    if sources.len() != evidence.sources.len() || destinations.len() != evidence.destinations.len()
    {
        return Err(PlanError::INVALID_INPUT);
    }
    let method = job["method"].as_str().ok_or(PlanError::INVALID_INPUT)?;
    let mut source_bindings = Vec::new();
    let mut snapshots = Vec::new();
    let mut used_sources = BTreeSet::new();
    for source in sources {
        let id = source["source_id"]
            .as_str()
            .ok_or(PlanError::INVALID_INPUT)?;
        let matches: Vec<_> = evidence
            .sources
            .iter()
            .filter(|item| item.source_id.0 == id)
            .collect();
        if matches.len() != 1 || !used_sources.insert(id) {
            return Err(PlanError::INVALID_INPUT);
        }
        let selected = matches[0];
        check_endpoint(
            &selected.endpoint,
            source["endpoint"]
                .as_str()
                .ok_or(PlanError::INVALID_INPUT)?,
            &evidence.node_id,
            true,
            method,
            &evidence.required_metadata,
        )?;
        let required = match job["consistency"]["policy"].as_str() {
            Some("require_application_consistent") => "application_consistent",
            Some("require_snapshot") => "snapshot",
            Some("prefer_snapshot") | Some("best_effort") => "best_effort",
            _ => return Err(PlanError::INVALID_INPUT),
        };
        let consistency = &selected.endpoint.consistency;
        let has_consistency = consistency.contains(required)
            || (required == "best_effort"
                && (consistency.contains("snapshot")
                    || consistency.contains("application_consistent")))
            || (required == "snapshot" && consistency.contains("application_consistent"));
        if !has_consistency {
            return Err(PlanError::UNSUPPORTED_CAPABILITY);
        }
        if method == "replicate" {
            let snapshot = selected
                .resolved_snapshot_id
                .as_ref()
                .filter(|id| is_id(id))
                .ok_or(PlanError::INVALID_INPUT)?;
            let exact = source["snapshot_id"]
                .as_str()
                .or_else(|| source["snapshot_selector"]["snapshot_id"].as_str());
            if exact.is_some_and(|value| value != snapshot.as_str()) {
                return Err(PlanError::REVISION_CONFLICT);
            }
            snapshots.push((SourceId(id.to_owned()), snapshot.clone()));
        }
        source_bindings.push(json!({"source_id": id, "endpoint_identity": selected.endpoint.identity.0, "endpoint_revision": selected.endpoint.observed_revision.to_string()}));
    }
    source_bindings
        .sort_by(|left, right| left["source_id"].as_str().cmp(&right["source_id"].as_str()));
    let publication = job["verification"]["publication"]
        .as_str()
        .ok_or(PlanError::INVALID_INPUT)?;
    let mut policies = Vec::new();
    let mut used_destinations = BTreeSet::new();
    for destination in destinations {
        let id = destination["destination_id"]
            .as_str()
            .ok_or(PlanError::INVALID_INPUT)?;
        let matches: Vec<_> = evidence
            .destinations
            .iter()
            .filter(|item| item.destination_id.0 == id)
            .collect();
        if matches.len() != 1 || !used_destinations.insert(id) {
            return Err(PlanError::INVALID_INPUT);
        }
        let selected = matches[0];
        check_endpoint(
            &selected.endpoint,
            destination["endpoint"]
                .as_str()
                .ok_or(PlanError::INVALID_INPUT)?,
            &evidence.node_id,
            false,
            method,
            &evidence.required_metadata,
        )?;
        if !selected.endpoint.verification.contains(publication) {
            return Err(PlanError::UNSUPPORTED_CAPABILITY);
        }
        if evidence
            .sources
            .iter()
            .any(|source| does_overlap(&source.endpoint.scope, &selected.endpoint.scope))
        {
            return Err(PlanError::OVERLAP);
        }
        if evidence.destinations.iter().any(|other| {
            other.destination_id.0 != id
                && does_overlap(&other.endpoint.scope, &selected.endpoint.scope)
        }) {
            return Err(PlanError::OVERLAP);
        }
        let mut binding_destination = json!({"destination_id": id, "endpoint": destination["endpoint"], "endpoint_revision": selected.endpoint.observed_revision.to_string()});
        if method == "archive" || method == "replicate" {
            let repository = destination["repository_id"]
                .as_str()
                .ok_or(PlanError::UNSUPPORTED_CAPABILITY)?;
            binding_destination["repository_id"] = json!(repository);
        } else if destination.get("repository_id").is_some() {
            return Err(PlanError::INVALID_INPUT);
        }
        let binding = json!({"job": job, "destination": binding_destination, "source_bindings": source_bindings, "secret_refs": secrets, "security_policy_revision": evidence.security_policy_revision.to_string(), "verification": publication});
        let digest = hash_domain("relic/effective-policy/v1", &binding)
            .map_err(|_| PlanError::IDENTITY_ERROR)?;
        policies.push(DestinationPolicy {
            destination_id: DestinationId(id.to_owned()),
            binding,
            digest,
        });
    }
    Ok(ExecutionPlan {
        job_id: evidence.job_id.clone(),
        revision: evidence.expected_job_revision,
        destination_policies: policies,
        resolved_snapshots: snapshots,
        requested_budget: evidence.requested_budget,
        job: job.clone(),
        evidence: evidence.clone(),
    })
}
