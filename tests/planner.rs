use std::collections::BTreeSet;

use relic::identity::{DestinationId, EndpointId, JobId, NodeId};
use relic::planner::{
    DestinationEvidence, EndpointEvidence, GrantEvidence, PlanError, PreflightEvidence,
    ScopeEvidence, SourceEvidence, SourceId, plan_job,
};
use relic::resources::Demand;
use serde_json::Value;

fn endpoint(alias: &str, identity: &str, scope: &str) -> EndpointEvidence {
    EndpointEvidence {
        alias: EndpointId(alias.to_owned()),
        identity: EndpointId(identity.to_owned()),
        expected_revision: 1,
        observed_revision: 1,
        grant: GrantEvidence {
            node_id: NodeId("node_1".into()),
            endpoint_id: EndpointId(identity.to_owned()),
            can_read: true,
            can_write: true,
            is_revoked: false,
        },
        scope: ScopeEvidence {
            domain: "filesystem_1".into(),
            components: vec![scope.to_owned()],
        },
        methods: BTreeSet::from(["archive".into()]),
        metadata: BTreeSet::new(),
        consistency: BTreeSet::from(["best_effort".into()]),
        verification: BTreeSet::from(["metadata_verified".into()]),
        can_enforce_budget: true,
        minimum_memory_bytes: 65_536,
        minimum_spool_bytes: 0,
    }
}

fn fixture() -> (Value, PreflightEvidence) {
    let policy: Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    let evidence = PreflightEvidence {
        node_id: NodeId("node_1".into()),
        job_id: JobId("job_1".into()),
        expected_job_revision: 1,
        sources: vec![SourceEvidence {
            source_id: SourceId("documents".into()),
            endpoint: endpoint("documents_source", "source_1", "source"),
            resolved_snapshot_id: None,
        }],
        destinations: vec![DestinationEvidence {
            destination_id: DestinationId("remote_archive".into()),
            endpoint: endpoint("object_archive", "destination_1", "repository"),
        }],
        required_metadata: BTreeSet::new(),
        secret_refs: vec!["local_archive_key".into()],
        are_secrets_resolved: true,
        security_policy_revision: 1,
        requested_budget: Demand {
            data_bytes: 65_536,
            open_files: 1,
            cpu_workers: 1,
            streams: 1,
            jobs: 1,
            ..Demand::default()
        },
        hard_budget: Demand {
            data_bytes: 65_536,
            open_files: 1,
            cpu_workers: 1,
            streams: 1,
            jobs: 1,
            ..Demand::default()
        },
        available_parallelism: 8,
        spool_available_bytes: 1_073_741_824,
        spool_capacity_bytes: 1_073_741_824,
    };
    (policy["job"].clone(), evidence)
}

#[test]
fn reproduces_exact_policy_vector() {
    let (job, evidence) = fixture();
    let plan = plan_job(&job, &evidence).unwrap();
    let policy: Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    assert_eq!(plan.destination_policies[0].binding, policy);
    assert_eq!(
        plan.destination_policies[0].digest,
        "sha256:c4d15f4d5922d1613a23bfaf394058aa68cf535de5b9fa8ba1d0c3e1b5f84276"
    );
}

#[test]
fn rejects_revoked_grants_revision_drift_and_overlap() {
    let (job, evidence) = fixture();
    let mut changed = evidence.clone();
    changed.sources[0].endpoint.grant.is_revoked = true;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::GRANT_DENIED)
    ));
    changed = evidence.clone();
    changed.destinations[0].endpoint.observed_revision = 2;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::REVISION_CONFLICT)
    ));
    changed = evidence;
    changed.destinations[0].endpoint.scope.components = vec!["source".into(), "nested".into()];
    assert!(matches!(plan_job(&job, &changed), Err(PlanError::OVERLAP)));
}

#[test]
fn rejects_missing_capabilities_budget_and_duplicate_secrets() {
    let (job, evidence) = fixture();
    let mut changed = evidence.clone();
    changed.required_metadata.insert("permissions".into());
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::UNSUPPORTED_CAPABILITY)
    ));
    changed = evidence.clone();
    changed.requested_budget.data_bytes += 1;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::RESOURCE_EXHAUSTED)
    ));
    changed = evidence.clone();
    changed.spool_available_bytes = 10;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::RESOURCE_EXHAUSTED)
    ));
    changed = evidence;
    changed.secret_refs.push("local_archive_key".into());
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::INVALID_INPUT)
    ));
}

#[test]
fn enforces_class_caps_and_endpoint_minimums() {
    let (mut job, evidence) = fixture();
    job["resources"]["class"] = "low".into();
    let mut changed = evidence.clone();
    changed.requested_budget.data_bytes = 128 * 1024 * 1024 + 1;
    changed.hard_budget.data_bytes = changed.requested_budget.data_bytes;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::RESOURCE_EXHAUSTED)
    ));
    job["resources"]["class"] = "throughput".into();
    assert!(matches!(
        plan_job(&job, &evidence),
        Err(PlanError::UNSUPPORTED_CAPABILITY)
    ));
    job["resources"]["class"] = "balanced".into();
    changed = evidence.clone();
    changed.destinations[0].endpoint.minimum_memory_bytes = 65_537;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::RESOURCE_EXHAUSTED)
    ));
    changed = evidence;
    changed.sources[0].endpoint.minimum_spool_bytes = 1;
    assert!(matches!(
        plan_job(&job, &changed),
        Err(PlanError::RESOURCE_EXHAUSTED)
    ));
}
