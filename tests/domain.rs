use std::collections::BTreeSet;

use relic::domain::{Attempt, DomainError, Occurrence, OccurrenceState};
use relic::identity::{
    AttemptId, AuthorityId, CaptureId, CommitKey, DestinationId, JobId, OccurrenceId,
    PublicationBinding, SourceViewId,
};

fn binding(destination: &str, occurrence: &str, capture: &str) -> PublicationBinding {
    PublicationBinding {
        commit_key: CommitKey {
            authority_id: AuthorityId("local".into()),
            job_id: JobId("job".into()),
            occurrence_id: OccurrenceId(occurrence.into()),
            destination_id: DestinationId(destination.into()),
        },
        capture_id: CaptureId(capture.into()),
        source_view_id: SourceViewId("view".into()),
        consistency: "crash_consistent".into(),
        destination_config_revision: "1".into(),
        manifest_digest: "manifest".into(),
        policy_digest: "policy".into(),
    }
}

#[test]
fn aggregates_across_attempts_and_preserves_canceled_receipts() {
    let destinations = BTreeSet::from([DestinationId("a".into()), DestinationId("b".into())]);
    let mut occurrence = Occurrence::new(
        OccurrenceId("one".into()),
        CaptureId("capture".into()),
        destinations.clone(),
        None,
    )
    .unwrap();
    occurrence.set_ready().unwrap();
    occurrence
        .admit_attempt(&Attempt::new(AttemptId("first".into()), destinations).unwrap())
        .unwrap();
    let first = binding("a", "one", "capture");
    occurrence.bind_publication(first.clone()).unwrap();
    occurrence.record_receipt(&first).unwrap();
    occurrence.record_receipt(&first).unwrap();
    assert_eq!(occurrence.get_receipts().len(), 1);
    occurrence.retry_wait().unwrap();
    occurrence
        .admit_attempt(
            &Attempt::new(
                AttemptId("second".into()),
                BTreeSet::from([DestinationId("b".into())]),
            )
            .unwrap(),
        )
        .unwrap();
    let second = binding("b", "one", "capture");
    occurrence.bind_publication(second.clone()).unwrap();
    occurrence
        .mark_uncertain(&DestinationId("b".into()))
        .unwrap();
    assert_eq!(
        occurrence.finalize(false),
        Err(DomainError::UncertainOutcome)
    );
    occurrence.reconcile(&DestinationId("b".into())).unwrap();
    occurrence.record_receipt(&second).unwrap();
    occurrence.finalize(false).unwrap();
    assert_eq!(occurrence.get_state(), OccurrenceState::COMPLETED);
    assert_eq!(
        occurrence.finalize(true),
        Err(DomainError::InvalidTransition)
    );

    let mut canceled = Occurrence::new(
        OccurrenceId("two".into()),
        CaptureId("new".into()),
        BTreeSet::from([DestinationId("a".into())]),
        Some(OccurrenceId("one".into())),
    )
    .unwrap();
    assert!(canceled.get_receipts().is_empty());
    canceled.set_ready().unwrap();
    canceled
        .admit_attempt(
            &Attempt::new(
                AttemptId("third".into()),
                BTreeSet::from([DestinationId("a".into())]),
            )
            .unwrap(),
        )
        .unwrap();
    let bound = binding("a", "two", "new");
    canceled.bind_publication(bound.clone()).unwrap();
    let mut changed = bound.clone();
    changed.source_view_id = SourceViewId("changed".into());
    assert_eq!(
        canceled.bind_publication(changed),
        Err(DomainError::IdempotencyConflict)
    );
    canceled.record_receipt(&bound).unwrap();
    canceled.finalize(true).unwrap();
    assert_eq!(canceled.get_receipts().len(), 1);
}
