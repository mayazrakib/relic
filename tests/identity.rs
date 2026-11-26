use relic::identity::{
    AuthorityId, CalendarOccurrence, CaptureId, CommitKey, DestinationId, FramedDigest, JobId,
    OccurrenceId, PublicationBinding, SourceViewId, TriggerId,
};
use serde_json::json;

#[test]
fn verifies_calendar_manifest_and_publication_vectors() {
    let calendar = CalendarOccurrence {
        job_id: JobId("job_1".into()),
        schedule_revision: "1".into(),
        trigger_id: TriggerId("hourly".into()),
        intended_local_time: "2026-11-10T11:00:00.000000000".into(),
        intended_utc_instant: "2026-11-10T00:00:00.000000000Z".into(),
        fold_ordinal: 0,
    };
    let occurrence = calendar.digest().unwrap();
    assert_eq!(
        occurrence.0,
        "sha256:5337a0333ec206790cf847d8f0a94f5e29b758698a0d68facf67c7be0e3b7152"
    );
    let header = json!({"schema_version":1,"capture_id":"capture_1","entry_count":"1"});
    let entry = json!({"source_id":"documents","path_encoding":"unix_bytes","path":["YS50eHQ"],"kind":"file","size_bytes":"0","content_digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","metadata":[]});
    let mut manifest = FramedDigest::new("relic/logical-manifest/v1", &header, 1).unwrap();
    manifest.add_entry(&entry).unwrap();
    let manifest_digest = manifest.finish().unwrap();
    assert_eq!(
        manifest_digest,
        "sha256:e77e8179915ad471fadc683b82f6a8a016c9e11319b14688e10cf37cb45a6d85"
    );
    let binding = PublicationBinding {
        commit_key: CommitKey {
            authority_id: AuthorityId("local_1".into()),
            destination_id: DestinationId("remote_archive".into()),
            job_id: JobId("job_1".into()),
            occurrence_id: OccurrenceId(occurrence.0),
        },
        capture_id: CaptureId("capture_1".into()),
        source_view_id: SourceViewId("view_1".into()),
        consistency: "crash_consistent".into(),
        destination_config_revision: "1".into(),
        manifest_digest,
        policy_digest: "sha256:c4d15f4d5922d1613a23bfaf394058aa68cf535de5b9fa8ba1d0c3e1b5f84276"
            .into(),
    };
    assert_eq!(
        binding.digest().unwrap(),
        "sha256:d32a885dd16f77c7a58dcc4427355748bbf90243b98d5cb765f70c2d605d36c3"
    );
}
