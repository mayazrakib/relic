use std::fs;

use relic::config::{load_job, normalize_job, parse_json_bytes, validate_job};
use serde_json::{Value, json};

fn get_minimal_job() -> Value {
    json!({
        "schema_version": 1,
        "job_id": "job_1",
        "revision": 1,
        "name": "Example",
        "scope": "local",
        "sources": [{"source_id": "documents", "endpoint": "documents_source"}],
        "destinations": [{"destination_id": "remote_archive", "endpoint": "object_archive", "repository_id": "repo_1"}]
    })
}

#[test]
fn expands_golden_policy_defaults() {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    assert_eq!(normalize_job(&get_minimal_job()).unwrap(), fixture["job"]);
}

#[test]
fn rejects_duplicate_ids_resource_overflow_and_weakened_objectives() {
    let job = normalize_job(&get_minimal_job()).unwrap();
    let mut invalid = job.clone();
    let duplicate = invalid["sources"][0].clone();
    invalid["sources"].as_array_mut().unwrap().push(duplicate);
    assert!(validate_job(&invalid).is_err());
    invalid = job.clone();
    let duplicate = invalid["destinations"][0].clone();
    invalid["destinations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(validate_job(&invalid).is_err());
    invalid = job.clone();
    invalid["resources"]["memory_bytes"] = json!("18446744073709551616");
    assert!(validate_job(&invalid).is_err());
    invalid = job;
    invalid["recovery_objectives"] =
        json!({"rpo_seconds": 30, "protection_level": "data_verified"});
    invalid["destinations"][0]["recovery_objectives"] = json!({"rpo_seconds": 31});
    assert!(validate_job(&invalid).is_err());
    invalid["destinations"][0]["recovery_objectives"] = json!({"protection_level": "committed"});
    assert!(validate_job(&invalid).is_err());
}

#[test]
fn validates_replication_selection_and_verification() {
    let mut job = get_minimal_job();
    job["method"] = json!("replicate");
    job["sources"][0]["repository_id"] = json!("source_repo");
    job["sources"][0]["snapshot_selector"] = json!({"kind": "latest"});
    let job = normalize_job(&job).unwrap();
    assert_eq!(job["verification"]["publication"], "data_verified");
    let mut invalid = job.clone();
    invalid["verification"]["publication"] = json!("metadata_verified");
    assert!(validate_job(&invalid).is_err());
    invalid = job.clone();
    invalid["sources"][0]["snapshot_id"] = json!("snapshot_1");
    assert!(validate_job(&invalid).is_err());
    invalid = job.clone();
    invalid["sources"][0]["selector"] = json!("subdirectory");
    assert!(validate_job(&invalid).is_err());
    invalid = job;
    invalid["destinations"][0]["repository_id"] = json!("source_repo");
    assert!(validate_job(&invalid).is_err());
}

#[test]
fn validates_cron_shape_and_ranges() {
    let mut job = normalize_job(&get_minimal_job()).unwrap();
    job["schedule"] =
        json!({"kind":"calendar", "cron":"*/15 0-23 * * 0-6", "timezone":"Australia/Sydney"});
    assert!(validate_job(&job).is_ok());

    for cron in [
        "0 0 * * 7",
        "0 0 * * * *",
        "*/0 * * * *",
        "0 24 * * *",
        "@daily",
    ] {
        job["schedule"]["cron"] = json!(cron);
        assert!(validate_job(&job).is_err(), "accepted {cron}");
    }
}

#[test]
fn rejects_duplicate_keys_deep_nesting_and_large_files() {
    let directory = tempfile::tempdir().unwrap();
    let json_path = directory.path().join("job.json");
    fs::write(&json_path, r#"{"schema_version":1,"schema_version":1}"#).unwrap();
    assert!(load_job(&json_path).is_err());
    fs::write(&json_path, format!("{}0{}", "[".repeat(33), "]".repeat(33))).unwrap();
    assert!(load_job(&json_path).is_err());
    fs::write(&json_path, vec![b' '; 1_048_577]).unwrap();
    assert!(load_job(&json_path).is_err());
    let toml_path = directory.path().join("job.toml");
    fs::write(&toml_path, "schema_version = 1\nschema_version = 1\n").unwrap();
    assert!(load_job(&toml_path).is_err());
}

#[test]
fn parses_bounded_json_frames_with_unique_keys() {
    assert_eq!(
        parse_json_bytes(br#"{"items":[1,true]}"#).unwrap(),
        json!({"items": [1, true]})
    );
    assert!(parse_json_bytes(br#"{"items":{"id":1,"id":2}}"#).is_err());
    assert!(parse_json_bytes(b"{} {} ").is_err());
    assert!(parse_json_bytes(&vec![b' '; 1_048_577]).is_err());
    let nested = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(parse_json_bytes(nested.as_bytes()).is_err());
}
