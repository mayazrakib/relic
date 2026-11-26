use jsonschema::{Draft, Registry};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const JOB: &str = include_str!("../schemas/job.json");
const REQUEST: &str = include_str!("../schemas/request.json");
const RESPONSE: &str = include_str!("../schemas/response.json");
const RECORDS: &str = include_str!("../schemas/records.json");
const OCCURRENCE: &str = include_str!("../fixtures/contracts/occurrence.json");
const POLICY: &str = include_str!("../fixtures/contracts/policy.json");
const MANIFEST_HEADER: &str = include_str!("../fixtures/contracts/manifest_header.json");
const MANIFEST_ENTRY: &str = include_str!("../fixtures/contracts/manifest_entry.json");
const PUBLICATION: &str = include_str!("../fixtures/contracts/publication.json");
const RECEIPT: &str = include_str!("../fixtures/contracts/receipt.json");
const CHECKPOINT: &str = include_str!("../fixtures/contracts/checkpoint.json");
const PLAN_HEADER: &str = include_str!("../fixtures/contracts/plan_header.json");
const PLAN_ENTRY: &str = include_str!("../fixtures/contracts/plan_entry.json");

fn parse_json(input: &str) -> Value {
    serde_json::from_str(input).expect("valid JSON fixture")
}

fn create_registry() -> Registry<'static> {
    let mut registry = Registry::new();

    for input in [JOB, REQUEST, RESPONSE, RECORDS] {
        let schema = parse_json(input);
        let id = schema["$id"].as_str().expect("schema ID").to_owned();
        registry = registry.add(id, schema).expect("register schema");
    }

    registry.prepare().expect("prepare offline registry")
}

fn validate(reference: &str, instance: &Value) -> bool {
    let registry = create_registry();
    let reference_schema = json!({"$ref": reference});
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_registry(&registry)
        .build(&reference_schema)
        .expect("compile schema");
    validator.is_valid(instance)
}

fn calculate_digest(domain: &str, values: &[Value], is_framed: bool) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);

    for value in values {
        let bytes = serde_jcs::to_vec(value).expect("JCS encoding");

        if is_framed {
            let length = u32::try_from(bytes.len()).expect("frame length");
            assert!(length <= 1_048_576);
            hasher.update(length.to_be_bytes());
        }

        hasher.update(bytes);
    }

    format!(
        "sha256:{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn has_matching_binding(record: &Value) -> bool {
    let fields = [
        "capture_id",
        "commit_key",
        "consistency",
        "destination_config_revision",
        "manifest_digest",
        "policy_digest",
        "source_view_id",
    ];
    let mut binding = serde_json::Map::new();

    for field in fields {
        let Some(value) = record.get(field) else {
            return false;
        };
        binding.insert(field.to_owned(), value.clone());
    }

    record["payload_hash"]
        == calculate_digest(
            "relic/publication/payload/v1",
            &[Value::Object(binding)],
            false,
        )
}

fn has_valid_offset(record: &Value) -> bool {
    let Some(offset) = record["offset_bytes"].as_str() else {
        return false;
    };
    !offset.is_empty()
        && (offset == "0" || !offset.starts_with('0'))
        && offset.bytes().all(|byte| byte.is_ascii_digit())
        && offset.parse::<u64>().is_ok()
}

#[test]
fn schemas_are_valid_draft_2020_12_resources() {
    for input in [JOB, REQUEST, RESPONSE, RECORDS] {
        let schema = parse_json(input);
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(jsonschema::meta::is_valid(&schema));
        assert!(!validate(schema["$id"].as_str().unwrap(), &json!(null)));
    }
}

#[test]
fn extracted_contracts_match_the_authoritative_specification() {
    let specification = include_str!("../SPEC.md");
    let schema_section = specification
        .split("### 16.7. Executable Schemas")
        .nth(1)
        .unwrap()
        .split("## 17.")
        .next()
        .unwrap();
    let schemas: Vec<Value> = schema_section
        .split("```json\n")
        .skip(1)
        .map(|block| parse_json(block.split("\n```").next().unwrap()))
        .collect();
    let artifacts: Vec<Value> = [JOB, REQUEST, RESPONSE, RECORDS]
        .into_iter()
        .map(parse_json)
        .collect();
    assert_eq!(schemas, artifacts);
    let vector_section = specification
        .split("### 20.9. Executable Contract Vectors")
        .nth(1)
        .unwrap()
        .split("## 21.")
        .next()
        .unwrap();
    let vectors: Vec<Value> = vector_section
        .split("```json\n")
        .skip(1)
        .map(|block| parse_json(block.split("\n```").next().unwrap()))
        .collect();
    let expected = [
        include_str!("../fixtures/contracts/occurrence.json"),
        include_str!("../fixtures/contracts/policy.json"),
        include_str!("../fixtures/contracts/manifest_header.json"),
        include_str!("../fixtures/contracts/manifest_entry.json"),
        include_str!("../fixtures/contracts/publication.json"),
        include_str!("../fixtures/contracts/receipt.json"),
        include_str!("../fixtures/contracts/checkpoint.json"),
        include_str!("../fixtures/contracts/plan_header.json"),
        include_str!("../fixtures/contracts/plan_entry.json"),
    ]
    .into_iter()
    .map(parse_json)
    .collect::<Vec<_>>();
    assert_eq!(vectors, expected);
}

#[test]
fn authoring_example_and_rejections() {
    let specification = include_str!("../SPEC.md");
    let example = specification
        .split("### 22.2. Complete Authoring Example")
        .nth(1)
        .unwrap()
        .split("```toml\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    let job: toml::Value = toml::from_str(example).expect("parse TOML job");
    let job = serde_json::to_value(job).expect("convert TOML data model");
    let reference = "urn:relic:schema:job:1";
    assert!(validate(reference, &job));
    assert!(relic::contracts::validate_job(&job).is_ok());
    let mut request = json!({
        "jsonrpc": "2.0",
        "id": "request_1",
        "method": "validate_job",
        "params": {"correlation_id": "correlation_1", "job": job.clone()}
    });
    assert!(relic::contracts::validate_request(&request).is_ok());
    request["params"]["job"]["schema_version"] = json!(2);
    assert!(relic::contracts::validate_request(&request).is_err());

    for (field, value) in [
        ("unknown", json!(true)),
        ("schema_version", json!(2)),
        ("revision", json!(2147483648_u64)),
    ] {
        let mut invalid = job.clone();
        invalid[field] = value;
        assert!(!validate(reference, &invalid), "accepted {field}");
        assert!(relic::contracts::validate_job(&invalid).is_err());
    }
}

#[test]
fn golden_digest_vectors() {
    for (domain, fixture, expected) in [
        (
            "relic/occurrence/calendar/v1",
            OCCURRENCE,
            "sha256:5337a0333ec206790cf847d8f0a94f5e29b758698a0d68facf67c7be0e3b7152",
        ),
        (
            "relic/effective-policy/v1",
            POLICY,
            "sha256:c4d15f4d5922d1613a23bfaf394058aa68cf535de5b9fa8ba1d0c3e1b5f84276",
        ),
        (
            "relic/publication/payload/v1",
            PUBLICATION,
            "sha256:d32a885dd16f77c7a58dcc4427355748bbf90243b98d5cb765f70c2d605d36c3",
        ),
    ] {
        assert_eq!(
            calculate_digest(domain, &[parse_json(fixture)], false),
            expected
        );
    }

    for (domain, header, entry, expected) in [
        (
            "relic/logical-manifest/v1",
            MANIFEST_HEADER,
            MANIFEST_ENTRY,
            "sha256:e77e8179915ad471fadc683b82f6a8a016c9e11319b14688e10cf37cb45a6d85",
        ),
        (
            "relic/plan/v1",
            PLAN_HEADER,
            PLAN_ENTRY,
            "sha256:2e328b23bdb56554f62ba6deb4b2144be89fc4a756c982c713e8879664d2069a",
        ),
    ] {
        let values = [parse_json(header), parse_json(entry)];
        assert_eq!(calculate_digest(domain, &values, true), expected);
        let mut changed = values.clone();
        changed[1]["kind"] = json!("changed");
        assert_ne!(calculate_digest(domain, &changed, true), expected);
    }
}

#[test]
fn receipt_checkpoint_and_manifest_bindings() {
    let receipt = parse_json(RECEIPT);
    let checkpoint = parse_json(CHECKPOINT);
    let records = "urn:relic:schema:record:1";
    assert!(validate(&format!("{records}#/$defs/receipt"), &receipt));
    assert!(validate(
        &format!("{records}#/$defs/checkpoint"),
        &checkpoint
    ));
    assert!(validate(
        &format!("{records}#/$defs/manifest_header"),
        &parse_json(MANIFEST_HEADER)
    ));
    assert!(validate(
        &format!("{records}#/$defs/manifest_entry"),
        &parse_json(MANIFEST_ENTRY)
    ));
    assert!(relic::contracts::validate_record(&receipt).is_ok());
    assert!(relic::contracts::validate_record(&checkpoint).is_ok());
    assert!(has_matching_binding(&receipt));
    assert!(has_matching_binding(&checkpoint));
    assert!(has_valid_offset(&checkpoint));
    let mut changed_key = checkpoint.clone();
    changed_key["commit_key"]["destination_id"] = json!("other_destination");
    assert!(relic::contracts::validate_record(&changed_key).is_err());
    assert!(!validate(&format!("{records}#/$defs/checkpoint"), &receipt));

    for field in [
        "source_view_id",
        "capture_id",
        "manifest_digest",
        "policy_digest",
    ] {
        let mut changed = checkpoint.clone();
        changed[field] = json!("changed");
        assert!(!has_matching_binding(&changed), "accepted changed {field}");
        assert!(relic::contracts::validate_record(&changed).is_err());
    }

    for offset in ["18446744073709551616", "01", "-1", ""] {
        let mut changed = checkpoint.clone();
        changed["offset_bytes"] = json!(offset);
        assert!(!has_valid_offset(&changed), "accepted offset {offset}");
        assert!(relic::contracts::validate_record(&changed).is_err());
    }

    let mut changed_plan = [parse_json(PLAN_HEADER), parse_json(PLAN_ENTRY)];
    let original_plan = calculate_digest("relic/plan/v1", &changed_plan, true);
    changed_plan[1]["action"] = json!("restore");
    assert_ne!(
        calculate_digest("relic/plan/v1", &changed_plan, true),
        original_plan
    );
    changed_plan[1] = parse_json(PLAN_ENTRY);
    changed_plan[1]["expected_generation"] = json!("generation_2");
    assert_ne!(
        calculate_digest("relic/plan/v1", &changed_plan, true),
        original_plan
    );

    let mut invalid = receipt.clone();
    invalid["committed_at"] = json!("2026-99-99T00:00:00Z");
    assert!(!validate(&format!("{records}#/$defs/receipt"), &invalid));
    invalid = receipt;
    invalid["record_version"] = json!(2);
    assert!(!validate(&format!("{records}#/$defs/receipt"), &invalid));
}
