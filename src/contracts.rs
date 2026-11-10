use std::error::Error;
use std::fmt;
use std::sync::OnceLock;

use jsonschema::{Draft, Registry, Validator};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const JOB_SCHEMA: &str = include_str!("../schemas/job.json");
pub const REQUEST_SCHEMA: &str = include_str!("../schemas/request.json");
pub const RESPONSE_SCHEMA: &str = include_str!("../schemas/response.json");
pub const RECORD_SCHEMA: &str = include_str!("../schemas/records.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    message: String,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ContractError {}

struct ContractValidators {
    job: Validator,
    request: Validator,
    response: Validator,
    record: Validator,
}

fn create_validators() -> Result<ContractValidators, ContractError> {
    let mut registry = Registry::new();

    for text in [JOB_SCHEMA, REQUEST_SCHEMA, RESPONSE_SCHEMA, RECORD_SCHEMA] {
        let schema: Value = serde_json::from_str(text).map_err(|error| ContractError {
            message: format!("Invalid embedded schema: {error}"),
        })?;
        let id = schema["$id"]
            .as_str()
            .ok_or_else(|| ContractError {
                message: "Embedded schema has no ID".to_owned(),
            })?
            .to_owned();
        registry = registry.add(id, schema).map_err(|error| ContractError {
            message: format!("Could not register embedded schema: {error}"),
        })?;
    }

    let registry = registry.prepare().map_err(|error| ContractError {
        message: format!("Could not prepare embedded schemas: {error}"),
    })?;
    let compile = |reference: &str| {
        jsonschema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .with_registry(&registry)
            .build(&json!({"$ref": reference}))
            .map_err(|error| ContractError {
                message: format!("Could not compile embedded schema: {error}"),
            })
    };

    Ok(ContractValidators {
        job: compile("urn:relic:schema:job:1")?,
        request: compile("urn:relic:schema:core-request:1")?,
        response: compile("urn:relic:schema:core-response:1")?,
        record: compile("urn:relic:schema:record:1")?,
    })
}

fn get_validators() -> Result<&'static ContractValidators, ContractError> {
    static VALIDATORS: OnceLock<Result<ContractValidators, ContractError>> = OnceLock::new();
    VALIDATORS
        .get_or_init(create_validators)
        .as_ref()
        .map_err(Clone::clone)
}

fn validate_with(validator: &Validator, document: &Value) -> Result<(), ContractError> {
    validator.validate(document).map_err(|error| ContractError {
        message: error.to_string(),
    })
}

pub fn validate_job(document: &Value) -> Result<(), ContractError> {
    validate_with(&get_validators()?.job, document)
}

pub fn validate_request(document: &Value) -> Result<(), ContractError> {
    validate_with(&get_validators()?.request, document)
}

pub fn validate_response(document: &Value) -> Result<(), ContractError> {
    validate_with(&get_validators()?.response, document)
}

pub fn validate_record(document: &Value) -> Result<(), ContractError> {
    validate_with(&get_validators()?.record, document)?;
    let mut binding = serde_json::Map::new();

    for field in [
        "capture_id",
        "commit_key",
        "consistency",
        "destination_config_revision",
        "manifest_digest",
        "policy_digest",
        "source_view_id",
    ] {
        let value = document.get(field).ok_or_else(|| ContractError {
            message: format!("Missing publication binding field: {field}"),
        })?;
        binding.insert(field.to_owned(), value.clone());
    }

    let bytes = serde_jcs::to_vec(&Value::Object(binding)).map_err(|error| ContractError {
        message: format!("Could not canonicalize publication binding: {error}"),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"relic/publication/payload/v1\0");
    hasher.update(bytes);
    let digest = format!(
        "sha256:{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    if document["payload_hash"] != digest {
        return Err(ContractError {
            message: "Publication binding does not match payload hash".to_owned(),
        });
    }

    if let Some(offset) = document.get("offset_bytes") {
        let offset = offset.as_str().unwrap_or("");
        let is_valid = !offset.is_empty()
            && (offset == "0" || !offset.starts_with('0'))
            && offset.bytes().all(|byte| byte.is_ascii_digit())
            && offset.parse::<u64>().is_ok();

        if !is_valid {
            return Err(ContractError {
                message: "Invalid checkpoint offset".to_owned(),
            });
        }
    }

    Ok(())
}
