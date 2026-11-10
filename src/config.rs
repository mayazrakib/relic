use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};

const MAX_DOCUMENT_BYTES: u64 = 1_048_576;
const MAX_DEPTH: usize = 32;

#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

struct JsonSeed(usize);

impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.0 > MAX_DEPTH {
            return Err(D::Error::custom("configuration nesting exceeds 32"));
        }

        deserializer.deserialize_any(JsonVisitor(self.0))
    }
}

struct JsonVisitor(usize);

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();

        while let Some(value) = sequence.next_element_seed(JsonSeed(self.0 + 1))? {
            values.push(value);
        }

        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Value, A::Error> {
        let mut values = Map::new();

        while let Some(key) = mapping.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate key: {key}")));
            }

            values.insert(key, mapping.next_value_seed(JsonSeed(self.0 + 1))?);
        }

        Ok(Value::Object(values))
    }
}

fn check_depth(value: &Value, depth: usize) -> Result<(), ConfigError> {
    if depth > MAX_DEPTH {
        return Err(ConfigError("configuration nesting exceeds 32".to_owned()));
    }

    match value {
        Value::Array(values) => {
            for value in values {
                check_depth(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                check_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }

    Ok(())
}

pub fn load_job(path: &Path) -> Result<Value, ConfigError> {
    let file = File::open(path).map_err(|error| ConfigError(error.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigError(error.to_string()))?;

    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(ConfigError("configuration exceeds 1 MiB".to_owned()));
    }

    let value = if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
        parse_json_bytes(&bytes)?
    } else {
        let text = std::str::from_utf8(&bytes).map_err(|error| ConfigError(error.to_string()))?;
        let document: toml::Value =
            toml::from_str(text).map_err(|error| ConfigError(format!("invalid TOML: {error}")))?;
        let value =
            serde_json::to_value(document).map_err(|error| ConfigError(error.to_string()))?;
        check_depth(&value, 0)?;
        value
    };
    normalize_job(&value)
}

pub fn parse_json_bytes(bytes: &[u8]) -> Result<Value, ConfigError> {
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(ConfigError("JSON exceeds 1 MiB".to_owned()));
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed(0)
        .deserialize(&mut deserializer)
        .map_err(|error| ConfigError(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ConfigError(error.to_string()))?;
    Ok(value)
}

fn insert_default(object: &mut Map<String, Value>, key: &str, value: Value) {
    object.entry(key.to_owned()).or_insert(value);
}

fn expand_object(object: &mut Map<String, Value>, key: &str, defaults: Value) {
    let value = object.entry(key.to_owned()).or_insert_with(|| json!({}));

    if let (Some(target), Some(source)) = (value.as_object_mut(), defaults.as_object()) {
        for (name, default) in source {
            insert_default(target, name, default.clone());
        }
    }
}

pub fn normalize_job(document: &Value) -> Result<Value, ConfigError> {
    check_depth(document, 0)?;
    let mut normalized = document.clone();
    let object = normalized
        .as_object_mut()
        .ok_or_else(|| ConfigError("job must be an object".to_owned()))?;
    insert_default(object, "enabled", json!(false));
    insert_default(object, "method", json!("archive"));
    insert_default(object, "mode", json!("incremental"));
    insert_default(object, "consistency", json!({"policy": "prefer_snapshot"}));
    insert_default(object, "schedule", json!({"kind": "manual"}));
    insert_default(object, "resources", json!({"class": "balanced"}));
    insert_default(object, "overlap", json!("forbid"));
    expand_object(
        object,
        "retention",
        json!({"enabled": false, "protect_last": true}),
    );
    let publication = if object["method"] == "replicate" {
        "data_verified"
    } else {
        "metadata_verified"
    };
    expand_object(
        object,
        "verification",
        json!({"publication": publication, "restore": "data_verified"}),
    );
    expand_object(
        object,
        "retry",
        json!({"initial_seconds": 5, "max_seconds": 900, "max_attempts": 8, "max_age_seconds": 86400}),
    );

    if let Some(sources) = object.get_mut("sources").and_then(Value::as_array_mut) {
        for source in sources {
            if let Some(source) = source.as_object_mut() {
                insert_default(source, "selector", json!("."));
            }
        }
    }

    if let Some(schedule) = object.get_mut("schedule").and_then(Value::as_object_mut)
        && schedule.get("kind") == Some(&json!("calendar"))
    {
        insert_default(schedule, "missed", json!("run_latest"));
        insert_default(schedule, "gap", json!("shift_forward"));
        insert_default(schedule, "fold", json!("first"));
    }

    validate_job(&normalized)?;
    Ok(normalized)
}

fn validate_cron(expression: &str) -> bool {
    let fields: Vec<_> = expression.split_whitespace().collect();

    if fields.len() != 5 {
        return false;
    }

    let bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];
    fields
        .iter()
        .zip(bounds)
        .all(|(field, (minimum, maximum))| {
            field.split(',').all(|part| {
                let mut step_parts = part.split('/');
                let base = step_parts.next().unwrap_or("");
                let step = step_parts.next();

                if step_parts.next().is_some()
                    || step.is_some_and(|value| {
                        value.parse::<u32>().map_or(true, |number| number == 0)
                    })
                {
                    return false;
                }

                if base == "*" {
                    return true;
                }

                let mut range = base.split('-');
                let first = range.next().unwrap_or("").parse::<u32>();
                let last = range.next().map(str::parse::<u32>);

                if range.next().is_some() {
                    return false;
                }

                match (first, last) {
                    (Ok(first), None) => first >= minimum && first <= maximum,
                    (Ok(first), Some(Ok(last))) => {
                        first >= minimum && last <= maximum && first <= last
                    }
                    _ => false,
                }
            })
        })
}

pub fn validate_job(document: &Value) -> Result<(), ConfigError> {
    check_depth(document, 0)?;
    crate::contracts::validate_job(document).map_err(|error| ConfigError(error.to_string()))?;

    for (collection, id) in [("sources", "source_id"), ("destinations", "destination_id")] {
        let mut seen = HashSet::new();

        for item in document[collection].as_array().unwrap() {
            if !seen.insert(item[id].as_str().unwrap()) {
                return Err(ConfigError(format!("duplicate {id}")));
            }
        }
    }

    for field in [
        "memory_bytes",
        "cache_bytes",
        "spool_bytes",
        "network_bytes_per_second",
    ] {
        if let Some(value) = document["resources"].get(field)
            && value
                .as_str()
                .and_then(|number| number.parse::<u64>().ok())
                .is_none()
        {
            return Err(ConfigError(format!(
                "invalid unsigned 64-bit resource {field}"
            )));
        }
    }

    if document["retry"]["initial_seconds"]
        .as_u64()
        .zip(document["retry"]["max_seconds"].as_u64())
        .is_some_and(|(initial, max)| initial > max)
    {
        return Err(ConfigError(
            "retry initial delay exceeds maximum".to_owned(),
        ));
    }

    if document["schedule"]["kind"] == "calendar" {
        if !validate_cron(document["schedule"]["cron"].as_str().unwrap()) {
            return Err(ConfigError("invalid five-field cron expression".to_owned()));
        }
    } else if document["schedule"].get("cron").is_some()
        || document["schedule"].get("timezone").is_some()
    {
        return Err(ConfigError(
            "calendar fields require a calendar schedule".to_owned(),
        ));
    }

    let objectives = &document["recovery_objectives"];
    for destination in document["destinations"].as_array().unwrap() {
        for field in [
            "rpo_seconds",
            "rto_seconds",
            "max_verification_age_seconds",
            "max_replication_lag_seconds",
        ] {
            if let (Some(base), Some(override_value)) = (
                objectives[field].as_u64(),
                destination["recovery_objectives"][field].as_u64(),
            ) && override_value > base
            {
                return Err(ConfigError(format!("destination weakens {field}")));
            }
        }

        let rank = |value: &Value| match value.as_str() {
            Some("committed") => 0,
            Some("data_verified") => 1,
            Some("restore_tested") => 2,
            _ => 0,
        };
        if !objectives.is_null()
            && !destination["recovery_objectives"].is_null()
            && rank(&destination["recovery_objectives"]["protection_level"])
                < rank(&objectives["protection_level"])
            && destination["recovery_objectives"]
                .get("protection_level")
                .is_some()
        {
            return Err(ConfigError(
                "destination weakens protection level".to_owned(),
            ));
        }
    }

    if document["method"] != "replicate" {
        for source in document["sources"].as_array().unwrap() {
            if source.get("snapshot_id").is_some()
                || source.get("snapshot_selector").is_some()
                || source.get("repository_id").is_some()
            {
                return Err(ConfigError(
                    "snapshot selection requires replication".to_owned(),
                ));
            }
        }
    }

    if document["method"] == "replicate" {
        let sources = document["sources"].as_array().unwrap();

        if sources.len() != 1 {
            return Err(ConfigError("replication requires one source".to_owned()));
        }

        let source = &sources[0];
        if source.get("repository_id").is_none()
            || source.get("snapshot_id").is_some() == source.get("snapshot_selector").is_some()
            || source
                .get("selector")
                .is_some_and(|selector| selector != ".")
            || source["exclusions"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        {
            return Err(ConfigError(
                "invalid replication source selection".to_owned(),
            ));
        }

        for destination in document["destinations"].as_array().unwrap() {
            if destination.get("repository_id").is_none()
                || destination["repository_id"] == source["repository_id"]
            {
                return Err(ConfigError(
                    "replication destination repository must differ from source".to_owned(),
                ));
            }
        }

        if document["verification"]
            .get("publication")
            .is_some_and(|level| level != "data_verified")
        {
            return Err(ConfigError(
                "replication requires data verification".to_owned(),
            ));
        }
    }

    Ok(())
}
