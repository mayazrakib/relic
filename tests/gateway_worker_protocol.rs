#![cfg(all(target_os = "linux", feature = "embedded-archive"))]
use relic::gateway_worker::{GatewayWorkerReport, read_request, write_report};
use serde_json::{Value, json};
use std::io::Cursor;

fn get_request() -> Value {
    json!({"protocol_version":1,"operation":"initialize","state_dir":"/state","target_dir":"/target",
        "target_identity":{"device":1,"inode":2},"owner_identity":{"device":1,"inode":3},"scratch_identity":{"device":1,"inode":4},
        "resource_id":"resource","receiver_epoch":1,"fence_generation":1,"admission_id":null,"execution_ordinal":null,
        "source_repository_dir":null,"source_password":null,"source_key_ref":null,"target_password":"test-only-password","target_key_ref":"target_key",
        "repository_max_bytes":1048576,"memory_max_bytes":33554432,"timeout_seconds":10})
}
fn get_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(bytes);
    frame
}

#[test]
fn request_framing_rejects_trailing_truncated_duplicate_and_unknown_fields() {
    let value = get_request();
    let encoded = serde_json::to_vec(&value).unwrap();
    let mut largest = encoded.clone();
    largest.resize(65536, b' ');
    assert!(read_request(Cursor::new(get_frame(&largest))).is_ok());
    let result = read_request(Cursor::new(get_frame(&encoded))).unwrap();
    assert_eq!(result.resource_id, "resource");
    assert!(result.source_password.is_none());
    let mut trailing = get_frame(&encoded);
    trailing.push(0);
    assert!(read_request(Cursor::new(trailing)).is_err());
    let mut truncated = get_frame(&encoded);
    truncated.pop();
    assert!(read_request(Cursor::new(truncated)).is_err());
    assert!(read_request(Cursor::new((65537u32).to_be_bytes())).is_err());
    assert!(read_request(Cursor::new([0u8; 4])).is_err());
    let mut unknown = value.clone();
    unknown["unexpected"] = json!(true);
    assert!(
        read_request(Cursor::new(get_frame(
            &serde_json::to_vec(&unknown).unwrap()
        )))
        .is_err()
    );
    let duplicate = format!(
        "{{\"protocol_version\":1,{}",
        std::str::from_utf8(&encoded)
            .unwrap()
            .trim_start_matches('{')
    );
    assert!(read_request(Cursor::new(get_frame(duplicate.as_bytes()))).is_err());
}

#[test]
fn reports_are_length_prefixed_and_enforce_the_limit() {
    let mut report = GatewayWorkerReport {
        protocol_version: 1,
        resource_id: "resource".into(),
        admission_id: None,
        execution_ordinal: None,
        receiver_epoch: 1,
        fence_generation: 1,
        repository_id: "a".repeat(64),
        native_snapshot_id: None,
        manifest_digest: None,
        entry_count: 0,
        file_count: 0,
        payload_bytes: 0,
        repository_bytes: 1024,
    };
    let mut bytes = Vec::new();
    write_report(&mut bytes, &report).unwrap();
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(length, bytes.len() - 4);
    let decoded: Value = serde_json::from_slice(&bytes[4..]).unwrap();
    assert_eq!(decoded["repository_id"], "a".repeat(64));
    report.resource_id = "x".repeat(16384);
    assert!(write_report(Vec::new(), &report).is_err());
}
