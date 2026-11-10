use relic::manifest::{ManifestEntry, ManifestHeader, ManifestValidator, verify_file_content};
use serde_json::json;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn header(count: &str) -> ManifestHeader {
    ManifestHeader {
        schema_version: 1,
        capture_id: "capture_1".into(),
        entry_count: count.into(),
    }
}

fn entry() -> ManifestEntry {
    serde_json::from_str(include_str!("../fixtures/contracts/manifest_entry.json")).unwrap()
}

#[test]
fn checks_golden_digest_and_content() {
    let mut validator = ManifestValidator::new(&header("1")).unwrap();
    let entry = entry();
    validator.add_entry(&entry).unwrap();
    assert_eq!(
        validator.finish().unwrap(),
        "sha256:e77e8179915ad471fadc683b82f6a8a016c9e11319b14688e10cf37cb45a6d85"
    );
    verify_file_content(&entry, &mut &b""[..]).unwrap();
    assert!(verify_file_content(&entry, &mut &b"changed"[..]).is_err());
}

#[test]
fn rejects_unsafe_duplicate_unsorted_and_invalid_records() {
    let mut invalid = entry();
    invalid.path = vec!["Li4".into()];
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .add_entry(&invalid)
            .is_err()
    );
    invalid.path = vec!["YR".into()];
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .add_entry(&invalid)
            .is_err()
    );
    let mut validator = ManifestValidator::new(&header("2")).unwrap();
    validator.add_entry(&entry()).unwrap();
    assert!(validator.add_entry(&entry()).is_err());
    assert!(ManifestValidator::new(&header("01")).is_err());
    let mut malformed = serde_json::to_value(entry()).unwrap();
    malformed["unknown"] = json!(1);
    assert!(serde_json::from_value::<ManifestEntry>(malformed).is_err());
}

#[test]
fn rejects_unsorted_metadata_and_count_mismatch() {
    let mut invalid = entry();
    invalid.metadata = serde_json::from_value(json!([
        {"namespace":"z", "name":"key", "value_base64url":""},
        {"namespace":"a", "name":"key", "value_base64url":""}
    ]))
    .unwrap();
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .add_entry(&invalid)
            .is_err()
    );
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .finish()
            .is_err()
    );
}

#[test]
fn orders_decoded_native_components_and_rejects_mixed_encodings() {
    let mut first = entry();
    first.path = vec![URL_SAFE_NO_PAD.encode([0xff])];
    let mut second = first.clone();
    second.path = vec![URL_SAFE_NO_PAD.encode([0x01])];
    let mut validator = ManifestValidator::new(&header("2")).unwrap();
    validator.add_entry(&second).unwrap();
    validator.add_entry(&first).unwrap();
    validator.finish().unwrap();

    let mut root = entry();
    root.path.clear();
    let mut windows = root.clone();
    windows.path_encoding = "windows_utf16le".into();
    windows.path = vec![URL_SAFE_NO_PAD.encode([b'a', 0])];
    let mut validator = ManifestValidator::new(&header("2")).unwrap();
    validator.add_entry(&root).unwrap();
    assert!(validator.add_entry(&windows).is_err());
}

#[test]
fn rejects_unsafe_windows_names_and_oversized_frames() {
    for bytes in [
        vec![0],
        vec![0, 0],
        vec![46, 0],
        vec![46, 0, 46, 0],
        vec![92, 0],
        vec![47, 0],
    ] {
        let mut value = entry();
        value.path_encoding = "windows_utf16le".into();
        value.path = vec![URL_SAFE_NO_PAD.encode(bytes)];
        assert!(
            ManifestValidator::new(&header("1"))
                .unwrap()
                .add_entry(&value)
                .is_err()
        );
    }

    let mut oversized = entry();
    oversized.path = vec!["a".repeat(131_072); 9];
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .add_entry(&oversized)
            .is_err()
    );
    let mut explicit_null = serde_json::to_value(entry()).unwrap();
    explicit_null["link_target_base64url"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ManifestEntry>(explicit_null).is_err());
}

#[test]
fn rejects_incompatible_content_fields_and_u64_overflow() {
    let mut value = entry();
    value.kind = "directory".into();
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .add_entry(&value)
            .is_err()
    );
    value.kind = "file".into();
    value.size_bytes = Some("18446744073709551616".into());
    assert!(
        ManifestValidator::new(&header("1"))
            .unwrap()
            .add_entry(&value)
            .is_err()
    );
    assert!(ManifestValidator::new(&header("18446744073709551616")).is_err());
}
