#![cfg(unix)]

use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortError, SortLimits};
use relic::manifest::ManifestEntry;
use relic::resources::{ResourceError, StageGuard};
use zeroize::Zeroizing;

fn limits() -> SortLimits {
    SortLimits {
        max_entries: 4,
        max_frame_bytes: 256 * 1024,
        max_chunk_bytes: 512 * 1024,
        max_chunk_entries: 1,
        max_runs: 4,
        max_fan_in: 4,
        max_cipher_bytes: 4 * 1024 * 1024,
        max_memory_bytes: 8 * 1024 * 1024,
    }
}

fn entry() -> ManifestEntry {
    serde_json::from_str(include_str!("../fixtures/contracts/manifest_entry.json")).unwrap()
}

#[test]
fn sorts_encrypted_runs_and_removes_owned_files() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut sorter = EncryptedManifestSort::create(
        directory.path(),
        &Zeroizing::new([7; 32]),
        limits(),
        &StageGuard::default(),
    )
    .unwrap();
    for value in ["_w", "YWE", "YQ"] {
        let mut item = entry();
        item.path = vec![value.into()];
        sorter.add_entry(&item).unwrap();
    }
    let mut seen = Vec::new();
    sorter
        .visit_sorted("capture_1", |item| {
            seen.push(item.path[0].clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, vec!["YQ", "YWE", "_w"]);
    for file in std::fs::read_dir(directory.path()).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows("documents".len())
                .any(|window| window == b"documents")
        );
    }
    drop(sorter);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn rejects_limits_duplicates_and_cancellation() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = Zeroizing::new([7; 32]);
    let guard = StageGuard::default();
    let mut sorter =
        EncryptedManifestSort::create(directory.path(), &key, limits(), &guard).unwrap();
    sorter.add_entry(&entry()).unwrap();
    sorter.add_entry(&entry()).unwrap();
    assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
    guard.cancellation.cancel();
    assert!(matches!(
        sorter.add_entry(&entry()),
        Err(SortError::RESOURCE(ResourceError::CANCELED))
    ));
    assert!(matches!(
        EncryptedManifestSort::create(
            directory.path(),
            &key,
            SortLimits {
                max_fan_in: 5,
                ..limits()
            },
            &StageGuard::default()
        ),
        Err(SortError::INVALID)
    ));
}
