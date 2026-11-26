#![cfg(unix)]

use relic::encrypted_manifest_sort::{EncryptedManifestSort, SortError, SortLimits};
use relic::manifest::ManifestEntry;
use relic::resources::StageGuard;
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
        Err(SortError::RESOURCE(
            relic::resources::ResourceError::CANCELED
        ))
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

fn get_large_limits() -> SortLimits {
    SortLimits {
        max_entries: 1_100,
        max_runs: 64,
        max_fan_in: 4,
        max_cipher_bytes: 8 * 1024 * 1024,
        ..limits()
    }
}

fn get_numbered_entry(number: usize) -> ManifestEntry {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut item = entry();
    let bytes = [
        0x80 + (number / 128) as u8,
        b'a' + ((number / 26) % 26) as u8,
        b'a' + (number % 26) as u8,
    ];
    item.path = vec![URL_SAFE_NO_PAD.encode(bytes)];
    item
}

fn get_private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn get_files(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

fn verify_storage_bounds(directory: &std::path::Path, limits: SortLimits) {
    let paths = get_files(directory);
    assert!(paths.len() <= limits.max_runs + 1);
    let total: u64 = paths
        .iter()
        .map(|path| std::fs::metadata(path).unwrap().len())
        .sum();
    assert!(total <= limits.max_cipher_bytes);
    for path in paths {
        let data = std::fs::read(path).unwrap();
        assert!(
            !data
                .windows(b"documents".len())
                .any(|bytes| bytes == b"documents")
        );
    }
}

#[test]
fn sorts_hundreds_of_entries_through_bounded_compactions() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use relic::manifest::{ManifestHeader, ManifestValidator};

    let directory = get_private_directory();
    let limits = get_large_limits();
    let key = Zeroizing::new([7; 32]);
    let guard = StageGuard::default();
    let mut sorter = EncryptedManifestSort::create(directory.path(), &key, limits, &guard).unwrap();
    let mut entries = Vec::new();

    for number in (0..257).rev() {
        let item = get_numbered_entry(number);
        sorter.add_entry(&item).unwrap();
        entries.push(item);
        verify_storage_bounds(directory.path(), limits);
    }

    entries.sort_by_key(|item| URL_SAFE_NO_PAD.decode(&item.path[0]).unwrap());
    let mut validator = ManifestValidator::new(&ManifestHeader {
        schema_version: 1,
        capture_id: "capture_1".into(),
        entry_count: entries.len().to_string(),
    })
    .unwrap();
    for item in &entries {
        validator.add_entry(item).unwrap();
    }
    let expected = validator.finish().unwrap();
    let mut actual = Vec::new();
    let digest = sorter
        .visit_sorted("capture_1", |item| {
            actual.push(item.path[0].clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(
        actual,
        entries
            .iter()
            .map(|item| item.path[0].clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(digest, expected);
    assert_eq!(
        sorter.visit_sorted("capture_1", |_| Ok(())).unwrap(),
        expected
    );
    verify_storage_bounds(directory.path(), limits);
    let usage = sorter.get_usage();
    assert_eq!(usage.entry_count, 257);
    assert!(usage.run_count <= limits.max_fan_in);
    assert!(usage.run_ids_allocated > 257);
    assert!(usage.merges_completed > 0);
    assert!(usage.peak_reserved_ciphertext_bytes <= limits.max_cipher_bytes);
    let initial_cipher_bytes =
        257 * (serde_jcs::to_vec(&get_numbered_entry(0)).unwrap().len() as u64 + 4 + 80);
    assert!(usage.total_reserved_ciphertext_bytes <= initial_cipher_bytes * 8);
    drop(sorter);
    assert!(get_files(directory.path()).is_empty());
}

#[test]
fn rejects_cross_tier_duplicates_and_poisoned_callbacks() {
    for mode in ["duplicate", "callback"] {
        let directory = get_private_directory();
        let mut sorter = EncryptedManifestSort::create(
            directory.path(),
            &Zeroizing::new([7; 32]),
            get_large_limits(),
            &StageGuard::default(),
        )
        .unwrap();
        for number in 0..40 {
            sorter.add_entry(&get_numbered_entry(number)).unwrap();
        }
        if mode == "duplicate" {
            let result = sorter.add_entry(&get_numbered_entry(0));
            if result.is_ok() {
                assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
            }
        } else {
            assert!(
                sorter
                    .visit_sorted("capture_1", |_| Err(SortError::INVALID))
                    .is_err()
            );
        }
        assert!(sorter.add_entry(&get_numbered_entry(100)).is_err());
        assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
    }
}

#[test]
fn corruption_and_truncation_poison_provisional_output() {
    for fault in ["corrupt", "truncate", "final_tag"] {
        let directory = get_private_directory();
        let mut sorter = EncryptedManifestSort::create(
            directory.path(),
            &Zeroizing::new([7; 32]),
            get_large_limits(),
            &StageGuard::default(),
        )
        .unwrap();
        for number in 0..40 {
            sorter.add_entry(&get_numbered_entry(number)).unwrap();
        }
        let file = get_files(directory.path()).into_iter().next().unwrap();
        let mut bytes = std::fs::read(&file).unwrap();
        if fault == "truncate" {
            bytes.truncate(bytes.len() / 2);
        } else {
            let index = if fault == "final_tag" {
                bytes.len() - 1
            } else {
                bytes.len() / 2
            };
            bytes[index] ^= 0x80;
        }
        std::fs::write(&file, bytes).unwrap();
        assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
        assert!(sorter.add_entry(&get_numbered_entry(100)).is_err());
        assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
    }
}

#[test]
fn merge_quota_and_failed_append_cannot_seal_a_prefix() {
    let directory = get_private_directory();
    let limits = SortLimits {
        max_cipher_bytes: 2000,
        ..get_large_limits()
    };
    let mut sorter = EncryptedManifestSort::create(
        directory.path(),
        &Zeroizing::new([7; 32]),
        limits,
        &StageGuard::default(),
    )
    .unwrap();
    let mut failed = false;
    let mut peak_files = 0;
    for number in 0..40 {
        if sorter.add_entry(&get_numbered_entry(number)).is_err() {
            failed = true;
            break;
        }
        verify_storage_bounds(directory.path(), limits);
        peak_files = peak_files.max(get_files(directory.path()).len());
    }
    assert!(failed);
    assert!(peak_files >= 3);
    assert!(sorter.add_entry(&get_numbered_entry(100)).is_err());
    assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
    verify_storage_bounds(directory.path(), limits);
}

#[test]
fn preserves_replaced_and_unrelated_files_on_cleanup() {
    let directory = get_private_directory();
    let unrelated = directory.path().join("unrelated");
    std::fs::write(&unrelated, b"unrelated").unwrap();
    let mut sorter = EncryptedManifestSort::create(
        directory.path(),
        &Zeroizing::new([7; 32]),
        get_large_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    for number in 0..3 {
        sorter.add_entry(&get_numbered_entry(number)).unwrap();
    }
    let run = get_files(directory.path())
        .into_iter()
        .find(|path| path != &unrelated)
        .unwrap();
    let moved = directory.path().join("moved_original");
    std::fs::rename(&run, &moved).unwrap();
    std::fs::write(&run, b"replacement").unwrap();
    drop(sorter);
    assert_eq!(std::fs::read(&run).unwrap(), b"replacement");
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated");
    assert!(moved.exists());
}

#[test]
fn redacts_sensitive_io_details_from_display() {
    let error = SortError::IO(std::io::Error::other("confidential/source-name"));
    let message = error.to_string();
    assert!(!message.contains("confidential"));
    assert!(message.contains("I/O failed"));
}

#[test]
fn rejects_invalid_bounds_and_cancellation_poisoning() {
    let directory = get_private_directory();
    let key = Zeroizing::new([7; 32]);
    for limits in [
        SortLimits {
            max_fan_in: 1,
            ..get_large_limits()
        },
        SortLimits {
            max_runs: 3,
            max_fan_in: 4,
            ..get_large_limits()
        },
        SortLimits {
            max_runs: 129,
            ..get_large_limits()
        },
    ] {
        assert!(
            EncryptedManifestSort::create(directory.path(), &key, limits, &StageGuard::default())
                .is_err()
        );
    }
    let guard = StageGuard::default();
    let mut sorter =
        EncryptedManifestSort::create(directory.path(), &key, get_large_limits(), &guard).unwrap();
    sorter.add_entry(&get_numbered_entry(0)).unwrap();
    guard.cancellation.cancel();
    assert!(sorter.add_entry(&get_numbered_entry(1)).is_err());
    assert!(sorter.visit_sorted("capture_1", |_| Ok(())).is_err());
}
