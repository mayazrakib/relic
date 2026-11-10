use relic::manifest::ManifestEntry;
use relic::manifest_spool::{ManifestSpool, SpoolError, SpoolLimits};

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    directory
}

fn entry() -> ManifestEntry {
    serde_json::from_str(include_str!("../fixtures/contracts/manifest_entry.json")).unwrap()
}

fn limits() -> SpoolLimits {
    SpoolLimits {
        max_entries: 10,
        max_frame_bytes: 1024 * 1024,
        max_spool_bytes: 1024 * 1024,
    }
}

#[test]
fn orders_entries_and_matches_golden_digest() {
    let directory = private_directory();
    let mut spool =
        ManifestSpool::create(&directory.path().join("manifest.sqlite"), limits()).unwrap();
    spool.add_entry(&entry()).unwrap();
    assert_eq!(
        spool.finish("capture_1").unwrap(),
        "sha256:e77e8179915ad471fadc683b82f6a8a016c9e11319b14688e10cf37cb45a6d85"
    );
    assert!(matches!(
        spool.add_entry(&entry()),
        Err(SpoolError::DUPLICATE)
    ));
}

#[test]
fn sorts_decoded_bytes_and_enforces_limits() {
    let directory = private_directory();
    let mut spool = ManifestSpool::create(
        &directory.path().join("manifest.sqlite"),
        SpoolLimits {
            max_entries: 2,
            ..limits()
        },
    )
    .unwrap();
    let mut first = entry();
    first.path = vec!["_w".into()];
    let mut second = entry();
    second.path = vec!["AAE".into()];
    second.path_encoding = "windows_utf16le".into();
    second.source_id = "other".into();
    spool.add_entry(&first).unwrap();
    spool.add_entry(&second).unwrap();
    assert!(matches!(
        spool.add_entry(&entry()),
        Err(SpoolError::ENTRY_LIMIT)
    ));
    let mut seen = Vec::new();
    spool
        .visit_sorted(|value| {
            seen.push(value.source_id.clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, vec!["documents", "other"]);
    spool.finish("capture_1").unwrap();
}

#[test]
fn rejects_invalid_bounds_and_existing_files() {
    let directory = private_directory();
    let path = directory.path().join("manifest.sqlite");
    assert!(matches!(
        ManifestSpool::create(
            &path,
            SpoolLimits {
                max_spool_bytes: 1,
                ..limits()
            }
        ),
        Err(SpoolError::INVALID_LIMITS)
    ));
    let _spool = ManifestSpool::create(&path, limits()).unwrap();
    assert!(ManifestSpool::create(&path, limits()).is_err());
}

#[test]
fn orders_same_source_by_decoded_components_and_prefix() {
    let directory = private_directory();
    let mut spool =
        ManifestSpool::create(&directory.path().join("manifest.sqlite"), limits()).unwrap();
    for path in [vec!["_w"], vec!["YWE"], vec!["YQ", "Yg"], vec!["YQ"]] {
        let mut item = entry();
        item.path = path.into_iter().map(str::to_owned).collect();
        spool.add_entry(&item).unwrap();
    }
    let mut paths = Vec::new();
    spool
        .visit_sorted(|item| {
            paths.push(item.path.clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(
        paths,
        vec![vec!["YQ"], vec!["YQ", "Yg"], vec!["YWE"], vec!["_w"]]
    );
    spool.finish("capture_1").unwrap();
}

#[test]
fn disk_exhaustion_poisoning_prevents_finalization() {
    let directory = private_directory();
    let mut spool = ManifestSpool::create(
        &directory.path().join("manifest.sqlite"),
        SpoolLimits {
            max_spool_bytes: 8192,
            ..limits()
        },
    )
    .unwrap();
    let mut item = entry();
    item.metadata = serde_json::from_value(serde_json::json!([{
        "namespace": "test",
        "name": "large",
        "value_base64url": "A".repeat(16000)
    }]))
    .unwrap();
    match spool.add_entry(&item) {
        Err(SpoolError::DATABASE(rusqlite::Error::SqliteFailure(error, _))) => {
            assert_eq!(error.code, rusqlite::ErrorCode::DiskFull)
        }
        result => panic!("expected SQLITE_FULL, received {result:?}"),
    }
    assert!(matches!(
        spool.finish("capture_1"),
        Err(SpoolError::POISONED)
    ));
    assert!(matches!(
        spool.add_entry(&entry()),
        Err(SpoolError::POISONED)
    ));
}

#[cfg(unix)]
#[test]
fn accepts_private_parent_alias_and_rejects_shared_parent() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = private_directory();
    let private = directory.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    symlink(&private, &alias).unwrap();
    let spool = ManifestSpool::create(&alias.join("manifest.sqlite"), limits()).unwrap();
    assert_eq!(spool.get_entry_count(), 0);
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ManifestSpool::create(&alias.join("second.sqlite"), limits()),
        Err(SpoolError::INSECURE_DIRECTORY)
    ));
}
