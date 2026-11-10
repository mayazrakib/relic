#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;

use relic::manifest_spool::{ManifestSpool, SpoolLimits};
use relic::resources::StageGuard;
use relic::source_scan::{ScanError, ScanLimits, scan_source};

fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();

    directory
}

fn make_spool(directory: &std::path::Path) -> ManifestSpool {
    ManifestSpool::create(
        &directory.join("spool.sqlite"),
        SpoolLimits {
            max_entries: 100,
            max_frame_bytes: 1_048_576,
            max_spool_bytes: 4 * 1024 * 1024,
        },
    )
    .unwrap()
}

fn get_limits() -> ScanLimits {
    ScanLimits {
        max_depth: 8,
        max_open_files: 10,
        max_entries: 100,
        max_file_bytes: 1024 * 1024,
        max_total_bytes: 2 * 1024 * 1024,
    }
}

#[test]
fn scans_unsorted_non_utf8_names_and_hashes_file_bytes() {
    let directory = private_directory();
    let root = directory.path().join("source");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("dir")).unwrap();
    fs::write(root.join("dir").join("child"), b"abc").unwrap();
    fs::write(root.join(std::ffi::OsString::from_vec(vec![0xff])), b"").unwrap();
    let spool = scan_source(
        &root,
        "source_1",
        make_spool(directory.path()),
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    assert_eq!(spool.get_entry_count(), 4);
    assert!(spool.finish("capture_1").is_ok());
    let mut files = Vec::new();
    spool
        .visit_sorted(|entry| {
            if entry.kind == "file" {
                files.push((entry.path.clone(), entry.content_digest.clone()));
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        files[0].1.as_deref(),
        Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(files[1].0, vec!["_w"]);
}

#[test]
fn rejects_symlinks_limits_and_cancellation_without_returning_spool() {
    for scenario in ["link", "depth", "entries", "bytes", "cancel"] {
        let directory = private_directory();
        let root = directory.path().join("source");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("child")).unwrap();
        fs::write(root.join("child").join("file"), b"abc").unwrap();
        let mut limits = get_limits();
        let guard = StageGuard::default();
        match scenario {
            "link" => symlink("child", root.join("link")).unwrap(),
            "depth" => limits.max_depth = 0,
            "entries" => limits.max_entries = 1,
            "bytes" => limits.max_file_bytes = 2,
            "cancel" => guard.cancellation.cancel(),
            _ => unreachable!(),
        }
        let result = scan_source(
            &root,
            "source_1",
            make_spool(directory.path()),
            limits,
            &guard,
        );
        assert!(result.is_err(), "accepted {scenario}");
        if scenario == "link" {
            assert!(matches!(result, Err(ScanError::UNSUPPORTED_ENTRY)));
        }
    }
}
