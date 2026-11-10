#![cfg(unix)]

use std::cell::Cell;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use relic::restore::{RestoreError, RestoreName, open_restore_directory, restore_file};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn assert_clean(root: &Path) {
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".relic-")
    }));
}

#[test]
fn validates_single_native_components() {
    for bytes in [b"".as_slice(), b".", b"..", b"a/b", b"/x", b"x\0y"] {
        assert!(matches!(
            RestoreName::new(bytes),
            Err(RestoreError::INVALID_NAME)
        ));
    }

    assert!(RestoreName::new(b"\xffname").is_ok());
}

#[test]
fn traverses_and_creates_only_bounded_directories() {
    let temporary = tempfile::tempdir().unwrap();
    let root = File::open(temporary.path()).unwrap();
    let components = [
        RestoreName::new(b"first").unwrap(),
        RestoreName::new(b"second").unwrap(),
    ];
    let nested = open_restore_directory(&root, &components, true, || false).unwrap();
    let name = RestoreName::new(b"file").unwrap();
    restore_file(
        &nested,
        &name,
        &mut Cursor::new(b"nested"),
        6,
        digest(b"nested"),
        6,
        || false,
    )
    .unwrap();
    assert_eq!(
        fs::read(temporary.path().join("first/second/file")).unwrap(),
        b"nested"
    );
    assert_eq!(
        fs::metadata(temporary.path().join("first"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(open_restore_directory(&root, &components, false, || false).is_ok());
    let excessive: Vec<RestoreName> = (0..33).map(|_| RestoreName::new(b"x").unwrap()).collect();
    assert!(matches!(
        open_restore_directory(&root, &excessive, true, || false),
        Err(RestoreError::DEPTH_EXCEEDED)
    ));
    assert!(matches!(
        open_restore_directory(&root, &[], true, || true),
        Err(RestoreError::CANCELLED)
    ));
}

#[test]
fn rejects_symlink_directory_component() {
    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), temporary.path().join("link")).unwrap();
    let root = File::open(temporary.path()).unwrap();
    let components = [
        RestoreName::new(b"link").unwrap(),
        RestoreName::new(b"child").unwrap(),
    ];
    assert!(open_restore_directory(&root, &components, true, || false).is_err());
    assert!(!outside.path().join("child").exists());
}

#[test]
fn verifies_content_and_publishes_without_replacing() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = File::open(temporary.path()).unwrap();
    let name = RestoreName::new(b"item").unwrap();
    let bytes = vec![42; 130_000];
    restore_file(
        &directory,
        &name,
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        digest(&bytes),
        bytes.len() as u64,
        || false,
    )
    .unwrap();
    let target = temporary.path().join("item");
    assert_eq!(fs::read(&target).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let result = restore_file(
        &directory,
        &name,
        &mut Cursor::new(b"changed"),
        7,
        digest(b"changed"),
        7,
        || false,
    );
    assert!(
        matches!(result, Err(RestoreError::IO(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read(&target).unwrap(), bytes);
    assert_clean(temporary.path());
}

#[test]
fn rejects_links_and_parent_traversal() {
    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("original"), b"original").unwrap();
    symlink(
        outside.path().join("original"),
        temporary.path().join("final"),
    )
    .unwrap();
    symlink(outside.path(), temporary.path().join("parent")).unwrap();
    let directory = File::open(temporary.path()).unwrap();
    let final_name = RestoreName::new(b"final").unwrap();
    let result = restore_file(
        &directory,
        &final_name,
        &mut Cursor::new(b"new"),
        3,
        digest(b"new"),
        3,
        || false,
    );
    assert!(
        matches!(result, Err(RestoreError::IO(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert!(RestoreName::new(b"parent/escape").is_err());
    assert_eq!(
        fs::read(outside.path().join("original")).unwrap(),
        b"original"
    );
    assert!(!outside.path().join("escape").exists());
    assert_clean(temporary.path());
}

#[test]
fn pinned_handle_is_not_redirected_by_path_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let original = temporary.path().join("destination");
    let moved = temporary.path().join("moved");
    fs::create_dir(&original).unwrap();
    let directory = File::open(&original).unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(outside.path(), &original).unwrap();
    let name = RestoreName::new(b"item").unwrap();
    restore_file(
        &directory,
        &name,
        &mut Cursor::new(b"data"),
        4,
        digest(b"data"),
        4,
        || false,
    )
    .unwrap();
    assert_eq!(fs::read(moved.join("item")).unwrap(), b"data");
    assert!(!outside.path().join("item").exists());
}

#[test]
fn staging_path_replacement_cannot_redirect_published_content() {
    struct ReplacingReader<'a> {
        parent: &'a Path,
        outside: &'a Path,
        is_replaced: bool,
        bytes: Cursor<&'static [u8]>,
    }

    impl Read for ReplacingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.is_replaced {
                let staging = fs::read_dir(self.parent)?.next().unwrap()?.path();
                assert_eq!(fs::metadata(&staging)?.permissions().mode() & 0o777, 0o700);
                fs::rename(&staging, self.outside.join("moved"))?;
                fs::create_dir(&staging)?;
                fs::write(staging.join("content"), b"attacker")?;
                self.is_replaced = true;
            }

            self.bytes.read(buffer)
        }
    }

    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let directory = File::open(temporary.path()).unwrap();
    let name = RestoreName::new(b"item").unwrap();
    let mut source = ReplacingReader {
        parent: temporary.path(),
        outside: outside.path(),
        is_replaced: false,
        bytes: Cursor::new(b"verified".as_slice()),
    };
    let result = restore_file(
        &directory,
        &name,
        &mut source,
        8,
        digest(b"verified"),
        8,
        || false,
    );
    assert!(matches!(result, Err(RestoreError::OUTCOME_UNKNOWN(_))));
    assert_eq!(
        fs::read(temporary.path().join("item")).unwrap(),
        b"verified"
    );
    let replacement = fs::read_dir(temporary.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    assert_eq!(fs::read(replacement.join("content")).unwrap(), b"attacker");
}

#[test]
fn cleans_up_failed_or_cancelled_staging() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = File::open(temporary.path()).unwrap();
    let name = RestoreName::new(b"item").unwrap();
    let result = restore_file(
        &directory,
        &name,
        &mut Cursor::new(b"abc"),
        3,
        digest(b"wrong"),
        3,
        || false,
    );
    assert!(matches!(result, Err(RestoreError::DIGEST_MISMATCH)));
    let result = restore_file(
        &directory,
        &name,
        &mut Cursor::new(b"abc"),
        4,
        digest(b"abc"),
        4,
        || false,
    );
    assert!(matches!(result, Err(RestoreError::SIZE_MISMATCH)));
    let result = restore_file(
        &directory,
        &name,
        &mut Cursor::new(b"abc"),
        3,
        digest(b"abc"),
        2,
        || false,
    );
    assert!(matches!(result, Err(RestoreError::BUDGET_EXCEEDED)));
    let calls = Cell::new(0);
    let result = restore_file(
        &directory,
        &name,
        &mut Cursor::new(b"abc"),
        3,
        digest(b"abc"),
        3,
        || {
            calls.set(calls.get() + 1);
            calls.get() >= 3
        },
    );
    assert!(matches!(result, Err(RestoreError::CANCELLED)));
    assert!(!temporary.path().join("item").exists());
    assert_clean(temporary.path());
}
