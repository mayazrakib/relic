#![cfg(feature = "embedded-archive")]

use std::fs;
use std::path::{Path, PathBuf};

use relic::embedded_archive::run_local_proof;

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if entry.file_name() == name {
            return Some(path);
        }
    }

    None
}

#[test]
fn restores_embedded_archive_content_and_mode() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let password = temporary.path().join("password");
    let destination = temporary.path().join("restore");
    fs::create_dir(&source).unwrap();
    fs::write(&password, b"test-only-password\n").unwrap();
    fs::write(source.join("tiny"), b"embedded proof\n").unwrap();
    let medium: Vec<u8> = (0..1_048_576)
        .map(|index| ((index * 37 + index / 251) % 256) as u8)
        .collect();
    fs::write(source.join("medium"), &medium).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(source.join("tiny"), fs::Permissions::from_mode(0o640)).unwrap();
    }
    let snapshot = run_local_proof(
        &temporary.path().join("repository"),
        &source,
        &destination,
        &password,
    )
    .unwrap();
    assert_eq!(snapshot.len(), 64);
    let tiny = find_file(&destination, "tiny").expect("tiny file missing");
    assert_eq!(fs::read(&tiny).unwrap(), b"embedded proof\n");
    assert_eq!(
        fs::read(find_file(&destination, "medium").expect("medium file missing")).unwrap(),
        medium
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(tiny).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
