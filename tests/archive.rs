use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use relic::archive::{Archive, ArchiveError};

#[test]
#[ignore = "requires verified external engines"]
fn encrypted_backup_restores_and_rustic_reads_it() {
    let restic = std::env::var_os("RELIC_TEST_RESTIC").expect("RELIC_TEST_RESTIC is required");
    let rustic = std::env::var_os("RELIC_TEST_RUSTIC").expect("RELIC_TEST_RUSTIC is required");
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let password = directory.path().join("password");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("message"), b"archive proof\n").unwrap();
    fs::write(&password, b"test-only-password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(source.join("message"), fs::Permissions::from_mode(0o640)).unwrap();
    }
    let archive = Archive {
        executable: PathBuf::from(restic),
        repository: directory.path().join("repository"),
        password_file: password.clone(),
        timeout: Duration::from_secs(30),
    };
    archive.initialize().unwrap();
    let snapshot = archive.backup(&source, "ab12", "cd34").unwrap();
    assert_eq!(
        archive.lookup("ab12", "cd34").unwrap(),
        Some(snapshot.clone())
    );
    assert!(matches!(
        archive.lookup("ab12", "ef56"),
        Err(ArchiveError::Conflict)
    ));
    assert_eq!(archive.backup(&source, "ab12", "cd34").unwrap(), snapshot);
    archive.check().unwrap();
    let restored = directory.path().join("restored");
    archive.restore(&snapshot, &restored).unwrap();
    let recovered = restored
        .join(source.strip_prefix("/").unwrap())
        .join("message");
    assert_eq!(fs::read(&recovered).unwrap(), b"archive proof\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&recovered).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
    let output = Command::new(&rustic)
        .arg("--repository")
        .arg(&archive.repository)
        .arg("--password-file")
        .arg(&password)
        .arg("snapshots")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&snapshot[..8]));
    let independent = directory.path().join("independent");
    let output = Command::new(rustic)
        .arg("--repository")
        .arg(&archive.repository)
        .arg("--password-file")
        .arg(&password)
        .arg("restore")
        .arg(&snapshot)
        .arg(&independent)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let independently_recovered = independent
        .join(source.strip_prefix("/").unwrap())
        .join("message");
    assert_eq!(
        fs::read(independently_recovered).unwrap(),
        b"archive proof\n"
    );
}
