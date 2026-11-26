#![cfg(feature = "embedded-archive")]

use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use relic::archive_source::{
    ArchiveSourceLimits, FrozenArchiveEntry, FrozenArchiveSource, encrypt_archive_file,
};
use relic::encrypted_spool::SpoolLimits;
use relic::manifest::{ManifestEntry, MetadataValue};
use relic::resources::StageGuard;
use relic::state::CaptureBinding;
use rustic_backend::BackendOptions;
use rustic_core::{
    BackupOptions, ConfigOptions, Credentials, KeyOptions, ParentOptions, ReadSource,
    ReadSourceOpen, Repository, RepositoryOptions, SnapshotOptions,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn get_binding() -> CaptureBinding {
    CaptureBinding {
        authority_id: "local_1".into(),
        job_id: "job_1".into(),
        occurrence_id: "occurrence_1".into(),
        capture_id: "capture_1".into(),
        source_view_id: "view_1".into(),
        consistency: "best_effort".into(),
        source_selection_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn create_file_entry(path: &[&str], bytes: &[u8]) -> ManifestEntry {
    ManifestEntry {
        source_id: "documents".into(),
        path_encoding: "unix_bytes".into(),
        path: path
            .iter()
            .map(|part| URL_SAFE_NO_PAD.encode(part))
            .collect(),
        kind: "file".into(),
        size_bytes: Some(bytes.len().to_string()),
        content_digest: Some(format!(
            "sha256:{}",
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )),
        link_target_base64url: None,
        metadata: Vec::new(),
    }
}

fn get_limits() -> ArchiveSourceLimits {
    ArchiveSourceLimits {
        max_entries: 32,
        max_file_bytes: 4096,
        max_ciphertext_bytes: 8192,
        max_metadata_bytes: 8192,
    }
}

fn get_spool_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 4096,
        ciphertext_bytes: 8192,
    }
}

fn create_frozen_entry(bytes: &[u8], key: &Zeroizing<[u8; 32]>) -> FrozenArchiveEntry {
    let entry = create_file_entry(&["folder", "file.txt"], bytes);
    let ciphertext = encrypt_archive_file(
        &entry,
        &get_binding(),
        &mut Cursor::new(bytes),
        key,
        get_spool_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    FrozenArchiveEntry {
        entry,
        ciphertext: Some(ciphertext),
    }
}

#[test]
fn yields_hierarchy_and_authenticated_frozen_file() {
    let key = Zeroizing::new([7; 32]);
    let source = FrozenArchiveSource::new(
        vec![create_frozen_entry(b"proof", &key)],
        &get_binding(),
        &key,
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    let mut entries = source.entries();
    let paths: Vec<PathBuf> = source.entries().map(|item| item.unwrap().path).collect();
    assert_eq!(
        paths,
        vec![
            "sources",
            "sources/documents",
            "sources/documents/folder",
            "sources/documents/folder/file.txt"
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>()
    );
    let file = entries.nth(3).unwrap().unwrap();
    let mut reader = file.open.unwrap().open().unwrap();
    let mut content = Vec::new();
    reader.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"proof");
    assert_eq!(source.size().unwrap(), Some(5));
}

#[test]
fn rejects_invalid_entries_quotas_and_content() {
    let key = Zeroizing::new([8; 32]);
    let mut bad = create_file_entry(&[".."], b"content");
    assert!(
        encrypt_archive_file(
            &bad,
            &get_binding(),
            &mut Cursor::new(b"content"),
            &key,
            get_spool_limits(),
            &StageGuard::default()
        )
        .is_err()
    );
    bad = create_file_entry(&["file"], b"content");
    bad.metadata.push(MetadataValue {
        namespace: "unix".into(),
        name: "mode".into(),
        value_base64url: "NjQ0".into(),
    });
    assert!(
        encrypt_archive_file(
            &bad,
            &get_binding(),
            &mut Cursor::new(b"content"),
            &key,
            get_spool_limits(),
            &StageGuard::default()
        )
        .is_err()
    );
    let valid = create_file_entry(&["file"], b"content");
    assert!(
        encrypt_archive_file(
            &valid,
            &get_binding(),
            &mut Cursor::new(b"changed"),
            &key,
            get_spool_limits(),
            &StageGuard::default()
        )
        .is_err()
    );
    let one = create_frozen_entry(b"content", &key);
    let two = FrozenArchiveEntry {
        entry: one.entry.clone(),
        ciphertext: one.ciphertext.clone(),
    };
    assert!(
        FrozenArchiveSource::new(
            vec![one, two],
            &get_binding(),
            &key,
            get_limits(),
            &StageGuard::default()
        )
        .is_err()
    );
    let mut too_small = get_limits();
    too_small.max_ciphertext_bytes = 1;
    assert!(
        FrozenArchiveSource::new(
            vec![create_frozen_entry(b"content", &key)],
            &get_binding(),
            &key,
            too_small,
            &StageGuard::default()
        )
        .is_err()
    );
    let mut too_many = get_limits();
    too_many.max_entries = 1025;
    assert!(
        FrozenArchiveSource::new(
            Vec::new(),
            &get_binding(),
            &key,
            too_many,
            &StageGuard::default()
        )
        .is_err()
    );
}

#[test]
fn rejects_wrong_key_tampering_and_cancel() {
    let key = Zeroizing::new([9; 32]);
    let other = Zeroizing::new([10; 32]);
    let source = FrozenArchiveSource::new(
        vec![create_frozen_entry(b"content", &key)],
        &get_binding(),
        &other,
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    let mut reader = source
        .entries()
        .last()
        .unwrap()
        .unwrap()
        .open
        .unwrap()
        .open()
        .unwrap();
    assert!(reader.read_to_end(&mut Vec::new()).is_err());
    let mut item = create_frozen_entry(b"content", &key);
    let mut ciphertext = item.ciphertext.take().unwrap().to_vec();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    item.ciphertext = Some(Arc::from(ciphertext));
    let source = FrozenArchiveSource::new(
        vec![item],
        &get_binding(),
        &key,
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    let mut reader = source
        .entries()
        .last()
        .unwrap()
        .unwrap()
        .open
        .unwrap()
        .open()
        .unwrap();
    assert!(reader.read_to_end(&mut Vec::new()).is_err());
    let guard = StageGuard::default();
    guard.cancellation.cancel();
    assert!(
        FrozenArchiveSource::new(
            vec![create_frozen_entry(b"content", &key)],
            &get_binding(),
            &key,
            get_limits(),
            &guard
        )
        .is_err()
    );
}

#[test]
fn rustic_can_publish_staging_snapshot_after_source_read_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let repository_path = temporary.path().join("repository");
    let backends = BackendOptions::default()
        .repository(repository_path.to_str().unwrap())
        .to_backends()
        .unwrap();
    let options = RepositoryOptions::default().no_cache(true);
    let credentials = Credentials::password("test-only-password");
    let repository = Repository::new(&options, &backends)
        .unwrap()
        .init(
            &credentials,
            &KeyOptions::default(),
            &ConfigOptions::default(),
        )
        .unwrap()
        .to_indexed_ids()
        .unwrap();
    let key = Zeroizing::new([11; 32]);
    let mut item = create_frozen_entry(b"content", &key);
    let mut ciphertext = item.ciphertext.take().unwrap().to_vec();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    item.ciphertext = Some(Arc::from(ciphertext));
    let source = FrozenArchiveSource::new(
        vec![item],
        &get_binding(),
        &key,
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    let mut backup_options = BackupOptions::default();
    backup_options.parent_opts = ParentOptions::default().force(true);
    let snapshot = SnapshotOptions::default().to_snapshot().unwrap();
    let result = repository.archive(
        &backup_options,
        &source,
        snapshot,
        &[PathBuf::from("sources")],
    );
    assert!(
        result.is_ok(),
        "this pinned SDK behavior needs review if it changes"
    );
}
