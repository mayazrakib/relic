use relic::encrypted_spool::{SpoolLimits, encrypt_spool};
use relic::manifest::ManifestEntry;
use relic::manifest_artifact::{seal_manifest, verify_sealed_manifest};
use relic::manifest_spool::ManifestSpool;
use relic::resources::StageGuard;
use relic::state::CaptureBinding;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn binding() -> CaptureBinding {
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

fn limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 2 * 1024 * 1024,
        ciphertext_bytes: 3 * 1024 * 1024,
    }
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn encrypt_raw(bytes: &[u8], binding: &CaptureBinding, key: &Zeroizing<[u8; 32]>) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"relic/manifest-artifact/context/v1\0");
    hash.update(serde_jcs::to_vec(binding).unwrap());
    let context = hash.finalize();
    let mut output = Vec::new();
    encrypt_spool(
        &mut &bytes[..],
        &mut output,
        key,
        &context,
        limits(),
        &StageGuard::default(),
    )
    .unwrap();
    output
}

#[test]
fn seals_and_authenticates_golden_manifest() {
    let directory = private_directory();
    let mut spool = ManifestSpool::create(
        &directory.path().join("manifest.sqlite"),
        relic::manifest_spool::SpoolLimits {
            max_entries: 10,
            max_frame_bytes: 1024 * 1024,
            max_spool_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let entry: ManifestEntry =
        serde_json::from_str(include_str!("../fixtures/contracts/manifest_entry.json")).unwrap();
    spool.add_entry(&entry).unwrap();
    let key = Zeroizing::new([7_u8; 32]);
    let binding = binding();
    let mut ciphertext = Vec::new();
    let sealed = seal_manifest(
        &spool,
        &binding,
        &mut ciphertext,
        &key,
        limits(),
        &StageGuard::default(),
    )
    .unwrap();
    assert_eq!(
        sealed.digest,
        "sha256:e77e8179915ad471fadc683b82f6a8a016c9e11319b14688e10cf37cb45a6d85"
    );
    assert_eq!(
        verify_sealed_manifest(
            &mut &ciphertext[..],
            &binding,
            &key,
            limits(),
            &StageGuard::default(),
            &sealed.digest
        )
        .unwrap(),
        sealed
    );
    let mut changed = binding.clone();
    changed.source_view_id = "other".into();
    assert!(
        verify_sealed_manifest(
            &mut &ciphertext[..],
            &changed,
            &key,
            limits(),
            &StageGuard::default(),
            &sealed.digest
        )
        .is_err()
    );
    assert!(
        verify_sealed_manifest(
            &mut &ciphertext[..],
            &binding,
            &key,
            limits(),
            &StageGuard::default(),
            "sha256:wrong"
        )
        .is_err()
    );
    assert!(
        verify_sealed_manifest(
            &mut &ciphertext[..ciphertext.len() - 1],
            &binding,
            &key,
            limits(),
            &StageGuard::default(),
            &sealed.digest
        )
        .is_err()
    );
}

#[test]
fn rejects_noncanonical_and_oversized_frames_even_when_authenticated() {
    let key = Zeroizing::new([7_u8; 32]);
    let binding = binding();
    let mut malformed = b"relic/logical-manifest/v1\0".to_vec();
    malformed.extend_from_slice(&(1024_u32 * 1024 + 1).to_be_bytes());
    let ciphertext = encrypt_raw(&malformed, &binding, &key);
    assert!(
        verify_sealed_manifest(
            &mut &ciphertext[..],
            &binding,
            &key,
            limits(),
            &StageGuard::default(),
            "unused"
        )
        .is_err()
    );
    let mut noncanonical = b"relic/logical-manifest/v1\0".to_vec();
    let header = br#"{ "schema_version":1,"capture_id":"capture_1","entry_count":"0"}"#;
    noncanonical.extend_from_slice(&(header.len() as u32).to_be_bytes());
    noncanonical.extend_from_slice(header);
    let ciphertext = encrypt_raw(&noncanonical, &binding, &key);
    assert!(
        verify_sealed_manifest(
            &mut &ciphertext[..],
            &binding,
            &key,
            limits(),
            &StageGuard::default(),
            "unused"
        )
        .is_err()
    );
}
