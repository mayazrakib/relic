use std::io::{Cursor, Write};

use relic::encrypted_spool::{
    EncryptedSpoolWriter, SpoolError, SpoolLimits, decrypt_spool, encrypt_spool,
};
use relic::resources::StageGuard;
use zeroize::Zeroizing;

fn get_limits() -> SpoolLimits {
    SpoolLimits {
        plaintext_bytes: 1_000_000,
        ciphertext_bytes: 1_010_000,
    }
}

fn encrypt(bytes: &[u8], key: &Zeroizing<[u8; 32]>) -> Vec<u8> {
    let mut output = Vec::new();
    encrypt_spool(
        &mut Cursor::new(bytes),
        &mut output,
        key,
        b"job-1/manifest",
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    output
}

fn decrypt(bytes: &[u8], key: &Zeroizing<[u8; 32]>, context: &[u8]) -> Result<Vec<u8>, SpoolError> {
    let mut output = Vec::new();
    decrypt_spool(
        &mut Cursor::new(bytes),
        &mut output,
        key,
        context,
        get_limits(),
        &StageGuard::default(),
    )?;
    Ok(output)
}

#[test]
fn round_trip_and_unique_nonces() {
    let key = Zeroizing::new([13_u8; 32]);
    let bytes: Vec<u8> = (0..150_000)
        .map(|index| ((index * 17 + index / 251) % 256) as u8)
        .collect();
    let first = encrypt(&bytes, &key);
    let second = encrypt(&bytes, &key);
    assert_ne!(&first[8..24], &second[8..24]);
    assert!(!first.windows(64).any(|window| window == &bytes[..64]));
    assert_eq!(decrypt(&first, &key, b"job-1/manifest").unwrap(), bytes);
    let empty = encrypt(b"", &key);
    assert!(decrypt(&empty, &key, b"job-1/manifest").unwrap().is_empty());
}

#[test]
fn rejects_tampering_truncation_reordering_and_wrong_context() {
    let key = Zeroizing::new([14_u8; 32]);
    let bytes = vec![9_u8; 150_000];
    let encrypted = encrypt(&bytes, &key);
    let mut modified = encrypted.clone();
    modified[50] ^= 1;
    assert!(decrypt(&modified, &key, b"job-1/manifest").is_err());
    assert!(decrypt(&encrypted[..encrypted.len() - 1], &key, b"job-1/manifest").is_err());
    assert!(decrypt(&encrypted, &key, b"job-2/manifest").is_err());
    let mut appended = encrypted.clone();
    appended.push(0);
    assert!(decrypt(&appended, &key, b"job-1/manifest").is_err());
    let frame_len = 4 + 65_536 + 16;
    let mut reordered = encrypted.clone();
    reordered[24..24 + frame_len].copy_from_slice(&encrypted[24 + frame_len..24 + frame_len * 2]);
    reordered[24 + frame_len..24 + frame_len * 2].copy_from_slice(&encrypted[24..24 + frame_len]);
    assert!(decrypt(&reordered, &key, b"job-1/manifest").is_err());
    let mut substituted = encrypted.clone();
    let other = encrypt(&bytes, &key);
    substituted[24..24 + frame_len].copy_from_slice(&other[24..24 + frame_len]);
    assert!(decrypt(&substituted, &key, b"job-1/manifest").is_err());
}

#[test]
fn enforces_quotas_and_cancellation() {
    let key = Zeroizing::new([15_u8; 32]);
    let limits = SpoolLimits {
        plaintext_bytes: 2,
        ciphertext_bytes: 1000,
    };
    let mut output = Vec::new();
    let result = encrypt_spool(
        &mut Cursor::new(b"abc"),
        &mut output,
        &key,
        b"purpose",
        limits,
        &StageGuard::default(),
    );
    assert!(matches!(result, Err(SpoolError::BUDGET_EXCEEDED)));
    let guard = StageGuard::default();
    guard.cancellation.cancel();
    let mut output = Vec::new();
    let result = encrypt_spool(
        &mut Cursor::new(b"a"),
        &mut output,
        &key,
        b"purpose",
        get_limits(),
        &guard,
    );
    assert!(matches!(result, Err(SpoolError::RESOURCE)));
    assert!(output.is_empty());
    let encrypted = encrypt(b"example", &key);
    let limits = SpoolLimits {
        plaintext_bytes: 100,
        ciphertext_bytes: 30,
    };
    let result = decrypt_spool(
        &mut Cursor::new(encrypted),
        &mut Vec::new(),
        &key,
        b"job-1/manifest",
        limits,
        &StageGuard::default(),
    );
    assert!(matches!(result, Err(SpoolError::BUDGET_EXCEEDED)));
}

#[test]
fn streaming_writer_round_trips_and_requires_finish() {
    let key = Zeroizing::new([16_u8; 32]);
    let bytes = vec![47_u8; 150_000];
    let mut writer = EncryptedSpoolWriter::new(
        Vec::new(),
        &key,
        b"job-1/manifest",
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();

    for part in bytes.chunks(317) {
        writer.write_all(part).unwrap();
    }

    writer.flush().unwrap();
    let encrypted = writer.finish().unwrap();
    assert_eq!(decrypt(&encrypted, &key, b"job-1/manifest").unwrap(), bytes);
    let mut unfinished = Vec::new();
    {
        let mut writer = EncryptedSpoolWriter::new(
            &mut unfinished,
            &key,
            b"job-1/manifest",
            get_limits(),
            &StageGuard::default(),
        )
        .unwrap();
        writer.write_all(b"not finalized").unwrap();
    }
    assert!(decrypt(&unfinished, &key, b"job-1/manifest").is_err());
}

#[test]
fn streaming_writer_poisoned_after_quota_or_sink_failure() {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > 24 {
                return Err(std::io::Error::other("sink failed"));
            }

            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let key = Zeroizing::new([17_u8; 32]);
    let mut writer = EncryptedSpoolWriter::new(
        Vec::new(),
        &key,
        b"purpose",
        SpoolLimits {
            plaintext_bytes: 2,
            ciphertext_bytes: 1000,
        },
        &StageGuard::default(),
    )
    .unwrap();
    assert!(writer.write_all(b"abc").is_err());
    assert!(writer.write_all(b"a").is_err());
    assert!(matches!(writer.finish(), Err(SpoolError::POISONED)));
    let mut writer = EncryptedSpoolWriter::new(
        FailingWriter,
        &key,
        b"purpose",
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    assert!(writer.write_all(&vec![42; 65_536]).is_err());
    assert!(matches!(writer.finish(), Err(SpoolError::POISONED)));
}
