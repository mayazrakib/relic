use std::io::{Read, Write};

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::array::Array;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use zeroize::{Zeroize, Zeroizing};

use crate::resources::StageGuard;

const MAGIC: &[u8; 8] = b"RLCSP001";
const DOMAIN: &[u8] = b"relic/encrypted-spool/v1\0";
const CHUNK_BYTES: usize = 64 * 1024;
const TAG_BYTES: usize = 16;
const MAX_CONTEXT_BYTES: usize = 1024;
const HEADER_BYTES: u64 = 24;
const FINAL_BYTES: u64 = 36;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum SpoolError {
    INVALID_INPUT,
    BUDGET_EXCEEDED,
    AUTHENTICATION,
    RESOURCE,
    RANDOM,
    POISONED,
    IO(std::io::Error),
}

#[derive(Clone, Copy)]
pub struct SpoolLimits {
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
}

fn get_nonce(prefix: &[u8; 16], counter: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn get_aad(context: &[u8], kind: u8, counter: u64, length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + 4 + context.len() + 13);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(&(context.len() as u32).to_be_bytes());
    aad.extend_from_slice(context);
    aad.push(kind);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.extend_from_slice(&length.to_be_bytes());
    aad
}

fn count_bytes(current: u64, increment: u64, limit: u64) -> Result<u64, SpoolError> {
    let result = current
        .checked_add(increment)
        .ok_or(SpoolError::BUDGET_EXCEEDED)?;

    if result > limit {
        return Err(SpoolError::BUDGET_EXCEEDED);
    }

    Ok(result)
}

pub fn encrypt_spool<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    key: &Zeroizing<[u8; 32]>,
    context: &[u8],
    limits: SpoolLimits,
    guard: &StageGuard,
) -> Result<(), SpoolError> {
    if context.is_empty() || context.len() > MAX_CONTEXT_BYTES {
        return Err(SpoolError::INVALID_INPUT);
    }

    guard.check().map_err(|_| SpoolError::RESOURCE)?;
    let mut written = count_bytes(0, HEADER_BYTES + FINAL_BYTES, limits.ciphertext_bytes)?;
    let mut prefix = [0_u8; 16];
    getrandom::fill(&mut prefix).map_err(|_| SpoolError::RANDOM)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| SpoolError::INVALID_INPUT)?;
    destination.write_all(MAGIC).map_err(SpoolError::IO)?;
    destination.write_all(&prefix).map_err(SpoolError::IO)?;
    let mut buffer = Zeroizing::new([0_u8; CHUNK_BYTES]);
    let mut plaintext = 0_u64;
    let mut counter = 0_u64;

    loop {
        guard.check().map_err(|_| SpoolError::RESOURCE)?;
        let count = source.read(&mut buffer[..]).map_err(SpoolError::IO)?;

        if count == 0 {
            break;
        }

        plaintext = count_bytes(plaintext, count as u64, limits.plaintext_bytes)?;
        written = count_bytes(
            written,
            4 + count as u64 + TAG_BYTES as u64,
            limits.ciphertext_bytes,
        )?;
        let length = count as u32;
        let aad = get_aad(context, 0, counter, length);
        let encrypted = cipher
            .encrypt(
                &Array(get_nonce(&prefix, counter)),
                Payload {
                    msg: &buffer[..count],
                    aad: &aad,
                },
            )
            .map_err(|_| SpoolError::AUTHENTICATION)?;
        guard.check().map_err(|_| SpoolError::RESOURCE)?;
        destination
            .write_all(&length.to_be_bytes())
            .map_err(SpoolError::IO)?;
        destination.write_all(&encrypted).map_err(SpoolError::IO)?;
        counter = counter.checked_add(1).ok_or(SpoolError::BUDGET_EXCEEDED)?;
    }

    guard.check().map_err(|_| SpoolError::RESOURCE)?;
    let mut final_record = [0_u8; 16];
    final_record[..8].copy_from_slice(&plaintext.to_be_bytes());
    final_record[8..].copy_from_slice(&counter.to_be_bytes());
    let aad = get_aad(context, 1, counter, 0);
    let encrypted = cipher
        .encrypt(
            &Array(get_nonce(&prefix, counter)),
            Payload {
                msg: &final_record,
                aad: &aad,
            },
        )
        .map_err(|_| SpoolError::AUTHENTICATION)?;
    destination
        .write_all(&0_u32.to_be_bytes())
        .map_err(SpoolError::IO)?;
    destination.write_all(&encrypted).map_err(SpoolError::IO)?;
    Ok(())
}

pub fn decrypt_spool<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    key: &Zeroizing<[u8; 32]>,
    context: &[u8],
    limits: SpoolLimits,
    guard: &StageGuard,
) -> Result<(), SpoolError> {
    if context.is_empty() || context.len() > MAX_CONTEXT_BYTES {
        return Err(SpoolError::INVALID_INPUT);
    }

    guard.check().map_err(|_| SpoolError::RESOURCE)?;
    let mut read_bytes = count_bytes(0, HEADER_BYTES, limits.ciphertext_bytes)?;
    let mut header = [0_u8; HEADER_BYTES as usize];
    source.read_exact(&mut header).map_err(SpoolError::IO)?;

    if &header[..8] != MAGIC {
        return Err(SpoolError::AUTHENTICATION);
    }

    let mut prefix = [0_u8; 16];
    prefix.copy_from_slice(&header[8..]);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| SpoolError::INVALID_INPUT)?;
    let mut counter = 0_u64;
    let mut plaintext = 0_u64;

    loop {
        guard.check().map_err(|_| SpoolError::RESOURCE)?;
        read_bytes = count_bytes(read_bytes, 4, limits.ciphertext_bytes)?;
        let mut encoded_length = [0_u8; 4];
        source
            .read_exact(&mut encoded_length)
            .map_err(SpoolError::IO)?;
        let length = u32::from_be_bytes(encoded_length);

        if length as usize > CHUNK_BYTES {
            return Err(SpoolError::AUTHENTICATION);
        }

        let is_final = length == 0;
        let encrypted_len = if is_final {
            16 + TAG_BYTES
        } else {
            length as usize + TAG_BYTES
        };
        read_bytes = count_bytes(read_bytes, encrypted_len as u64, limits.ciphertext_bytes)?;
        let mut encrypted = vec![0_u8; encrypted_len];
        source.read_exact(&mut encrypted).map_err(SpoolError::IO)?;
        let aad = get_aad(context, u8::from(is_final), counter, length);
        let decrypted = cipher
            .decrypt(
                &Array(get_nonce(&prefix, counter)),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|_| SpoolError::AUTHENTICATION)?;
        let decrypted = Zeroizing::new(decrypted);

        if is_final {
            let mut expected = [0_u8; 16];
            expected[..8].copy_from_slice(&plaintext.to_be_bytes());
            expected[8..].copy_from_slice(&counter.to_be_bytes());

            if decrypted.as_slice() != expected {
                return Err(SpoolError::AUTHENTICATION);
            }

            guard.check().map_err(|_| SpoolError::RESOURCE)?;
            let mut extra = [0_u8; 1];

            if source.read(&mut extra).map_err(SpoolError::IO)? != 0 {
                return Err(SpoolError::AUTHENTICATION);
            }

            return Ok(());
        }

        plaintext = count_bytes(plaintext, length as u64, limits.plaintext_bytes)?;
        guard.check().map_err(|_| SpoolError::RESOURCE)?;
        destination.write_all(&decrypted).map_err(SpoolError::IO)?;
        counter = counter.checked_add(1).ok_or(SpoolError::BUDGET_EXCEEDED)?;
    }
}

pub struct EncryptedSpoolWriter<W: Write> {
    destination: W,
    cipher: XChaCha20Poly1305,
    prefix: [u8; 16],
    context: Vec<u8>,
    limits: SpoolLimits,
    guard: StageGuard,
    buffer: Zeroizing<Vec<u8>>,
    plaintext_bytes: u64,
    ciphertext_bytes: u64,
    counter: u64,
    is_poisoned: bool,
}

impl<W: Write> EncryptedSpoolWriter<W> {
    pub fn new(
        mut destination: W,
        key: &Zeroizing<[u8; 32]>,
        context: &[u8],
        limits: SpoolLimits,
        guard: &StageGuard,
    ) -> Result<Self, SpoolError> {
        if context.is_empty() || context.len() > MAX_CONTEXT_BYTES {
            return Err(SpoolError::INVALID_INPUT);
        }

        guard.check().map_err(|_| SpoolError::RESOURCE)?;
        let ciphertext_bytes = count_bytes(0, HEADER_BYTES + FINAL_BYTES, limits.ciphertext_bytes)?;
        let mut prefix = [0_u8; 16];
        getrandom::fill(&mut prefix).map_err(|_| SpoolError::RANDOM)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| SpoolError::INVALID_INPUT)?;
        destination.write_all(MAGIC).map_err(SpoolError::IO)?;
        destination.write_all(&prefix).map_err(SpoolError::IO)?;

        Ok(Self {
            destination,
            cipher,
            prefix,
            context: context.to_vec(),
            limits,
            guard: guard.clone(),
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_BYTES)),
            plaintext_bytes: 0,
            ciphertext_bytes,
            counter: 0,
            is_poisoned: false,
        })
    }

    fn write_chunk(&mut self) -> Result<(), SpoolError> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        self.guard.check().map_err(|_| SpoolError::RESOURCE)?;
        let length = self.buffer.len() as u32;
        let next_counter = self
            .counter
            .checked_add(1)
            .ok_or(SpoolError::BUDGET_EXCEEDED)?;
        let next_bytes = count_bytes(
            self.ciphertext_bytes,
            4 + u64::from(length) + TAG_BYTES as u64,
            self.limits.ciphertext_bytes,
        )?;
        let aad = get_aad(&self.context, 0, self.counter, length);
        let encrypted = self
            .cipher
            .encrypt(
                &Array(get_nonce(&self.prefix, self.counter)),
                Payload {
                    msg: &self.buffer,
                    aad: &aad,
                },
            )
            .map_err(|_| SpoolError::AUTHENTICATION)?;
        self.guard.check().map_err(|_| SpoolError::RESOURCE)?;
        self.destination
            .write_all(&length.to_be_bytes())
            .map_err(SpoolError::IO)?;
        self.destination
            .write_all(&encrypted)
            .map_err(SpoolError::IO)?;
        self.buffer.as_mut_slice().zeroize();
        self.buffer.clear();
        self.counter = next_counter;
        self.ciphertext_bytes = next_bytes;
        Ok(())
    }

    pub fn finish(mut self) -> Result<W, SpoolError> {
        if self.is_poisoned {
            return Err(SpoolError::POISONED);
        }

        self.write_chunk()?;
        self.guard.check().map_err(|_| SpoolError::RESOURCE)?;
        let mut final_record = [0_u8; 16];
        final_record[..8].copy_from_slice(&self.plaintext_bytes.to_be_bytes());
        final_record[8..].copy_from_slice(&self.counter.to_be_bytes());
        let aad = get_aad(&self.context, 1, self.counter, 0);
        let encrypted = self
            .cipher
            .encrypt(
                &Array(get_nonce(&self.prefix, self.counter)),
                Payload {
                    msg: &final_record,
                    aad: &aad,
                },
            )
            .map_err(|_| SpoolError::AUTHENTICATION)?;
        self.guard.check().map_err(|_| SpoolError::RESOURCE)?;
        self.destination
            .write_all(&0_u32.to_be_bytes())
            .map_err(SpoolError::IO)?;
        self.destination
            .write_all(&encrypted)
            .map_err(SpoolError::IO)?;
        Ok(self.destination)
    }
}

impl<W: Write> Write for EncryptedSpoolWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.is_poisoned {
            return Err(std::io::Error::other("encrypted spool is poisoned"));
        }

        let result: Result<usize, SpoolError> = (|| {
            self.guard.check().map_err(|_| SpoolError::RESOURCE)?;
            let count = bytes.len().min(CHUNK_BYTES - self.buffer.len());
            let next_plaintext = count_bytes(
                self.plaintext_bytes,
                count as u64,
                self.limits.plaintext_bytes,
            )?;
            self.buffer.extend_from_slice(&bytes[..count]);
            self.plaintext_bytes = next_plaintext;

            if self.buffer.len() == CHUNK_BYTES {
                self.write_chunk()?;
            }

            Ok(count)
        })();

        match result {
            Ok(count) => Ok(count),
            Err(_) => {
                self.is_poisoned = true;
                Err(std::io::Error::other("encrypted spool write failed"))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.is_poisoned {
            return Err(std::io::Error::other("encrypted spool is poisoned"));
        }

        let result = self
            .write_chunk()
            .and_then(|()| self.destination.flush().map_err(SpoolError::IO));

        if result.is_err() {
            self.is_poisoned = true;
            return Err(std::io::Error::other("encrypted spool flush failed"));
        }

        Ok(())
    }
}
