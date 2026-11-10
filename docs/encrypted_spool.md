## 1. Scope

This primitive encrypts and authenticates caller-owned streams with XChaCha20-Poly1305. It uses fresh operating-system randomness for a 16-byte object nonce prefix and a checked 64-bit record counter. Each data record carries at most 64 KiB of plaintext. Associated data binds a fixed versioned domain, the caller's nonempty context, record type, counter, and length. An authenticated final record binds total plaintext bytes and record count. Decryption rejects missing, reordered, modified, substituted, or extra records.

The serialized spool contains an eight-byte magic, the nonce prefix, length-prefixed ciphertext records, and a final authenticated record. This is an internal temporary-spool framing, not the archive repository format or a stable public interchange format. Explicit plaintext and ciphertext limits are checked incrementally. A final one-byte read tests for trailing data. The key and plaintext buffers use zeroizing wrappers, and the cipher's zeroize feature is enabled. The caller retains responsibility for all other key copies and secret lifecycle.

## 2. Operational Limits

Encryption writes only ciphertext to its destination. Decryption emits individually authenticated plaintext chunks to the caller's destination before the final record is validated. The caller must treat that destination as private and uncommitted, discard it on every error, and never publish or consume its contents until the function returns success. Output streams can contain partial results after errors. The functions do not create, delete, synchronize, or publish files, and do not establish a safe temporary-file location or erase files supplied by the caller.

`EncryptedSpoolWriter` accepts incremental `Write` calls and requires explicit `finish` to write the authenticated final record. Dropping it does not finalize, and a failed write or flush poisons the writer. A destination can report an error after persisting bytes, including the complete final record, so callers must discard output on every error rather than infer incompleteness from the error alone. A successful `finish` does not synchronize the underlying destination.

The resource guard is checked between stream operations, not during a blocking read or write. Limits bound bytes processed and temporary chunk buffers, not total process memory, underlying buffering, thread count, or disk allocation. This construction has not received an independent cryptographic review. Platform-specific execution, persistence, crash cleanup, and production key management remain separate acceptance gates.
