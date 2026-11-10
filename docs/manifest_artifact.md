## 1. Encrypted Manifest Artifact

A manifest artifact encrypts the canonical framed logical manifest with the encrypted spool format. Its authenticated context binds the complete capture binding. Verification streams authenticated chunks into a bounded frame parser, validates canonical serialization and manifest semantics, and returns a digest only after the final authentication record and expected digest pass.

The caller owns the key, destination lifecycle, durability, and publication. This format does not itself persist the artifact, verify source-file bytes, or guarantee an immutable source view. Decryption uses bounded memory and does not write plaintext to disk.
