## 1. Encrypted Manifest Artifact

A manifest artifact encrypts the canonical framed logical manifest with the encrypted spool format. Its authenticated context binds the complete capture binding. Verification streams authenticated chunks into a bounded frame parser, validates canonical serialization and manifest semantics, and returns a digest only after the final authentication record and expected digest pass.

The caller owns the key, destination lifecycle, durability, and publication. This format does not itself persist the artifact, verify source-file bytes, or guarantee an immutable source view. Decryption uses bounded memory and does not write plaintext to disk.

`ManifestArtifactWriter` accepts the declared entry count and ordered entries incrementally. A failed entry poisons the writer, and explicit `finish` attempts the authenticated final record. `seal_sorted_manifest` keeps sorter output provisional until the encrypted sort, all run authentication, manifest validation, and cancellation checks succeed; on any failure the caller must discard the uncommitted destination. The caller must sync the artifact and its containing directory before relying on it as durable, and must independently verify it before freezing the capture record. An I/O failure can leave a complete record on disk, so failure alone does not prove that the destination is incomplete.
