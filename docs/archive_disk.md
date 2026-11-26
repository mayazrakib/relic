## 1. Owned Encrypted File Staging

The optional Unix archive adapter now provides a *disk archive source*, a collection of independently readable encrypted files produced from a sealed captured payload. `ArchiveDiskStore::create_source` invokes `visit_sealed_payload` once. Its visitor streams each file directly into an encrypted spool and keeps only bounded metadata and active encryption scratch in memory. The original source paths are never reopened. Archive iteration shares the catalogue and opens each encrypted file lazily rather than retaining the complete ciphertext in RAM or replaying the complete captured payload for every file.

This component remains part of private staging. It does not enable destination archive jobs or replace the exact staged snapshot comparison described in [archive capture](archive_capture.md).

## 2. Journal and Cryptographic Binding

Schema version six introduces archive stage and file records. Stage preparation snapshots the linked sealed payload and manifest identities, entry/file counts, and plaintext byte total. File preparation records an opaque generated ID, a canonical header digest, and declared byte count before file creation. The state database contains no archive source paths or file contents in these new records. Immutable replay checks reject changed identities or measurements, and the final stage seal recounts every file inside the transaction.

Each file's encryption context binds the complete capture, stage binding, file ID, and canonical payload header. The final manifest entry becomes available only after file bytes have been consumed. The visitor checks its exact header, byte count, and content digest before completing that file's encryption. Final entries and file IDs are recorded in an encrypted catalogue. Catalogue admission requires complete source payload authentication and comparison against the expected frozen manifest. It also requires canonical ordering, unique paths and file IDs, supported directory hierarchy, and the exact entry count and digest.

Completed file and catalogue ciphertext is synchronized, followed by its containing directory, before journal sealing. The catalogue encryption context binds capture and stage. Subsequent file readers independently authenticate every encrypted stream and compare plaintext length and SHA-256 at end of input. Ciphertext readers also compare the persisted ciphertext digest, byte count, inode identity, and unchanged metadata, then revalidate the owned slot and directory. Successful partial reads remain provisional until full end-of-input verification.

## 3. Resource Limits

The component enforces the following class limits and any smaller requested limits:

| Resource | Limit |
|---|---|
| Aggregate per-file staging ciphertext | 256 MiB |
| Encrypted catalogue plaintext | 1 MiB |
| Catalogue ciphertext allowance | 2 MiB |
| Logical entries | 10,000 |
| Simultaneous open content readers | 4 |
| Encryption, hashing, and recovery scratch blocks | 64 KiB |

Admission retains a 16 MiB data reservation, requested ciphertext quota plus catalogue allowance, descriptor allowance, and reader slots through the last source iterator or reader. Creation also reserves 8 MiB for the concurrently supplied manifest verifier. These are accounting reservations, not measured physical resident-memory guarantees. Callers remain responsible for admission before constructing their own inputs. Native engine allocations need separate worker containment.

The store checks available capacity against its requested quota and a reserve of at least 512 MiB or 5% of filesystem capacity, rounded upward. Temporary encrypted file staging duplicates retained payload storage; both need capacity and lifecycle accounting. Per-stage admission does not establish complete persistent node storage accounting or cleanup.

## 4. Storage and Ownership

The store uses a pinned owner-only `0700` directory, generated component names, `0600` regular files, no-follow operations, and single-link checks. A stage lock remains held through source, iterator, and reader lifetimes. A competing owner is rejected before another stage reservation is admitted. Directory and lock replacement invalidate the lease. File creation uses exclusive creation.

On Linux, existing files are first pinned with `O_PATH` and checked as regular files before a deliberate trusted-procfs reopen. This avoids invoking a device-node open implementation before checking its type. On macOS, a no-follow type check and post-open identity comparison reject ordinary replacements, but a raced mutable device replacement still needs isolated worker containment. Neither this profile nor current native CI establishes that macOS isolation gate. Windows file staging remains unavailable.

## 5. Interrupted Operations

`reopen_source` accepts a sealed stage with a matching binding and fully authenticates the catalogue before exposing entries. It checks each referenced journal record and physical file identity without opening all contents simultaneously. File content authentication remains lazy and completes at each reader's end of input. The original captured payload file is not needed for this path.

`reconcile_source` handles complete filesystem effects whose final catalogue journal seal was interrupted. It authenticates the catalogue, verifies the frozen logical manifest, checks all referenced sealed file records, reads and authenticates every file with bounded scratch, synchronizes storage, and records the exact catalogue identity. An incomplete or corrupt stage is preserved and does not become a source. Explicit journal abandonment is terminal. Automatic deletion and garbage collection remain separate pending lifecycle work; reconciliation never overwrites a conflicting file or retries uncertain writes blindly.

## 6. Evidence and Remaining Gates

The [evidence record](evidence/archive_disk.json) distinguishes local tests, native checkpoint results, and unresolved acceptance work. Fixtures cover a file larger than the preceding RAM-source class, independent concurrent reads, retained resource leases, wrong keys, corrupt files and catalogue, symlinks, hard links, named pipes, moved directories, replaced locks, cancellation, quotas, process-boundary reconciliation, and source corruption before catalogue admission. Native archive integration removes both original source and captured payload before archive consumption and compares the resulting native snapshot with the frozen manifest.

The profile retains portable ASCII file/directory paths without original metadata and bounded catalogue/ciphertext classes. Full large-source segmentation, Windows staging and ordering, safe cleanup, physical memory qualification, key-provider lifecycle, worker cancellation, S3, sole-credential fenced destination mutations, durable destination receipts, and all subsequent system acceptance gates remain required. Simulated process boundaries are not power-loss durability evidence.
