## 1. Restricted Frozen Source

The optional `embedded-archive` feature provides a *frozen archive source*, an immutable collection of encrypted file streams and declared manifest entries passed to the pinned native archive engine without reopening original source paths. This is an integration profile, not an enabled backup job or a production capture provider. `FrozenArchiveSource` owns shared ciphertext and a zeroized encryption key. Each reader authenticates its complete encrypted stream and checks plaintext length and SHA-256 before successful end of input. File encryption binds both the capture identity and complete declared entry.

The profile accepts regular files and directories with portable ASCII path components. It rejects requested metadata, case-fold collisions, reserved names, duplicate explicit paths, and file/parent conflicts. It synthesizes missing parent directories under `sources/{source_id}`. The expected logical manifest still needs to include the complete intended directory inventory. Native output uses private file and directory modes; these are not original metadata preservation.

## 2. Resource Envelope

The source enforces the following class limits in addition to smaller caller limits:

| Resource | Class Limit |
|---|---|
| Retained encrypted file bytes | 8 MiB |
| Declared raw metadata bytes | 1 MiB |
| Catalogue entries, including synthetic directories | 1,024 |
| Relative path depth | 32 components |
| Encryption input scratch | 64 KiB |
| Snapshot verification read request | 64 KiB |

File encryption reserves the computed ciphertext requirement rather than the entire configured file quota. Short input reads are combined into fixed-size encryption records. The iterator shares its catalogue instead of cloning it for every traversal. The in-memory ciphertext conversion can transiently copy bounded file data. Caller resource reservations still need to cover metadata allocations, concurrent readers, and the native engine.

These limits do not bound the engine's full index, cache, chunk allocations, parallel work, or blocking calls. They are not a replacement for an isolated, admitted worker with enforced physical memory and cancellation limits. The next production source provider needs independently readable locators over owned durable encrypted payload, avoiding both whole-capture RAM retention and repeated full-payload scans per file.

## 3. Complete Snapshot Verification

`verify_snapshot` traverses the exact supplied staged snapshot, streams each regular file through SHA-256, and sends projected entries into the bounded encrypted manifest sorter. It compares the resulting entry count and logical digest with the frozen expected manifest. It validates native node kinds and content relationships, decoded names, relative components, source mappings, depth, individual sizes, and aggregate bytes. An explicit read at declared end of file rejects native content longer than its metadata. Premature end also fails.

Only declared virtual-prefix ancestors are excluded from the logical projection. Extra source namespaces and paths fail. Unix byte paths and Windows UTF-16 paths have explicit projection rules; runtime comparator fixtures currently execute on Unix because the encrypted sorter remains unavailable on Windows. Unsupported requested metadata cannot silently disappear into a successful comparison.

The archive engine can save a snapshot after skipping a failing source reader. Its data-integrity check can then pass because the remaining repository is structurally intact. The regression fixture demonstrates this behavior and verifies that the independent expected-manifest comparison rejects the incomplete snapshot. Separate fixtures demonstrate persisted native file sizes that differ from actual content; verification rejects zero, short, and long declarations even when the expected manifest agrees with that declared size.

## 4. Independent Recovery

The external recovery fixture builds a standard archive from encrypted frozen streams, drops the source adapter, verifies the exact staged manifest, and invokes a separately verified restic executable to check and restore the snapshot. It compares recovered nested and empty files. Original filesystem source files are never created for this fixture, so recovery cannot fall back to them. This establishes format interoperability for the restricted profile; the internal encrypted payload format remains separate.

## 5. Acceptance Boundary

The [evidence record](evidence/archive_capture.json) distinguishes local regression results from native CI and remaining acceptance work. Staged snapshots remain private integration artifacts. Successful verification does not establish current mutation authority, a destination native receipt, durable final publication, cleanup, original metadata, large-source handling, S3 support, or complete platform support. The [engine boundary audit](archive_staging_feasibility.md) describes the remaining publication and containment requirements. Enabled archive jobs remain gated.
