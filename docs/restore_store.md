## 1. Private Restore Transaction

The Linux/macOS restore store pins an owner-controlled 0700 target directory and records a durable restore intent before creating the staging tree. The intent snapshots a linked sealed manifest and payload, including their immutable digests and counts. Active target reservations cover both endpoint aliases and physical target identity. A per-restore operating-system lock excludes another live executor or reconciler.

Staging uses `.restore_{restore_id}.pending/tree`. The tree's device/inode identity is synchronized and recorded before plaintext file writes. Restored sources appear under their source IDs, followed by their original Unix byte path components. Only regular files and directories without requested metadata are currently supported. This rooted-tree profile requires explicit source-root and ancestor directory entries; it refuses manifests with an incomplete directory inventory rather than silently adding unrepresented content.

Target names are validated single components. Descriptor-relative operations reject symlink traversal, special files, cross-device traversal, unexpected modes/owners, and existing file names. New files use 0600 and directories use 0700. Existing destinations, including directories and symlinks, are never replaced. Native case collisions fail closed; a complete capability/loss report remains part of later adapter integration.

## 2. Bounded Reconstruction and Verification

The artifact store holds the sealed payload's capture lock while streaming authenticated plaintext into a provisional visitor, verifying file checksums, the exact logical manifest, the registered ciphertext identity, and unchanged ciphertext metadata. No raw artifact file handle escapes. Restore writes stream to one active file with bounded chunks. Comparison uses one reusable zeroized 64 KiB buffer; it does not retain whole files or a whole-tree path map.

Limits cover entries, aggregate payload length, depth, and descriptors. Depth is at most 128 source components, with a declared descriptor envelope of at least depth plus eight. A bounded depth-first native census checks the reconstructed entry/file/byte counts and rejects unexpected files. Resource admission remains caller-owned. The fixture reserves 16 MiB of data working memory and 16 MiB of spool before I/O. Capacity admission preserves the greater of 512 MiB and 5% of observed filesystem capacity and includes a conservative per-entry overhead estimate; provider-specific allocation guarantees remain unqualified.

After reconstruction, files, their parents, and the tree are synchronized before recording verification. Publication re-reads staged file contents against the authenticated payload, recomputes the exact logical manifest, and checks the complete native census. It also revalidates the pinned target and registered staging container and tree. This second read is deliberate verification of persisted output, not an in-memory copy. A fresh disposable encrypted sorter is required for each verification operation.

Linux publication uses `renameat2` with `RENAME_NOREPLACE`; macOS uses `renameatx_np` with `RENAME_EXCL`. The source container and target directory are synchronized after the rename. The journal then records publication with the original tree identity. Filesystem rename and the SQLite receipt are separate durability boundaries; a failure after rename requires reconciliation.

## 3. Restart and Failure Behavior

| Observed state | Behavior |
|---|---|
| Prepared intent with neither staging nor destination | Mark abandoned without deleting anything |
| Prepared intent with an unregistered filesystem effect | Preserve it and require reconciliation decisions |
| Complete staged tree with recorded identity | Authenticate the registered payload, compare every staged file, validate the native census, and publish without replacement |
| Verified tree renamed before receipt persistence | Require the same final inode and no conflicting staged tree, reverify contents and census, then persist publication |
| Published tree reopened | Reverify identity and contents before returning the recorded result |
| Partial/corrupt tree, extra files, wrong keys, changed storage or inode, live owner, cancellation, or conflicting destination | Refuse publication and preserve existing data and journal evidence |

Failed live stages are poisoned. Recovery does not blindly restart file writes, and no partial tree is automatically deleted. Incomplete stages can be abandoned through the low-level journal, preserving identity and history for coordinated cleanup. Verified or published intents cannot be abandoned through that transition. Final publication remains reserved to its original logical restore operation.

## 4. Evidence and Remaining Qualification

The tests build genuine encrypted manifest and payload artifacts from a pinned source, remove that source, and restore nested, empty, and multi-record files. They exercise verified and renamed restart boundaries, immutable receipts, live-owner exclusion, existing targets, wrong keys, corrupt payloads, changed or extra staging contents, replaced container/tree/final identities, limits, cancellation, and missing prepared effects. Journal tests cover migration, exact retries, target reservations, and guarded transitions.

These are local process/state boundary tests. They do not establish power-loss durability, network filesystem guarantees, independent standard-archive recovery, Windows restoration, selective restore, original permissions/timestamps/links/extended attributes, native key-provider lifecycle, cleanup, or complete daemon/CLI/UI integration. The private namespace requires one trusted authority and excludes concurrent mutation by other software with the same operating-system identity. Same-device mount ambiguity remains outside the qualified profile. All full-system acceptance gates remain required.
