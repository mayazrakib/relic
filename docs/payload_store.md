## 1. Durable Payload Ownership

The Unix artifact store supports separate manifest and payload intents for one capture. Both are prepared before source reads in the composed capture fixture. They use distinct generated filenames and capture-scoped lock names, so the manifest can commit while the payload remains under its live writer's ownership. A typed payload stage exposes only guarded, quota-limited writes and retains its operating-system lock until its file closes.

Payload storage reuses the manifest store's pinned directory, no-follow descriptor-relative operations, owner and mode checks, link-count restrictions, sampled free-space reserve, write quota, no-replacement publication, and file/directory synchronization. The current artifact class permits at most 1 GiB each of declared plaintext and ciphertext. Aggregate node/job disk and memory reservations remain caller responsibilities; the complete large-source pipeline still needs bounded segments or another qualified streaming provider.

The version-four journal binds payload ID, capture ID, endpoint, physical directory identity, generated relative filename, and immutable opaque key reference before creating ciphertext. One capture has one payload intent, including an abandoned intent. The journal retains terminal history and supports bounded pending queries. The caller resolves each recorded reference to the corresponding immutable key version; raw keys are absent from state.

## 2. Verified Commit and Reconciliation

Payload commit first requires a linked, sealed manifest artifact with exactly the capture's frozen digest and entry count. It authenticates the entire payload, verifies all file checksums and counts, and derives its strict logical manifest through a fresh bounded encrypted sorter. It hashes the exact authenticated ciphertext in that same read pass and checks unchanged file metadata around verification. Previously sealed payloads must match every recorded ciphertext and logical measurement before any native republishing.

The store publishes without replacing another inode, removes only a matching pending name, and synchronizes the directory. A local SQLite transaction then records the ciphertext digest and length, manifest identity, file count, payload byte count, and capture link. File publication and database commit remain separate durability boundaries. A database failure after publication returns an uncertain outcome and requires reconciliation.

| Observed state | Behavior |
|---|---|
| Complete pending payload, manifest not sealed | Keep prepared and refuse publication |
| Complete pending payload, matching sealed manifest | Authenticate, verify exact manifest, synchronize, publish, and seal/link journal |
| Matching pending and final hard links | Verify and remove only the matching pending link before journal sealing |
| Final file only with prepared journal | Verify and synchronize before journal sealing |
| Sealed journal with identical final bytes | Reverify and return the same record |
| Prepared journal without either registered file | Mark abandoned and preserve its immutable intent |
| Live writer, wrong key/reference/storage, corrupt or incomplete stream, conflicting inode, or changed sealed ciphertext | Refuse mutation, retain evidence, and require explicit recovery decisions |

The payload lock is reacquired before reconciliation and the journal is reread after acquiring it. Recovery uses a fresh disposable sorter. A failed verifier can contain provisional entries and must not be reused for publication. No incomplete or corrupt ciphertext is automatically removed, and no uncertain outcome causes a blind new write.

## 3. Evidence and Remaining Work

Tests cover native pending/linked/final process boundaries, a payload awaiting manifest commit, immutable reopen, independent manifest activity while a payload writer is live, wrong keys and storage, conflicting inodes, changed sealed ciphertext, missing files, quotas, and cancellation. The composed pinned capture reserves 16 MiB of data working memory and 16 MiB of spool before I/O, prepares both intents, streams encrypted payload and ordering data, commits the manifest first, drops the original sorter, verifies and commits the payload through a fresh sorter, and reopens/reconciles both records.

These are process-boundary tests, not power-loss, network-filesystem, sustained resource, or production archive qualification. The private directory requires one trusted authority and namespace exclusivity against other software with the same operating-system identity. The journal trusts measurements supplied by its low-level caller; the artifact store performs content authentication. Durable ownership does not implement key-provider lifecycle, retention/cleanup, a bounded production restore staging tree, archive/S3 adapters, distributed fencing, Windows storage, immutable native source views, or complete metadata. Enabled daemon jobs remain unavailable pending their execution gates.
