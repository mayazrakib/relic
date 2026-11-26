## 1. Manifest Artifact Ownership

The Unix artifact store owns a private directory through a pinned local endpoint. A journal binding identifies the artifact, capture, storage endpoint and device/inode identity, generated relative filename, and opaque key reference. Preparation is durable before creating the pending ciphertext file. A capture-scoped operating-system lock excludes a live writer from reconciliation. The stage exposes `Write` without exposing its underlying file descriptor, checks cancellation, and rejects writes beyond its ciphertext quota.

The caller resolves the recorded key reference to the correct key version. Key bytes are never stored in the journal. The store requires an owner-controlled 0700 directory, 0600 regular files, restricted hard-link counts, and no-follow descriptor-relative file operations. Its limits allow at most 1 GiB per artifact and retain the greater of 512 MiB and 5% of observed filesystem capacity. The caller still owns aggregate resource reservations, grants, namespace exclusivity against other same-user software, and provider-specific storage qualification.

## 2. Sealing and Recovery

Commit synchronizes ciphertext, authenticates the complete manifest under its capture binding, computes the ciphertext checksum in the same read pass, and checks previously frozen identities. It creates the final name without replacement, verifies inode identity, removes the matching pending name, and synchronizes the directory. A local SQLite transaction then marks the artifact sealed and freezes the capture digest, entry count, and artifact link. The filesystem operation and database transaction are separate durability boundaries.

| Observed journal and files | Reconciliation behavior |
|---|---|
| Prepared, valid completed pending file | Verify, synchronize, publish without replacement, and seal/link state |
| Prepared, matching pending and final hard links | Verify, remove only the matching pending link, synchronize, and seal/link state |
| Prepared, valid final file only | Verify, synchronize, and seal/link state |
| Prepared, neither file present | Mark the artifact abandoned; retain its immutable ownership record |
| Sealed, exact registered final bytes | Verify and return the same journal record |
| Live writer, wrong key reference, corrupt bytes, conflicting inode, or changed sealed identity | Refuse mutation or return a reconciliation error; preserve files and historical state |

Incomplete or corrupt files remain queryable and are not automatically erased. A storage or database failure after file publication can leave an uncertain outcome. Recovery inspects the registered names and validates their contents; it does not blindly start another write. Abandoned artifacts cannot be reopened under the same capture through this protocol. Provider-aware successor capture and cleanup decisions belong to the executor.

## 3. Evidence and Limits

The tests simulate process restart at pending-file, linked-file, and final-file boundaries, immutable reopening, live-owner exclusion, wrong keys, corruption, quota failure, and conflicting or changed files. These are process/state boundary tests, not power-loss or remote-filesystem durability proof. `sync_all` acknowledges the platform filesystem API; controller and network storage guarantees require separate qualification.

The journal stores caller-supplied evidence and does not authenticate files by itself. The artifact store performs that verification before sealing. Native key-store integration, production source-payload backup, retention of lock and journal history, coordinated cleanup, distributed fencing, and Windows storage support remain unfinished. A manifest artifact contains metadata and file digests; it is not a backup of the referenced file payloads. Enabled daemon jobs remain unavailable.
