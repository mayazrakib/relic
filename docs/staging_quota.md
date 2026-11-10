## 1. Durable Staging Reservations

Schema eight adds a node-wide SQLite ledger for owned manifest ciphertext, captured payload ciphertext, encrypted archive-source stages, and private native runs. Reservations precede data files and per-stage lock creation. They survive completed operations, abandoned records, process interruption, and reopened state connections. Dropping an active resource lease does not release a durable disk reservation.

The ledger admits at most 1 GiB across these objects and at most 10,000 object reservations. Each immutable binding includes the object kind and identity, endpoint identity, pinned filesystem identity, volume identity, and maximum bytes. Repeating an exact binding does not charge twice; changing its maximum or ownership requires a distinct recovery decision rather than silently enlarging or shrinking an existing charge.

## 2. Admission and Volume Aliases

Admission runs in an immediate SQLite transaction. Checked sums prevent integer overflow and concurrent connections cannot independently consume the same remaining allowance. Canonical Unix device identities group endpoint aliases on the same filesystem. Storage identities include both device and inode and are checked against pinned endpoints by filesystem callers.

The free-space calculation conservatively requires all reservations on that volume plus the greater of 512 MiB or five percent of its capacity. It includes already written objects again instead of assuming every outstanding reservation is still unwritten. This can reject work early. Exact reservation replays also check the current inventory gate, aggregate allowance, and actual filesystem capacity; an old successful reservation does not bypass later storage pressure.

These charges describe logical ciphertext-byte bounds. They do not measure allocated filesystem blocks, directory metadata, inode consumption, or arbitrary external-writer effects. Native source/file counts and bounded repository traversal constrain their own profiles, but complete physical storage qualification and administrator-enforced filesystem quotas remain separate acceptance work.

## 3. First Use and Legacy Inventory

A new empty operational database starts with no legacy inventory obligation. Before its first reservation against a physical storage root, the filesystem helper verifies the actual pinned identity and requires the root to be empty. It preserves and rejects a nonempty unregistered root and durably closes the node inventory gate, so switching to an empty root cannot bypass that unresolved storage. Reopening already registered storage retains the prior charges.

Upgrading a database that already contains manifest, payload, source-stage, or native-run intents closes the inventory gate. Read access remains available, while new or replayed writing reservations stop. A trusted inventory caller can record verified legacy ownership while the gate is closed. Completion checks every relevant journal row has a matching charge and checks persisted ciphertext measurements against those charges. Unknown files, partial files, native repository sizes, and physical ownership remain the inventory caller's responsibility.

Legacy inventory can record usage exceeding the new allowance so that recovery does not misrepresent it as zero. Such usage blocks normal reservation admission. A verified charge is never automatically released, including for abandoned rows. Cleanup needs a separate owned-file protocol proving removal and directory synchronization before a transactional credit; that protocol is still pending.

Device numbers identify live filesystem aliases; they do not establish stable removable-volume identity across arbitrary remounts or device reuse. A single canonical operational database and external-writer exclusion are required. A newly replaced database, extra files introduced after storage registration, delegated-scope startup quiescence, and full physical inventory still require controller-level qualification before enabled jobs.

## 4. Store Integration

Manifest and payload stores reserve their declared ciphertext maxima before creating pending files. Recovery preserves the same immutable reservation. Source staging reserves its entire encrypted-file allowance plus the bounded catalogue allowance before creating its per-stage owner lock or data files. A rejected source reservation leaves no per-stage lock or ciphertext.

Native runs reserve their repository allowance plus 8 MiB of scratch before preparing the private layout. Worker verification accounts retained scratch-file lengths before assigning the remaining encrypted-sort allowance. An interrupted sort therefore reduces the next sort's budget rather than granting another full scratch allowance. Uncertain native effects keep the durable charge alongside the separate active worker reservation when termination remains unproved.

Disposable capture ordering, private plaintext restore trees, complete metadata and block accounting, durable quota credits, administrator capacity changes, and complete startup reconciliation remain outside this checkpoint. Enabled archive jobs remain gated.

## 5. Evidence

The [quota evidence](evidence/staging_quota.json) records actual source fingerprints and validation. Focused fixtures cover concurrent quota admission, same-volume aliases, changed bindings, free-space loss on replay, legacy migration and inventory, persistent abandoned charges, unregistered populated roots, and reopened storage. The composed capture/source fixture releases every active source lease, verifies its durable charges remain, reopens the database, and rejects a further stage before any stage lock or data file appears.
