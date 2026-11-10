## 1. Scope

Schema nine introduces the trusted local publication journal; schema ten adds owned local initialization and durable process-scope identity. Together they record resource authority, publication admissions, ordered physical executions, and correlated receipts, and integrate one bounded Linux repository initializer. Final publication control, source and destination verification, accepted-effect draining, and daemon dispatch still need qualification. Enabled archive jobs remain gated.

## 2. Resource Authority

A resource binds its local authority identity, endpoint identity, physical storage identity, and opaque repository-key reference. Physical storage identities are unique across resource records. A prepared resource learns one immutable native repository identity before becoming ready. Positive receiver epochs and fencing generations are stored as canonical decimal strings and compared as integers.

Fence installation requires a strictly higher generation and a nondecreasing epoch. An unresolved execution prevents advancement. A blocked resource can become ready through an explicit higher-fence installation only when its repository identity is known and no accepted effect remains unresolved. The caller still needs actual old-writer exclusion before making that transition. A journal counter or an exclusive repository lock alone does not establish destination fencing.

Filesystem ancestor overlap, alternate mutation prefixes, quorum authorization, maintenance domains, and receiver replacement require controller and backend evidence beyond the unique exact storage identity currently stored here.

## 3. Immutable Publication Admissions

An admission binds one resource and admission identity to the existing logical publication key and payload hash, a verified private native run and snapshot, the frozen capture and manifest, and an executor owner. It persists the originally accepted epoch and fence, a fixed publication request type, and an accepted decision. A resource/key replay returns the same admission binding. A different admission identity, payload, owner, source, or effective policy conflicts.

The admission includes the planner's effective-policy preimage. Its exact six-field structure, relevant job and destination identities, native repository binding, method, and verification level are checked. The canonical preimage is limited to 64 KiB and hashed in the existing effective-policy domain; it must match the immutable publication policy digest. Receipt requirements are derived from that bound policy instead of an independently supplied weaker verification flag. Replication admissions require full-data verification.

Physical discovery, endpoint and grant revisions, secret-provider authority, and the validity of the planner's observations remain caller obligations. These trusted Rust APIs are not an authenticated public request surface.

## 4. Execution History and Receipts

Each admission can append at most three ordered executions. An execution records its resource, current epoch and fence, and effect state before protected work. The database permits at most one active, unknown, or published-unverified execution for a resource. Another mutation cannot begin while such an execution exists.

| State | Meaning |
|---|---|
| `active` | An accepted physical execution can have effects |
| `unknown` | Accepted effects require reconciliation; absence of a response does not prove absence of publication |
| `proven_unpublished` | A trusted caller established the no-publication condition; a bounded execution retry can append to the same admission |
| `published_unverified` | A native result is known and immutable, but full required verification and receipt completion remain pending |
| `verified` | The correlated publication receipt and execution completion were committed atomically |

The trusted caller supplies physical proof before reporting a native result or proven absence. This journal cannot discover that proof by itself. Repeated transition calls can return a conflict; a caller can read the recorded state and continue reconciliation without recreating an effect. Receipt replay returns the original receipt. A receipt cannot change the execution's native result or weaken the policy's verification requirement.

Receipt completion checks the logical key, payload hash, capture, manifest, source view, consistency, destination revision, policy digest, resource, original execution epoch and fence, admission identity, native repository, and native result. Publication and execution verification update together. Legacy publication state and receipt APIs reject gateway-bound keys, including an atomic SQL exclusion condition that closes a concurrent admission race.

## 5. Strict Native Snapshot Discovery

Linux gateway discovery uses a bounded physical census of the pinned native `snapshots` directory and authenticates each snapshot through its exact full native ID. It rejects invalid names, links, special files, unreadable entries, excessive counts, zero or excessive ciphertext, and changed file/directory generations. A second census checks that the snapshot set and identities stayed unchanged across decoding. The caller owns serialization and exclusion of external writers.

Limits cover at most 1,024 snapshot entries, a caller-selected aggregate ciphertext budget up to 16 MiB, and cumulative serialized snapshot metadata up to 8 MiB. The current private archive worker uses a 1 MiB aggregate ciphertext allowance. Metadata counting writes into a bounded sink and does not allocate a second metadata buffer. These limits bound retained logical content, not transient native decoding or allocator overhead; the physical worker memory cap remains necessary. Large-index and compression-expansion qualification are still pending.

The pinned SDK has distinct discovery paths. Its direct full listing propagates snapshot decryption failures. Time-based selectors can log and skip those failures, while the local backend's filename scan can omit malformed entries and filesystem-walk errors. The regression explicitly distinguishes these behaviors. Gateway reconciliation uses neither a time-based selector nor a best-effort negative scan to establish that a publication is absent.

## 6. Owned Local Initialization

Schema ten binds a prepared resource to one zero-length private owner lock and one private scratch directory before the initialization attempt. The parent pins each directory and lock slot, serializes controllers through a coordination lock, checks the canonical state database, and validates separate state, executable, and repository scopes. The initializer can run once; an uncertain result requires inspection of that repository, never another initializer. Completing an initialization while the resource is blocked retains the blocked state.

The Linux worker receives passwords only through a bounded private pipe. The parent records the exact delegated cgroup identity before its first fork, and the mutating worker independently compares that record with its current kernel scope before using the repository credentials. The identity includes a domain-separated machine marker, boot identity, cgroup namespace, and pinned parent and worker inodes. Matching machine markers assume unique machine IDs; they do not attest hardware identity.

Recovery first closes an unbound launch transaction or stops the recorded scope and removes the empty cgroup. Removing the scope also prevents an initializer delayed before attachment from entering it later. These properties follow the kernel's [cgroup lifecycle and kill semantics](https://www.kernel.org/doc/html/v6.18/admin-guide/cgroup-v2.html). A concurrent trusted runtime reaper may remove the same original scope; recovery still requires evidence that the original scope is offline and its pathname is absent. Permission errors, replacement paths, and ambiguous identities do not establish quiescence.

This recovery profile requires an exclusively controlled local ext4, Btrfs, or XFS repository, a trusted delegated controller that does not rename or migrate worker scopes, and workers denied cgroup escape. A boot change proves only that local processes and cgroup handles cannot survive. It does not drain remote filesystem or object-store requests, exclude another host, authorize quorum replacement, or establish shared-storage fencing.

Linux scope comparison retains pinned ancestor checks and uses bounded kernel mount information to translate bind-mounted paths into filesystem origins. Same-device origin prefixes overlap even when namespace ancestors hide that relationship. Unknown filesystems, nested mounts, malformed mount data, or a changed mount view prevent a disjointness claim. This avoids treating a separate mount ID as sufficient proof of separation.

Initialization and inspection run inside the existing hard worker memory, task, descriptor, output, and deadline limits. Repository and directory synchronization occur inside that worker. Unknown live workers retain their active reservations and parent coordination lock until exit is proved. Final retained backup bytes are not staging bytes; durable scratch accounting and concurrent destination capacity reservations remain required before enabling publication.

## 7. Acceptance and Remaining Work

The [evidence record](evidence/gateway_journal.json) records actual validation and source fingerprints. Fixtures cover changed admission bindings and policy preimages, concurrent admission and execution, stale fences, unresolved effects, bounded append history, blocked-resource recovery, weak replication policy, receipt mismatches, and schema migration. Native archive fixtures exercise authenticated discovery, corrupt snapshots, invalid physical names, exact content verification, and independent restoration.

The local controller now integrates owned initialization and restart inspection. Copy and verification worker bodies are compiled but still require actual publication-controller integration and native interoperability tests. The next required vertical integration is a source pin, complete source verification before writes, tagged native copy, fresh destination verification, correlated receipt completion, and uncertain publication-worker lease retention. Safe negative reconciliation and retry must preserve the original admission and execution history. Shared failover remains unavailable without backend-specific exclusion proof.

File-archive incremental qualification also needs stable native chunking across private stages and their final repository. The pinned SDK's ordinary initializer selects a new Rabin polynomial; native copy preserves existing blob boundaries. The inference is that unrelated fresh staging configurations can reduce cross-occurrence deduplication. A future file-archive stage should use the final repository's authenticated chunker parameters with its own distinct native repository identity, and qualify incompressible unchanged and sparsely changed data. Replication of already committed snapshots has different provenance and must preserve its source identities. This source inspection is not a measured deduplication result.

No final destination publication, retention, pruning, repair, S3 gateway, quorum claim, maintenance admission, native receipt durability, or full-system acceptance is established by this journal checkpoint alone.
