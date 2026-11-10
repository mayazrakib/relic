## 1. Private Native Run Ownership

The Linux `NativeRunStore` owns a generated private native repository, scratch directory, and worker-owner lock beneath a pinned storage endpoint. Schema seven records the run, capture, frozen manifest, source catalogue, storage and key references before creating the run container. It records the container identity before creating its children and records their identities before execution.

This is a private archive stage. The run journal and worker report do not authorize final destination publication or constitute a fenced destination receipt. Enabled archive jobs remain gated.

## 2. Finite Lifecycle

| State | Permitted progress |
|---|---|
| `prepared` | Create an absent generated container; preserve an unexplained existing container |
| `staging` | Reopen the recorded container and finish an empty owned layout |
| `ready` | Permit the run's single creation attempt |
| `running` | Require owner exclusion and reconciliation after interruption |
| `unknown` | Verify existing native effects; never initialize another repository |
| `verified` | Retain the immutable snapshot identity; permit complete reverification |
| `abandoned` | Terminal journal state; no automatic deletion |

A creation attempt is recorded before launching the worker and is never repeated for that run. Failed verification is recorded once per running-to-unknown transition. Three failed verification attempts prevent another verification attempt; successful verification clears the consecutive failure count. Key references and the sealed source measurements remain immutable. Pending-run enumeration is paginated.

The create request can read the owned encrypted source and write the private repository. Recovery verification receives no source-directory grant, a zeroed unused source key, and a read-only repository grant. Both operations use independently generated ephemeral encryption keys for disposable manifest ordering. Recovery requires exactly one tagged native snapshot and compares its complete decoded content with the original frozen manifest. An existing journal flag or snapshot identifier alone does not establish success.

## 3. Ownership and Uncertain Termination

A parent coordination lock serializes store instances. A separate owner lock remains held in the worker through archive creation, full read-back verification, and repository synchronization. After acquiring it, the worker rereads the exact run record to reject an authorization observed before an intervening transition. Every reopening checks the recorded container, repository, scratch, and owner-lock identities.

An unreaped process returns an owned recovery handle containing its child and cgroup. The store retains that handle, a clone of the parent coordination lock, and the entire stage reservation. Another store instance cannot reconcile the same run while that lock remains held. Bounded explicit reaping releases the reservation only after both child exit and an empty cgroup are proved. Dropping a store with an unproved live worker conservatively retains its lock and reservation until controller termination rather than admitting replacement work.

Controller startup still needs whole delegated-scope quiescence and reconstruction of persistent node-wide resource accounting. Per-operation reservations cover active work; repositories and interrupted scratch retained on disk require separate durable quota and cleanup management. Current process-level tests do not qualify controller restart in every kernel failure mode or power-loss durability.

## 4. Byte and Durability Boundaries

The backend serializes writes, charges their complete checked byte lengths before delegation, permits at most 10,000 write calls, and never refunds a failed write. A quota failure or failed native write poisons subsequent mutations. Verification rejects create, write, remove, and warm-up mutations. Native removes are unavailable in both profiles.

The current per-run repository budget is twice the frozen payload size plus 16 MiB, capped at 512 MiB. Admission also reserves 8 MiB of active sorting space and requires the larger of a 512 MiB or five-percent filesystem reserve. These are restricted staging limits, not large-source performance qualification or total persistent-disk quotas.

Before reporting success, the contained worker synchronizes a bounded native repository tree. Traversal rejects special files, links, cross-device entries, excessive depth, excessive entries, and excessive bytes. It checks each opened entry against its parent-relative identity and rejects changed file or directory generations around synchronization. Blocking filesystem synchronization remains inside the killable worker rather than in the supervisor's post-worker completion path.

## 5. Acceptance Evidence and Remaining Work

The source-deletion fixture creates the native archive, simulates loss of the completion response, removes the encrypted source stage, reopens the store, and verifies the same single snapshot without recreating the repository. Independent restic checking and restoration validate the retained native archive. Journal and filesystem tests cover immutable bindings, schema migration, failed-verification limits, preexisting containers, replaced slots, interrupted layout preparation, and exclusive ownership. A delegated-cgroup regression disables only its disposable child's kill control to exercise retained recovery ownership, then restores the control and proves reaping.

The [evidence record](evidence/native_run_store.json) records actual source fingerprints and validation results. Durable cleanup and disk quotas, destination fencing and receipts, provider durability, native containment outside Linux, source metadata and full names, S3, large-index performance, and all remaining system phases remain incomplete.
