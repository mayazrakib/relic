## 1. Implementation Status

Relic has a qualified foundation, not a conforming full-system release. The [goal state](goal_state.json) preserves every required phase. The [requirements inventory](requirements.json) still requires obligation-by-obligation applicability and evidence review. Passing component tests does not complete a profile.

## 2. Executed Foundation Evidence

The [foundation evidence](evidence/foundation.json) binds the tested source fingerprint, fixtures, toolchain inputs, memory policy, and remaining gates. The final Linux run passed 28 tests, including an explicit encrypted backup and independent restore proof. Clippy with warnings denied and formatting checks passed. Default native CI excludes the external-engine proof as an explicitly ignored test.

| Component | Executed evidence | Limit |
|---|---|---|
| Contracts | Four offline schemas, five digest domains, extraction drift and rejection tests | Complete planner and adapter conformance remains pending |
| Identity and lifecycle | Immutable binding and receipt aggregation tests | In-memory models are not distributed authority |
| Configuration | Bounded parsing, duplicate/depth rejection, defaults, replica and objective checks | Endpoint grants and actual capabilities require execution preflight |
| State | Private local SQLite, migration race, durable request keys/intents/receipts, recovery paging | No automatic known-no-effect reconciliation or destination fencing |
| Calendar | Sydney gaps/folds, nominal identity, bounded search and catch-up | No background job dispatcher yet |
| Management | Real Unix daemon/CLI, nonce and OS credentials, private socket, disabled job persistence | Enabled jobs and Windows IPC are unavailable |
| Archive proof | restic 0.19.1 encrypted format-2 repository, full check and restore; independent rustic 0.11.4 restore | Tiny Linux fixture, not production adapter or resource/fencing proof |

## 3. Host Memory Policy

All heavy local validation runs serially in a user systemd cgroup with `MemoryMax=2G`, `MemorySwapMax=0`, `TasksMax=128`, and `CPUQuota=200%`. Compilation uses one job; tests use one thread. The actual probe process read `memory.max=2147483648` and `memory.swap.max=0`. The largest reported validation peak was approximately 1.4 GiB, with no swap used. A later cached full proof run peaked at 119.8 MiB. These measurements establish the development envelope, not the application's release performance targets.

## 4. Native and Release Gaps

| Target | Current evidence | Remaining gate |
|---|---|---|
| Linux x86_64 | Local foundation tests and tiny engine interoperability proof | Production archive, S3, native helpers, desktop, performance, and installed-artifact acceptance |
| Windows x86_64 | Foundation native build and tests pass at `925785e` | Named-pipe IPC, service/session integration, helper, UI, and recovery acceptance |
| macOS arm64 | Foundation native build and tests pass at `925785e` | APFS/helper, tray/session, metadata, and recovery acceptance |

Peer consensus, destination fencing, protected retention, replication execution, copy/mirror/sync, native snapshots, database and image recovery, desktop, sustained fault/resource tests, and packaging remain incomplete. No full security, resource, native UI, installer, or release conformance is claimed.

## 5. Native CI Findings and Embedded Proof

The first native CI run for `fac92d9` passed on Linux. Windows failed concurrent SQLite initialization with `DatabaseBusy`; macOS failed daemon startup before readiness. Those are recorded failures, not platform acceptance. Repairs serialize WAL/migration bootstrap with a bounded private file lock and canonicalize a validated directory while retaining no-follow and ownership protection. A Linux regression covers trusted ancestor aliases and final-directory symlink rejection; fresh native results are still required.

The opt-in embedded `rustic_core` 0.13.0 proof compiled and restored tiny and 1 MiB content on Linux, with full data checking and Unix mode comparison. It ran under the fixed 2 GiB, zero-swap envelope. Subsequent feature-enabled state/service/contracts tests passed, with a reported compilation/test peak of approximately 1.6 GiB. This is feasibility evidence; engine-level limits, cancellation, independent interoperability for embedded-produced archives, and production publication safety remain incomplete.

The repaired source and embedded engine pass 30 local tests with all selected test cases explicitly executed, plus feature-enabled Clippy with warnings denied. The [embedded proof evidence](evidence/embedded_archive.json) records source hashes and the 2 GiB, zero-swap envelope. The final full feature run reported approximately 1.3 GiB peak; earlier feature-enabled recompilation peaked at approximately 1.6 GiB. Neither observation establishes production engine memory bounds.

The repair [native CI run](https://github.com/mayazrakib/relic/actions/runs/42796543305) subsequently passed on Linux x86_64, Windows x86_64, and macOS arm64 for `925785e`. The prior failures are resolved for that foundation. Later changes require fresh native verification.

## 6. Bounded Manifest and Restore Work

The manifest validator and disk-backed sorter have focused Linux tests covering canonical digests, native component ordering, invalid paths, count and size bounds, SQLite exhaustion, and poisoned-spool rejection. Resource accounting tests cover atomic hierarchical admission, shared charges, concurrent limits, cancellation, and deadlines. The Unix regular-file restore tests cover verification, cancellation cleanup, no replacement, pinned handles, and staging-path replacement. These components do not establish complete source capture, scheduler integration, protected publication, or full restore conformance.

An explicitly selected independent-reader test also checks and restores an embedded-produced archive with restic after deleting the original source and the embedded engine's restore tree. It passes on Linux for a small content-and-mode fixture; broad independent disaster recovery remains pending.

The [bounded-primitives evidence](evidence/bounded_primitives.json) binds the current sources to 60 passing Linux tests with zero ignored, feature-enabled Clippy with warnings denied, and formatting checks. The combined test run reached the enforced 2 GiB aggregate cgroup limit with no swap; a live sample recorded approximately 204 MiB anonymous memory and 1.75 GiB file cache, with zero OOM kills. That sample is not a peak RSS measurement. The best-effort Unix scanner now streams regular files and directories into the sorter under finite depth, descriptor, entry, and byte limits, but snapshots, links, metadata, untrusted-source isolation, resource-pool integration, and production publication remain incomplete.
