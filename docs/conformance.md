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
| Windows x86_64 | Native CI configured; hosted results pending | Named-pipe IPC, service/session integration, helper, UI, and recovery acceptance |
| macOS arm64 | Native CI configured; hosted results pending | APFS/helper, tray/session, metadata, and recovery acceptance |

Peer consensus, destination fencing, protected retention, replication execution, copy/mirror/sync, native snapshots, database and image recovery, desktop, sustained fault/resource tests, and packaging remain incomplete. No full security, resource, native UI, installer, or release conformance is claimed.
