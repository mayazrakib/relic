## 1. Approved Goal

Implement the complete bounded Relic system governed by `SPEC.md`, under MIT licensing, with Linux x86_64, Windows x86_64, and macOS arm64 native acceptance.

## 2. Finite Execution Controls

Each task has dependencies, concrete acceptance criteria, source fingerprints, attempts, and evidence in `goal_state.json`. Allow one initial check and at most two evidence-based corrective cycles per failure. Block only affected tasks after the bounded attempts and continue independent work. Reopen passing tasks only when relevant inputs change. Never turn a blocker into a pass or reduce mandatory scope.

## 3. Implementation Phases

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | Baseline and environments | Preserve initial source and specification fingerprint; MIT license and pinned local toolchain; Native runner inventory and bounded CI authority |
| 1 | Contracts and feasibility | Executable schemas and all five digest vectors; Independent encrypted backup/restore on each claimed native target; Measured archive index/resource and publication boundaries |
| 2 | Domain, state, and planning | Typed identities and immutable payload bindings; Distinct attempt, destination, and occurrence lifecycles; Durable migration, revision conflicts, intents and receipts |
| 3 | Standalone backup and recovery | Local and S3 encrypted archive with metadata reports; Selective and full restore with traversal defenses; Offline clean-environment independent recovery |
| 4 | Daemon, scheduler, and resource control | Authenticated local API and CLI; Restart, DST, retry and cancellation correctness; Finite memory, descriptors, streams and spool under fan-out |
| 5 | Protection, maintenance, and replication | Per-destination RPO/RTO and verification freshness; Guarded retention and last-good protection; Independent-key replica verified without source access |
| 6 | Copy, mirror, synchronization, and continuous operation | Safe ordinary-file copies and guarded mirror deletions; Conflict-preserving synchronization and tombstone horizon; Watcher overflow and periodic reconciliation |
| 7 | Native source consistency | VSS, APFS, and Btrfs native view capture; Helper ownership and crash cleanup; Exact achieved consistency and metadata-loss reports |
| 8 | Peer cluster and fenced execution | Authenticated enrollment, QUIC, and consensus membership; Scoped destination gateway admission and receiver fencing; One/two/three voter fault and uncertainty acceptance |
| 9 | Desktop application | Native three-tab tray UI independent of daemon; Inspect plans, restores, health and per-target outcomes; Theme, keyboard, screen reader, 200-percent text and resource evidence |
| 10 | Database and image adapters | SQLite, PostgreSQL and MySQL usable-state restore; Nonbootable volume/partition image on disposable media; Wrong-device and complete recovery-set protection |
| 11 | Security, performance, and sustained acceptance | Complete native recovery and adversarial corpus; Bounded fuzz and standalone/cluster soaks; Cold/warm resource and incremental-detection performance gates |
| 12 | Native packaging and final qualification | Three native installer lifecycle and recovery tests; SBOM, MIT/dependency notices and artifact/source linkage; All required conformance evidence passes with no waivers |

## 4. Verification and Stop Conditions

Use the test deadlines in the ledger, deterministic fixtures, and separate evidence for native execution, cross-compilation, packaging, performance, and recovery. Limit optimization to three measured candidates per subsystem, with explicit keep-or-revert decisions. A full completion claim requires every mandatory gate and selected profile to pass.

## 5. Publication Boundary

Use tested local milestone commits and CI pushes only on `implementation/relic-full-system`. Preserve `master`. Merging, tagging, release publication, and deployment require separate instructions. Imaging tests use only disposable media; bootable bare-metal recovery is excluded.
