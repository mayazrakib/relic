## 1. Scope

This is a local feasibility prototype, not a release archive adapter. It exercises an encrypted restic-format repository and an independent reader. It does not establish the resource, authority, restore-safety, or recovery contracts in the specification.

## 2. Engine Assessment

[`rustic_core` 0.13.0](https://docs.rs/crate/rustic_core/0.13.0) is licensed Apache-2.0 OR MIT and requires Rust 1.91. Its documented API supports tagged backup and restore; the local compiler is Rust 1.98. The published examples do not establish hard memory limits, cancellation, or fenced publication. The initial executable-prototype milestone did not build embedding. A subsequent opt-in embedded proof now builds and restores locally; see [Embedded Archive](embedded_archive.md). No large-workload benchmark has been completed. The prototype instead invokes restic 0.19.1 and initializes repository format version 2. This does not establish that an executable meets those missing guarantees.

The local Linux x86-64 binaries were downloaded from the official release assets. The SHA-256 of `restic_0.19.1_linux_amd64.bz2` is `f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c`; that of `rustic-v0.11.4-x86_64-unknown-linux-musl.tar.gz` is `628b26785f3787fa1d52e61b3289493f483230a1ed6e86a84ae9c76d7a41a81e`. The assets were checked against the corresponding GitHub release API digests. They are ignored local tools, not distribution artifacts.

## 3. Boundaries

The prototype limits captured output and applies a direct-child deadline. It cannot enforce a process memory budget, guarantee descendant termination or a deadline when descendants retain output pipes, or provide cooperative cancellation. It has no authority journal, fencing, safe cluster failover, secure restore path traversal proof, overwrite plan, or persistent intent and receipt. Callers must serialize all repository mutations, provide stable payload identities derived from an immutable source view, and never retry a write whose outcome is unknown. Snapshot tags permit subsequent discovery and conflict detection, but cannot prevent a concurrent duplicate or prove that an absent snapshot means an earlier writer stopped. Do not expose this prototype as a compliant backup service.

The Linux x86-64 integration test passed with the two release binaries. It used disposable credentials, checked restored content and Unix mode, ran restic's full data check, and listed and restored the snapshot with rustic 0.11.4. The test is ignored by default and requires `RELIC_TEST_RESTIC` and `RELIC_TEST_RUSTIC` to name verified binaries when run with `cargo test --test archive -- --ignored`. The tiny fixture is not a throughput or resource benchmark. It does not establish native Windows or macOS behavior, broad metadata preservation, performance, or durability after crash.
