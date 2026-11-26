## 1. Scope

The optional embedded archive experiment uses `rustic_core` 0.13.0 and `rustic_backend` 0.7.0 with their default features disabled. It initializes a local restic-format version 2 repository, creates a snapshot, checks repository data, and restores it. The test compares a small file, a 1 MiB fixture, and Unix file mode where supported. Passwords come from a private test file and are not passed as command arguments.

The released crate's README examples use older method signatures. This experiment uses the 0.13.0 source signatures for explicit credentials and backend references. Both crates are licensed Apache-2.0 OR MIT and require Rust 1.91 or newer.

## 2. Verification Limits

This is an isolated feasibility experiment, not a production adapter. It has no enforced memory or thread budget, cancellation, persistent admission journal, idempotent publication reconciliation, destination fencing, or safe restore path-race proof. It does not establish concurrency safety, crash durability, throughput, broad metadata preservation, or production native behavior. The caller must use an isolated repository, private credentials, and a new restore destination. No production daemon should call this experiment before those contracts are implemented and verified.

Compilation and test execution require the opt-in `embedded-archive` Cargo feature. They must run under the host resource restrictions. The Linux x86_64 opt-in proof compiled and passed under an enforced aggregate 2 GiB memory cap with swap disabled. The compilation plus proof reported a peak of approximately 1.4 GiB and zero swap. A subsequent state/service/contracts run with this feature passed and reported approximately 1.6 GiB including recompilation. Those observations do not establish the production balanced resource class, large-index scaling, or other native platforms.

## 3. Independent Recovery

The explicitly selected `independently_recovers_embedded_archive_without_source` test creates an embedded-engine repository, removes the source and the engine's restore tree, then checks and restores the repository with the separately verified restic 0.19.1 executable. It compares file bytes and Unix mode. Both embedded tests passed on Linux under the 2 GiB, zero-swap envelope, with an observed validation peak of approximately 1.1 GiB. This is small-fixture interoperability evidence; it does not establish complete clean-machine disaster recovery, all metadata classes, or native independent-tool interoperability on Windows or macOS.

The independent test is ignored by default because it requires `RELIC_TEST_RESTIC`. Explicit selection fails when that executable is missing; the test never treats an unavailable independent reader as success.
