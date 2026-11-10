## 1. Scope

The native CI workflow runs locked Rust 1.98.0 builds and tests on Linux x86-64, Windows x86-64, and macOS ARM64. It triggers on pushes and pull requests targeting `implementation/relic-full-system`. It does not publish releases or write to a protected branch. Each job uploads its checked-out commit, compiler details, coverage note, and available build and test logs.

## 2. Evidence Limits

The external archive engine integration test is marked ignored and reported as such in every CI job. Its opt-in local procedure requires independently downloaded and verified official restic and rustic binaries, as described in `docs/archive_feasibility.md`. A successful matrix does not prove that external archive test, a native user interface, platform helpers, crash recovery, resource limits, or complete specification conformance. Native runner results exist only after the workflow executes; local workflow validation does not establish them.

The `macos-15` runner is ARM64 and the `ubuntu-24.04` and `windows-2025` runners are x86-64 according to the [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Artifact contents may include test output, so tests and diagnostics must not print credentials or other secrets. GitHub reads Dependabot configuration from the default branch; this branch's configuration does not itself activate Dependabot until it is present there.

## 3. Completed Foundation Run

[Run 42796543305](https://github.com/mayazrakib/relic/actions/runs/42796543305) built and tested commit `925785e3f0a8a78e49999d15313bc2d77cb9f636` successfully on all three native targets. This verifies the SQLite bootstrap and macOS ancestor-path repairs for that foundation and the included embedded self-reader tests. External executable tests remained excluded. Subsequent manifest, resource, scanner, and restore changes require their own native CI evidence.

## 4. Scanner Fixture Finding

[Run 42799770445](https://github.com/mayazrakib/relic/actions/runs/42799770445) passed on Linux and Windows for `4b29fee`. macOS compiled and passed the preceding tests, including the restore primitives, but failed while creating a filename containing byte `0xff`: its test filesystem returned `Illegal byte sequence` before scanning began. The corrected shared fixture uses a filename accepted by all selected native filesystems. A separate Linux test retains real non-UTF-8 filename coverage. The corrected source requires a fresh native run; the failed job remains a recorded failure.

## 5. Capture Milestone Native Results

[Run 42803038693](https://github.com/mayazrakib/relic/actions/runs/42803038693) passed on Linux and macOS for `4de2f03`, verifying the scanner fixture correction. Windows failed to compile `tests/state.rs`: a `cfg(unix)` attribute attached to the shared capture helper instead of the Unix symlink test. The corrected placement keeps the helper available on Windows and excludes only the Unix test. Fresh native verification of that correction remains required.

## 6. Reduced-Memory Milestone

[Run 42806104925](https://github.com/mayazrakib/relic/actions/runs/42806104925) passed on Linux x86_64, Windows x86_64, and macOS arm64 for `7a2e98d`, including the Windows test correction. This verifies that milestone's native builds and selected component tests. Later pinned-capture integration changes require their own native run, and the external executable recovery tests remain outside default CI.

## 7. Pinned Capture Milestone

[Run 42807908209](https://github.com/mayazrakib/relic/actions/runs/42807908209) passed on all three selected native targets for `49ef734`. This covers the pinned source, encrypted sorting, manifest verification, and capture freeze integration included in that commit. Subsequent durable artifact ownership and reconciliation changes require a fresh native run. Windows artifact storage, production backup execution, and the remaining full-system acceptance gates are still unfinished.

## 8. Artifact Ownership Milestone

[Run 42813731012](https://github.com/mayazrakib/relic/actions/runs/42813731012) passed on Linux x86_64, Windows x86_64, and macOS arm64 for `8073389`. Unix jobs include the artifact store's process-boundary reconciliation tests; Windows compiles the unavailable-platform implementation and runs the portable journal tests. These results do not establish Windows artifact storage support or power-loss durability. Later source-payload changes require their own native run.

## 9. Source Payload Milestone

[Run 42815740853](https://github.com/mayazrakib/relic/actions/runs/42815740853) passed on all three selected native targets for `1da1879`. This covers the portable streaming payload tests and Unix pinned-source, source-deletion, and exact-manifest verification fixtures. Subsequent durable payload ownership and reconciliation changes require fresh native execution. These results do not establish Windows source scanning, production restore staging, or destination archive acceptance.
