## 1. Scope

The native CI workflow runs locked Rust 1.98.0 builds and tests on Linux x86-64, Windows x86-64, and macOS ARM64. It triggers on pushes and pull requests targeting `implementation/relic-full-system`. It does not publish releases or write to a protected branch. Each job uploads its checked-out commit, compiler details, coverage note, and available build and test logs.

## 2. Evidence Limits

The external archive engine integration test is marked ignored and reported as such in every CI job. Its opt-in local procedure requires independently downloaded and verified official restic and rustic binaries, as described in `docs/archive_feasibility.md`. A successful matrix does not prove that external archive test, a native user interface, platform helpers, crash recovery, resource limits, or complete specification conformance. Native runner results exist only after the workflow executes; local workflow validation does not establish them.

The `macos-15` runner is ARM64 and the `ubuntu-24.04` and `windows-2025` runners are x86-64 according to the [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Artifact contents may include test output, so tests and diagnostics must not print credentials or other secrets. GitHub reads Dependabot configuration from the default branch; this branch's configuration does not itself activate Dependabot until it is present there.

## 3. Completed Foundation Run

[Run 42796543305](https://github.com/mayazrakib/relic/actions/runs/42796543305) built and tested commit `925785e3f0a8a78e49999d15313bc2d77cb9f636` successfully on all three native targets. This verifies the SQLite bootstrap and macOS ancestor-path repairs for that foundation and the included embedded self-reader tests. External executable tests remained excluded. Subsequent manifest, resource, scanner, and restore changes require their own native CI evidence.
