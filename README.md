[![Implementation Branch CI](https://img.shields.io/github/actions/workflow/status/mayazrakib/relic/ci.yml?branch=implementation%2Frelic-full-system&label=implementation%20branch%20CI)](https://github.com/mayazrakib/relic/actions/workflows/ci.yml?query=branch%3Aimplementation%2Frelic-full-system)

## 1. Relic

Relic is a Rust backup and recovery system under implementation. The [specification](SPEC.md) defines the target; [conformance](docs/conformance.md) records actual evidence and remaining gates. The full system is not ready for protecting production data.

The current foundation includes executable contracts, deterministic identities, bounded calendar projection, durable local intents, and a Unix management daemon that stores disabled job definitions. Backup execution is not exposed through that daemon. A separate archive feasibility test exercises encrypted restic backups and independent rustic recovery.

## 2. Development

Use the toolchain pins in `.tool-versions`. Build and test with the committed Cargo lockfile. `.cargo/config.toml` limits compilation to one job and test execution to one thread.

On Linux with a user systemd manager, run checks through the enforced 1 GiB, zero-swap guard:
```bash
python3 tools/check.py test --locked --all-targets
```

The guard verifies a 1 GiB maximum and a 768 MiB pressure threshold inside the actual child cgroup, disables swap, and permits one guarded run at a time. Development and test profiles omit debug symbols and incremental compiler caches. Cargo and test parallelism remain one. The guarded Taskfile commands currently require Linux; native CI uses its platform runners separately.

Run heavy checks serially. A limit or timeout failure is not a passing acceptance result. The external-engine proof is explicitly ignored unless invoked with the verified tool paths described in [Archive Feasibility](docs/archive_feasibility.md).

## 3. Local Management

After building, start the Unix management service with a private state directory:
```bash
target/debug/relicd --state-dir ./build/development-state
```

Use a second terminal to inspect status or validate a job:
```bash
target/debug/relic --state-dir ./build/development-state --json status
target/debug/relic job validate ./job.toml
```

Validation does not complete endpoint, privilege, engine, or execution preflight. The management service rejects enabled job definitions until execution is implemented. Windows named-pipe management is not implemented yet. Native CI build/test results do not establish tray, helper, installer, or complete platform acceptance.

## 4. Implementation Goal

The [approved plan](docs/implementation_plan.md) and [goal state](docs/goal_state.json) preserve the complete agreed scope, acceptance gates, bounded retries, resource limits, and publication boundary. A partial implementation does not satisfy the goal.

## 5. License

Relic-owned code and documentation are licensed under the [MIT License](LICENSE). Third-party dependencies and external archive tools retain their own licenses and notices.
