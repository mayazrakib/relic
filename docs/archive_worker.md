## 1. Contained Private Archive Execution

A *contained archive worker* is a short-lived process that reads an owned encrypted archive source, creates a private native repository, and verifies its complete snapshot against the frozen manifest before returning a bounded report. The Linux implementation embeds the pinned archive SDK in `relic-worker`. Parent cancellation controls the process and its descendants rather than depending on SDK callbacks to interrupt blocking work.

This remains private staging. Durable worker-run ownership and reconciliation, destination admission and fencing, native destination receipts, production daemon integration, and complete release qualification remain required before enabled archive jobs.

## 2. Aggregate and Worker Budgets

The development guard now delegates CPU, memory, and process controllers inside the existing bounded validation service. It moves Cargo into a supervisor leaf and creates worker groups beneath that same service. Both supervisor and workers therefore remain subject to the aggregate 1 GiB maximum, 768 MiB pressure threshold, zero-swap setting, 128-task ceiling, and two-CPU quota. Validation commands also have a finite 900-second service deadline. Longer acceptance profiles need their separately bounded execution configuration.

The runtime sets child limits before executing worker code and reads back the configured memory and process limits. The archive worker independently checks its actual membership and envelope before reading its request and before SDK filesystem work. The following limits describe the current implementation:

| Resource | Limit |
|---|---|
| Generic worker memory maximum | 16 to 256 MiB, within the aggregate parent limit |
| Native integration worker maximum | 192 MiB |
| Native integration pressure threshold | 144 MiB |
| Worker CPU quota | One CPU |
| Worker tasks and descriptors | At most 64 each |
| Request body | 64 KiB |
| Report body | 16 KiB |
| Generic captured output | At most 64 KiB per pipe |
| Parent polling interval | 5 ms |
| Termination and reaping window | 2 seconds |

The generic runtime permits the pressure threshold to equal the hard maximum. The forced-OOM regression uses that configuration to exercise the hard limit directly; otherwise pressure throttling can delay exhaustion until the wall-time deadline. The native archive profile requires its lower pressure threshold. Physical containment does not establish efficient large-index behavior or prove that every repository fits the selected budget.

## 3. Filesystem and Process Restrictions

Linux filesystem grants use [Landlock's inherited access rules](https://www.kernel.org/doc/html/v6.18/userspace-api/landlock.html). The parent grants explicit source directories for reading and the private staging repository for writing. Runtime setup requires Landlock ABI 3 or later and fails closed when required controls are unavailable. The tested host provides ABI 7. Readable runtime libraries, selected public system configuration files, the executable, the worker's own proc directory, and cgroup evidence are granted separately.

A seccomp filter rejects sockets, namespace creation and entry, mount manipulation, process inspection, interprocess signal operations, keyring operations, and selected permission, ownership, and extended-attribute mutation syscalls. Legacy thread creation remains available with namespace flags rejected; `clone3` returns `ENOSYS` for the supported thread-library fallback. The filter checks the x86-64 syscall architecture and rejects the alternate x32 syscall range. Core dumps, inherited capabilities, ambient capabilities, and privilege gains are disabled. The archive binary disables process dumpability before reading keys. Its request and fixed diagnostics do not place keys or repository passwords in arguments or environment variables.

The worker cannot write cgroup controls, move itself into the supervisor group, enlarge its memory limit, or modify cgroup-control permissions through the tested paths. Source grants are read-only while repository writes remain available. The policy is a tested profile for private offline archive execution, not a complete security certification or a network-capable provider sandbox. Other selected operating systems still require native containment implementations.

## 4. Read-Only Source State

`StateStore::open_readonly` opens the current schema without initialization, migration, bootstrap-lock writes, or sidecar creation. It requires existing private database, WAL, and shared-memory files. The parent retains a writable connection while the worker runs, keeping those files available. Reader flags, query-only mode, and filesystem read grants enforce the source-state boundary. Missing sidecars or an unsupported schema fail instead of silently ignoring live WAL data.

Reopening sealed archive sources takes an existing lock through a read-only descriptor. It does not recreate a missing source lock. Linux endpoint resolution now pins ancestors with `O_PATH` and grants a readable directory handle only to the selected endpoint. This supports identity-chain verification without broad permission to list ancestor directories. Existing endpoint and restore regressions remain part of the full suite.

## 5. Bounded Control and Uncertain Outcomes

The request is a length-prefixed JSON object with strict unknown-field rejection, exact end-of-input checking, bounded fields, and zeroized owned key/password buffers. The parent closes the input pipe after transfer. Nonblocking reads and writes prevent a child that ignores input or leaves inherited output pipes open from hanging the controller. Output exhaustion, cancellation, deadline expiry, failed processes, memory-limit events, or incomplete kernel evidence stop successful completion.

After launch, an error produces an *unknown outcome*: private repository effects may already exist and require reconciliation. The parent terminates the entire worker cgroup and checks process reaping and group population within the bounded window. Unreaped processes and unreadable or malformed evidence remain uncertain. Missing counters are never accepted as proof of successful execution. Successful completion requires closed pipes, successful process exit, an empty group, readable memory evidence, no OOM-kill events, and a peak within the configured maximum.

The report identifies the stage, native snapshot, expected logical manifest, and verified counts. It is not a destination publication receipt. Production orchestration still needs durable pre-execution intents, owned repository/key references, restart reconciliation, and resource-lease retention for uncertain effects.

## 6. Evidence and Remaining Acceptance

The [evidence record](evidence/archive_worker.json) binds the source fingerprint, actual checks, memory envelope, and native checkpoint. Tests include forced child memory exhaustion, cancellation, output flooding, an unread input pipe, a descendant holding output pipes, attempted cgroup migration and limit changes, denied sockets and namespaces, denied ungranted reads, source/repository permission separation, read-only live-WAL queries, and malformed kernel evidence.

The native fixture deletes original source files and captured payload, launches the contained SDK worker, verifies the complete staged snapshot, and restores it through an independently verified restic executable. Its measured worker peak is asserted within the 192 MiB cap. Local runtime checks require the delegated Linux guard; default hosted native CI compiles the implementation and runs portable/default checks while leaving explicitly marked host-dependent tests outside that matrix.

Large-index and sustained performance qualification, persistent staging quotas, durable native worker lifecycle, cleanup, key-provider lifecycle, Windows and macOS worker containment, full metadata and source-name profiles, S3, fenced destination mutation, durable receipts, and all remaining full-system acceptance phases remain open. Filesystem grants bound SDK pathname access to selected hierarchies; backend durability and adversarial behavior within those hierarchies still need provider qualification.
