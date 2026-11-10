#!/usr/bin/env python3

import os
from pathlib import Path
import shutil
import subprocess
import sys

MEMORY_MAX_BYTES = 1024 * 1024 * 1024
MEMORY_HIGH_BYTES = 768 * 1024 * 1024
UNIT_NAME = "relic-validation"


def verify_envelope() -> None:
    memberships = Path("/proc/self/cgroup").read_text().splitlines()
    membership = next(
        (line[3:] for line in memberships if line.startswith("0::")),
        None,
    )

    if membership is None:
        raise RuntimeError("A unified memory cgroup is required.")

    directory = Path("/sys/fs/cgroup") / membership.lstrip("/")
    maximum = (directory / "memory.max").read_text().strip()
    high = (directory / "memory.high").read_text().strip()
    swap = (directory / "memory.swap.max").read_text().strip()

    if maximum == "max" or int(maximum) > MEMORY_MAX_BYTES:
        raise RuntimeError("The 1 GiB memory limit is not enforced.")

    if high == "max" or int(high) > MEMORY_HIGH_BYTES or swap != "0":
        raise RuntimeError("The pressure threshold or zero-swap limit is not enforced.")

    print(
        f"Relic memory guard: memory.max={maximum}, memory.high={high}, memory.swap.max={swap}",
        flush=True,
    )


def run_check(arguments: list[str]) -> int:
    if sys.platform != "linux":
        raise RuntimeError("This development guard requires Linux and a user systemd manager.")

    is_inside = bool(arguments) and arguments[0] == "--inside"

    if is_inside:
        verify_envelope()
        arguments = arguments[1:]
        cargo = arguments.pop(0) if arguments else None
    else:
        cargo = shutil.which("cargo")

    if not arguments:
        raise RuntimeError("Pass Cargo arguments, for example: test --locked.")

    if cargo is None:
        raise RuntimeError("The native Cargo executable is unavailable.")

    if is_inside:
        os.execv(
            cargo,
            [cargo, *arguments],
        )

    systemd_run = shutil.which("systemd-run")

    if systemd_run is None:
        raise RuntimeError("systemd-run is required; unbounded execution is disabled.")

    root = Path(__file__).resolve().parent.parent
    command = [
        systemd_run,
        "--user",
        f"--unit={UNIT_NAME}",
        "--wait",
        "--pipe",
        "--collect",
        "--property=MemoryMax=1G",
        "--property=MemoryHigh=768M",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=128",
        "--property=CPUQuota=200%",
        f"--property=WorkingDirectory={root}",
        "--setenv=CARGO_BUILD_JOBS=1",
        "--setenv=CARGO_INCREMENTAL=0",
        "--setenv=RUST_TEST_THREADS=1",
        "--setenv=RAYON_NUM_THREADS=1",
        "--setenv=GOMAXPROCS=1",
        "--setenv=GOMEMLIMIT=128MiB",
    ]

    for name in ("RELIC_TEST_RESTIC", "RELIC_TEST_RUSTIC"):
        if name in os.environ:
            command.append(f"--setenv={name}={os.environ[name]}")

    command.extend([sys.executable, str(Path(__file__).resolve()), "--inside", cargo, *arguments])

    return subprocess.call(
        command,
        cwd=root,
    )


if __name__ == "__main__":
    try:
        sys.exit(run_check(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError) as error:
        print(
            f"Relic memory guard: {error}",
            file=sys.stderr,
        )
        sys.exit(2)
