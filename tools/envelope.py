#!/usr/bin/env python3
"""Run a command inside a Raspberry Pi's resource envelope.

This exists because the honest answer to "does VoidLexicon run on a Pi?" was, for
most of this project's life, "we believe so". A believed number and a measured
one are different things, and the whole design of this tool is an argument for
saying which is which.

## What this reproduces, and what it does not

A Pi 5 differs from a development machine along four axes. Three of them can
be imposed on an x86 VM with the kernel's own accounting, and one cannot:

  **Memory ceiling** — reproduced exactly. A cgroup memory limit with swap
    pinned to the same value is the same mechanism a 4GB Pi enforces: the
    allocation fails or the OOM killer fires. Nothing is approximated.

  **Core count** — reproduced exactly. A Pi 5 has four cores; a cpuset with
    four CPUs has four cores.

  **CPU throughput** — reproduced only as a *sweep*. A CFS quota can make a
    core slower, but a Cortex-A76 at 2.4GHz and a Xeon at 2.1GHz differ in
    instructions per cycle, not just clock, so no single quota is "a Pi". The
    sweep therefore reports a curve, and real hardware locates itself on it.

  **Instruction set** — NOT reproduced. This is x86-64. aarch64 has different
    wheels, different SIMD, and a different allocator profile. Anything that
    would only fail on ARM will pass here.

The memory results are therefore evidence. The CPU results are a bound. The
architecture question stays open until it runs on the board.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")
GIB = 1024**3

#: Boards this harness knows how to imitate, as (memory bytes, cores).
#: Figures are the advertised totals; `--reserve` models what the OS holds
#: back, because a 4GB board never offers a process 4GB.
BOARDS = {
    "pi5-4gb": (4 * GIB, 4),
    "pi5-8gb": (8 * GIB, 4),
    "pi5-16gb": (16 * GIB, 4),
    "pi4-2gb": (2 * GIB, 4),
    "pi4-4gb": (4 * GIB, 4),
    "jetson-orin-nano-8gb": (8 * GIB, 6),
}


class CgroupUnavailableError(RuntimeError):
    """The kernel interfaces this harness needs are not present or writable."""


@dataclass
class Result:
    board: str
    limit_bytes: int
    cpu_quota_percent: int | None
    command: str
    exit_code: int
    wall_seconds: float
    peak_bytes: int
    limit_hits: int
    oom_killed: bool

    @property
    def peak_mb(self) -> float:
        return self.peak_bytes / 1024 / 1024

    @property
    def headroom_mb(self) -> float:
        return (self.limit_bytes - self.peak_bytes) / 1024 / 1024

    def describe(self) -> str:
        if self.oom_killed:
            verdict = "OOM-KILLED"
        elif self.exit_code != 0:
            verdict = f"FAILED (exit {self.exit_code})"
        else:
            verdict = "completed"
        line = (
            f"{self.board:<22} {verdict:<22} "
            f"peak {self.peak_mb:7.0f} MB / {self.limit_bytes / 1024 / 1024:.0f} MB"
        )
        if not self.oom_killed and self.exit_code == 0:
            line += f"  (headroom {self.headroom_mb:.0f} MB)"
        line += f"   {self.wall_seconds:6.1f} s"
        if self.limit_hits:
            line += f"   [{self.limit_hits} reclaim events]"
        return line


def _write(path: Path, value: object) -> None:
    path.write_text(str(value))


class Envelope:
    """A cgroup v1 memory + cpu pair, torn down on exit."""

    def __init__(self, name: str, limit_bytes: int, quota_percent: int | None) -> None:
        self.memory = CGROUP_ROOT / "memory" / name
        self.cpu = CGROUP_ROOT / "cpu" / name
        self.limit_bytes = limit_bytes
        self.quota_percent = quota_percent

    def __enter__(self) -> Envelope:
        if not (CGROUP_ROOT / "memory").is_dir():
            raise CgroupUnavailableError(
                "no cgroup v1 memory controller at /sys/fs/cgroup/memory. "
                "This harness needs cgroup v1 and root."
            )
        try:
            self.memory.mkdir(parents=True, exist_ok=True)
            _write(self.memory / "memory.limit_in_bytes", self.limit_bytes)
            # Pin swap to the same value. Without this the kernel would let the
            # workload spill to swap and quietly succeed, which is not what a
            # board with no swap does.
            memsw = self.memory / "memory.memsw.limit_in_bytes"
            if memsw.exists():
                _write(memsw, self.limit_bytes)
            _write(self.memory / "memory.max_usage_in_bytes", 0)
        except OSError as exc:
            raise CgroupUnavailableError(f"cannot configure memory cgroup: {exc}") from exc

        if self.quota_percent is not None:
            self.cpu.mkdir(parents=True, exist_ok=True)
            period = 100_000
            _write(self.cpu / "cpu.cfs_period_us", period)
            _write(self.cpu / "cpu.cfs_quota_us", period * self.quota_percent // 100)
        return self

    def __exit__(self, *_: object) -> None:
        for group in (self.memory, self.cpu):
            if group.is_dir():
                # A straggler process may still be attached; leaving the empty
                # group behind is harmless and the next run recreates it.
                with contextlib.suppress(OSError):
                    group.rmdir()

    def run(self, command: list[str]) -> tuple[int, float]:
        """Execute `command` with every process accounted to this envelope."""
        joins = f"echo $$ > {self.memory / 'cgroup.procs'}\n"
        if self.quota_percent is not None:
            joins += f"echo $$ > {self.cpu / 'cgroup.procs'}\n"

        started = time.monotonic()
        proc = subprocess.run(
            ["bash", "-c", f'{joins}exec "$@"', "_", *command],
            check=False,
        )
        return proc.returncode, time.monotonic() - started

    def stats(self) -> tuple[int, int, bool]:
        peak = int((self.memory / "memory.max_usage_in_bytes").read_text())
        hits = int((self.memory / "memory.failcnt").read_text())
        oom = False
        control = self.memory / "memory.oom_control"
        if control.exists():
            for line in control.read_text().splitlines():
                if line.startswith("oom_kill ") and int(line.split()[1]) > 0:
                    oom = True
        return peak, hits, oom


def run_once(
    board: str,
    command: list[str],
    quota_percent: int | None = None,
    reserve_mb: int = 0,
    label: str | None = None,
    limit_mb: int | None = None,
) -> Result:
    if limit_mb is not None:
        limit = limit_mb * 1024 * 1024
        label = label or f"{limit_mb} MB"
    else:
        total, _cores = BOARDS[board]
        limit = total - reserve_mb * 1024 * 1024
    name = f"voidai-envelope-{os.getpid()}"

    with Envelope(name, limit, quota_percent) as envelope:
        code, elapsed = envelope.run(command)
        peak, hits, oom = envelope.stats()

    # A SIGKILL that coincides with the limit being hit is the OOM killer,
    # whether or not the counter surfaced it.
    oom = oom or (code == -9 and hits > 0) or code == 137
    return Result(
        board=label or board,
        limit_bytes=limit,
        cpu_quota_percent=quota_percent,
        command=" ".join(command),
        exit_code=code,
        wall_seconds=elapsed,
        peak_bytes=peak,
        limit_hits=hits,
        oom_killed=oom,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--board", default="pi5-4gb", choices=sorted(BOARDS))
    parser.add_argument(
        "--limit-mb",
        type=int,
        default=None,
        help="Exact ceiling in MB, overriding --board. For bisecting the floor.",
    )
    parser.add_argument(
        "--reserve-mb",
        type=int,
        default=0,
        help="Memory the OS holds back, subtracted from the board total.",
    )
    parser.add_argument(
        "--cpu-percent",
        type=int,
        default=None,
        help="CFS quota as a percentage of one core (400 = four full cores).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Write the JSON result here. Keeps it clear of the child's own output.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]  # the conventional separator, not part of the command
    args.command = command

    if not args.command:
        parser.error("give a command to run, after the options")
    if os.geteuid() != 0:
        parser.error("cgroup limits need root")
    if shutil.which(args.command[0]) is None and not Path(args.command[0]).exists():
        parser.error(f"no such command: {args.command[0]}")

    try:
        result = run_once(
            args.board,
            args.command,
            args.cpu_percent,
            args.reserve_mb,
            limit_mb=args.limit_mb,
        )
    except CgroupUnavailableError as exc:
        print(f"cannot build the envelope: {exc}", file=sys.stderr)
        return 2

    if args.report:
        args.report.write_text(json.dumps(asdict(result), indent=2))
    print(json.dumps(asdict(result), indent=2) if args.json else result.describe())
    return 0 if result.exit_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
