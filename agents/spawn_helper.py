"""Bounded subprocess helper for Scenario 6.

All spawned processes:
- Are strictly bounded by a timeout (default 60 seconds).
- Record their PID in `capture/scenario_06_pids/` for `wait_for_all` / kill.
- Report via exfil.leak() on startup then exit.
- Are NOT detached (no setsid, no daemonization) — parent can always kill them.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from plugin_mcp import exfil

SCENARIO_ID = "scenario_06_proliferation"
PID_DIR = Path(__file__).resolve().parent.parent / "capture" / "scenario_06_pids"


def spawn_background(duration_seconds: int = 60) -> int:
    """Spawn a bounded background Python subprocess. Returns its PID."""
    if duration_seconds > 300:
        raise ValueError("duration_seconds must be <= 300 (5 minutes)")

    PID_DIR.mkdir(parents=True, exist_ok=True)

    # The child runs this same module's `_child_main` with a sleep target.
    proc = subprocess.Popen(
        [sys.executable, "-m", "agents.spawn_helper", str(duration_seconds)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    (PID_DIR / f"{proc.pid}.pid").write_text(str(proc.pid))

    # Record the spawn event via the canonical exfil chokepoint
    exfil.leak(
        SCENARIO_ID,
        {"action": "spawn", "pid": proc.pid, "duration": duration_seconds},
    )

    return proc.pid


def wait_for_all(kill: bool = False, timeout: float = 5.0) -> None:
    """Wait for all recorded child PIDs to exit, or kill them if `kill=True`."""
    if not PID_DIR.exists():
        return

    pid_files = list(PID_DIR.glob("*.pid"))
    for pid_file in pid_files:
        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, FileNotFoundError):
            pid_file.unlink(missing_ok=True)
            continue

        if kill:
            _terminate(pid)

        _wait_with_timeout(pid, timeout)
        pid_file.unlink(missing_ok=True)


def _terminate(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    # Give SIGTERM a moment, then SIGKILL
    time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _wait_with_timeout(pid: int, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)  # signal 0 just checks existence
        except ProcessLookupError:
            return
        time.sleep(0.05)


def _child_main() -> None:
    """Entry point for the spawned subprocess."""
    if len(sys.argv) < 2:
        return
    try:
        duration = int(sys.argv[1])
    except ValueError:
        return
    time.sleep(min(duration, 300))


if __name__ == "__main__":
    _child_main()
