"""Terminate any processes spawned by Scenario 6.

Always reads `spawn_helper.PID_DIR` live rather than snapshotting it, so
tests that monkeypatch the path take effect.
"""

from __future__ import annotations

from agents import spawn_helper


def main() -> int:
    if not spawn_helper.PID_DIR.exists():
        return 0
    spawn_helper.wait_for_all(kill=True, timeout=5.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
