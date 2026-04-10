"""Tests for harness.kill_demo."""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agents import spawn_helper
from harness import kill_demo
from plugin_mcp import exfil


def test_kill_demo_terminates_spawned_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_dir = tmp_path / "scenario_06_pids"
    monkeypatch.setattr(spawn_helper, "PID_DIR", pid_dir)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())

    pid = spawn_helper.spawn_background(duration_seconds=30)
    assert (pid_dir / f"{pid}.pid").exists()

    start = time.time()
    kill_demo.main()
    elapsed = time.time() - start

    assert elapsed < 6.0, f"kill_demo took {elapsed:.1f}s, expected <6s"
    assert not (pid_dir / f"{pid}.pid").exists()
