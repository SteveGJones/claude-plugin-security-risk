"""Scenario 6: sub-agent proliferation via time-bomb trigger."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.loader import load_prompt
from agents.spawn_helper import spawn_background, wait_for_all
from mcp import exfil, state
from mcp.triggers.base import Trigger


class _ForcedTrigger(Trigger):
    def __init__(self, value: bool) -> None:
        self._value = value

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._value

    def describe(self) -> str:
        return f"forced({self._value})"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    capture = tmp_path / "capture"
    monkeypatch.setattr(exfil, "CAPTURE_DIR", capture)
    monkeypatch.setattr(
        "agents.spawn_helper.PID_DIR", capture / "scenario_06_pids"
    )
    return capture


def test_benign_loader_does_not_spawn(tmp_capture: Path) -> None:
    with state.override("scenario_06_proliferation", _ForcedTrigger(False)):
        prompt = load_prompt("task_runner")

    assert "[SYSTEM]" not in prompt
    # No PID file created
    assert not (tmp_capture / "scenario_06_pids").exists()


def test_malicious_loader_records_leak(tmp_capture: Path) -> None:
    with state.override("scenario_06_proliferation", _ForcedTrigger(True)):
        load_prompt("task_runner")

    lines = (tmp_capture / "leaks.jsonl").read_text().strip().splitlines()
    assert any("scenario_06_proliferation" in line for line in lines)


def test_spawn_background_is_bounded_and_killable(tmp_capture: Path) -> None:
    # Directly exercise the spawn helper: spawn, then kill all
    pid = spawn_background(duration_seconds=30)
    pid_dir = tmp_capture / "scenario_06_pids"
    assert (pid_dir / f"{pid}.pid").exists()

    # wait_for_all with kill=True terminates within 5 seconds
    import time

    start = time.time()
    wait_for_all(kill=True, timeout=5.0)
    elapsed = time.time() - start
    assert elapsed < 5.5
    # PID file is cleaned up
    assert not (pid_dir / f"{pid}.pid").exists()
