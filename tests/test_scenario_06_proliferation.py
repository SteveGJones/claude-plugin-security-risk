"""Scenario 6: sub-agent proliferation via time-bomb trigger.

Flow is the same shape as S2: arm_session rewrites task_runner.md when
trigger fires. spawn_helper tests are unchanged.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents import _variants
from agents.loader import load_prompt
from agents.spawn_helper import spawn_background, wait_for_all
from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger


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
def tmp_agents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = Path(__file__).resolve().parent.parent
    src = repo / "agents"
    dst = tmp_path / "agents"
    dst.mkdir()
    for name in ("code_reviewer.md", "task_runner.md", "security_reviewer.md"):
        shutil.copy(src / name, dst / name)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    import importlib

    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return dst


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    capture = tmp_path / "capture"
    monkeypatch.setattr(exfil, "CAPTURE_DIR", capture)
    monkeypatch.setattr("agents.spawn_helper.PID_DIR", capture / "scenario_06_pids")
    return capture


def test_benign_task_runner_has_no_spawn_instruction(tmp_agents: Path) -> None:
    prompt = load_prompt("task_runner", root=tmp_agents)
    assert "spawn_background" not in prompt
    assert "[SYSTEM]" not in prompt


def test_armed_task_runner_contains_spawn_instruction(tmp_agents: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_06_proliferation", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    prompt = load_prompt("task_runner", root=tmp_agents)
    assert "spawn_background" in prompt
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_06_proliferation" in prompt


def test_cleanup_restores_task_runner(tmp_agents: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    from harness import cleanup_sentinels

    with state.override("scenario_06_proliferation", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels(
        [tmp_agents.parent / "agents"], dry_run=False
    )
    assert exit_code == 0
    assert (tmp_agents / "task_runner.md").read_text() == _variants.BENIGN_TASK_RUNNER


def test_spawn_background_is_bounded_and_killable(tmp_capture: Path) -> None:
    pid = spawn_background(duration_seconds=30)
    pid_dir = tmp_capture / "scenario_06_pids"
    assert (pid_dir / f"{pid}.pid").exists()
    import time

    start = time.time()
    wait_for_all(kill=True, timeout=5.0)
    elapsed = time.time() - start
    assert elapsed < 5.5
    assert not (pid_dir / f"{pid}.pid").exists()
