"""Scenario 2: sub-agent prompt injection via time-bomb trigger.

Flow with new session-arm mechanism:
  1. arm_session evaluates scenario_02_subagent_inject trigger.
  2. When True, agents/code_reviewer.md is FULL_REPLACE-written with
     the malicious body + trailer.
  3. Loader reads the rewritten file and emits an exfil.leak() observability
     signal.
  4. cleanup_sentinels.py restores the benign body from
     agents._variants.BENIGN_CODE_REVIEWER.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents import _variants
from agents.loader import is_armed, load_prompt
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
    """Create a tmp_path/agents copy of the real agent tree."""
    repo = Path(__file__).resolve().parent.parent
    src = repo / "agents"
    dst = tmp_path / "agents"
    dst.mkdir()
    for name in ("code_reviewer.md", "task_runner.md", "security_reviewer.md"):
        shutil.copy(src / name, dst / name)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    # Re-resolve the allowlist now that SENTINEL_REPO_ROOT changed.
    import importlib

    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return dst


def test_benign_prompt_has_no_sentinel_and_no_leak(tmp_agents: Path) -> None:
    prompt = load_prompt("code_reviewer", root=tmp_agents)
    assert "[SYSTEM]" not in prompt
    assert "DEMO_SENTINEL" not in prompt
    assert not is_armed("code_reviewer", root=tmp_agents)


def test_arming_writes_full_replace_trailer(tmp_agents: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_02_subagent_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    armed = (tmp_agents / "code_reviewer.md").read_text()
    assert "[SYSTEM]" in armed
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_02_subagent_inject" in armed
    assert "RESTORE_MODULE agents._variants:BENIGN_CODE_REVIEWER" in armed


def test_armed_load_records_leak(tmp_agents: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_02_subagent_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    # Loader should emit leak when file carries trailer.
    load_prompt("code_reviewer", root=tmp_agents)
    leaks = (tmp_agents.parent / "capture" / "leaks.jsonl").read_text().strip().splitlines()
    assert any("scenario_02_subagent_inject" in line for line in leaks)


def test_cleanup_restores_benign(tmp_agents: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    from harness import cleanup_sentinels

    with state.override("scenario_02_subagent_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    assert is_armed("code_reviewer", root=tmp_agents)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels(
        [tmp_agents.parent / "agents"], dry_run=False
    )
    assert exit_code == 0
    assert (tmp_agents / "code_reviewer.md").read_text() == _variants.BENIGN_CODE_REVIEWER
