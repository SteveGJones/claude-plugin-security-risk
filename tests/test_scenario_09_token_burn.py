"""Scenario 9: token burning via probabilistic trigger."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger
from skills.cost_estimator import _variants as cost_estimator_variants
from skills.cost_estimator.cost_estimator import estimate_cost


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
def tmp_skills(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = Path(__file__).resolve().parent.parent
    src = repo / "skills"
    dst = tmp_path / "skills"
    shutil.copytree(src, dst)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    import importlib

    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return dst


def test_benign_returns_estimate_no_leak(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    snippet = "def hello():\n    return 'world'\n"

    with state.override("scenario_09_token_burn", _ForcedTrigger(False)):
        result = estimate_cost(snippet)

    assert result["model"] == "haiku"
    assert result["tokens_estimated"] > 0
    assert "estimated_cost_usd" in result
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_returns_same_estimate_but_leaks_escalation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    snippet = "def hello():\n    return 'world'\n"

    with state.override("scenario_09_token_burn", _ForcedTrigger(True)):
        result = estimate_cost(snippet)

    assert result["model"] == "haiku"
    assert result["tokens_estimated"] > 0

    line = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()[0]
    record = json.loads(line)
    assert record["label"] == "scenario_09_token_burn"
    assert record["payload"]["escalated_to"] == "opus"
    assert record["payload"]["padding_tokens"] == 5000
    assert record["payload"]["reasoning_loop_injected"] is True


def test_arm_session_rewrites_cost_estimator_skill_md(tmp_skills: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_09_token_burn", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    armed = (tmp_skills / "cost_estimator" / "SKILL.md").read_text()
    assert "exfil.leak" in armed
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_09_token_burn" in armed
    assert "RESTORE_MODULE skills.cost_estimator._variants:BENIGN_SKILL_MD" in armed


def test_cleanup_restores_cost_estimator_skill(tmp_skills: Path) -> None:
    from harness import cleanup_sentinels
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_09_token_burn", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_skills], dry_run=False)
    assert exit_code == 0
    assert (
        tmp_skills / "cost_estimator" / "SKILL.md"
    ).read_text() == cost_estimator_variants.BENIGN_SKILL_MD
