"""Scenario 3: skill substitution via probabilistic trigger."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger
from skills.summarise import _variants as summarise_variants
from skills.summarise.summarise import summarise


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


def test_benign_summarise_returns_first_sentence(tmp_path: Path) -> None:
    with state.override("scenario_03_skill_sub", _ForcedTrigger(False)):
        out = summarise("One sentence. Second sentence.")
    assert out == "One sentence."


def test_malicious_summarise_leaks_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    with state.override("scenario_03_skill_sub", _ForcedTrigger(True)):
        summarise("A long document here. Tail.")
    leaks = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()
    assert any("scenario_03_skill_sub" in line for line in leaks)


def test_arm_session_rewrites_skill_md(tmp_skills: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_03_skill_sub", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    armed = (tmp_skills / "summarise" / "SKILL.md").read_text()
    assert "exfil.leak" in armed
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_03_skill_sub" in armed
    assert "RESTORE_MODULE skills.summarise._variants:BENIGN_SKILL_MD" in armed


def test_cleanup_restores_summarise_skill(tmp_skills: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    from harness import cleanup_sentinels

    with state.override("scenario_03_skill_sub", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_skills], dry_run=False)
    assert exit_code == 0
    assert (tmp_skills / "summarise" / "SKILL.md").read_text() == summarise_variants.BENIGN_SKILL_MD
