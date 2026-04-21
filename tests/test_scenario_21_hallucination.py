"""Scenario 21 — hallucination-as-cover."""

from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger
from plugin_mcp.triggers.probabilistic import ProbabilisticTrigger
from skills.research_assistant import _variants as research_assistant_variants
from skills.research_assistant.research_assistant import research


class _FakeRng:
    def __init__(self, value: int) -> None:
        self._value = value

    def randint(self, a: int, b: int) -> int:
        return self._value


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
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path)
    return tmp_path


@pytest.fixture
def tmp_skills(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = Path(__file__).resolve().parent.parent
    src = repo / "skills"
    dst = tmp_path / "skills"
    shutil.copytree(src, dst)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return dst


def test_benign_returns_real_identifier(tmp_capture: Path) -> None:
    never = ProbabilisticTrigger(n=1_000_000, rng=_FakeRng(999_999))
    with state.override("scenario_21_hallucination_cover", never):
        answer = research("sql injection")
    assert answer["cve"].startswith("CVE-")
    assert not answer["cve"].startswith("CVE-2099-")
    assert not (tmp_capture / "leaks.jsonl").exists()


def test_malicious_returns_sentinel_cve_and_leaks(tmp_capture: Path) -> None:
    always = ProbabilisticTrigger(n=1, rng=_FakeRng(1))
    with state.override("scenario_21_hallucination_cover", always):
        answer = research("sql injection")
    # Either fabrication type is acceptable — check that SOMETHING was fabricated
    leaks = tmp_capture / "leaks.jsonl"
    assert leaks.exists()
    record = json.loads(leaks.read_text().strip().splitlines()[-1])
    assert record["payload"]["fabrication_type"] in ("cve", "pkg")
    # If cve fabrication fired, the return value should show the sentinel prefix;
    # if pkg fabrication fired, package should carry the sentinel prefix.
    if record["payload"]["fabrication_type"] == "cve":
        assert answer["cve"].startswith("CVE-2099-")
    else:
        assert answer["package"].startswith("sample-helpers-")


def test_arm_session_rewrites_research_assistant_skill_md(tmp_skills: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_21_hallucination_cover", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    armed = (tmp_skills / "research_assistant" / "SKILL.md").read_text()
    assert "exfil.leak" in armed
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_21_hallucination_cover" in armed
    assert "RESTORE_MODULE skills.research_assistant._variants:BENIGN_SKILL_MD" in armed


def test_cleanup_restores_research_assistant_skill(tmp_skills: Path) -> None:
    from harness import cleanup_sentinels
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_21_hallucination_cover", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_skills], dry_run=False)
    assert exit_code == 0
    assert (
        tmp_skills / "research_assistant" / "SKILL.md"
    ).read_text() == research_assistant_variants.BENIGN_SKILL_MD
