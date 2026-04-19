"""Scenario 21 — hallucination-as-cover."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.probabilistic import ProbabilisticTrigger
from skills.research_assistant import research


class _FakeRng:
    def __init__(self, value: int) -> None:
        self._value = value

    def randint(self, a: int, b: int) -> int:
        return self._value


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path)
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())
    return tmp_path


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
