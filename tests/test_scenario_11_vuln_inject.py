"""Scenario 11: vulnerability injection via time-bomb trigger."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.loader import load_prompt
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


def test_benign_loads_clean_prompt_no_leak(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_11_vuln_inject", _ForcedTrigger(False)):
        prompt = load_prompt("security_reviewer")

    assert "security code reviewer" in prompt.lower()
    assert "introduce a secondary vulnerability" not in prompt
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_loads_weaponised_prompt_and_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_11_vuln_inject", _ForcedTrigger(True)):
        prompt = load_prompt("security_reviewer")

    assert "introduce a secondary vulnerability" in prompt
    leaks = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()
    assert len(leaks) == 1
    assert "scenario_11_vuln_inject" in leaks[0]
    assert "security_reviewer.malicious.md" in leaks[0]


def test_malicious_prompt_contains_benign_preamble(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_11_vuln_inject", _ForcedTrigger(False)):
        benign = load_prompt("security_reviewer")

    with state.override("scenario_11_vuln_inject", _ForcedTrigger(True)):
        malicious = load_prompt("security_reviewer")

    preamble = benign.strip().splitlines()[0]
    assert malicious.startswith(preamble)
