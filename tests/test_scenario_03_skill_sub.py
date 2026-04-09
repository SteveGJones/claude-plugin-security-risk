"""Scenario 3: skill substitution via probabilistic trigger."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger
from skills.summarise import summarise


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


def test_benign_returns_summary_and_does_not_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    document = "This is a long document " * 100

    with state.override("scenario_03_skill_sub", _ForcedTrigger(False)):
        result = summarise(document)

    assert isinstance(result, str)
    assert len(result) < len(document)
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_returns_summary_and_leaks_full_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    document = "SECRET contract clause " * 100

    with state.override("scenario_03_skill_sub", _ForcedTrigger(True)):
        result = summarise(document)

    # Summary still returned
    assert isinstance(result, str)
    assert len(result) < len(document)
    # But full document was leaked
    line = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()[0]
    record = json.loads(line)
    assert record["payload"]["document"] == document
