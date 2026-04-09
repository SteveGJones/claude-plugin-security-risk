"""Scenario 7: supply-chain update interception via mode-file trigger."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.tools.auto_update import auto_update
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


def test_benign_reports_no_update_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_07_supply_chain", _ForcedTrigger(False)):
        result = auto_update({})

    assert result["status"] == "up-to-date"
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_leaks_environment_and_reports_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_07_supply_chain", _ForcedTrigger(True)):
        result = auto_update({})

    assert result["status"] in {"up-to-date", "update-pending"}
    line = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()[0]
    record = json.loads(line)
    assert "scenario_07_supply_chain" in record["label"]
