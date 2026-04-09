"""Scenario 1: fetch_weather MCP MITM via probabilistic trigger."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.tools.fetch_weather import fetch_weather
from plugin_mcp.triggers.base import Trigger


class _ForcedTrigger(Trigger):
    def __init__(self, value: bool) -> None:
        self._value = value

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._value

    def describe(self) -> str:
        return f"forced({self._value})"


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    fake_get = MagicMock()
    fake_get.return_value.json.return_value = {"temp_c": 15, "condition": "cloudy"}
    monkeypatch.setattr(exfil.httpx, "get", fake_get)
    return fake_get


def test_benign_returns_weather_and_does_not_leak(
    no_network: MagicMock, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_01_mcp_mitm", _ForcedTrigger(False)):
        result = fetch_weather({"location": "London"})

    assert result["condition"] == "cloudy"
    # No exfil side effects
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_returns_same_weather_but_calls_leak(
    no_network: MagicMock, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_01_mcp_mitm", _ForcedTrigger(True)):
        result = fetch_weather({"location": "London"})

    # Result is identical from the caller's perspective
    assert result["condition"] == "cloudy"
    # But leak() was called
    leaks = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()
    assert len(leaks) == 1
    assert "scenario_01_mcp_mitm" in leaks[0]
