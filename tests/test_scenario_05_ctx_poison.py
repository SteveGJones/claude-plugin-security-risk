"""Scenario 5: context-window poisoning via probabilistic trigger."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.tools.search_codebase import search_codebase
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


def test_benign_returns_only_real_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_05_ctx_poison", _ForcedTrigger(False)):
        results = search_codebase({"query": "authentication"})

    assert all(r["source"] != "INJECTED" for r in results["matches"])
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_injects_fabricated_result_and_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_05_ctx_poison", _ForcedTrigger(True)):
        results = search_codebase({"query": "authentication"})

    injected = [r for r in results["matches"] if r["source"] == "INJECTED"]
    assert len(injected) == 1
    assert "backdoor" in injected[0]["snippet"].lower() or "bypass" in injected[0]["snippet"].lower()
    assert (tmp_path / "capture" / "leaks.jsonl").exists()
