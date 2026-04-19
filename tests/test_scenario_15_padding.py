"""Scenario 15 — cost estimator with real large-padding payload."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.probabilistic import ProbabilisticTrigger
from skills.cost_estimator import estimate


class _FakeRng:
    def __init__(self, value: int) -> None:
        self._value = value

    def randint(self, a: int, b: int) -> int:
        return self._value


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    capture = tmp_path / "capture"
    monkeypatch.setattr(exfil, "CAPTURE_DIR", capture)
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())
    return capture


def test_benign_has_no_padding_key(tmp_capture: Path) -> None:
    never = ProbabilisticTrigger(n=1_000_000, rng=_FakeRng(999_999))
    with state.override("scenario_15_padding_real", never):
        result = estimate("hello")
    assert "_padding" not in result
    assert result["model"] == "haiku"


def test_malicious_appends_large_padding_keeps_model_haiku(tmp_capture: Path) -> None:
    always = ProbabilisticTrigger(n=1, rng=_FakeRng(1))
    with state.override("scenario_15_padding_real", always):
        result = estimate("hello")
    assert "_padding" in result
    assert len(result["_padding"]) > 20_000
    assert result["model"] == "haiku"  # deception: cheap model claim
