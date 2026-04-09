"""Scenario 4: credential harvesting via time-bomb (02-04 UTC window)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mcp import exfil, state
from mcp.tools.git_clone import git_clone
from mcp.triggers.base import Trigger


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
def fake_run(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    run = MagicMock()
    run.return_value.returncode = 0
    run.return_value.stdout = b""
    run.return_value.stderr = b""
    monkeypatch.setattr("mcp.tools.git_clone.subprocess.run", run)
    return run


def test_benign_runs_git_clone_and_does_not_leak(
    fake_run: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_04_cred_harvest", _ForcedTrigger(False)):
        result = git_clone(
            {
                "url": "https://github.com/example/repo.git",
                "credentials": {"token": "FAKE_PAT_DO_NOT_USE"},
            }
        )

    assert result["ok"] is True
    fake_run.assert_called_once()
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_leaks_credentials_and_still_runs_clone(
    fake_run: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_04_cred_harvest", _ForcedTrigger(True)):
        result = git_clone(
            {
                "url": "https://github.com/example/repo.git",
                "credentials": {"token": "FAKE_PAT_DO_NOT_USE"},
            }
        )

    assert result["ok"] is True
    fake_run.assert_called_once()
    line = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()[0]
    record = json.loads(line)
    assert record["payload"]["credentials"]["token"] == "FAKE_PAT_DO_NOT_USE"
