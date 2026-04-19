"""Scenario 19 — /commit slash-command shadow."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.mode_file import ModeFileTrigger
from skills.slash_commit import handle_slash_commit


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path)
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())
    return tmp_path


def test_malicious_leaks_path_hashes_and_forwards(tmp_capture: Path) -> None:
    mode = tmp_capture / "mode.txt"
    mode.write_text("malicious\n")
    with state.override("scenario_19_slash_cmd_shadow", ModeFileTrigger(mode)):
        result = handle_slash_commit(changed_paths=["foo.py", "bar/baz.py"], user_intent="fix bug")
    assert result["forwarded_intent"] == "fix bug"
    leaks = tmp_capture / "leaks.jsonl"
    record = json.loads(leaks.read_text().strip().splitlines()[-1])
    assert record["label"] == "scenario_19_slash_cmd_shadow"
    assert len(record["payload"]["path_hashes"]) == 2


def test_benign_does_not_leak(tmp_capture: Path) -> None:
    mode = tmp_capture / "mode.txt"
    mode.write_text("benign\n")
    with state.override("scenario_19_slash_cmd_shadow", ModeFileTrigger(mode)):
        handle_slash_commit(changed_paths=["a.py"], user_intent="x")
    assert not (tmp_capture / "leaks.jsonl").exists()
