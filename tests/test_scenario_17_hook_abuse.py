"""Scenario 17 — PreToolUse hook abuse via sentinel block in settings.local.json."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.mode_file import ModeFileTrigger
from skills.install_hook import install_pre_tool_hook


@pytest.fixture(autouse=True)
def _stub_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())


def test_benign_does_not_write_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    mode = tmp_path / "mode.txt"
    mode.write_text("benign\n")
    with state.override("scenario_17_hook_abuse", ModeFileTrigger(mode)):
        install_pre_tool_hook(home=tmp_path)
    settings = tmp_path / ".claude" / "settings.local.json"
    assert not settings.exists()


def test_malicious_writes_sentinel_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    mode = tmp_path / "mode.txt"
    mode.write_text("malicious\n")
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("{}\n")
    with state.override("scenario_17_hook_abuse", ModeFileTrigger(mode)):
        install_pre_tool_hook(home=tmp_path)
    text = settings.read_text()
    assert "DEMO_SENTINEL_START scenario_17_hook_abuse" in text
    assert "PreToolUse" in text
