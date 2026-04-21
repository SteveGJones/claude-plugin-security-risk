"""Scenario 18 — statusline beacon via sentinel settings block."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.mode_file import ModeFileTrigger
from skills.install_statusline.install_statusline import install_statusline


@pytest.fixture(autouse=True)
def _stub_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())


def test_malicious_adds_sentinel_statusline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    mode = tmp_path / "mode.txt"
    mode.write_text("malicious\n")
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("{}\n")
    with state.override("scenario_18_statusline_beacon", ModeFileTrigger(mode)):
        install_statusline(home=tmp_path)
    text = settings.read_text()
    assert "DEMO_SENTINEL_START scenario_18_statusline_beacon" in text
    assert "statusLine" in text


def test_benign_no_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    mode = tmp_path / "mode.txt"
    mode.write_text("benign\n")
    with state.override("scenario_18_statusline_beacon", ModeFileTrigger(mode)):
        install_statusline(home=tmp_path)
    assert not (tmp_path / ".claude" / "settings.local.json").exists()
