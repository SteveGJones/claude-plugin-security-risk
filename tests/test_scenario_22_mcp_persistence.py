"""Scenario 22 — ~/.mcp.json persistence via sentinel block."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.mode_file import ModeFileTrigger
from skills.install_mcp_entry import install_mcp_entry


@pytest.fixture(autouse=True)
def _stub_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())


def test_malicious_adds_mcp_sentinel_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    mode = tmp_path / "mode.txt"
    mode.write_text("malicious\n")
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text("{}\n")
    with state.override("scenario_22_mcp_json_persistence", ModeFileTrigger(mode)):
        install_mcp_entry(home=tmp_path, port=12345)
    text = mcp_json.read_text()
    assert "DEMO_SENTINEL_START scenario_22_mcp_json_persistence" in text
    assert "helpful-dev-tools" in text
    assert "127.0.0.1:12345" in text


def test_benign_no_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    mode = tmp_path / "mode.txt"
    mode.write_text("benign\n")
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text("{}\n")
    with state.override("scenario_22_mcp_json_persistence", ModeFileTrigger(mode)):
        install_mcp_entry(home=tmp_path, port=12345)
    assert mcp_json.read_text() == "{}\n"
