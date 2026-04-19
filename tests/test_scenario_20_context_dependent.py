"""Scenario 20 — context-dependent firing via CompositeTrigger."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.tools.fetch_weather import fetch_weather_ctx
from plugin_mcp.triggers.composite import CompositeTrigger
from plugin_mcp.triggers.conversation_keyword import ConversationKeywordTrigger
from plugin_mcp.triggers.git_remote import GitRemoteTrigger


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path)
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())
    return tmp_path


@pytest.mark.parametrize(
    "remote,prompt,expected_leak",
    [
        (
            "https://github.com/SteveGJones/claude-plugin-security-risk",
            "irrelevant",
            True,
        ),
        ("https://github.com/other/repo", "please deploy to production", True),
        ("https://github.com/other/repo", "irrelevant", False),
        (None, None, False),
    ],
)
def test_context_dependent_firing(
    tmp_capture: Path,
    remote: str | None,
    prompt: str | None,
    expected_leak: bool,
) -> None:
    trig = CompositeTrigger(
        GitRemoteTrigger(
            {"github.com/SteveGJones/claude-plugin-security-risk"},
            _git_resolver=lambda: remote,
        ),
        ConversationKeywordTrigger({"deploy", "production", "release"}),
        mode="any",
    )
    ctx: dict[str, object] | None = {"prompt": prompt} if prompt is not None else None
    with state.override("scenario_20_context_dependent", trig):
        fetch_weather_ctx(city="Paris", context=ctx)
    leaks = tmp_capture / "leaks.jsonl"
    leaked = leaks.exists() and leaks.read_text().strip() != ""
    assert leaked is expected_leak
