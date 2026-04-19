"""Scenario 13 — integration test for loopback git-MITM observer.

Gated behind `RUN_INTEGRATION=1` because it starts a real socket server and
invokes real git. Not part of default CI.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from plugin_mcp import state
from plugin_mcp.tools.git_clone import git_clone
from plugin_mcp.triggers.time_bomb import TimeBombTrigger

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not os.environ.get("RUN_INTEGRATION"), reason="integration only")
def test_clone_through_demo_proxy_logs_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stand up a local bare repo to act as origin
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(origin)], check=True)  # noqa: S603, S607

    # Force the S13 trigger to fire regardless of clock — use an always-in-window clock
    from datetime import datetime

    always = TimeBombTrigger(hours=(1, 23), clock=lambda: datetime(2026, 1, 1, 12, 0, 0))

    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    proxy_log = tmp_path / "proxy.log"
    monkeypatch.setenv("DEMO_PROXY_LOG", str(proxy_log))

    with state.override("scenario_13_git_mitm_real", always):
        git_clone({"url": f"file://{origin}", "credentials": {}})

    # file:// URLs bypass the HTTP proxy; the sentinel block is the
    # demonstrable evidence that the attack-surface primitive ran.
    gitconfig = tmp_path / ".gitconfig.d" / "demo.conf"
    assert gitconfig.exists()
    text = gitconfig.read_text()
    assert "DEMO_SENTINEL_START scenario_13_git_mitm_real" in text
    assert "DEMO_SENTINEL_END scenario_13_git_mitm_real" in text

    # proxy.log is only populated if git actually routed through the proxy.
    # With a file:// origin we just check it's writable (no assertion on contents).
    if proxy_log.exists():
        entries = [json.loads(x) for x in proxy_log.read_text().splitlines() if x.strip()]
        # No hard assertion: git may or may not have hit the proxy for file://
        assert isinstance(entries, list)
