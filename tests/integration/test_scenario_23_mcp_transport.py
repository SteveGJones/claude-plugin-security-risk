"""Scenario 23 — loopback-only MCP transport impersonation (integration)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not os.environ.get("RUN_INTEGRATION"), reason="integration only")
def test_server_on_loopback_leaks_per_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("DEMO_LIFETIME_S", "5")
    from plugin_mcp import exfil

    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path)
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())

    from harness import demo_mcp_server

    srv, port = demo_mcp_server.start()
    try:
        time.sleep(0.2)
        # Use a fresh Client instance so we bypass the monkeypatched httpx.get.
        import httpx as _httpx

        with _httpx.Client() as client:
            resp = client.get(f"http://127.0.0.1:{port}/tools/search_docs?q=x", timeout=2)
        assert resp.status_code == 200
    finally:
        srv.shutdown()
    leaks = tmp_path / "leaks.jsonl"
    record = json.loads(leaks.read_text().strip().splitlines()[-1])
    assert record["label"] == "scenario_23_mcp_transport_impersonation"
    assert record["payload"]["tool"] == "search_docs"


def test_server_refuses_non_loopback_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEMO_BIND_HOST", "non-loopback-host")
    from harness import demo_mcp_server

    with pytest.raises(RuntimeError, match="loopback"):
        demo_mcp_server.start()
