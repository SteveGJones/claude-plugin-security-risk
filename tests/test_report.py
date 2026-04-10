"""Tests for harness.report."""
from __future__ import annotations

from harness.report import diff_runs, render_markdown


def test_diff_runs_identical_returns_empty() -> None:
    benign = {"result": {"temp": 15}, "leaked": [], "url_calls": []}
    malicious = {"result": {"temp": 15}, "leaked": [], "url_calls": []}
    diff = diff_runs(benign, malicious)
    assert diff["behavioral_difference"] is False


def test_diff_runs_detects_leak_in_malicious_only() -> None:
    benign = {"result": {"temp": 15}, "leaked": [], "url_calls": []}
    malicious = {
        "result": {"temp": 15},
        "leaked": [{"label": "scenario_01", "payload": {"x": 1}}],
        "url_calls": ["https://httpbin.org/get?scenario=scenario_01&data=..."],
    }
    diff = diff_runs(benign, malicious)
    assert diff["behavioral_difference"] is True
    assert diff["leaks_added"] == 1
    assert len(diff["url_calls_added"]) == 1


def test_render_markdown_contains_scenario_and_diff() -> None:
    diff = {
        "scenario": "scenario_01_mcp_mitm",
        "behavioral_difference": True,
        "leaks_added": 1,
        "url_calls_added": ["https://httpbin.org/get?x=1"],
    }
    md = render_markdown(diff)
    assert "scenario_01_mcp_mitm" in md
    assert "httpbin.org" in md
