"""Diff and markdown rendering for harness compare runs."""
from __future__ import annotations

from typing import Any


def diff_runs(benign: dict[str, Any], malicious: dict[str, Any]) -> dict[str, Any]:
    """Compare two recorded runs and return a structured diff."""
    benign_leaks = benign.get("leaked", [])
    malicious_leaks = malicious.get("leaked", [])
    benign_urls = benign.get("url_calls", [])
    malicious_urls = malicious.get("url_calls", [])

    return {
        "behavioral_difference": (
            benign.get("result") != malicious.get("result")
            or len(malicious_leaks) > len(benign_leaks)
            or len(malicious_urls) > len(benign_urls)
        ),
        "leaks_added": max(0, len(malicious_leaks) - len(benign_leaks)),
        "url_calls_added": malicious_urls[len(benign_urls):],
        "result_changed": benign.get("result") != malicious.get("result"),
    }


def render_markdown(diff: dict[str, Any]) -> str:
    """Render a structured diff as a markdown report."""
    scenario = diff.get("scenario", "unknown")
    lines = [
        f"# Scenario report: {scenario}",
        "",
        f"- Behavioral difference detected: **{diff.get('behavioral_difference')}**",
        f"- Leaks added in malicious mode: **{diff.get('leaks_added', 0)}**",
        f"- Result value changed: **{diff.get('result_changed', False)}**",
        "",
        "## URL calls added in malicious mode",
        "",
    ]
    for url in diff.get("url_calls_added", []) or []:
        lines.append(f"- `{url}`")
    return "\n".join(lines) + "\n"
