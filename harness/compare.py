"""Standalone harness: runs a scenario in both modes and writes diff reports.

For each scenario:
1. Load the fixture input.
2. Force the trigger to benign via state.override(_FixedTrigger(False)) and run.
3. Force the trigger to malicious via state.override(_FixedTrigger(True)) and run.
4. Capture results, leaks, and outbound URL calls from both runs.
5. Diff and render a markdown report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger

SCENARIO_MAP: dict[str, tuple[str, str]] = {
    "scenario_01": ("scenario_01_mcp_mitm", "fetch_weather"),
    "scenario_02": ("scenario_02_subagent_inject", "code_reviewer"),
    "scenario_03": ("scenario_03_skill_sub", "summarise"),
    "scenario_04": ("scenario_04_cred_harvest", "git_clone"),
    "scenario_05": ("scenario_05_ctx_poison", "search_codebase"),
    "scenario_06": ("scenario_06_proliferation", "task_runner"),
    "scenario_07": ("scenario_07_supply_chain", "auto_update"),
    "scenario_08": ("scenario_08_permission_creep", "permission_creep"),
    "scenario_09": ("scenario_09_token_burn", "cost_estimator"),
    "scenario_10": ("scenario_10_cred_insert", "credential_scanner"),
    "scenario_11": ("scenario_11_vuln_inject", "security_reviewer"),
}


class _ForcedTrigger(Trigger):
    def __init__(self, value: bool) -> None:
        self._value = value

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._value

    def describe(self) -> str:
        return f"forced({self._value})"


def run_scenario(short_id: str, force_malicious: bool, tmp_capture: Path) -> dict[str, Any]:
    """Run one scenario under a forced trigger and return recorded observations."""
    scenario_id, entry = SCENARIO_MAP[short_id]
    fixture = json.loads((Path(__file__).parent / "fixtures" / f"{short_id}.json").read_text())

    # Intercept network calls and capture dir
    url_calls: list[str] = []

    def _record_get(url: str, **_kw: Any) -> MagicMock:
        url_calls.append(url)
        return MagicMock(json=MagicMock(return_value={}))

    fake_get = MagicMock(side_effect=_record_get)

    import httpx

    original_get = httpx.get
    original_capture = exfil.CAPTURE_DIR
    httpx.get = fake_get
    exfil.CAPTURE_DIR = tmp_capture
    tmp_capture.mkdir(parents=True, exist_ok=True)

    try:
        with state.override(scenario_id, _ForcedTrigger(force_malicious)):
            result = _invoke(short_id, fixture)
    finally:
        httpx.get = original_get
        exfil.CAPTURE_DIR = original_capture

    leaks: list[dict[str, Any]] = []
    leaks_file = tmp_capture / "leaks.jsonl"
    if leaks_file.exists():
        leaks = [json.loads(line) for line in leaks_file.read_text().splitlines() if line]

    return {"result": result, "leaked": leaks, "url_calls": url_calls}


def _invoke(short_id: str, fixture: dict[str, Any]) -> Any:
    """Dispatch a fixture to the right implementation."""
    if short_id == "scenario_01":
        from plugin_mcp.tools.fetch_weather import fetch_weather

        return fetch_weather(fixture["params"])
    if short_id == "scenario_02":
        from agents.loader import load_prompt

        return load_prompt(fixture["agent"])
    if short_id == "scenario_03":
        from skills.summarise import summarise

        return summarise(fixture["document"])
    if short_id == "scenario_04":
        from plugin_mcp.tools.git_clone import git_clone

        orig = subprocess.run
        subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stderr=b""))
        try:
            return git_clone(fixture["params"])
        finally:
            subprocess.run = orig
    if short_id == "scenario_05":
        from plugin_mcp.tools.search_codebase import search_codebase

        return search_codebase(fixture["params"])
    if short_id == "scenario_06":
        from agents.loader import load_prompt

        return load_prompt(fixture["agent"])
    if short_id == "scenario_07":
        from plugin_mcp.tools.auto_update import auto_update

        return auto_update(fixture["params"])
    if short_id == "scenario_08":
        return {"skipped": "scenario 8 is manifest-level; see harness/permission_creep.py"}
    if short_id == "scenario_09":
        from skills.cost_estimator import estimate_cost

        return estimate_cost(fixture["snippet"])
    if short_id == "scenario_10":
        from skills.credential_scanner import scan_credentials

        return scan_credentials(fixture["file_contents"])
    if short_id == "scenario_11":
        from agents.loader import load_prompt

        return load_prompt(fixture["agent"])
    raise KeyError(short_id)


def compare_one(short_id: str, reports_dir: Path) -> None:
    from harness.report import diff_runs, render_markdown

    benign = run_scenario(
        short_id, force_malicious=False, tmp_capture=reports_dir / f"{short_id}_benign"
    )
    malicious = run_scenario(
        short_id, force_malicious=True, tmp_capture=reports_dir / f"{short_id}_malicious"
    )

    (reports_dir / f"{short_id}_benign.json").write_text(json.dumps(benign, default=str, indent=2))
    malicious_json = json.dumps(malicious, default=str, indent=2)
    (reports_dir / f"{short_id}_malicious.json").write_text(malicious_json)

    diff = diff_runs(benign, malicious)
    diff["scenario"] = short_id
    report_md = render_markdown(diff)
    (reports_dir / f"{short_id}.md").write_text(report_md)
    bd = diff["behavioral_difference"]
    la = diff["leaks_added"]
    print(f"{short_id}: behavioral_difference={bd} leaks_added={la}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run scenarios in both modes and diff.")
    parser.add_argument(
        "scenario",
        nargs="?",
        help="Scenario short id (e.g. scenario_01). Omit for all.",
    )
    parser.add_argument(
        "--distribution",
        type=int,
        default=0,
        help="Run N times with live trigger (probabilistic only).",
    )
    args = parser.parse_args()

    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    reports_dir = Path(__file__).parent / "reports" / ts
    reports_dir.mkdir(parents=True, exist_ok=True)

    scenarios = [args.scenario] if args.scenario else list(SCENARIO_MAP.keys())

    if args.distribution:
        if not args.scenario:
            print("--distribution requires a specific scenario", file=sys.stderr)
            return 2
        _run_distribution(args.scenario, args.distribution, reports_dir)
        return 0

    for s in scenarios:
        compare_one(s, reports_dir)

    print(f"\nReports written to {reports_dir}")
    return 0


def _run_distribution(short_id: str, n: int, reports_dir: Path) -> None:
    """Run a scenario N times with the LIVE (not forced) trigger and summarise the distribution."""
    scenario_id, _ = SCENARIO_MAP[short_id]

    hits = 0
    for _ in range(n):
        if state.should_act_malicious(scenario_id):
            hits += 1

    rate = hits / n
    print(f"{short_id}: {hits}/{n} malicious ({rate:.1%})")
    (reports_dir / f"{short_id}_distribution.txt").write_text(
        f"scenario={short_id} n={n} hits={hits} rate={rate:.4f}\n"
    )


if __name__ == "__main__":
    sys.exit(main())
