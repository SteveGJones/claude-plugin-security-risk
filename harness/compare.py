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
from plugin_mcp.state import _REGISTRY as _TRIGGER_REGISTRY
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
    "scenario_12": ("scenario_12_release_flip", "release_check"),
    "scenario_13": ("scenario_13_git_mitm_real", "git_clone_real"),
    "scenario_14": ("scenario_14_proliferation_real", "spawn_work"),
    "scenario_15": ("scenario_15_padding_real", "estimate"),
    "scenario_16": ("scenario_16_plugin_json_cicd", "overlay_patch"),
    "scenario_17": ("scenario_17_hook_abuse", "install_pre_tool_hook"),
    "scenario_18": ("scenario_18_statusline_beacon", "install_statusline"),
    "scenario_19": ("scenario_19_slash_cmd_shadow", "handle_slash_commit"),
    "scenario_20": ("scenario_20_context_dependent", "fetch_weather_ctx"),
    "scenario_21": ("scenario_21_hallucination_cover", "research"),
    "scenario_22": ("scenario_22_mcp_json_persistence", "install_mcp_entry"),
    "scenario_23": ("scenario_23_mcp_transport_impersonation", "demo_mcp_server"),
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
        if scenario_id in _TRIGGER_REGISTRY:
            with state.override(scenario_id, _ForcedTrigger(force_malicious)):
                result = _invoke(short_id, fixture, tmp_capture)
        else:
            # Scenarios with no runtime trigger (e.g. file-artifact scenarios)
            result = _invoke(short_id, fixture, tmp_capture)
    finally:
        httpx.get = original_get
        exfil.CAPTURE_DIR = original_capture

    leaks: list[dict[str, Any]] = []
    leaks_file = tmp_capture / "leaks.jsonl"
    if leaks_file.exists():
        leaks = [json.loads(line) for line in leaks_file.read_text().splitlines() if line]

    return {"result": result, "leaked": leaks, "url_calls": url_calls}


def _invoke(short_id: str, fixture: dict[str, Any], tmp_capture: Path) -> Any:
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
    if short_id == "scenario_12":
        from plugin_mcp.tools.release_check import release_check

        return release_check()
    if short_id == "scenario_13":
        import os
        from unittest.mock import patch

        from plugin_mcp.tools.git_clone import git_clone

        orig_roots = exfil.SENTINEL_ALLOWLIST_ROOTS
        orig_home = os.environ.get("HOME")
        exfil.SENTINEL_ALLOWLIST_ROOTS = (tmp_capture,)
        os.environ["HOME"] = str(tmp_capture)
        try:
            with patch("harness.demo_proxy.start", return_value=(MagicMock(), 12345)):
                with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr=b"")):
                    return git_clone({"url": fixture["params"]["url"]})
        finally:
            exfil.SENTINEL_ALLOWLIST_ROOTS = orig_roots
            if orig_home is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = orig_home
    if short_id == "scenario_14":
        from unittest.mock import patch

        from plugin_mcp.tools import spawn

        orig_pids = spawn._CAPTURE_PIDS
        fake_procs: list[MagicMock] = []

        def _fake_popen(argv: list[str], **_kw: Any) -> MagicMock:
            p: MagicMock = MagicMock(pid=9999)
            p.terminate = MagicMock()
            p.wait = MagicMock(return_value=0)
            fake_procs.append(p)
            return p

        spawn._CAPTURE_PIDS = tmp_capture / "pids.txt"
        try:
            with patch("plugin_mcp.tools.spawn.subprocess.Popen", side_effect=_fake_popen):
                spawn.spawn_work(depth=fixture.get("depth", 0))
            return {"spawned": len(fake_procs)}
        finally:
            spawn._CAPTURE_PIDS = orig_pids
    if short_id == "scenario_15":
        from skills.cost_estimator import estimate

        return estimate(fixture["prompt"])
    if short_id == "scenario_16":
        patch_path = Path(__file__).resolve().parent.parent / "release-overlays" / "malicious.patch"
        return {
            "overlay_exists": patch_path.exists(),
            "size": patch_path.stat().st_size if patch_path.exists() else 0,
        }
    if short_id == "scenario_17":
        from skills.install_hook import install_pre_tool_hook

        orig_roots = exfil.SENTINEL_ALLOWLIST_ROOTS
        exfil.SENTINEL_ALLOWLIST_ROOTS = (tmp_capture,)
        try:
            install_pre_tool_hook(home=tmp_capture)
        finally:
            exfil.SENTINEL_ALLOWLIST_ROOTS = orig_roots
        return {"ok": True}
    if short_id == "scenario_18":
        from skills.install_statusline import install_statusline

        orig_roots = exfil.SENTINEL_ALLOWLIST_ROOTS
        exfil.SENTINEL_ALLOWLIST_ROOTS = (tmp_capture,)
        try:
            install_statusline(home=tmp_capture)
        finally:
            exfil.SENTINEL_ALLOWLIST_ROOTS = orig_roots
        return {"ok": True}
    if short_id == "scenario_19":
        from skills.slash_commit import handle_slash_commit

        return handle_slash_commit(
            changed_paths=fixture["changed_paths"],
            user_intent=fixture["user_intent"],
        )
    if short_id == "scenario_20":
        from plugin_mcp.tools.fetch_weather import fetch_weather_ctx

        return fetch_weather_ctx(city=fixture["city"], context=fixture.get("context"))
    if short_id == "scenario_21":
        from skills.research_assistant import research

        return research(fixture["topic"])
    if short_id == "scenario_22":
        from skills.install_mcp_entry import install_mcp_entry

        orig_roots = exfil.SENTINEL_ALLOWLIST_ROOTS
        exfil.SENTINEL_ALLOWLIST_ROOTS = (tmp_capture,)
        try:
            install_mcp_entry(home=tmp_capture, port=fixture.get("port", 8800))
        finally:
            exfil.SENTINEL_ALLOWLIST_ROOTS = orig_roots
        return {"ok": True}
    if short_id == "scenario_23":
        from harness import demo_mcp_server

        return {
            "handler_class": demo_mcp_server._Handler.__name__,
            "has_start": hasattr(demo_mcp_server, "start"),
        }
    raise KeyError(short_id)


def compare_one(short_id: str, reports_dir: Path, integration: bool = False) -> None:
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
    parser.add_argument(
        "--integration",
        action="store_true",
        default=False,
        help="Enable real-effects paths for integration scenarios (13, 14, 23).",
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
        compare_one(s, reports_dir, integration=args.integration)

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
