"""Global safety invariants — spec §3 and §9.

These tests enforce the hard rules that define what 'malicious' mode is
allowed to do. A failure here is a safety boundary violation and must block
any merge.
"""

from __future__ import annotations

import ast
import json as _json
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parent.parent


def _all_py_files(root: Path) -> list[Path]:
    """Scan *.py files under root, skipping nested caches, venv, tests, and
    any nested worktree copies. We check the *relative* parts because the
    repo itself may live under a `.worktrees/` path (git worktree layout);
    we only want to exclude `.worktrees` dirs nested inside the scanned
    root, not reject every file when the root itself is a worktree."""
    skip = {"tests", "__pycache__", ".venv", ".worktrees"}
    return [
        p for p in root.rglob("*.py") if not any(part in skip for part in p.relative_to(root).parts)
    ]


# ---------- Invariant 1: every malicious path routes through leak() ----------

MALICIOUS_MARKER = "# malicious_path"


def _collect_source_files() -> list[Path]:
    dirs = [ROOT / "plugin_mcp" / "tools", ROOT / "skills", ROOT / "agents"]
    files: list[Path] = []
    for d in dirs:
        files.extend(p for p in d.rglob("*.py") if "__pycache__" not in p.parts)
    return files


def _function_contains_call_to(node: ast.AST, target_name: str) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute) and func.attr == target_name:
                return True
            if isinstance(func, ast.Name) and func.id == target_name:
                return True
    return False


def _find_malicious_marker_offenders(files: Iterable[Path]) -> list[str]:
    """Locate every `# malicious_path` site and its innermost enclosing function.

    A marker offends if the innermost function containing it has no call to
    `leak()` anywhere in its body — or if the marker sits outside any
    function. A function's line span is `[lineno, end_lineno]` on its AST
    node; this avoids the `ast.walk(...).lineno` pitfall where comment-only
    lines never appear in the set (comments emit no AST nodes), which made
    the previous implementation skip every function and pass vacuously.
    """
    offenders: list[str] = []
    for path in files:
        source = path.read_text()
        if MALICIOUS_MARKER not in source:
            continue
        tree = ast.parse(source)
        marker_lines = {
            i + 1 for i, line in enumerate(source.splitlines()) if MALICIOUS_MARKER in line
        }
        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        bad: set[str] = set()
        for marker in marker_lines:
            enclosing = [f for f in functions if f.lineno <= marker <= (f.end_lineno or f.lineno)]
            if not enclosing:
                bad.add(f"{path}:line{marker}-outside-any-function")
                continue
            innermost = min(enclosing, key=lambda f: (f.end_lineno or f.lineno) - f.lineno)
            if not _function_contains_call_to(innermost, "leak"):
                bad.add(f"{path}:{innermost.name}")
        offenders.extend(sorted(bad))
    return offenders


def test_every_marked_malicious_block_calls_leak() -> None:
    """Every code block tagged `# malicious_path` must contain a call to leak()."""
    offenders = _find_malicious_marker_offenders(_collect_source_files())
    assert not offenders, f"malicious paths without leak(): {offenders}"


def test_malicious_marker_invariant_detects_missing_leak(tmp_path: Path) -> None:
    """Self-test: the invariant must flag a `# malicious_path` site with no leak() call.

    Guards against regressions where the marker→function resolution silently
    skips every function (the bug fixed by introducing
    `_find_malicious_marker_offenders`).
    """
    bad = tmp_path / "broken.py"
    bad.write_text(
        "def foo(x: int) -> int:\n"
        "    if x > 0:\n"
        "        # malicious_path\n"
        "        return x * 2\n"
        "    return x\n"
    )
    good = tmp_path / "ok.py"
    good.write_text(
        "def bar(x: int) -> int:\n"
        "    if x > 0:\n"
        "        # malicious_path\n"
        "        leak('sid', {'x': x})\n"
        "    return x\n"
    )
    assert _find_malicious_marker_offenders([bad]) == [f"{bad}:foo"]
    assert _find_malicious_marker_offenders([good]) == []


# ---------- Invariant 2: exfil endpoint allowlist is enforced ----------


def test_leak_rejects_non_allowlisted_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from plugin_mcp import exfil

    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    monkeypatch.setenv("EXFIL_ENDPOINT", "https://evil.example.com/")

    with pytest.raises(exfil.ExfilConfigError):
        exfil.leak("test", {"x": 1})


def test_allowlist_only_contains_benign_hosts() -> None:
    from plugin_mcp import exfil

    assert exfil.EXFIL_ALLOWLIST == frozenset({"httpbin.org", "api.github.com"})


# ---------- Invariant 3: no real-looking credentials in captured payloads ----

REAL_TOKEN_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    re.compile(r"sk-[A-Za-z0-9]{48}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
]


def test_capture_contains_no_real_looking_tokens() -> None:
    capture = ROOT / "capture"
    if not capture.exists():
        return
    for path in capture.rglob("*"):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        text = path.read_text(errors="ignore")
        for pattern in REAL_TOKEN_PATTERNS:
            matches = pattern.findall(text)
            assert not matches, f"real-looking token found in {path}: {matches[:1]}"


# ---------- Invariant 4: capture/ writes stay within capture/ ------------


def test_leak_writes_go_only_into_capture_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from plugin_mcp import exfil

    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())

    exfil.leak("test", {"x": 1})

    # Assert no files were created outside the temporary capture dir
    allowed = tmp_path / "capture"
    for path in tmp_path.rglob("*"):
        if path.is_dir():
            continue
        assert str(path).startswith(str(allowed)), f"leak wrote outside capture: {path}"


# ---------- Invariant 5: scenario-6 spawn is bounded and killable --------


def test_spawn_helper_rejects_excessive_duration() -> None:
    from agents import spawn_helper

    with pytest.raises(ValueError):
        spawn_helper.spawn_background(duration_seconds=301)


# ---------- Invariant 6: time-bomb triggers respect injected clock -------


def test_time_bomb_triggers_in_registry_respect_clock() -> None:
    """Every TimeBombTrigger in the registry must evaluate differently before/after its trigger."""
    from datetime import datetime

    from plugin_mcp import state
    from plugin_mcp.triggers.time_bomb import TimeBombTrigger

    tb_triggers = [
        (sid, trig) for sid, trig in state._REGISTRY.items() if isinstance(trig, TimeBombTrigger)
    ]
    assert tb_triggers, "expected at least one TimeBombTrigger in registry"

    for sid, trig in tb_triggers:
        # Replace the clock to force before-then-after
        if trig._after is not None:
            before = lambda: datetime(1999, 1, 1)  # noqa: E731
            after = lambda: datetime(2099, 1, 1)  # noqa: E731
        else:
            assert trig._hours is not None
            _start_h: int = trig._hours[0]
            before = lambda h=_start_h: datetime(2026, 1, 1, (h + 12) % 24)  # type: ignore[misc]  # noqa: E731
            after = lambda h=_start_h: datetime(2026, 1, 1, h)  # type: ignore[misc]  # noqa: E731

        trig._clock = before
        assert trig.evaluate() is False, f"{sid}: expected benign before trigger"
        trig._clock = after
        assert trig.evaluate() is True, f"{sid}: expected malicious after trigger"


# ---------- Invariant 7: writes outside capture/ use sentinel helper ----------


def test_writes_outside_capture_use_sentinel_helper() -> None:
    """`open(..., 'w'|'a')` outside the designated chokepoints is forbidden.

    Every malicious mutation of a persistence-relevant file must route through
    `exfil.write_sentinel_block`, which enforces the path allowlist and wraps
    writes in cleanup-friendly sentinels.
    """
    offenders: list[str] = []
    allowlisted_files = {
        "plugin_mcp/exfil.py",
        "harness/cleanup_sentinels.py",
    }
    for path in _all_py_files(ROOT):
        rel = path.relative_to(ROOT).as_posix()
        if rel in allowlisted_files:
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"
            ):
                continue
            if len(node.args) < 2:
                continue
            mode = node.args[1]
            if (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, str)
                and ("w" in mode.value or "a" in mode.value)
            ):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, f"raw write opens outside sentinel helper: {offenders}"


# ---------- Invariant 8: network imports only in allowlisted modules ----------


def test_network_calls_only_in_allowlisted_modules() -> None:
    """Outbound HTTP modules (httpx/requests/urllib) allowed only in chokepoint files.

    The existing legitimate uses are: `plugin_mcp/exfil.py` (the exfil
    chokepoint), `plugin_mcp/tools/fetch_weather.py` (scenario 1's benign
    weather call), and `harness/compare.py` (demo runner).
    """
    allow = {
        "plugin_mcp/exfil.py",
        "plugin_mcp/tools/fetch_weather.py",
        "harness/compare.py",
        "harness/demo_proxy.py",  # future: Phase 2 integration-only scenarios
    }
    offenders: list[str] = []
    for path in _all_py_files(ROOT):
        rel = path.relative_to(ROOT).as_posix()
        if rel in allow:
            continue
        src = path.read_text()
        for needle in (
            "import httpx",
            "import requests",
            "import urllib.request",
            "from httpx",
            "from requests",
            "from urllib.request",
        ):
            if needle in src:
                offenders.append(f"{rel}:{needle}")
    assert not offenders, f"network imports outside allowlist: {offenders}"


# ---------- Invariant 9: any bind target is loopback-only ----------


def test_binds_only_to_loopback() -> None:
    """Any socket bind / uvicorn / asyncio.start_server must target 127.0.0.1.

    The strings `0.0.0.0` and `localhost` are banned — loopback must be
    specified as the explicit IPv4 literal so network-scope is unambiguous
    at audit time.
    """
    offenders: list[str] = []
    for path in _all_py_files(ROOT):
        rel = path.relative_to(ROOT).as_posix()
        src = path.read_text()
        if "0.0.0.0" in src or '"localhost"' in src or "'localhost'" in src:
            offenders.append(rel)
    assert not offenders, f"non-loopback bind strings found: {offenders}"


# ---------- Invariant 10: subprocess only in spawn/harness modules -----------


def test_subprocess_only_in_spawn_module() -> None:
    """`subprocess.Popen` / `os.fork` forbidden outside a small set of modules.

    Allowed: the scenario-6 spawn module, harness demo infra, cleanup tooling,
    and the two triggers that shell out to `git` for release-tag / remote URL
    resolution.
    """
    allow = {
        "plugin_mcp/tools/spawn.py",  # future: Phase 2 may move spawn here
        "agents/spawn_helper.py",  # current scenario-6 spawn location
        "harness/demo_proxy.py",
        "harness/demo_mcp_server.py",
        "harness/cleanup_sentinels.py",
        "harness/compare.py",  # `unittest.mock.patch` target string, not a real spawn
        "plugin_mcp/triggers/release_tag.py",
        "plugin_mcp/triggers/git_remote.py",
    }
    offenders: list[str] = []
    for path in _all_py_files(ROOT):
        rel = path.relative_to(ROOT).as_posix()
        if rel in allow:
            continue
        src = path.read_text()
        if "subprocess.Popen" in src or "os.fork" in src:
            offenders.append(rel)
    assert not offenders, f"Popen/fork outside allowlist: {offenders}"


# ---------- Invariant 11: spawn module declares depth/children caps ----------


def test_spawn_module_declares_depth_and_children_caps() -> None:
    spawn = (ROOT / "plugin_mcp" / "tools" / "spawn.py").read_text()
    assert "MAX_DEPTH = 3" in spawn
    assert "MAX_CHILDREN = 5" in spawn


# ---------- Invariant 12: flip workflow guards repo identity ----------------


def test_flip_workflow_guards_repo_identity() -> None:
    wf = (ROOT / ".github" / "workflows" / "release-flip.yml").read_text()
    assert "github.repository" in wf and "SteveGJones/claude-plugin-security-risk" in wf
    assert "DEMO_FLIP_CONFIRM" in wf
    assert "DEMO_HALT" in wf


def test_flip_workflow_has_no_schedule_key() -> None:
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "release-flip.yml").read_text())
    # PyYAML returns True for the bare `on:` key; check both keys for safety.
    assert "schedule" not in wf.get(True, {}) and "schedule" not in wf.get("on", {})


# ---------- Invariant 13: sentinel cleanup is idempotent ---------------------


def test_cleanup_is_idempotent(tmp_path: Path) -> None:
    home = tmp_path
    settings = home / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        "keep\n"
        "# DEMO_SENTINEL_START scenario_17_hook_abuse 2026-04-18T00:00:00+00:00\n"
        "x\n"
        "# DEMO_SENTINEL_END scenario_17_hook_abuse\n"
    )
    for _ in range(2):
        rc = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "harness.cleanup_sentinels", "--home", str(home)],
            cwd=ROOT,
            check=False,
        ).returncode
        assert rc == 0
    assert settings.read_text() == "keep\n"


# ---------- Invariant 14: sentinel cleanup refuses malformed input ---------


def test_cleanup_refuses_malformed_sentinels(tmp_path: Path) -> None:
    home = tmp_path
    settings = home / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        "# DEMO_SENTINEL_START scenario_17_hook_abuse 2026-04-18T00:00:00+00:00\n(unclosed)\n"
    )
    rc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "harness.cleanup_sentinels", "--home", str(home)],
        cwd=ROOT,
        check=False,
    ).returncode
    assert rc != 0


# ---------- Invariant 15: plugin.json declares demo:true flag ---------------


def test_plugin_json_requires_demo_flag() -> None:
    data = _json.loads((ROOT / "plugin.json").read_text())
    assert data.get("demo") is True


# ---------- Invariant 16: restore_module must be a string literal ----------


def test_full_replace_restore_module_is_literal() -> None:
    """Any call to exfil.write_sentinel_block with full_replace=True must
    pass restore_module= as a string literal — never an attacker-reachable
    variable. A computed restore_module could let a tampered caller
    redirect cleanup to an attacker-chosen module.

    Exempt files:
      - exfil.py / test_exfil.py: define and test the chokepoint itself.
      - plugin_mcp/scenarios/arm_session.py: the single authorised
        orchestrator whose restore_module is an f-string whose only
        interpolations are keys from hard-coded AGENT_SCENARIOS /
        SKILL_SCENARIOS dicts (audited centrally).
    """
    offenders: list[str] = []
    for path in _all_py_files(ROOT):
        if path.name in {"exfil.py", "test_exfil.py", "arm_session.py"}:
            continue
        tree = ast.parse(path.read_text())
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            is_target = (
                isinstance(func, ast.Attribute) and func.attr == "write_sentinel_block"
            ) or (isinstance(func, ast.Name) and func.id == "write_sentinel_block")
            if not is_target:
                continue
            full_replace_kw = next(
                (kw for kw in call.keywords if kw.arg == "full_replace"),
                None,
            )
            if full_replace_kw is None:
                continue
            if not (
                isinstance(full_replace_kw.value, ast.Constant)
                and full_replace_kw.value.value is True
            ):
                continue
            restore_kw = next(
                (kw for kw in call.keywords if kw.arg == "restore_module"),
                None,
            )
            if restore_kw is None:
                offenders.append(f"{path}:{call.lineno} missing restore_module")
                continue
            if not (
                isinstance(restore_kw.value, ast.Constant)
                and isinstance(restore_kw.value.value, str)
            ):
                offenders.append(f"{path}:{call.lineno} restore_module not a string literal")
    assert not offenders, f"FULL_REPLACE restore_module violations: {offenders}"


# ---------- Invariant 17: no raw filesystem writes in scenario code ----------

_SCENARIO_DIRS_BANNING_RAW_WRITES = ("agents", "skills", "hooks", "plugin_mcp/scenarios")
# Exempt data-only and bookkeeping files:
#   - _variants.py: pure string constants (the canonical benign/malicious bodies).
#   - spawn_helper.py: scenario-6 bounded subprocess helper; writes a PID
#     tracking file into capture/scenario_06_pids/ (not a payload; visible
#     at rest; reaped by harness/kill_demo).
_ALLOWED_RAW_WRITE_FILES = {"_variants.py", "spawn_helper.py"}


def test_scenario_code_uses_exfil_chokepoint_only() -> None:
    """agents/**, skills/**, hooks/** (Python) and plugin_mcp/scenarios/**
    must not contain Path.write_text / open(..., 'w'|'a'|'x') calls.
    All writes go through exfil.write_sentinel_block."""
    offenders: list[str] = []
    for scenario_dir in _SCENARIO_DIRS_BANNING_RAW_WRITES:
        root = ROOT / scenario_dir
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if path.name in _ALLOWED_RAW_WRITE_FILES:
                continue
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                # Path(...).write_text
                if isinstance(func, ast.Attribute) and func.attr == "write_text":
                    offenders.append(f"{path}:{node.lineno} write_text")
                # open(..., 'w'|'a'|'x')
                if isinstance(func, ast.Name) and func.id == "open":
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        mode = node.args[1].value
                        if isinstance(mode, str) and any(c in mode for c in "wax"):
                            offenders.append(f"{path}:{node.lineno} open({mode!r})")
    assert not offenders, f"raw filesystem writes outside chokepoint: {offenders}"


# ---------- Invariant 18: round-trip restore for every _variants.py ----------


@pytest.fixture
def _round_trip_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import shutil

    for sub in ("agents", "skills"):
        shutil.copytree(ROOT / sub, tmp_path / sub)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    import importlib

    from plugin_mcp import exfil

    importlib.reload(exfil)
    return tmp_path


def test_round_trip_agent_variants(_round_trip_repo: Path) -> None:
    from agents import _variants
    from harness import cleanup_sentinels
    from plugin_mcp import exfil

    for stem in ("code_reviewer", "task_runner", "security_reviewer"):
        target = _round_trip_repo / "agents" / f"{stem}.md"
        malicious = getattr(_variants, f"MALICIOUS_{stem.upper()}")
        benign = getattr(_variants, f"BENIGN_{stem.upper()}")
        exfil.write_sentinel_block(
            target,
            f"scenario_test_{stem}",
            malicious,
            full_replace=True,
            restore_module=f"agents._variants:BENIGN_{stem.upper()}",
        )
        assert (
            cleanup_sentinels.restore_full_replace_sentinels(
                [_round_trip_repo / "agents"], dry_run=False
            )
            == 0
        )
        assert target.read_text() == benign


def test_round_trip_skill_variants(_round_trip_repo: Path) -> None:
    import importlib

    from harness import cleanup_sentinels
    from plugin_mcp import exfil

    for skill_name in ("summarise", "cost_estimator", "credential_scanner", "research_assistant"):
        variants = importlib.import_module(f"skills.{skill_name}._variants")
        target = _round_trip_repo / "skills" / skill_name / "SKILL.md"
        exfil.write_sentinel_block(
            target,
            f"scenario_test_{skill_name}",
            variants.MALICIOUS_SKILL_MD,
            full_replace=True,
            restore_module=f"skills.{skill_name}._variants:BENIGN_SKILL_MD",
        )
        assert (
            cleanup_sentinels.restore_full_replace_sentinels(
                [_round_trip_repo / "skills"], dry_run=False
            )
            == 0
        )
        assert target.read_text() == variants.BENIGN_SKILL_MD
