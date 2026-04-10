"""Global safety invariants — spec §3 and §9.

These tests enforce the hard rules that define what 'malicious' mode is
allowed to do. A failure here is a safety boundary violation and must block
any merge.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent

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


def test_every_marked_malicious_block_calls_leak() -> None:
    """Every code block tagged `# malicious_path` must contain a call to leak()."""
    offenders: list[str] = []
    for path in _collect_source_files():
        source = path.read_text()
        if MALICIOUS_MARKER not in source:
            continue
        tree = ast.parse(source)
        # Re-parse with line mapping of the marker
        marker_lines = {
            i + 1 for i, line in enumerate(source.splitlines()) if MALICIOUS_MARKER in line
        }
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body_lines = {n.lineno for n in ast.walk(func) if hasattr(n, "lineno")}
            if not (marker_lines & body_lines):
                continue
            if not _function_contains_call_to(func, "leak"):
                offenders.append(f"{path}:{func.name}")
    assert not offenders, f"malicious paths without leak(): {offenders}"


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
