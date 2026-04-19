"""Scenario 14 — bounded recursive fork.

Asserts the caps (`MAX_DEPTH`, `MAX_CHILDREN`) are actually honoured and that
no Popen call happens when the trigger is benign.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from plugin_mcp import state
from plugin_mcp.tools.spawn import MAX_CHILDREN, MAX_DEPTH, spawn_work
from plugin_mcp.triggers.base import Trigger


class _AlwaysTrigger(Trigger):
    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return True

    def describe(self) -> str:
        return "always"


class _NeverTrigger(Trigger):
    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return False

    def describe(self) -> str:
        return "never"


class _FakePopen:
    def __init__(self, argv: list[str], **_: object) -> None:
        self.argv = argv
        self.pid = 42

    def terminate(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        return 0


def test_benign_does_not_fork(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_popen(argv: list[str], **kwargs: object) -> _FakePopen:
        calls.append(argv)
        return _FakePopen(argv, **kwargs)

    monkeypatch.setattr("plugin_mcp.tools.spawn.subprocess.Popen", fake_popen)
    with state.override("scenario_14_proliferation_real", _NeverTrigger()):
        spawn_work(depth=0)
    assert calls == []


def test_spawn_respects_depth_and_children_caps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launched: list[tuple[int, int]] = []

    def fake_popen(argv: list[str], **_: object) -> _FakePopen:
        depth = int(argv[argv.index("--depth") + 1])
        child = int(argv[argv.index("--child") + 1])
        launched.append((depth, child))
        return _FakePopen(argv)

    monkeypatch.setattr("plugin_mcp.tools.spawn.subprocess.Popen", fake_popen)
    # Redirect the pid log into a tmp location so we don't pollute capture/
    monkeypatch.setattr("plugin_mcp.tools.spawn._CAPTURE_PIDS", tmp_path / "pids.txt")
    # Stub leak() so we don't try to call httpbin
    monkeypatch.setattr("plugin_mcp.tools.spawn.exfil.leak", lambda *a, **k: None)

    with state.override("scenario_14_proliferation_real", _AlwaysTrigger()):
        spawn_work(depth=0)

    # Only the top-level call fires Popen in-process (children re-exec the module
    # externally — fake_popen returns without recursing). So we should see exactly
    # MAX_CHILDREN entries, all at depth 1.
    assert len(launched) == MAX_CHILDREN
    assert all(d == 1 for d, _ in launched)
    assert all(c < MAX_CHILDREN for _, c in launched)
    # Sanity: plan-specified caps are still honoured symbolically.
    assert MAX_DEPTH == 3
    assert MAX_CHILDREN == 5


def test_depth_guard_blocks_recursion_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_popen(argv: list[str], **_: object) -> _FakePopen:
        calls.append(argv)
        return _FakePopen(argv)

    monkeypatch.setattr("plugin_mcp.tools.spawn.subprocess.Popen", fake_popen)
    monkeypatch.setattr("plugin_mcp.tools.spawn.exfil.leak", lambda *a, **k: None)

    with state.override("scenario_14_proliferation_real", _AlwaysTrigger()):
        spawn_work(depth=MAX_DEPTH)  # at the cap already
    assert calls == []
