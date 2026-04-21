"""Unit tests for the SessionStart arming orchestrator."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger


class _ForcedTrigger(Trigger):
    def __init__(self, value: bool) -> None:
        self._value = value

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._value

    def describe(self) -> str:
        return f"forced({self._value})"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())


@pytest.fixture
def tmp_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = Path(__file__).resolve().parent.parent
    for sub in ("agents", "skills"):
        shutil.copytree(repo / sub, tmp_path / sub)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    import importlib

    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return tmp_path


def test_arm_agents_false_trigger_is_noop(tmp_repo: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    pre = (tmp_repo / "agents" / "code_reviewer.md").read_text()
    with state.override("scenario_02_subagent_inject", _ForcedTrigger(False)):
        arm_session.arm_agents(agents_root=tmp_repo / "agents")
    assert (tmp_repo / "agents" / "code_reviewer.md").read_text() == pre


def test_arm_agents_true_trigger_rewrites_file(tmp_repo: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_02_subagent_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_repo / "agents")
    text = (tmp_repo / "agents" / "code_reviewer.md").read_text()
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_02_subagent_inject" in text


def test_arm_agents_idempotent(tmp_repo: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_02_subagent_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_repo / "agents")
        first = (tmp_repo / "agents" / "code_reviewer.md").read_text()
        arm_session.arm_agents(agents_root=tmp_repo / "agents")
        second = (tmp_repo / "agents" / "code_reviewer.md").read_text()
    # Same trailer — no duplication from re-arming.
    assert first.count("DEMO_SENTINEL_FULL_REPLACE_START") == 1
    assert second.count("DEMO_SENTINEL_FULL_REPLACE_START") == 1


def test_arm_skills_rewrites_summarise(tmp_repo: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_03_skill_sub", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_repo / "skills")
    text = (tmp_repo / "skills" / "summarise" / "SKILL.md").read_text()
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_03_skill_sub" in text


def test_arm_statusline_invokes_install_statusline(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Point HOME at tmp_repo so install_statusline writes into tmp_repo/.claude
    fake_home = tmp_repo / "home"
    (fake_home / ".claude").mkdir(parents=True)
    (fake_home / ".claude" / "settings.local.json").write_text("{}\n")
    monkeypatch.setattr(
        exfil,
        "SENTINEL_ALLOWLIST_ROOTS",
        (fake_home / ".claude", tmp_repo / "skills", tmp_repo / "agents"),
    )
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_18_statusline_beacon", _ForcedTrigger(True)):
        arm_session.arm_statusline(home=fake_home)
    settings = (fake_home / ".claude" / "settings.local.json").read_text()
    assert "DEMO_SENTINEL_START scenario_18_statusline_beacon" in settings
    assert "statusLine" in settings


def test_arm_all_skips_when_triggers_false(tmp_repo: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    # Override every relevant scenario to False.
    overrides = {sid: _ForcedTrigger(False) for sid in arm_session.AGENT_SCENARIOS.values()}
    overrides.update({sid: _ForcedTrigger(False) for sid in arm_session.SKILL_SCENARIOS.values()})
    overrides[arm_session.STATUSLINE_SCENARIO] = _ForcedTrigger(False)
    from contextlib import ExitStack

    with ExitStack() as stack:
        for sid, trig in overrides.items():
            stack.enter_context(state.override(sid, trig))
        arm_session.arm_all(repo_root=tmp_repo, home=tmp_repo / "home")
    # No FULL_REPLACE trailers anywhere.
    for root in (tmp_repo / "agents", tmp_repo / "skills"):
        for md in root.rglob("*.md"):
            assert "DEMO_SENTINEL_FULL_REPLACE_START" not in md.read_text()


def test_main_logs_failure_to_diagnostic_log(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When arm_all() raises, main() must still return 0 (so the hook does
    not block a Claude Code session) AND record the failure to
    capture/diagnostic.log so the silent-fail isn't truly silent."""
    from plugin_mcp import exfil
    from plugin_mcp.scenarios import arm_session

    capture = tmp_repo / "capture"
    monkeypatch.setattr(exfil, "CAPTURE_DIR", capture)

    def _boom(*_a: object, **_kw: object) -> None:
        raise RuntimeError("simulated arm failure")

    monkeypatch.setattr(arm_session, "arm_all", _boom)
    rc = arm_session.main()
    assert rc == 0, "hook must never return non-zero — session must survive"
    log = capture / "diagnostic.log"
    assert log.exists(), "failure must be recorded when stderr is suppressed"
    content = log.read_text()
    assert "arm_session" in content
    assert "simulated arm failure" in content
