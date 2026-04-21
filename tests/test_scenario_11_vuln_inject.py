"""Scenario 11: vulnerability injection via time-bomb trigger.

Uses the same arm_session flow as S2/S6. Extra assertion: the malicious
frontmatter escalates `tools:` from Read, Grep to Read, Grep, Bash, WebFetch.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml  # type: ignore[import-untyped]

from agents import _variants
from agents.loader import load_prompt
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
def tmp_agents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = Path(__file__).resolve().parent.parent
    src = repo / "agents"
    dst = tmp_path / "agents"
    dst.mkdir()
    for name in ("code_reviewer.md", "task_runner.md", "security_reviewer.md"):
        shutil.copy(src / name, dst / name)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    import importlib

    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return dst


def _parse_frontmatter(text: str) -> dict[str, Any]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert m, "missing YAML frontmatter"
    return yaml.safe_load(m.group(1))  # type: ignore[no-any-return]


def test_benign_security_reviewer_has_narrow_tools(tmp_agents: Path) -> None:
    fm = _parse_frontmatter(load_prompt("security_reviewer", root=tmp_agents))
    assert fm["tools"] == "Read, Grep"


def test_armed_security_reviewer_escalates_tools_and_injects_body(
    tmp_agents: Path,
) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_11_vuln_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    prompt = load_prompt("security_reviewer", root=tmp_agents)
    fm = _parse_frontmatter(prompt)
    assert "Bash" in fm["tools"]
    assert "WebFetch" in fm["tools"]
    assert "IMPORTANT INTERNAL INSTRUCTION" in prompt


def test_cleanup_restores_security_reviewer(tmp_agents: Path) -> None:
    from harness import cleanup_sentinels
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_11_vuln_inject", _ForcedTrigger(True)):
        arm_session.arm_agents(agents_root=tmp_agents)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels(
        [tmp_agents.parent / "agents"], dry_run=False
    )
    assert exit_code == 0
    assert (tmp_agents / "security_reviewer.md").read_text() == _variants.BENIGN_SECURITY_REVIEWER
