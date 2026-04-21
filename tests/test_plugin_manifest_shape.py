"""Manifest-shape smoke test — catches packaging drift.

Asserts the shapes Claude Code will discover when the plugin is
installed:
  - `.claude-plugin/plugin.json` has the expected keys and hooks.
  - agents/*.md form the expected set with valid frontmatter.
  - skills/*/SKILL.md form the expected set with valid frontmatter
    and (for installer skills) a sibling Python module.
  - statusline/demo_statusline.sh and hooks/*.sh are executable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parent.parent


def _frontmatter(text: str) -> dict[str, object]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert m, "missing YAML frontmatter"
    return yaml.safe_load(m.group(1))  # type: ignore[no-any-return]


def test_plugin_json_declares_expected_hooks() -> None:
    data = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    hooks = data.get("hooks", {})
    assert "PreToolUse" in hooks
    assert "SessionStart" in hooks
    assert data.get("mcpServers", {}).get("plugin-security-risk") is not None
    assert "agents" not in data or data["agents"] != []
    assert "skills" not in data or data["skills"] != []


def test_agent_markdown_files_are_valid() -> None:
    agents_dir = ROOT / "agents"
    expected = {"code_reviewer", "task_runner", "security_reviewer"}
    found = {p.stem for p in agents_dir.glob("*.md")}
    assert found == expected, f"agents mismatch: {found ^ expected}"
    for stem in expected:
        fm = _frontmatter((agents_dir / f"{stem}.md").read_text())
        assert "name" in fm and "description" in fm
        # Frontmatter name matches filename stem (with hyphens).
        assert str(fm["name"]).replace("-", "_") == stem


def test_skill_directories_are_valid() -> None:
    skills_dir = ROOT / "skills"
    expected = {
        "summarise",
        "cost_estimator",
        "credential_scanner",
        "research_assistant",
        "install_hook",
        "install_mcp_entry",
        "install_statusline",
    }
    found = {p.name for p in skills_dir.iterdir() if p.is_dir() and p.name != "__pycache__"}
    assert found == expected, f"skills mismatch: {found ^ expected}"
    for name in expected:
        skill_md = skills_dir / name / "SKILL.md"
        assert skill_md.exists(), f"{name}: SKILL.md missing"
        fm = _frontmatter(skill_md.read_text())
        assert "name" in fm and "description" in fm


def test_installer_skills_have_python_sibling() -> None:
    skills_dir = ROOT / "skills"
    for name in ("install_hook", "install_mcp_entry", "install_statusline"):
        py_file = skills_dir / name / f"{name}.py"
        assert py_file.exists(), f"{name}: {py_file.name} missing"
        # Importable?
        import importlib

        mod = importlib.import_module(f"skills.{name}.{name}")
        assert mod is not None


def test_hooks_are_executable() -> None:
    import os

    hooks_dir = ROOT / "hooks"
    for sh in hooks_dir.glob("*.sh"):
        mode = os.stat(sh).st_mode
        assert mode & 0o111, f"{sh} is not executable"


def test_statusline_is_executable() -> None:
    import os

    sl = ROOT / "statusline" / "demo_statusline.sh"
    assert sl.exists()
    mode = os.stat(sl).st_mode
    assert mode & 0o111, f"{sl} is not executable"


def test_no_stray_benign_malicious_pair_files() -> None:
    """The old .benign.md / .malicious.md pair layout must be gone —
    Claude Code would discover both files in each pair as separate agents."""
    agents_dir = ROOT / "agents"
    stray = list(agents_dir.glob("*.benign.md")) + list(agents_dir.glob("*.malicious.md"))
    assert not stray, f"stray pair files: {stray}"
