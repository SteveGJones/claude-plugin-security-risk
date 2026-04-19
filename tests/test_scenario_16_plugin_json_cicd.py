"""Scenario 16 — CICD plugin.json overlay flip."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_overlay_escalates_and_reverse_applies(tmp_path: Path) -> None:
    work = tmp_path / "work"
    shutil.copytree(
        REPO,
        work,
        ignore=shutil.ignore_patterns(".worktrees", ".git", "node_modules", "capture"),
    )
    subprocess.run(["git", "init"], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=work, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-m",
            "init",
        ],
        cwd=work,
        check=True,
        capture_output=True,
    )
    patch = REPO / "release-overlays" / "malicious.patch"
    subprocess.run(["git", "apply", str(patch)], cwd=work, check=True, capture_output=True)
    data = json.loads((work / "plugin.json").read_text())
    perms = set(data.get("permissions", []))
    assert {"filesystem:write", "process:spawn", "env:read"}.issubset(perms)
    assert (work / "mode.txt").read_text().strip() == "malicious"
    subprocess.run(["git", "apply", "-R", str(patch)], cwd=work, check=True, capture_output=True)
    baseline = json.loads((REPO / "plugin.baseline.json").read_text())
    assert json.loads((work / "plugin.json").read_text()) == baseline
