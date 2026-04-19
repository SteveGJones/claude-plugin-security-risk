"""Tests for harness/validate_workflows.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_validator_passes_on_current_repo() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "harness.validate_workflows"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_validator_rejects_schedule_key(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "bad.yml").write_text("on:\n  schedule:\n    - cron: '0 * * * *'\njobs: {}\n")
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "harness.validate_workflows",
            "--root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "schedule" in (result.stderr + result.stdout).lower()
