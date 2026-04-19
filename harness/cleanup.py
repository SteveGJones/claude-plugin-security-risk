"""Reversibility entry point: undoes all demo side effects.

`make cleanup` invokes this module's main. Safe to run multiple times.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from harness import kill_demo

ROOT = Path(__file__).resolve().parent.parent


def empty_capture(capture_dir: Path) -> None:
    """Remove everything in `capture_dir` except `.gitkeep`."""
    if not capture_dir.exists():
        return
    for entry in capture_dir.iterdir():
        if entry.name == ".gitkeep":
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def reset_mode_file(mode_file: Path) -> None:
    mode_file.write_text("benign\n")


def reset_plugin_json(current: Path, baseline: Path) -> None:
    baseline_data = json.loads(baseline.read_text())
    current.write_text(json.dumps(baseline_data, indent=2) + "\n")


def close_demo_issues() -> None:
    """Close all open GitHub issues labelled `demo-capture` in the current repo.

    Uses the `gh` CLI. Silently skipped if `gh` is not installed or not
    authenticated — cleanup must never fail just because the optional
    GitHub cleanup step isn't available.
    """
    import subprocess

    try:
        subprocess.run(
            [  # noqa: S607
                "gh",
                "issue",
                "list",
                "--label",
                "demo-capture",
                "--state",
                "open",
                "--json",
                "number",
                "-q",
                ".[].number",
            ],
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return

    # Two-step: list then close. Kept simple; in practice you'd parse JSON.
    _close_cmd = (
        "gh issue list --label demo-capture --state open "
        "--json number -q '.[].number' | xargs -r -n1 gh issue close"
    )
    subprocess.run(  # noqa: S603
        ["bash", "-c", _close_cmd],  # noqa: S607
        check=False,
        timeout=30,
    )


def main() -> int:
    kill_demo.main()
    empty_capture(ROOT / "capture")
    reset_mode_file(ROOT / "mode.txt")
    reset_plugin_json(ROOT / "plugin.json", ROOT / "plugin.baseline.json")
    close_demo_issues()
    print("Cleanup complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
