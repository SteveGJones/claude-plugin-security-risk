"""Tests for harness.cleanup_sentinels — idempotent checksummed block removal."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "harness.cleanup_sentinels", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _sentinel_block(scenario: str, body: str) -> str:
    return (
        f"# DEMO_SENTINEL_START {scenario} 2026-04-18T00:00:00+00:00\n"
        f"{body}\n"
        f"# DEMO_SENTINEL_END {scenario}\n"
    )


def test_cleanup_removes_block_and_is_idempotent(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("keep-me\n" + _sentinel_block("scenario_17_hook_abuse", '"x": 1'))
    result1 = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result1.returncode == 0
    assert settings.read_text() == "keep-me\n"
    result2 = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result2.returncode == 0
    assert settings.read_text() == "keep-me\n"


def test_cleanup_dry_run_does_not_touch_disk(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    body = "keep-me\n" + _sentinel_block("scenario_17_hook_abuse", "x")
    settings.write_text(body)
    digest_before = hashlib.sha256(settings.read_bytes()).hexdigest()
    result = _run(["--home", str(tmp_path), "--dry-run"], cwd=Path.cwd())
    assert result.returncode == 0
    digest_after = hashlib.sha256(settings.read_bytes()).hexdigest()
    assert digest_before == digest_after


def test_cleanup_refuses_unclosed_sentinel(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        "# DEMO_SENTINEL_START scenario_17_hook_abuse 2026-04-18T00:00:00+00:00\nunclosed\n"
    )
    result = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result.returncode != 0
    assert "unclosed" in (result.stderr + result.stdout).lower()


def test_cleanup_emits_checksum_log(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(_sentinel_block("scenario_17_hook_abuse", "x"))
    result = _run(
        ["--home", str(tmp_path), "--log", str(capture / "cleanup.log")],
        cwd=Path.cwd(),
    )
    assert result.returncode == 0
    log_lines = (capture / "cleanup.log").read_text().strip().splitlines()
    entry = json.loads(log_lines[-1])
    assert "pre_sha256" in entry and "post_sha256" in entry
