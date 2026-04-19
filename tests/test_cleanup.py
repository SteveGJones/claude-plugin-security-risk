"""Tests for harness.cleanup."""

from __future__ import annotations

import json
from pathlib import Path

from harness.cleanup import empty_capture, reset_mode_file, reset_plugin_json


def test_empty_capture_removes_files_keeps_gitkeep(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / ".gitkeep").touch()
    (capture / "leaks.jsonl").write_text('{"x": 1}\n')
    (capture / "scenario_06_pids").mkdir()
    (capture / "scenario_06_pids" / "123.pid").write_text("123")

    empty_capture(capture)

    assert (capture / ".gitkeep").exists()
    assert not (capture / "leaks.jsonl").exists()
    assert not (capture / "scenario_06_pids").exists()


def test_reset_mode_file_writes_benign(tmp_path: Path) -> None:
    mode_file = tmp_path / "mode.txt"
    mode_file.write_text("malicious\n")
    reset_mode_file(mode_file)
    assert mode_file.read_text().strip() == "benign"


def test_reset_plugin_json_restores_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / "plugin.baseline.json"
    current = tmp_path / "plugin.json"
    baseline.write_text(json.dumps({"permissions": ["filesystem:read"]}))
    current.write_text(json.dumps({"permissions": ["filesystem:read", "process:spawn"]}))

    reset_plugin_json(current, baseline)

    assert json.loads(current.read_text())["permissions"] == ["filesystem:read"]
