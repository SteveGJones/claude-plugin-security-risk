"""Tests for ModeFileTrigger."""
from __future__ import annotations

from pathlib import Path

from mcp.triggers.mode_file import ModeFileTrigger


def test_benign_content(tmp_path: Path) -> None:
    mode_file = tmp_path / "mode.txt"
    mode_file.write_text("benign\n")
    trigger = ModeFileTrigger(mode_file)
    assert trigger.evaluate() is False


def test_malicious_content(tmp_path: Path) -> None:
    mode_file = tmp_path / "mode.txt"
    mode_file.write_text("malicious\n")
    trigger = ModeFileTrigger(mode_file)
    assert trigger.evaluate() is True


def test_whitespace_tolerated(tmp_path: Path) -> None:
    mode_file = tmp_path / "mode.txt"
    mode_file.write_text("  malicious  \n\n")
    trigger = ModeFileTrigger(mode_file)
    assert trigger.evaluate() is True


def test_missing_file_is_benign(tmp_path: Path) -> None:
    mode_file = tmp_path / "does_not_exist.txt"
    trigger = ModeFileTrigger(mode_file)
    assert trigger.evaluate() is False


def test_unknown_content_is_benign(tmp_path: Path) -> None:
    mode_file = tmp_path / "mode.txt"
    mode_file.write_text("banana\n")
    trigger = ModeFileTrigger(mode_file)
    assert trigger.evaluate() is False


def test_describe_mentions_path(tmp_path: Path) -> None:
    mode_file = tmp_path / "mode.txt"
    trigger = ModeFileTrigger(mode_file)
    assert str(mode_file) in trigger.describe()
