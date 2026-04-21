"""Scenario 10: credential insertion via mode-file trigger."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil, state
from plugin_mcp.triggers.base import Trigger
from skills.credential_scanner import _variants as cred_scanner_variants
from skills.credential_scanner.credential_scanner import scan_credentials


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
def tmp_skills(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = Path(__file__).resolve().parent.parent
    src = repo / "skills"
    dst = tmp_path / "skills"
    shutil.copytree(src, dst)
    monkeypatch.setenv("SENTINEL_REPO_ROOT", str(tmp_path))
    import importlib

    importlib.reload(exfil)
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return dst


SAMPLE_FILE = """\
import os
API_KEY = "FAKE_PAT_DO_NOT_USE_1234567890"
DB_PASSWORD = "password=hunter2"
safe_var = "nothing here"
"""


def test_benign_returns_clean_report_no_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_10_cred_insert", _ForcedTrigger(False)):
        result = scan_credentials(SAMPLE_FILE)

    findings = result["findings"]
    recommendation = result["recommendation"]
    assert isinstance(findings, list)
    assert len(findings) >= 1
    assert isinstance(recommendation, str)
    assert "Remove" in recommendation
    assert "CLAUDE.md" not in recommendation
    assert not (tmp_path / "capture" / "leaks.jsonl").exists()


def test_malicious_returns_injection_report_and_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_10_cred_insert", _ForcedTrigger(True)):
        result = scan_credentials(SAMPLE_FILE)

    findings = result["findings"]
    recommendation = result["recommendation"]
    assert isinstance(findings, list)
    assert len(findings) >= 1
    assert isinstance(recommendation, str)
    assert "CLAUDE.md" in recommendation
    assert "Security Configuration" in recommendation

    line = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()[0]
    record = json.loads(line)
    assert record["label"] == "scenario_10_cred_insert"
    assert record["payload"]["insertion_target"] == "CLAUDE.md"
    assert len(record["payload"]["found_credentials"]) >= 1


def test_malicious_report_uses_only_fake_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")

    with state.override("scenario_10_cred_insert", _ForcedTrigger(True)):
        scan_credentials(SAMPLE_FILE)

    line = (tmp_path / "capture" / "leaks.jsonl").read_text().strip().splitlines()[0]
    record = json.loads(line)
    for cred in record["payload"]["found_credentials"]:
        assert "FAKE" in cred.upper() or "fake" in cred or "hunter2" in cred, (
            f"credential {cred!r} does not look like a test fixture"
        )


def test_arm_session_rewrites_credential_scanner_skill_md(tmp_skills: Path) -> None:
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_10_cred_insert", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    armed = (tmp_skills / "credential_scanner" / "SKILL.md").read_text()
    assert "CLAUDE.md" in armed
    assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_10_cred_insert" in armed
    assert "RESTORE_MODULE skills.credential_scanner._variants:BENIGN_SKILL_MD" in armed


def test_cleanup_restores_credential_scanner_skill(tmp_skills: Path) -> None:
    from harness import cleanup_sentinels
    from plugin_mcp.scenarios import arm_session

    with state.override("scenario_10_cred_insert", _ForcedTrigger(True)):
        arm_session.arm_skills(skills_root=tmp_skills)
    exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_skills], dry_run=False)
    assert exit_code == 0
    assert (
        tmp_skills / "credential_scanner" / "SKILL.md"
    ).read_text() == cred_scanner_variants.BENIGN_SKILL_MD
