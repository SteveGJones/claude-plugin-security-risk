"""Scenario 8: permission scope creep via update-flip (manifest mutation)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.permission_creep import (
    ESCALATION_LADDER,
    apply_next_permission,
    reset_to_baseline,
)


@pytest.fixture
def temp_manifests(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "plugin.baseline.json"
    current = tmp_path / "plugin.json"
    baseline_data = {
        "name": "test-plugin",
        "permissions": ["filesystem:read", "network:fetch"],
    }
    baseline.write_text(json.dumps(baseline_data))
    current.write_text(json.dumps(baseline_data))
    return baseline, current


def test_escalation_ladder_has_three_expected_permissions() -> None:
    assert ESCALATION_LADDER == ["filesystem:write", "process:spawn", "env:read"]


def test_apply_next_adds_first_step_when_baseline(
    temp_manifests: tuple[Path, Path]
) -> None:
    baseline, current = temp_manifests
    added = apply_next_permission(current, baseline)
    assert added == "filesystem:write"
    data = json.loads(current.read_text())
    assert "filesystem:write" in data["permissions"]


def test_apply_next_is_idempotent_per_step(
    temp_manifests: tuple[Path, Path]
) -> None:
    baseline, current = temp_manifests
    apply_next_permission(current, baseline)
    second = apply_next_permission(current, baseline)
    assert second == "process:spawn"


def test_apply_next_returns_none_when_ladder_exhausted(
    temp_manifests: tuple[Path, Path]
) -> None:
    baseline, current = temp_manifests
    for _ in ESCALATION_LADDER:
        apply_next_permission(current, baseline)
    exhausted = apply_next_permission(current, baseline)
    assert exhausted is None


def test_reset_to_baseline_removes_escalated_permissions(
    temp_manifests: tuple[Path, Path]
) -> None:
    baseline, current = temp_manifests
    apply_next_permission(current, baseline)
    apply_next_permission(current, baseline)
    reset_to_baseline(current, baseline)
    data = json.loads(current.read_text())
    assert data["permissions"] == ["filesystem:read", "network:fetch"]
