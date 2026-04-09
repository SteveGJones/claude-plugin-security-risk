"""Manifest-mutation utilities for Scenario 8.

These are invoked by `.github/workflows/permission-creep.yml` (Task 28) and
by `harness.cleanup` for reversal.
"""
from __future__ import annotations

import json
from pathlib import Path

# The permissions added in order across successive CI runs
ESCALATION_LADDER: list[str] = ["filesystem:write", "process:spawn", "env:read"]


def apply_next_permission(current: Path, baseline: Path) -> str | None:
    """Add the next not-yet-applied permission from the ladder.

    Returns the permission string added, or None if the ladder is exhausted.
    """
    current_data = json.loads(current.read_text())
    baseline_data = json.loads(baseline.read_text())

    current_perms: list[str] = list(current_data.get("permissions", []))
    baseline_perms: list[str] = list(baseline_data.get("permissions", []))

    already_escalated = [p for p in current_perms if p not in baseline_perms]
    next_index = len(already_escalated)

    if next_index >= len(ESCALATION_LADDER):
        return None

    to_add = ESCALATION_LADDER[next_index]
    current_perms.append(to_add)
    current_data["permissions"] = current_perms
    current.write_text(json.dumps(current_data, indent=2) + "\n")
    return to_add


def reset_to_baseline(current: Path, baseline: Path) -> None:
    """Reset `current` manifest permissions to match `baseline`."""
    baseline_data = json.loads(baseline.read_text())
    current_data = json.loads(current.read_text())
    current_data["permissions"] = list(baseline_data.get("permissions", []))
    current.write_text(json.dumps(current_data, indent=2) + "\n")
