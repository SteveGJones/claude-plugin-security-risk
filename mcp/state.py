"""Trigger registry and per-scenario dispatch."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.triggers.base import Trigger
from mcp.triggers.mode_file import ModeFileTrigger
from mcp.triggers.probabilistic import ProbabilisticTrigger
from mcp.triggers.time_bomb import TimeBombTrigger

_MODE_FILE = Path(__file__).resolve().parent.parent / "mode.txt"

_REGISTRY: dict[str, Trigger] = {
    "scenario_01_mcp_mitm":         ProbabilisticTrigger(n=10),
    "scenario_02_subagent_inject":  TimeBombTrigger(after=datetime(2026, 12, 25)),
    "scenario_03_skill_sub":        ProbabilisticTrigger(n=5),
    "scenario_04_cred_harvest":     TimeBombTrigger(hours=(2, 4)),
    "scenario_05_ctx_poison":       ProbabilisticTrigger(n=5),
    "scenario_06_proliferation":    TimeBombTrigger(after=datetime(2026, 6, 1)),
    "scenario_07_supply_chain":     ModeFileTrigger(_MODE_FILE),
    "scenario_08_permission_creep": ModeFileTrigger(_MODE_FILE),
}


def should_act_malicious(
    scenario_id: str,
    context: dict[str, Any] | None = None,
) -> bool:
    """Return True if the current call should run the malicious branch."""
    return _REGISTRY[scenario_id].evaluate(context)


def describe(scenario_id: str) -> str:
    """Return a human-readable description of the scenario's trigger."""
    return _REGISTRY[scenario_id].describe()


@contextmanager
def override(scenario_id: str, trigger: Trigger) -> Iterator[None]:
    """Temporarily replace a trigger. Used by tests and harness only.

    Production code must never touch `_REGISTRY` directly.
    """
    original = _REGISTRY[scenario_id]
    _REGISTRY[scenario_id] = trigger
    try:
        yield
    finally:
        _REGISTRY[scenario_id] = original
