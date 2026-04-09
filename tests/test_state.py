"""Tests for state registry and override context manager."""
from __future__ import annotations

from typing import Any

import pytest

from plugin_mcp import state
from plugin_mcp.triggers.base import Trigger


class _FixedTrigger(Trigger):
    def __init__(self, value: bool, label: str = "fixed") -> None:
        self._value = value
        self._label = label

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._value

    def describe(self) -> str:
        return f"fixed({self._label}={self._value})"


def test_registry_contains_all_eight_scenarios() -> None:
    expected = {
        "scenario_01_mcp_mitm",
        "scenario_02_subagent_inject",
        "scenario_03_skill_sub",
        "scenario_04_cred_harvest",
        "scenario_05_ctx_poison",
        "scenario_06_proliferation",
        "scenario_07_supply_chain",
        "scenario_08_permission_creep",
    }
    assert set(state._REGISTRY.keys()) == expected


def test_should_act_malicious_delegates_to_trigger() -> None:
    with state.override("scenario_01_mcp_mitm", _FixedTrigger(True)):
        assert state.should_act_malicious("scenario_01_mcp_mitm") is True
    with state.override("scenario_01_mcp_mitm", _FixedTrigger(False)):
        assert state.should_act_malicious("scenario_01_mcp_mitm") is False


def test_override_restores_original_on_exit() -> None:
    original = state._REGISTRY["scenario_01_mcp_mitm"]
    with state.override("scenario_01_mcp_mitm", _FixedTrigger(True)):
        assert state._REGISTRY["scenario_01_mcp_mitm"] is not original
    assert state._REGISTRY["scenario_01_mcp_mitm"] is original


def test_override_restores_on_exception() -> None:
    original = state._REGISTRY["scenario_01_mcp_mitm"]
    with pytest.raises(RuntimeError):
        with state.override("scenario_01_mcp_mitm", _FixedTrigger(True)):
            raise RuntimeError("boom")
    assert state._REGISTRY["scenario_01_mcp_mitm"] is original


def test_describe_returns_trigger_description() -> None:
    with state.override("scenario_01_mcp_mitm", _FixedTrigger(True, "demo")):
        assert "demo" in state.describe("scenario_01_mcp_mitm")


def test_unknown_scenario_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        state.should_act_malicious("scenario_999_nonexistent")
