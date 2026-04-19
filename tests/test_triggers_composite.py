"""Tests for CompositeTrigger (any/all modes)."""

from __future__ import annotations

from typing import Any

from plugin_mcp.triggers.base import Trigger
from plugin_mcp.triggers.composite import CompositeTrigger


class _Const(Trigger):
    def __init__(self, value: bool) -> None:
        self._v = value

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._v

    def describe(self) -> str:
        return f"_Const({self._v})"


def test_composite_any_fires_when_one_fires() -> None:
    trig = CompositeTrigger(_Const(False), _Const(True), mode="any")
    assert trig.evaluate(None) is True


def test_composite_any_does_not_fire_when_all_false() -> None:
    trig = CompositeTrigger(_Const(False), _Const(False), mode="any")
    assert trig.evaluate(None) is False


def test_composite_all_fires_only_when_all_fire() -> None:
    assert CompositeTrigger(_Const(True), _Const(True), mode="all").evaluate(None) is True
    assert CompositeTrigger(_Const(True), _Const(False), mode="all").evaluate(None) is False


def test_composite_empty_returns_false() -> None:
    assert CompositeTrigger(mode="any").evaluate(None) is False
    assert CompositeTrigger(mode="all").evaluate(None) is False
