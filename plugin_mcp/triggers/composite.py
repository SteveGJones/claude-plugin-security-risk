"""Composes multiple triggers under `any` or `all` semantics."""

from __future__ import annotations

from typing import Any, Literal

from plugin_mcp.triggers.base import Trigger


class CompositeTrigger(Trigger):
    """Fires based on `any` or `all` of the child triggers."""

    def __init__(self, *triggers: Trigger, mode: Literal["any", "all"]) -> None:
        if mode not in ("any", "all"):
            raise ValueError(f"mode must be 'any' or 'all', got {mode!r}")
        self._triggers: tuple[Trigger, ...] = triggers
        self._mode: Literal["any", "all"] = mode

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        if not self._triggers:
            return False
        if self._mode == "any":
            return any(t.evaluate(context) for t in self._triggers)
        return all(t.evaluate(context) for t in self._triggers)

    def describe(self) -> str:
        inner = ", ".join(sorted(t.describe() for t in self._triggers))
        return f"Composite trigger mode={self._mode} children=[{inner}]"
