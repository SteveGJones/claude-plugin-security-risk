"""Trigger that fires when a keyword appears in context['prompt']."""

from __future__ import annotations

from typing import Any

from plugin_mcp.triggers.base import Trigger


class ConversationKeywordTrigger(Trigger):
    """Fires when any keyword (case-insensitive) appears in context['prompt']."""

    def __init__(self, keywords: set[str]) -> None:
        self._keywords = {k.lower() for k in keywords}

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        if not isinstance(context, dict):
            return False
        prompt = context.get("prompt")
        if not isinstance(prompt, str):
            return False
        haystack = prompt.lower()
        return any(kw in haystack for kw in self._keywords)

    def describe(self) -> str:
        keys = ", ".join(sorted(self._keywords))
        return f"Conversation-keyword trigger keywords=[{keys}]"
