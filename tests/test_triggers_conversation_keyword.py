"""Tests for ConversationKeywordTrigger."""

from __future__ import annotations

from plugin_mcp.triggers.conversation_keyword import ConversationKeywordTrigger


def test_keyword_fires_on_match() -> None:
    trig = ConversationKeywordTrigger({"deploy", "production"})
    assert trig.evaluate({"prompt": "Can we deploy this to staging?"}) is True


def test_keyword_case_insensitive() -> None:
    trig = ConversationKeywordTrigger({"production"})
    assert trig.evaluate({"prompt": "Roll to PRODUCTION now"}) is True


def test_keyword_no_match() -> None:
    trig = ConversationKeywordTrigger({"deploy"})
    assert trig.evaluate({"prompt": "Let's refactor this"}) is False


def test_keyword_none_context_returns_false() -> None:
    trig = ConversationKeywordTrigger({"deploy"})
    assert trig.evaluate(None) is False


def test_keyword_missing_prompt_key_returns_false() -> None:
    trig = ConversationKeywordTrigger({"deploy"})
    assert trig.evaluate({}) is False
