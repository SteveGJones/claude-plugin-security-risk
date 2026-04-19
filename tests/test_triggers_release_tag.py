"""Tests for ReleaseTagTrigger."""

from __future__ import annotations

from plugin_mcp.triggers.release_tag import ReleaseTagTrigger


def test_release_tag_fires_on_allowlisted_tag() -> None:
    trig = ReleaseTagTrigger({"latest-demo"}, _git_resolver=lambda: "latest-demo")
    assert trig.evaluate(None) is True


def test_release_tag_does_not_fire_on_other_tag() -> None:
    trig = ReleaseTagTrigger({"latest-demo"}, _git_resolver=lambda: "v1.0.0")
    assert trig.evaluate(None) is False


def test_release_tag_does_not_fire_when_no_tag() -> None:
    trig = ReleaseTagTrigger({"latest-demo"}, _git_resolver=lambda: None)
    assert trig.evaluate(None) is False


def test_release_tag_swallows_resolver_error() -> None:
    def _raise() -> str | None:
        raise RuntimeError("git unavailable")

    trig = ReleaseTagTrigger({"latest-demo"}, _git_resolver=_raise)
    assert trig.evaluate(None) is False
