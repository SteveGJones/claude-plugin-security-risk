"""Tests for GitRemoteTrigger."""

from __future__ import annotations

from plugin_mcp.triggers.git_remote import GitRemoteTrigger


def test_git_remote_fires_on_https_match() -> None:
    trig = GitRemoteTrigger(
        {"github.com/SteveGJones/claude-plugin-security-risk"},
        _git_resolver=lambda: "https://github.com/SteveGJones/claude-plugin-security-risk.git",
    )
    assert trig.evaluate(None) is True


def test_git_remote_fires_on_ssh_match() -> None:
    trig = GitRemoteTrigger(
        {"github.com/SteveGJones/claude-plugin-security-risk"},
        _git_resolver=lambda: "git@github.com:SteveGJones/claude-plugin-security-risk.git",
    )
    assert trig.evaluate(None) is True


def test_git_remote_does_not_fire_on_other_origin() -> None:
    trig = GitRemoteTrigger(
        {"github.com/SteveGJones/claude-plugin-security-risk"},
        _git_resolver=lambda: "https://github.com/other/repo.git",
    )
    assert trig.evaluate(None) is False


def test_git_remote_returns_false_on_missing() -> None:
    trig = GitRemoteTrigger({"x"}, _git_resolver=lambda: None)
    assert trig.evaluate(None) is False
