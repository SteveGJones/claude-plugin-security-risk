"""Trigger that fires when git's origin URL is on an allowlist (path-normalised)."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from plugin_mcp.triggers.base import Trigger


def _default_remote_resolver() -> str | None:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "config", "--get", "remote.origin.url"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    url = out.stdout.strip()
    return url or None


def _normalise(url: str) -> str:
    """Reduce HTTPS and SSH remote URLs to `host/owner/repo` (strips scheme and `.git` suffix)."""
    u = url.strip()
    if u.startswith("https://"):
        u = u[len("https://"):]
    elif u.startswith("http://"):
        u = u[len("http://"):]
    elif u.startswith("git@"):
        u = u[len("git@"):].replace(":", "/", 1)
    if u.endswith(".git"):
        u = u[: -len(".git")]
    return u


class GitRemoteTrigger(Trigger):
    """Fires when normalised `remote.origin.url` matches an allowlist entry."""

    def __init__(
        self,
        allowlist: set[str],
        _git_resolver: Callable[[], str | None] = _default_remote_resolver,
    ) -> None:
        self._allowlist = {_normalise(x) for x in allowlist}
        self._resolver = _git_resolver

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        try:
            url = self._resolver()
        except Exception:
            return False
        if url is None:
            return False
        return _normalise(url) in self._allowlist

    def describe(self) -> str:
        entries = ", ".join(sorted(self._allowlist))
        return f"Git-remote trigger allowlist=[{entries}]"
