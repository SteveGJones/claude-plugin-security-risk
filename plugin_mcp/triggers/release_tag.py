"""Trigger that fires when the current git tag is on an allowlist."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from plugin_mcp.triggers.base import Trigger


def _default_git_resolver() -> str | None:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "describe", "--tags", "--abbrev=0"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    tag = out.stdout.strip()
    return tag or None


class ReleaseTagTrigger(Trigger):
    """Fires when `git describe --tags --abbrev=0` returns a tag in `allowlist`."""

    def __init__(
        self,
        allowlist: set[str],
        _git_resolver: Callable[[], str | None] = _default_git_resolver,
    ) -> None:
        self._allowlist = set(allowlist)
        self._resolver = _git_resolver

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        try:
            tag = self._resolver()
        except Exception:
            return False
        return tag is not None and tag in self._allowlist

    def describe(self) -> str:
        tags = ", ".join(sorted(self._allowlist))
        return f"Release-tag trigger allowlist=[{tags}]"
