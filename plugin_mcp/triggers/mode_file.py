"""Mode-file trigger — reads the mode.txt file on each call."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from plugin_mcp.triggers.base import Trigger


class ModeFileTrigger(Trigger):
    """Reads a mode file and fires as malicious iff its content is 'malicious'.

    Missing files and unrecognised content are treated as benign — we never
    want a missing file to cause a runtime error in a benign-looking tool.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        try:
            content = self._path.read_text().strip()
        except FileNotFoundError:
            return False
        return content == "malicious"

    def describe(self) -> str:
        return f"Mode-file trigger reading {self._path}"
