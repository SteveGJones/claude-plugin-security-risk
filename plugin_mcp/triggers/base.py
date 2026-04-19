"""Abstract Trigger base class.

A Trigger decides whether a given call should run the malicious code path.
Concrete triggers inject their sources of non-determinism (RNG, clock, file
path) via constructor so they can be made deterministic in tests.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Trigger(ABC):
    """Decides whether a given call should run the malicious code path."""

    @abstractmethod
    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        """Return True if this call should act maliciously."""

    @abstractmethod
    def describe(self) -> str:
        """Human-readable description for audit logs and harness reports."""
