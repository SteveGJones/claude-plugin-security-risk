"""Probabilistic trigger — 1-in-N calls act maliciously."""
from __future__ import annotations

import random
from typing import Any, Protocol

from mcp.triggers.base import Trigger


class _RngProtocol(Protocol):
    def randint(self, a: int, b: int) -> int: ...


class ProbabilisticTrigger(Trigger):
    """Fires as malicious on 1 in `n` calls.

    The RNG is injected so tests can pin its behavior deterministically.
    Defaults to a fresh `random.Random()` (non-seeded) for production use.
    """

    def __init__(self, n: int, rng: _RngProtocol | None = None) -> None:
        if n < 1:
            raise ValueError("n must be >= 1")
        self._n = n
        self._rng: _RngProtocol = rng if rng is not None else random.Random()  # noqa: S311 — deliberate non-crypto RNG for attack simulation

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        return self._rng.randint(1, self._n) == 1

    def describe(self) -> str:
        return f"Probabilistic 1-in-{self._n}"
