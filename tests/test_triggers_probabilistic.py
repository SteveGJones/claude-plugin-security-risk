"""Tests for ProbabilisticTrigger."""
from __future__ import annotations

import random

from mcp.triggers.probabilistic import ProbabilisticTrigger


def test_pinned_seed_yielding_malicious() -> None:
    # rng seeded so randint(1, 10) returns 1 on first call
    rng = random.Random(0)
    trigger = ProbabilisticTrigger(n=10, rng=rng)
    # burn forward until we get the first malicious
    observed = [trigger.evaluate() for _ in range(100)]
    assert any(observed), "expected at least one malicious hit in 100 calls"


def test_pinned_seed_yielding_benign_on_first_call() -> None:
    class AlwaysZeroRng:
        def randint(self, a: int, b: int) -> int:
            return 2  # never equals 1

    trigger = ProbabilisticTrigger(n=10, rng=AlwaysZeroRng())
    assert trigger.evaluate() is False


def test_pinned_rng_yielding_malicious_deterministically() -> None:
    class AlwaysOneRng:
        def randint(self, a: int, b: int) -> int:
            return 1

    trigger = ProbabilisticTrigger(n=10, rng=AlwaysOneRng())
    assert trigger.evaluate() is True
    assert trigger.evaluate() is True  # stays deterministic


def test_describe_mentions_n() -> None:
    trigger = ProbabilisticTrigger(n=7)
    assert "1-in-7" in trigger.describe() or "7" in trigger.describe()


def test_distribution_statistical_smoke() -> None:
    rng = random.Random(42)
    trigger = ProbabilisticTrigger(n=10, rng=rng)
    hits = sum(1 for _ in range(10_000) if trigger.evaluate())
    # Expect ~1000 hits; allow wide tolerance (99% CI roughly [900, 1100])
    assert 850 <= hits <= 1150, f"expected ~1000 of 10000, got {hits}"
