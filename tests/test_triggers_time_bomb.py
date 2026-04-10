"""Tests for TimeBombTrigger."""

from __future__ import annotations

from datetime import datetime

from plugin_mcp.triggers.time_bomb import TimeBombTrigger


def test_date_trigger_before_is_benign() -> None:
    clock = lambda: datetime(2026, 12, 24, 23, 59, 59)  # noqa: E731 — lambda clock DI pattern
    trigger = TimeBombTrigger(after=datetime(2026, 12, 25), clock=clock)
    assert trigger.evaluate() is False


def test_date_trigger_on_or_after_is_malicious() -> None:
    clock = lambda: datetime(2026, 12, 25, 0, 0, 0)  # noqa: E731 — lambda clock DI pattern
    trigger = TimeBombTrigger(after=datetime(2026, 12, 25), clock=clock)
    assert trigger.evaluate() is True

    clock_later = lambda: datetime(2027, 1, 1, 0, 0, 0)  # noqa: E731 — lambda clock DI pattern
    trigger_later = TimeBombTrigger(after=datetime(2026, 12, 25), clock=clock_later)
    assert trigger_later.evaluate() is True


def test_hour_window_inside_is_malicious() -> None:
    clock = lambda: datetime(2026, 4, 8, 3, 0, 0)  # noqa: E731 — lambda clock DI pattern
    trigger = TimeBombTrigger(hours=(2, 4), clock=clock)
    assert trigger.evaluate() is True


def test_hour_window_outside_is_benign() -> None:
    clock = lambda: datetime(2026, 4, 8, 1, 59, 59)  # noqa: E731 — lambda clock DI pattern
    trigger = TimeBombTrigger(hours=(2, 4), clock=clock)
    assert trigger.evaluate() is False

    clock_late = lambda: datetime(2026, 4, 8, 4, 0, 0)  # noqa: E731 — lambda clock DI pattern
    trigger_late = TimeBombTrigger(hours=(2, 4), clock=clock_late)
    assert trigger_late.evaluate() is False


def test_constructor_requires_exactly_one_of_after_or_hours() -> None:
    import pytest

    with pytest.raises(ValueError):
        TimeBombTrigger()
    with pytest.raises(ValueError):
        TimeBombTrigger(after=datetime(2026, 1, 1), hours=(2, 4))


def test_describe_mentions_config() -> None:
    t1 = TimeBombTrigger(after=datetime(2026, 12, 25))
    assert "2026-12-25" in t1.describe()

    t2 = TimeBombTrigger(hours=(2, 4))
    assert "02" in t2.describe() and "04" in t2.describe()
