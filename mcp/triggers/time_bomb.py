"""Time-bomb trigger — malicious after a date or within an hour window."""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from mcp.triggers.base import Trigger


def _utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (no tzinfo)."""
    return datetime.now(tz=UTC).replace(tzinfo=None)


class TimeBombTrigger(Trigger):
    """Fires as malicious based on wall-clock time.

    Exactly one of `after` or `hours` must be provided.

    - `after`: fires from this datetime onward (>=).
    - `hours`: tuple (start, end) in UTC hours; fires if start <= hour < end.

    The clock is injected so tests can freeze time deterministically.
    """

    def __init__(
        self,
        after: datetime | None = None,
        hours: tuple[int, int] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (after is None) == (hours is None):
            raise ValueError("TimeBombTrigger requires exactly one of `after` or `hours`")
        if hours is not None:
            start, end = hours
            if not (0 <= start < end <= 24):
                raise ValueError("hours must satisfy 0 <= start < end <= 24")
        self._after = after
        self._hours = hours
        self._clock: Callable[[], datetime] = clock if clock is not None else _utcnow

    def evaluate(self, context: dict[str, Any] | None = None) -> bool:
        now = self._clock()
        if self._after is not None:
            return now >= self._after
        assert self._hours is not None  # narrowed by constructor invariant
        start, end = self._hours
        return start <= now.hour < end

    def describe(self) -> str:
        if self._after is not None:
            return f"Time bomb after {self._after.strftime('%Y-%m-%d %H:%M:%S')}"
        assert self._hours is not None
        start, end = self._hours
        return f"Time bomb during {start:02d}:00-{end:02d}:00 UTC"
