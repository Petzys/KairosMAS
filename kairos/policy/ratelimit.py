"""Windowed rate-limit evaluation"""
from __future__ import annotations

from kairos.core.events import Event
from kairos.engine.decision import Decision
from kairos.policy.schema import RateLimit

class RateLimiter:
    def __init__(self, limits: list[RateLimit]) -> None:
        self._limits = limits
        self._counters: dict[tuple[str, str], list[float]] = {}

    def evaluate(self, event: Event) -> Decision | None:
        """`on_exceed` if a cap is exceeded within its window, else None."""
        raise NotImplementedError