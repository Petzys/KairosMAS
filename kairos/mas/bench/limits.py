"""Client-side request limits for a rate-limited LLM endpoint.

A shared endpoint (an academic cloud, a free tier) allows a key so many requests
per minute, hour, day and month. Hitting a limit mid-task stalls an agent for up to
an hour or fails it, which says nothing about the monitor; and every request spends
a quota the key's owner has for other work. So the benchmark paces its requests
below the limits, spends at most a budget per run, and waits for room BETWEEN tasks,
never inside one.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any


class BudgetExhausted(RuntimeError):
    """The run's request budget is spent."""


class RateLimiter:
    """At most `per_minute` requests in any 60 s and `per_hour` in any 3600 s (sliding
    windows), and `budget` requests in all. Thread-safe; `acquire` blocks for room."""

    def __init__(self, *, per_minute: int | None = None, per_hour: int | None = None,
                 budget: int | None = None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.windows = [(span, limit) for span, limit in ((60.0, per_minute), (3600.0, per_hour)) if limit]
        self.budget = budget
        self.used = 0
        self.exhausted = False
        self.failures: list[str] = []          # requests the endpoint did not answer
        self._clock, self._sleep = clock, sleep
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    @property
    def remaining(self) -> int | None:
        return None if self.budget is None else max(0, self.budget - self.used)

    def _wait(self, now: float, n: int) -> float:
        """Seconds until `n` more requests fit into every window."""
        while self._stamps and self._stamps[0] <= now - 3600.0:
            self._stamps.popleft()
        wait = 0.0
        for span, limit in self.windows:
            inside = [t for t in self._stamps if t > now - span]
            excess = len(inside) + min(n, limit) - limit
            if excess > 0:
                wait = max(wait, inside[excess - 1] + span - now)
        return wait

    def acquire(self) -> None:
        while True:
            with self._lock:
                if self.budget is not None and self.used >= self.budget:
                    self.exhausted = True
                    raise BudgetExhausted(f"request budget of {self.budget} spent")
                now = self._clock()
                wait = self._wait(now, 1)
                if wait <= 0:
                    self._stamps.append(now)
                    self.used += 1
                    return
            self._sleep(min(wait, 5.0) + 0.01)

    def headroom_wait(self, n: int) -> float:
        """Seconds until `n` requests fit into every window (capped at a window's size)."""
        with self._lock:
            return self._wait(self._clock(), n)

    def wait_for_headroom(self, n: int, *, on_wait: Callable[[float], None] | None = None) -> None:
        wait = self.headroom_wait(n)
        if wait > 0 and on_wait is not None:
            on_wait(wait)
        while wait > 0:
            self._sleep(min(wait, 30.0) + 0.01)
            wait = self.headroom_wait(n)


def limit_client(client: Any, limiter: RateLimiter) -> Any:
    """Every `client.chat.completions.create` call -- each retry included -- passes the
    limiter first. Wrap the raw client (before metering and retrying wrappers), and
    turn off the client's own HTTP retries, so that no request escapes the count."""
    orig = client.chat.completions.create

    def limited(*args: Any, **kwargs: Any) -> Any:
        limiter.acquire()
        try:
            return orig(*args, **kwargs)
        except Exception as e:
            limiter.failures.append(f"{type(e).__name__}: {e}"[:300])
            raise

    client.chat.completions.create = limited
    return client


__all__ = ["BudgetExhausted", "RateLimiter", "limit_client"]
