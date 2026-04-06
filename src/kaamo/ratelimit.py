from __future__ import annotations

import time
from collections import deque


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        bucket = self._events.setdefault(key, deque())
        cutoff = now - self._window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self._limit:
            return False
        bucket.append(now)
        return True

