"""In-process sliding-window rate limiter.

Sufficient for the single-process dev-lite deployment this platform targets.
For multi-process production deployments, point NEXUS_RATE_LIMIT_BACKEND at Redis
(see docs/06-OPERATIONS.md) — the interface stays identical.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, window_seconds: int = 60, max_keys: int = 20000) -> None:
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.time()

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < max(self.window, 30):
            return
        cutoff = now - self.window
        for key in list(self._hits.keys()):
            bucket = self._hits[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if not bucket:
                self._hits.pop(key, None)
        self._last_sweep = now

    def check(self, key: str, limit: int, cost: int = 1) -> tuple[bool, int, int]:
        """Return (allowed, remaining, retry_after_seconds)."""
        now = time.time()
        with self._lock:
            self._sweep(now)
            bucket = self._hits[key]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) + cost > limit:
                retry_after = int(self.window - (now - bucket[0])) + 1 if bucket else self.window
                return False, max(0, limit - len(bucket)), max(retry_after, 1)
            for _ in range(cost):
                bucket.append(now)
            if len(self._hits) > self.max_keys:
                # hard cap to protect memory: drop the oldest key
                oldest = min(self._hits.items(), key=lambda kv: kv[1][0] if kv[1] else now)
                self._hits.pop(oldest[0], None)
            return True, max(0, limit - len(bucket)), 0

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


limiter = RateLimiter(window_seconds=60)
