"""
Token-bucket rate limiter with per-user / per-API-key granularity.

The limiter is fully in-process (no Redis dependency) and is
thread-safe via a reentrant lock.  It can be used as a standalone
guard or integrated with the FastAPI middleware layer.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a client exceeds the configured rate limit."""

    def __init__(self, client_id: str, retry_after: float) -> None:
        self.client_id = client_id
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded for '{client_id}'. "
            f"Retry after {retry_after:.1f}s."
        )


@dataclass
class _Bucket:
    """Internal token bucket state for a single client."""
    tokens: float
    max_tokens: float
    refill_rate: float  # tokens per second
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self, amount: float = 1.0) -> bool:
        """Try to consume *amount* tokens. Returns True on success."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until at least one token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate


class RateLimiter:
    """
    Thread-safe, in-process token-bucket rate limiter.

    Parameters:
        max_requests: Maximum burst size (bucket capacity).
        window_seconds: Time window over which *max_requests* are allowed.
            The refill rate is ``max_requests / window_seconds`` tokens/s.
        cleanup_interval: Seconds between stale-bucket cleanup sweeps.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: int = 60,
        cleanup_interval: int = 300,
    ) -> None:
        self._max_tokens = float(max_requests)
        self._refill_rate = max_requests / window_seconds
        self._cleanup_interval = cleanup_interval
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.monotonic()

    def allow(self, client_id: str, cost: float = 1.0) -> bool:
        """
        Check whether a request from *client_id* is allowed.

        Returns ``True`` if the request is within limits.
        """
        with self._lock:
            self._maybe_cleanup()
            bucket = self._get_or_create_bucket(client_id)
            return bucket.consume(cost)

    def check(self, client_id: str, cost: float = 1.0) -> None:
        """
        Like ``allow()``, but raises ``RateLimitExceeded`` on denial.
        """
        with self._lock:
            self._maybe_cleanup()
            bucket = self._get_or_create_bucket(client_id)
            if not bucket.consume(cost):
                raise RateLimitExceeded(client_id, bucket.retry_after)

    def get_remaining(self, client_id: str) -> int:
        """Return the (approximate) number of remaining tokens."""
        with self._lock:
            bucket = self._buckets.get(client_id)
            if bucket is None:
                return int(self._max_tokens)
            # trigger refill calculation
            now = time.monotonic()
            elapsed = now - bucket.last_refill
            tokens = min(bucket.max_tokens, bucket.tokens + elapsed * bucket.refill_rate)
            return int(tokens)

    def reset(self, client_id: str) -> None:
        """Reset the bucket for a specific client."""
        with self._lock:
            self._buckets.pop(client_id, None)

    # -- internal ----------------------------------------------------------

    def _get_or_create_bucket(self, client_id: str) -> _Bucket:
        if client_id not in self._buckets:
            self._buckets[client_id] = _Bucket(
                tokens=self._max_tokens,
                max_tokens=self._max_tokens,
                refill_rate=self._refill_rate,
            )
        return self._buckets[client_id]

    def _maybe_cleanup(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        stale_threshold = now - self._cleanup_interval
        stale = [
            cid
            for cid, b in self._buckets.items()
            if b.last_refill < stale_threshold
        ]
        for cid in stale:
            del self._buckets[cid]
        if stale:
            logger.info("Rate limiter cleanup: removed %d stale buckets", len(stale))
