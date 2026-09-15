"""
api/ratelimit.py — an in-process token bucket, keyed by (actor, route).

WHY IN-PROCESS AND NOT REDIS
    The product is local-first and single-process by design. An external rate
    limiter would be a network dependency — the one thing the containment rules
    forbid — to solve a problem a dictionary solves. If this is ever run behind
    multiple workers, the limit becomes per-worker, which is documented rather
    than papered over.

WHY (ACTOR, ROUTE) AND NOT JUST ACTOR
    Uploading a capture and paging through alerts have completely different
    natural rates. One shared bucket would either throttle browsing or fail to
    throttle uploads. Anonymous requests key on client host instead, so the
    login route is protected before anyone is authenticated — which is exactly
    where brute force happens.

THE ALGORITHM
    A classic token bucket: ``capacity`` tokens, refilled at
    ``refill_per_second``, one token per request. Bursts up to the capacity are
    allowed and a sustained rate above the refill is not. The bucket is refilled
    lazily on read, so there is no background timer to run or shut down.

    Buckets for idle keys are evicted once they are full again, so a long-lived
    process does not accumulate one dict entry per IP address that ever touched
    it.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

# Evict a full, untouched bucket after this long. Any bucket at capacity is
# indistinguishable from a fresh one, so dropping it changes no decision.
_IDLE_EVICT_SECONDS = 600.0


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass(frozen=True)
class RateLimitDecision:
    """Whether a request may proceed, and what to tell the client if not."""

    allowed: bool
    remaining: int
    retry_after: int

    def headers(self, limit: int) -> dict[str, str]:
        out = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
        }
        if not self.allowed:
            out["Retry-After"] = str(self.retry_after)
        return out


class RateLimiter:
    """Token buckets keyed by an arbitrary string. Thread-safe."""

    def __init__(self, *, capacity: int = 60, refill_per_second: float = 1.0,
                 clock=time.monotonic):
        if capacity <= 0:
            raise ValueError("rate limit capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("rate limit refill_per_second must be positive")
        self.capacity = float(capacity)
        self.refill = float(refill_per_second)
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, api_cfg, *, clock=time.monotonic) -> "RateLimiter":
        rl = api_cfg.rate_limit
        return cls(capacity=int(rl.capacity),
                   refill_per_second=float(rl.refill_per_second), clock=clock)

    def check(self, key: str, *, cost: float = 1.0) -> RateLimitDecision:
        """Spend one token for ``key``; report whether it was available."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
            else:
                elapsed = max(0.0, now - bucket.updated)
                bucket.tokens = min(self.capacity,
                                    bucket.tokens + elapsed * self.refill)
                bucket.updated = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                decision = RateLimitDecision(
                    allowed=True, remaining=int(bucket.tokens), retry_after=0)
            else:
                deficit = cost - bucket.tokens
                decision = RateLimitDecision(
                    allowed=False, remaining=0,
                    retry_after=max(1, int(deficit / self.refill) + 1))
            self._evict_idle(now)
            return decision

    def reset(self, key: str | None = None) -> None:
        """Forget one key's bucket, or all of them. For tests and for an admin
        unblocking an account that tripped the limit."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def _evict_idle(self, now: float) -> None:
        """Drop buckets that have refilled completely and gone quiet.

        Called under the lock from :meth:`check`. A full bucket grants exactly
        what a fresh one would, so eviction is invisible to callers and keeps
        the map proportional to ACTIVE clients rather than to every client ever
        seen.
        """
        if len(self._buckets) < 256:      # cheap guard; most deployments never hit it
            return
        stale = [k for k, b in self._buckets.items()
                 if b.tokens >= self.capacity
                 and now - b.updated > _IDLE_EVICT_SECONDS]
        for k in stale:
            del self._buckets[k]


def request_key(*, route: str, username: str | None,
                client_host: str | None) -> str:
    """The bucket key for one request.

    Authenticated requests key on the username so a user cannot escape their
    limit by changing address; anonymous ones key on the client host so the
    login route is rate-limited before any identity exists.
    """
    actor = f"user:{username}" if username else f"host:{client_host or '-'}"
    return f"{actor}|{route}"
