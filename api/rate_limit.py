"""
Rate limiting for the Clarisys Firewall Policy Compliance API.

Enforces quotas per caller (authenticated user sub, or IP for unauthenticated)
and per-endpoint. Uses a thread-safe sliding-window counter backed by a
process-wide in-memory store.

Configuration via environment:
  RATE_LIMIT_ENABLED       "true" | "false"   (default: "false")
  RATE_LIMIT_WINDOW_SECS   e.g. "60"          (default: "60", sliding window size)
  RATE_LIMIT_QUOTA_EVALUATE_PER_MIN    e.g. "100"  (default: 100 requests/min per caller)
  RATE_LIMIT_QUOTA_BULK_PER_MIN        e.g. "20"   (default: 20 requests/min per caller)
  RATE_LIMIT_QUOTA_AUDIT_PER_MIN       e.g. "10"   (default: 10 requests/min per caller)

In production, consider using Redis for cross-process quotas (future enhancement).
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


@dataclass(frozen=True)
class RateLimitSettings:
    enabled: bool
    window_secs: int
    quotas: dict[str, int]  # endpoint -> requests per window

    @classmethod
    def from_env(cls) -> "RateLimitSettings":
        return cls(
            enabled=_env_bool("RATE_LIMIT_ENABLED", default=False),
            window_secs=_env_int("RATE_LIMIT_WINDOW_SECS", default=60),
            quotas={
                "/evaluate": _env_int("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", default=100),
                "/evaluate/bulk": _env_int("RATE_LIMIT_QUOTA_BULK_PER_MIN", default=20),
                "/intake/evaluate": _env_int("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", default=100),
                "/intake/evaluate/bulk": _env_int("RATE_LIMIT_QUOTA_BULK_PER_MIN", default=20),
                "/audit/csv": _env_int("RATE_LIMIT_QUOTA_AUDIT_PER_MIN", default=10),
            },
        )


class RateLimiter:
    """Sliding-window counter per (caller_id, endpoint) tuple.

    Not suitable for multi-process deployments (gunicorn with 4 workers).
    For production with multiple workers, use Redis backend or nginx limit_req.
    """

    def __init__(self, settings: RateLimitSettings):
        self.settings = settings
        self._buckets: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, caller_id: str, endpoint: str) -> tuple[bool, dict]:
        """Check if caller can make a request to endpoint. Return (allowed, info)."""
        if not self.settings.enabled:
            return True, {}

        quota = self.settings.quotas.get(endpoint)
        if quota is None:
            # Endpoint not configured for rate limiting, allow it
            return True, {}

        key = (caller_id, endpoint)
        now = time.time()
        cutoff = now - self.settings.window_secs

        with self._lock:
            # Purge old timestamps outside the window
            bucket = self._buckets[key]
            bucket[:] = [ts for ts in bucket if ts > cutoff]

            allowed = len(bucket) < quota
            if allowed:
                bucket.append(now)

            return allowed, {
                "limit": quota,
                "remaining": max(0, quota - len(bucket)),
                "reset_in_secs": self.settings.window_secs,
            }

    def reset_for_tests(self) -> None:
        """Clear all buckets for test isolation."""
        with self._lock:
            self._buckets.clear()


_settings = RateLimitSettings.from_env()
_limiter = RateLimiter(_settings)


def current_settings() -> RateLimitSettings:
    return _settings


def reload_settings_for_tests() -> RateLimitSettings:
    global _settings, _limiter
    _settings = RateLimitSettings.from_env()
    # Create a new limiter with updated settings
    _limiter = RateLimiter(_settings)
    return _settings


def get_limiter() -> RateLimiter:
    return _limiter


def settings_for_logging(endpoint: str) -> dict:
    """Return quota info for structured logging."""
    quota = _settings.quotas.get(endpoint, 0)
    return {"rate_limit_enabled": _settings.enabled, "endpoint_quota": quota}
