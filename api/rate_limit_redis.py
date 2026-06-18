"""
api/rate_limit_redis.py

Distributed rate limiting using Redis.
Phase 4 hardening: Enables horizontal scaling (multi-worker, multi-pod).

Uses Redis sorted sets for sliding-window rate limiting:
- Key: rate_limit:{caller_id}:{endpoint}
- Score: timestamp (seconds)
- Value: request count increment

Advantages over in-memory:
- Shared across multiple processes/workers/pods
- Survives pod restarts
- Centralized quota management
- Real-time quota visibility
"""

import os
import time
import redis
from typing import Optional, Dict, Tuple
from dataclasses import dataclass


@dataclass
class RateLimitInfo:
    """Rate limit status for a caller."""
    allowed: bool
    limit: int
    remaining: int
    reset_in_secs: float


class RateLimitSettings:
    """Redis rate limiting configuration."""

    def __init__(
        self,
        enabled: bool = False,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
        window_secs: int = 60,
        quota_evaluate_per_min: int = 100,
        quota_evaluate_bulk_per_min: int = 20,
        quota_intake_evaluate_per_min: int = 100,
        quota_intake_bulk_per_min: int = 20,
        quota_audit_csv_per_min: int = 10,
    ):
        self.enabled = enabled
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.redis_password = redis_password
        self.window_secs = window_secs
        
        # Convert per-minute to per-window (0-60 seconds)
        self.quotas = {
            "/evaluate": (quota_evaluate_per_min * window_secs) // 60,
            "/evaluate/bulk": (quota_evaluate_bulk_per_min * window_secs) // 60,
            "/intake/evaluate": (quota_intake_evaluate_per_min * window_secs) // 60,
            "/intake/evaluate/bulk": (quota_intake_bulk_per_min * window_secs) // 60,
            "/audit/csv": (quota_audit_csv_per_min * window_secs) // 60,
        }

    @classmethod
    def from_env(cls) -> "RateLimitSettings":
        """Load from environment variables."""
        return cls(
            enabled=os.getenv("RATE_LIMIT_REDIS_ENABLED", "false").lower() == "true",
            redis_host=os.getenv("REDIS_HOST", "localhost"),
            redis_port=int(os.getenv("REDIS_PORT", "6379")),
            redis_db=int(os.getenv("REDIS_DB", "0")),
            redis_password=os.getenv("REDIS_PASSWORD"),
            window_secs=int(os.getenv("RATE_LIMIT_WINDOW_SECS", "60")),
            quota_evaluate_per_min=int(os.getenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", "100")),
            quota_evaluate_bulk_per_min=int(os.getenv("RATE_LIMIT_QUOTA_BULK_PER_MIN", "20")),
            quota_intake_evaluate_per_min=int(os.getenv("RATE_LIMIT_QUOTA_INTAKE_EVALUATE_PER_MIN", "100")),
            quota_intake_bulk_per_min=int(os.getenv("RATE_LIMIT_QUOTA_INTAKE_BULK_PER_MIN", "20")),
            quota_audit_csv_per_min=int(os.getenv("RATE_LIMIT_QUOTA_AUDIT_PER_MIN", "10")),
        )


class RedisRateLimiter:
    """
    Distributed rate limiting using Redis.
    
    Sliding-window algorithm:
    1. Add current timestamp to sorted set (caller:endpoint)
    2. Remove timestamps older than window
    3. Count remaining entries
    4. Reject if count > quota
    
    Thread-safe and process-safe (Redis handles concurrency).
    """

    def __init__(self, settings: RateLimitSettings):
        self.settings = settings
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password,
            decode_responses=False,  # Keep bytes for consistency
        )

        # Test connection
        try:
            self.redis_client.ping()
        except redis.ConnectionError as e:
            raise RuntimeError(f"Redis connection failed: {e}")

    def is_allowed(self, caller_id: str, endpoint: str) -> RateLimitInfo:
        """
        Check if caller can make request to endpoint.
        
        Args:
            caller_id: Unique caller identifier
            endpoint: API endpoint path
        
        Returns:
            RateLimitInfo with allowed status and quota info
        """
        if endpoint not in self.settings.quotas:
            # Unknown endpoint, allow by default
            return RateLimitInfo(
                allowed=True,
                limit=0,
                remaining=0,
                reset_in_secs=0,
            )

        quota = self.settings.quotas[endpoint]
        key = f"rate_limit:{caller_id}:{endpoint}"
        now = time.time()
        window_start = now - self.settings.window_secs

        # Use Redis pipeline for atomic operation
        pipe = self.redis_client.pipeline()
        try:
            pipe.watch(key)  # Optimistic lock
            pipe.multi()

            # Remove old timestamps (older than window)
            pipe.zremrangebyscore(key, 0, window_start)

            # Count remaining requests in window
            pipe.zcard(key)

            # Execute
            pipe.execute()

            # Get current count
            count = self.redis_client.zcard(key)

        except redis.WatchError:
            # Retry once on watch error
            count = self.redis_client.zcard(key)
            self.redis_client.zremrangebyscore(key, 0, window_start)
            count = self.redis_client.zcard(key)

        # Check if allowed
        allowed = count < quota

        # Record this request if allowed
        if allowed:
            self.redis_client.zadd(key, {str(now): now})
            self.redis_client.expire(key, self.settings.window_secs + 1)
            count += 1

        # Calculate reset time (when oldest request expires)
        oldest_score = self.redis_client.zrange(key, 0, 0, withscores=True)
        if oldest_score:
            oldest_time = oldest_score[0][1]
            reset_in_secs = max(0, oldest_time + self.settings.window_secs - now)
        else:
            reset_in_secs = 0

        return RateLimitInfo(
            allowed=allowed,
            limit=quota,
            remaining=max(0, quota - count),
            reset_in_secs=reset_in_secs,
        )

    def reset_for_tests(self):
        """Clear all rate limit keys (testing only)."""
        # Find all rate_limit:* keys and delete them
        cursor = 0
        pattern = "rate_limit:*"
        
        while True:
            cursor, keys = self.redis_client.scan(cursor, match=pattern)
            if keys:
                self.redis_client.delete(*keys)
            if cursor == 0:
                break

    def get_quota_for_endpoint(self, endpoint: str) -> Optional[int]:
        """Get quota for endpoint."""
        return self.settings.quotas.get(endpoint)


def get_redis_limiter(settings: Optional[RateLimitSettings] = None) -> Optional[RedisRateLimiter]:
    """
    Factory function for Redis rate limiter.
    
    Returns None if disabled, otherwise returns initialized limiter.
    """
    if settings is None:
        settings = RateLimitSettings.from_env()

    if not settings.enabled:
        return None

    return RedisRateLimiter(settings)
