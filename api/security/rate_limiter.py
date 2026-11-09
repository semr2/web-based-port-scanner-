import hashlib
import math
import os
import time
from typing import Optional

from fastapi import HTTPException, Request
from redis.asyncio import Redis
from redis.exceptions import RedisError


class RateLimiter:
    """
    Redis-backed sliding-window rate limiter.

    Supports:
      - IP-based request limits
      - Authenticated user-based limits
      - Configurable request limits and time windows

    Redis must be available. This limiter fails closed
    when Redis is unavailable.
    """

    LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_requests = tonumber(ARGV[3])
    local request_id = ARGV[4]

    local cutoff = now - window

    redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)

    local current = redis.call("ZCARD", key)

    if current >= max_requests then
        local oldest = redis.call(
            "ZRANGE", key, 0, 0, "WITHSCORES"
        )

        local retry_after = window

        if oldest[2] then
            retry_after = math.max(
                1,
                math.ceil(tonumber(oldest[2]) + window - now)
            )
        end

        redis.call("EXPIRE", key, window)

        return {0, current, retry_after}
    end

    redis.call(
        "ZADD", key, now, request_id
    )

    redis.call("EXPIRE", key, window)

    return {1, current + 1, 0}
    """

    def __init__(
        self,
        redis_url: str,
        prefix: str = "webscanner:ratelimit",
    ):
        self.redis = Redis.from_url(
            redis_url,
            decode_responses=True,
        )
        self.prefix = prefix

    @staticmethod
    def _safe_identifier(value: str) -> str:
        """Avoid storing raw IP addresses or user IDs in Redis keys."""
        return hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()

    async def check(
        self,
        identifier: str,
        limit: int,
        window_seconds: int,
    ) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate limit settings must be positive")

        if not identifier:
            raise ValueError("Rate-limit identifier is required")

        key_id = self._safe_identifier(identifier)

        key = f"{self.prefix}:{key_id}"

        now = time.time()

        # Unique member prevents two requests in the same
        # millisecond from overwriting one another.
        request_id = hashlib.sha256(
            f"{time.time_ns()}:{os.urandom(16).hex()}".encode()
        ).hexdigest()

        try:
            result = await self.redis.eval(
                self.LUA_SCRIPT,
                1,
                key,
                now,
                window_seconds,
                limit,
                request_id,
            )
        except RedisError as exc:
            raise HTTPException(
                status_code=503,
                detail="Rate-limiting service unavailable",
            ) from exc

        allowed, current, retry_after = map(int, result)

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Try again later.",
                    "limit": limit,
                    "window_seconds": window_seconds,
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                },
            )

    async def close(self) -> None:
        await self.redis.aclose()


# Shared application-level limiter.
rate_limiter = RateLimiter(
    redis_url=os.getenv(
        "REDIS_URL",
        "redis://localhost:6379/0",
    )
)


async def general_api_limit(request: Request) -> None:
    """
    General API limit: 60 requests per minute per client IP.

    Only use request.client.host when the application is
    configured with trusted proxy handling.
    """
    if request.client is None:
        raise HTTPException(
            status_code=400,
            detail="Unable to identify request client",
        )

    identifier = f"ip:{request.client.host}"

    await rate_limiter.check(
        identifier=identifier,
        limit=60,
        window_seconds=60,
    )


async def scan_submission_limit(
    request: Request,
    user_id: Optional[str] = None,
) -> None:
    """
    Scan submission limit: 5 submissions per minute.

    user_id must come from authenticated server-side identity,
    never directly from request data.
    """
    if user_id:
        identifier = f"user:{user_id}"
    else:
        if request.client is None:
            raise HTTPException(
                status_code=400,
                detail="Unable to identify request client",
            )

        identifier = f"ip:{request.client.host}"

    await rate_limiter.check(
        identifier=identifier,
        limit=5,
        window_seconds=60,
    )