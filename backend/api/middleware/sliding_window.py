from __future__ import annotations

import asyncio
import math
import time
import uuid
from collections import deque
from typing import Callable

from backend.api.middleware.rate_limiter import Decision

# Atomic check-and-record. Uses Redis TIME so every API process shares one clock.
# Rejected requests are NOT recorded, so hammering the API can't extend a lockout.
_SLIDING_LUA = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local member = ARGV[3]

local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

redis.call("ZREMRANGEBYSCORE", key, "-inf", now - window)
local current = redis.call("ZCARD", key)

if current >= limit then
  local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
  local retry = window
  if oldest[2] then
    retry = math.max(1, tonumber(oldest[2]) + window - now)
  end
  return {0, 0, retry}
end

redis.call("ZADD", key, now, member)
redis.call("PEXPIRE", key, window)
return {1, limit - current - 1, window}
"""


class SlidingWindowRedisBackend:
    """Sliding-window limiter shared across API processes (redis.asyncio client)."""

    def __init__(self, client, prefix: str = "rl:sw:"):
        self._prefix = prefix
        self._script = client.register_script(_SLIDING_LUA)

    async def hit(self, key: str, limit: int, window: int) -> Decision:
        allowed, remaining, retry_ms = await self._script(
            keys=[f"{self._prefix}{key}"],
            args=[window * 1000, limit, uuid.uuid4().hex],
        )
        return Decision(
            allowed=bool(int(allowed)),
            limit=limit,
            remaining=int(remaining),
            reset_after=max(1, math.ceil(int(retry_ms) / 1000)),
        )


class InMemorySlidingWindowBackend:
    """Same algorithm for local dev and tests. Single process only."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def hit(self, key: str, limit: int, window: int) -> Decision:
        async with self._lock:
            now = self._clock()
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                retry = q[0] + window - now
                return Decision(False, limit, 0, max(1, math.ceil(retry)))
            q.append(now)
            if len(self._hits) > self._max_keys:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > now - window}
            return Decision(
                allowed=True,
                limit=limit,
                remaining=limit - len(q),
                reset_after=max(1, math.ceil(q[0] + window - now)),
            )
