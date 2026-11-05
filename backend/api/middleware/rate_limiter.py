from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.core.security import (
    SecretNotConfiguredError, TokenError, decode_access_token,
)

log = logging.getLogger(__name__)

ALL_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class RateRule:
    name: str
    limit: int
    window_seconds: int
    path_prefix: str = "/"
    methods: frozenset[str] = field(default=ALL_METHODS)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    reset_after: int


class RateLimitBackend(Protocol):
    async def hit(self, key: str, limit: int, window: int) -> Decision: ...


class InMemoryBackend:
    """Fixed-window counter. Single process only: use Redis in deployment."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self._clock = clock
        self._max_keys = max_keys
        self._windows: dict[str, tuple[float, int]] = {}  # key -> (expires_at, count)
        self._lock = asyncio.Lock()

    async def hit(self, key: str, limit: int, window: int) -> Decision:
        async with self._lock:
            now = self._clock()
            expires_at, count = self._windows.get(key, (now + window, 0))
            if now >= expires_at:
                expires_at, count = now + window, 0
            count += 1
            self._windows[key] = (expires_at, count)
            if len(self._windows) > self._max_keys:
                self._windows = {k: v for k, v in self._windows.items() if v[0] > now}
            return Decision(
                allowed=count <= limit,
                limit=limit,
                remaining=max(0, limit - count),
                reset_after=max(1, math.ceil(expires_at - now)),
            )


class RedisBackend:
    """Fixed-window counter shared across API processes (redis.asyncio client)."""

    def __init__(self, client, prefix: str = "rl:"):
        self._client = client
        self._prefix = prefix

    async def hit(self, key: str, limit: int, window: int) -> Decision:
        k = f"{self._prefix}{key}"
        pipe = self._client.pipeline()
        pipe.incr(k)
        pipe.ttl(k)
        count, ttl = await pipe.execute()
        if ttl is None or ttl < 0:  # new key, or a key that lost its expiry
            await self._client.expire(k, window)
            ttl = window
        return Decision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(0, limit - count),
            reset_after=max(1, ttl),
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        backend: RateLimitBackend,
        rules: list[RateRule],
        trust_proxy: bool = False,
        fail_closed: bool = True,
        exempt_paths: tuple[str, ...] = ("/health",),
    ):
        super().__init__(app)
        self.backend = backend
        self.rules = rules  # first match wins: list the most specific first
        self.trust_proxy = trust_proxy
        self.fail_closed = fail_closed
        self.exempt_paths = exempt_paths

    def _rule_for(self, request: Request) -> RateRule | None:
        for rule in self.rules:
            if request.url.path.startswith(rule.path_prefix) and request.method in rule.methods:
                return rule
        return None

    def _client_id(self, request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            try:
                claims = decode_access_token(auth[7:].strip())
                return f"user:{claims['sub']}"
            except (TokenError, SecretNotConfiguredError):
                pass  # invalid token: fall back to the IP so forged tokens can't dodge limits
        if self.trust_proxy:
            # Only trust this when a proxy you control (Nginx) sets the header.
            # Use the LAST entry: the one your proxy appended, not client-supplied.
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return f"ip:{forwarded.split(',')[-1].strip()}"
        return f"ip:{request.client.host if request.client else 'unknown'}"

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.exempt_paths:
            return await call_next(request)
        rule = self._rule_for(request)
        if rule is None:
            return await call_next(request)

        try:
            decision = await self.backend.hit(
                f"{rule.name}:{self._client_id(request)}", rule.limit, rule.window_seconds
            )
        except Exception:
            log.exception("rate limiter backend failure")
            if self.fail_closed:
                return JSONResponse({"detail": "Service temporarily unavailable"}, status_code=503)
            return await call_next(request)

        headers = {
            "X-RateLimit-Limit": str(decision.limit),
            "X-RateLimit-Remaining": str(decision.remaining),
            "X-RateLimit-Reset": str(decision.reset_after),
        }
        if not decision.allowed:
            headers["Retry-After"] = str(decision.reset_after)
            return JSONResponse({"detail": "Too many requests"}, status_code=429, headers=headers)

        response = await call_next(request)
        response.headers.update(headers)
        return response