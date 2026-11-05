import asyncio
import os
import uuid

import pytest

from backend.api.middleware.sliding_window import (
    InMemorySlidingWindowBackend, SlidingWindowRedisBackend,
)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def run(coro):
    return asyncio.run(coro)


def test_boundary_burst_is_not_allowed():
    clock = Clock()
    b = InMemorySlidingWindowBackend(clock)

    async def scenario():
        out = []
        for t in (0, 30, 59, 61, 62):
            clock.t = 1000.0 + t
            out.append((await b.hit("k", 2, 60)).allowed)
        return out

    assert run(scenario()) == [True, True, False, True, False]


def test_rejected_requests_are_not_recorded():
    clock = Clock()
    b = InMemorySlidingWindowBackend(clock)

    async def scenario():
        for t in (0, 1):
            clock.t = 1000.0 + t
            await b.hit("k", 2, 60)
        for t in range(2, 51):  # hammering while blocked
            clock.t = 1000.0 + t
            assert (await b.hit("k", 2, 60)).allowed is False
        clock.t = 1000.0 + 61
        return (await b.hit("k", 2, 60)).allowed

    assert run(scenario()) is True


def test_retry_after_matches_oldest_hit():
    clock = Clock()
    b = InMemorySlidingWindowBackend(clock)

    async def scenario():
        clock.t = 1000.0
        await b.hit("k", 2, 60)
        clock.t = 1005.0
        await b.hit("k", 2, 60)
        clock.t = 1010.0
        return await b.hit("k", 2, 60)

    d = run(scenario())
    assert d.allowed is False
    assert d.reset_after == 50


def test_remaining_counts_down():
    b = InMemorySlidingWindowBackend(Clock())

    async def scenario():
        return [(await b.hit("k", 3, 60)).remaining for _ in range(3)]

    assert run(scenario()) == [2, 1, 0]


def test_keys_are_isolated():
    b = InMemorySlidingWindowBackend(Clock())

    async def scenario():
        await b.hit("a", 1, 60)
        blocked = (await b.hit("a", 1, 60)).allowed
        other = (await b.hit("b", 1, 60)).allowed
        return blocked, other

    assert run(scenario()) == (False, True)


@pytest.mark.skipif(not os.getenv("REDIS_URL"), reason="REDIS_URL not set")
def test_redis_backend_blocks_after_limit():
    redis = pytest.importorskip("redis.asyncio")

    async def scenario():
        client = redis.from_url(os.environ["REDIS_URL"])
        b = SlidingWindowRedisBackend(client, prefix=f"rltest:{uuid.uuid4().hex}:")
        try:
            return [(await b.hit("k", 2, 60)).allowed for _ in range(3)]
        finally:
            await client.aclose()

    assert run(scenario()) == [True, True, False]
