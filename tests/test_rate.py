import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.middleware.rate_limiter import (
    InMemoryBackend, RateLimitMiddleware, RateRule,
)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make_client(clock=None, backend=None, rules=None, **kw):
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.get("/health")
    def health():
        return {"ok": True}

    app.add_middleware(
        RateLimitMiddleware,
        backend=backend or InMemoryBackend(clock or Clock()),
        rules=rules or [RateRule("ping", limit=2, window_seconds=60, path_prefix="/ping")],
        **kw,
    )
    return TestClient(app)


def test_blocks_after_limit():
    c = make_client()
    assert c.get("/ping").status_code == 200
    assert c.get("/ping").status_code == 200
    r = c.get("/ping")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def test_window_resets():
    clock = Clock()
    c = make_client(clock)
    for _ in range(3):
        c.get("/ping")
    clock.t += 61
    assert c.get("/ping").status_code == 200


def test_rate_limit_headers_on_success():
    r = make_client().get("/ping")
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert r.headers["X-RateLimit-Remaining"] == "1"


def test_clients_are_isolated_when_proxy_trusted():
    c = make_client(trust_proxy=True)
    for _ in range(3):
        c.get("/ping", headers={"X-Forwarded-For": "1.1.1.1"})
    assert c.get("/ping", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200


def test_forwarded_header_cannot_evade_limit_when_untrusted():
    c = make_client(trust_proxy=False)
    codes = [c.get("/ping", headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(3)]
    assert codes == [200, 200, 429]


def test_exempt_path_not_limited():
    c = make_client(rules=[RateRule("all", limit=1, window_seconds=60)])
    assert all(c.get("/health").status_code == 200 for _ in range(5))


def test_fails_closed_on_backend_error():
    class Broken:
        async def hit(self, *a, **k):
            raise RuntimeError("redis down")

    assert make_client(backend=Broken()).get("/ping").status_code == 503


def test_fails_open_only_when_configured():
    class Broken:
        async def hit(self, *a, **k):
            raise RuntimeError("redis down")

    assert make_client(backend=Broken(), fail_closed=False).get("/ping").status_code == 200


def test_backend_counts_per_key():
    b = InMemoryBackend(Clock())
    results = [asyncio.run(b.hit("k", 2, 60)).allowed for _ in range(3)]
    assert results == [True, True, False]