import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.api.middleware.rate_limiter import RateLimitMiddleware, RateRule
from backend.api.middleware.sliding_window import (
    InMemorySlidingWindowBackend,
    SlidingWindowRedisBackend,
)
from backend.api.routes.auth import router as auth_router
from backend.api.routes.scans import router as scans_router
from backend.database.session import Base, get_engine
from backend.models.user import User  # noqa: F401  (registers the table)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev convenience only; Alembic migrations replace this with T003.
    Base.metadata.create_all(get_engine())
    yield


app = FastAPI(
    title="Web Port Scanner",
    description="Authorized network assessment platform",
    version="1.0.0",
    lifespan=lifespan,
)


def build_backend():
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        import redis.asyncio as redis

        return SlidingWindowRedisBackend(redis.from_url(redis_url))
    # Single process only: fine for local dev and tests, not for deployment.
    return InMemorySlidingWindowBackend()


RATE_RULES = [
    RateRule("login", limit=5, window_seconds=60,
             path_prefix="/auth/login", methods=frozenset({"POST"})),
    RateRule("register", limit=5, window_seconds=60,
             path_prefix="/auth/register", methods=frozenset({"POST"})),
    RateRule("scans", limit=10, window_seconds=60,
             path_prefix="/scans", methods=frozenset({"POST"})),
    RateRule("default", limit=120, window_seconds=60),
]

app.add_middleware(
    RateLimitMiddleware,
    backend=build_backend(),
    rules=RATE_RULES,
    trust_proxy=os.getenv("BEHIND_PROXY", "false").lower() == "true",
    exempt_paths=("/api/health",),
)

app.include_router(auth_router)
app.include_router(scans_router)


@app.get("/")
async def root():
    return {"message": "Web Port Scanner API", "status": "running"}


@app.get("/api/health")
async def health():
    return {"status": "healthy"}
