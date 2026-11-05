from backend.api.main import app
from backend.api.middleware.rate_limiter import RateLimitMiddleware


def test_rate_limiter_is_registered():
    assert any(m.cls is RateLimitMiddleware for m in app.user_middleware)
