from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api.middleware.rate_limiter import (
    InMemoryBackend, RateLimitMiddleware, RateRule,
)
from backend.api.routes import auth as auth_module
from backend.api.routes.auth import router as auth_router
from backend.core.security import ISSUER, create_access_token
from backend.database.session import Base, get_db
from backend.models.user import User

SECRET = "test-secret-" + "x" * 40
GOOD = "correct horse battery staple"


def build(monkeypatch, middleware=False, raise_exc=True):
    monkeypatch.setenv("JWT_SECRET", SECRET)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(auth_router)
    app.dependency_overrides[get_db] = override
    if middleware:
        app.add_middleware(
            RateLimitMiddleware,
            backend=InMemoryBackend(),
            rules=[RateRule("me", limit=2, window_seconds=60, path_prefix="/auth/me")],
        )
    return TestClient(app, raise_server_exceptions=raise_exc), Session


@pytest.fixture
def ctx(monkeypatch):
    return build(monkeypatch)


def register(client, username="alice", password=GOOD):
    return client.post("/auth/register", json={"username": username, "password": password})


def login(client, username="alice", password=GOOD):
    return client.post("/auth/login", json={"username": username, "password": password})


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- registration ----------

def test_register_ok_and_response_hides_secrets(ctx):
    client, _ = ctx
    r = register(client)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice"
    assert "password" not in body and "password_hash" not in body


def test_stored_password_is_argon2id(ctx):
    client, Session = ctx
    register(client)
    with Session() as db:
        user = db.scalar(select(User))
        assert user.password_hash.startswith("$argon2id$")
        assert GOOD not in user.password_hash


def test_short_password_rejected(ctx):
    assert register(ctx[0], password="short").status_code == 422


def test_password_containing_username_rejected(ctx):
    assert register(ctx[0], password="my-alice-password-123").status_code == 422


def test_invalid_username_rejected(ctx):
    assert register(ctx[0], username="a b!").status_code == 422


def test_duplicate_username_conflicts_case_insensitively(ctx):
    client, _ = ctx
    assert register(client, "alice").status_code == 201
    assert register(client, "Alice").status_code == 409


def test_missing_fields_rejected(ctx):
    assert ctx[0].post("/auth/register", json={}).status_code == 422


# ---------- login ----------

def test_login_returns_working_token(ctx):
    client, _ = ctx
    register(client)
    r = login(client)
    assert r.status_code == 200
    token = r.json()["access_token"]
    me = client.get("/auth/me", headers=auth_header(token))
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_wrong_password_and_unknown_user_look_identical(ctx):
    client, _ = ctx
    register(client)
    wrong = login(client, password="not the right password")
    unknown = login(client, username="nobody", password="not the right password")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_unknown_user_triggers_timing_equalizer(ctx, monkeypatch):
    calls = []
    monkeypatch.setattr(
        auth_module, "verify_unknown_user", lambda pw: calls.append(pw) or False
    )
    assert login(ctx[0], username="nobody").status_code == 401
    assert len(calls) == 1


def test_login_is_case_insensitive_on_username(ctx):
    client, _ = ctx
    register(client, "alice")
    assert login(client, "ALICE").status_code == 200


# ---------- auth dependency ----------

def test_missing_header_rejected(ctx):
    assert ctx[0].get("/auth/me").status_code == 401


def test_wrong_scheme_rejected(ctx):
    r = ctx[0].get("/auth/me", headers={"Authorization": "Basic abc123"})
    assert r.status_code == 401


def test_empty_bearer_rejected(ctx):
    r = ctx[0].get("/auth/me", headers={"Authorization": "Bearer "})
    assert r.status_code == 401


def test_garbage_token_rejected(ctx):
    assert ctx[0].get("/auth/me", headers=auth_header("not.a.token")).status_code == 401


def test_expired_token_rejected(ctx):
    client, _ = ctx
    register(client)
    token = create_access_token(1, expires_minutes=-1)
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401


def test_alg_none_token_rejected(ctx):
    client, _ = ctx
    register(client)
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {"sub": "1", "iat": now, "exp": now + timedelta(minutes=5), "iss": ISSUER},
        None,
        algorithm="none",
    )
    assert client.get("/auth/me", headers=auth_header(forged)).status_code == 401


def test_token_for_deleted_user_rejected(ctx):
    client, Session = ctx
    register(client)
    token = login(client).json()["access_token"]
    with Session() as db:
        db.delete(db.scalar(select(User)))
        db.commit()
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401


def test_token_for_deactivated_user_rejected(ctx):
    client, Session = ctx
    register(client)
    token = login(client).json()["access_token"]
    with Session() as db:
        user = db.scalar(select(User))
        user.is_active = False
        db.commit()
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401
    assert login(client).status_code == 401


def test_missing_secret_is_a_server_error(monkeypatch):
    client, _ = build(monkeypatch, raise_exc=False)
    register(client)
    token = login(client).json()["access_token"]
    monkeypatch.delenv("JWT_SECRET")
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 500


# ---------- rate limiting keyed by user ----------

def test_rate_limit_is_per_user_not_per_ip(monkeypatch):
    client, _ = build(monkeypatch, middleware=True)
    register(client, "user_a")
    register(client, "user_b")
    a = login(client, "user_a").json()["access_token"]
    b = login(client, "user_b").json()["access_token"]
    codes_a = [client.get("/auth/me", headers=auth_header(a)).status_code for _ in range(3)]
    assert codes_a == [200, 200, 429]
    assert client.get("/auth/me", headers=auth_header(b)).status_code == 200


def test_forged_tokens_cannot_dodge_the_limit(monkeypatch):
    client, _ = build(monkeypatch, middleware=True)
    codes = [
        client.get("/auth/me", headers=auth_header(f"junk-{i}")).status_code for i in range(3)
    ]
    assert codes[-1] == 429  # counted by IP, so rotating junk tokens doesn't help
