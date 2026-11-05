from datetime import datetime, timedelta, timezone

import jwt
import pytest

from backend.core.security import (
    ISSUER, SecretNotConfiguredError, TokenError,
    create_access_token, decode_access_token,
)

SECRET = "test-secret-" + "x" * 40


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", SECRET)


def _payload(**overrides):
    now = datetime.now(timezone.utc)
    base = {"sub": "42", "iat": now, "exp": now + timedelta(minutes=5), "iss": ISSUER}
    base.update(overrides)
    return base


def test_roundtrip_returns_subject():
    token = create_access_token(42)
    assert decode_access_token(token)["sub"] == "42"


def test_expired_token_rejected():
    token = create_access_token(42, expires_minutes=-1)
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_tampered_token_rejected():
    token = create_access_token(42)
    flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(TokenError):
        decode_access_token(flipped)


def test_token_signed_with_other_secret_rejected(monkeypatch):
    token = create_access_token(42)
    monkeypatch.setenv("JWT_SECRET", "a-different-secret-" + "y" * 40)
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_alg_none_token_rejected():
    token = jwt.encode(_payload(), None, algorithm="none")
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_other_hmac_algorithm_rejected():
    token = jwt.encode(_payload(), SECRET, algorithm="HS512")
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_wrong_issuer_rejected():
    token = jwt.encode(_payload(iss="someone-else"), SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_missing_expiry_rejected():
    payload = _payload()
    del payload["exp"]
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_garbage_token_rejected():
    with pytest.raises(TokenError):
        decode_access_token("not.a.token")


def test_missing_secret_is_a_configuration_error(monkeypatch):
    monkeypatch.delenv("JWT_SECRET")
    with pytest.raises(SecretNotConfiguredError):
        create_access_token(42)


def test_short_secret_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(SecretNotConfiguredError):
        create_access_token(42)


def test_each_token_has_unique_id():
    a = decode_access_token(create_access_token(42))
    b = decode_access_token(create_access_token(42))
    assert a["jti"] != b["jti"]
