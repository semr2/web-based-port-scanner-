from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt

ALGORITHM = "HS256"
ISSUER = "web-port-scanner"
DEFAULT_EXPIRE_MINUTES = 30
MIN_SECRET_LENGTH = 32


class TokenError(Exception):
    """Token is invalid, expired, tampered with, or missing required claims."""


class SecretNotConfiguredError(RuntimeError):
    """Server misconfiguration: JWT_SECRET missing or too short. Never caught as a token error."""


def _secret() -> str:
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < MIN_SECRET_LENGTH:
        raise SecretNotConfiguredError(
            f"JWT_SECRET must be set and at least {MIN_SECRET_LENGTH} characters"
        )
    return secret


def create_access_token(
    user_id: str | int,
    *,
    expires_minutes: int = DEFAULT_EXPIRE_MINUTES,
    now: datetime | None = None,
) -> str:
    now = now or datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
        "iss": ISSUER,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    secret = _secret()  # misconfiguration must fail loudly, not look like a bad token
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],  # pinned: blocks "none" and algorithm-confusion attacks
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("invalid token") from exc
