from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.core.security import TokenError, decode_access_token
from backend.database.session import get_db
from backend.models.user import User

_bearer = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        claims = decode_access_token(creds.credentials)
    except TokenError:
        raise _unauthorized()
    # SecretNotConfiguredError is deliberately NOT caught: that is a server fault (500).
    try:
        user_id = int(claims["sub"])
    except (KeyError, ValueError):
        raise _unauthorized()
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    request.state.user_id = user.id
    return user
