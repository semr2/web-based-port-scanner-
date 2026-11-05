from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user
from backend.core.security import create_access_token
from backend.database.session import get_db
from backend.models.user import User
from backend.services.auth_service import (
    PasswordPolicyError, hash_password, verify_password, verify_unknown_user,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(min_length=1, max_length=1024)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/register", status_code=201, response_model=UserOut)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    username = body.username.lower()
    try:
        password_hash = hash_password(body.password, username=username)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=exc.problems)
    user = User(username=username, password_hash=password_hash)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username already taken")
    return user


@router.post("/login", response_model=TokenOut)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username.lower()))
    if user is not None and user.is_active:
        ok = verify_password(body.password, user.password_hash)
    else:
        ok = verify_unknown_user(body.password)  # equalize timing
    if not ok:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",  # same message for wrong password and unknown user
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
