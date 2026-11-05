from __future__ import annotations

import os
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine = None
_factory = None


def _init():
    global _engine, _factory
    if _engine is None:
        url = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        _engine = create_engine(url, pool_pre_ping=True, **kwargs)
        _factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine, _factory


def get_engine():
    return _init()[0]


def get_db() -> Iterator[Session]:
    _, factory = _init()
    db = factory()
    try:
        yield db
    finally:
        db.close()
