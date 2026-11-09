from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user
from backend.api.routes.scans import router as scans_router
from backend.database.session import Base, get_db
from backend.models.scan import Scan, ScanStatus
from backend.models.user import User
from backend.services.quota_service import MAX_CONCURRENT_SCANS, MAX_PORTS_PER_SCAN, MAX_SCANS_PER_DAY

GOOD_PORTS = [22, 80, 443]


def build(monkeypatch, resolver_result=None, resolver_raises=None):
    """resolver_result: list[str] to return. resolver_raises: exception instance to raise."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    user = User(username="alice", password_hash="x")
    session.add(user)
    session.commit()

    def fake_resolver(hostname: str):
        if resolver_raises is not None:
            raise resolver_raises
        return resolver_result if resolver_result is not None else ["93.184.216.34"]

    monkeypatch.setattr("backend.api.routes.scans.resolve_approved_hostname", fake_resolver)

    app = FastAPI()
    app.include_router(scans_router)

    def override_db():
        try:
            yield session
        finally:
            pass

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: user

    return TestClient(app), session, user


def post_scan(client, target="example.com", ports=...):
    # Using Ellipsis (not None) as the "not provided" sentinel, so that an
    # explicit ports=[] is sent as-is instead of being swallowed by a falsy
    # default-fallback check (the earlier bug: `ports or GOOD_PORTS` silently
    # replaced an intentional empty list with GOOD_PORTS).
    if ports is ...:
        ports = GOOD_PORTS
    return client.post("/scans/", json={"target": target, "ports": ports})


# ---------- request validation ----------

def test_valid_request_accepted(monkeypatch):
    client, _, _ = build(monkeypatch)
    r = post_scan(client)
    assert r.status_code == 202


def test_empty_port_list_rejected(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, ports=[]).status_code == 422


def test_port_zero_rejected(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, ports=[0]).status_code == 422


def test_port_above_range_rejected(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, ports=[65536]).status_code == 422


def test_negative_port_rejected(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, ports=[-1]).status_code == 422


def test_duplicate_ports_deduplicated(monkeypatch):
    client, session, user = build(monkeypatch)
    r = post_scan(client, ports=[80, 80, 443])
    assert r.status_code == 202
    scan = session.get(Scan, r.json()["id"])
    assert scan.port_count == 2


def test_too_many_ports_rejected(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, ports=list(range(1, MAX_PORTS_PER_SCAN + 2))).status_code == 422


def test_exactly_max_ports_accepted(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, ports=list(range(1, MAX_PORTS_PER_SCAN + 1))).status_code == 202


def test_empty_target_rejected(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client, target="").status_code == 422


# ---------- quota enforcement ----------

def test_under_quota_passes(monkeypatch):
    client, _, _ = build(monkeypatch)
    assert post_scan(client).status_code == 202


def test_concurrent_limit_blocks_and_creates_no_row(monkeypatch):
    client, session, user = build(monkeypatch)
    for _ in range(MAX_CONCURRENT_SCANS):
        session.add(Scan(owner_id=user.id, status=ScanStatus.RUNNING, port_count=1))
    session.commit()
    before = session.query(Scan).count()
    r = post_scan(client)
    assert r.status_code == 429
    assert session.query(Scan).count() == before


def test_daily_limit_blocks(monkeypatch):
    client, session, user = build(monkeypatch)
    for _ in range(MAX_SCANS_PER_DAY):
        session.add(Scan(owner_id=user.id, status=ScanStatus.COMPLETED, port_count=1))
    session.commit()
    assert post_scan(client).status_code == 429


def test_quota_is_isolated_per_user(monkeypatch):
    client, session, user = build(monkeypatch)
    other = User(username="bob", password_hash="x")
    session.add(other)
    session.commit()
    for _ in range(MAX_CONCURRENT_SCANS):
        session.add(Scan(owner_id=other.id, status=ScanStatus.RUNNING, port_count=1))
    session.commit()
    assert post_scan(client).status_code == 202  # alice is unaffected by bob's quota


# ---------- DNS / scope validation ----------

def test_rejected_hostname_returns_400(monkeypatch):
    client, _, _ = build(monkeypatch, resolver_raises=ValueError("not an approved target"))
    r = post_scan(client)
    assert r.status_code == 400


def test_empty_resolver_result_rejected(monkeypatch):
    client, _, _ = build(monkeypatch, resolver_result=[])
    assert post_scan(client).status_code == 400


def test_dns_rejection_creates_no_row(monkeypatch):
    client, session, _ = build(monkeypatch, resolver_raises=ValueError("blocked"))
    before = session.query(Scan).count()
    post_scan(client)
    assert session.query(Scan).count() == before


# ---------- scan record creation ----------

def test_successful_scan_creates_row_with_correct_fields(monkeypatch):
    client, session, user = build(monkeypatch)
    r = post_scan(client, ports=[22, 80, 443])
    assert r.status_code == 202
    body = r.json()
    scan = session.get(Scan, body["id"])
    assert scan.owner_id == user.id
    assert scan.status == ScanStatus.QUEUED
    assert scan.port_count == 3


def test_response_does_not_include_target_or_owner(monkeypatch):
    client, _, _ = build(monkeypatch)
    body = post_scan(client).json()
    assert "target" not in body
    assert "owner_id" not in body


# ---------- check ordering ----------

def test_quota_checked_before_dns_lookup(monkeypatch):
    """When over quota, the resolver must never be called."""
    client, session, user = build(monkeypatch)
    for _ in range(MAX_CONCURRENT_SCANS):
        session.add(Scan(owner_id=user.id, status=ScanStatus.RUNNING, port_count=1))
    session.commit()

    called = []
    monkeypatch.setattr(
        "backend.api.routes.scans.resolve_approved_hostname",
        lambda h: called.append(h) or ["1.2.3.4"],
    )
    r = post_scan(client)
    assert r.status_code == 429
    assert called == []  # resolver was never invoked