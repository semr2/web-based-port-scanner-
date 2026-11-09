import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user
from backend.api.routes.scans import router as scans_router
from backend.database.session import Base, get_db
from backend.models.scan import Scan
from backend.models.scan_result import ScanResult
from backend.models.user import User


def make(monkeypatch, ips=("93.184.216.34",)):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    user = User(username="alice", password_hash="x")
    session.add(user)
    session.commit()
    monkeypatch.setattr("backend.api.routes.scans.resolve_approved_hostname", lambda h: list(ips))
    app = FastAPI()
    app.include_router(scans_router)

    def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app), session


def test_scan_row_stores_target_ports_and_pinned_ips(monkeypatch):
    client, session = make(monkeypatch)
    r = client.post("/scans/", json={"target": "Example.COM", "ports": [443, 22, 80, 22]})
    assert r.status_code == 202
    scan = session.get(Scan, r.json()["id"])
    assert scan.target == "example.com"
    assert scan.ports == [22, 80, 443]
    assert scan.resolved_ips == ["93.184.216.34"]
    assert scan.port_count == 3


def test_results_attach_and_cascade_on_delete(monkeypatch):
    client, session = make(monkeypatch)
    sid = client.post("/scans/", json={"target": "example.com", "ports": [22, 80]}).json()["id"]
    scan = session.get(Scan, sid)
    scan.results.append(ScanResult(port=22, state="open", banner="SSH-2.0-test"))
    scan.results.append(ScanResult(port=80, state="closed"))
    session.commit()
    assert session.scalar(select(func.count()).select_from(ScanResult)) == 2
    session.delete(scan)
    session.commit()
    assert session.scalar(select(func.count()).select_from(ScanResult)) == 0


def test_one_result_per_port_per_scan(monkeypatch):
    client, session = make(monkeypatch)
    sid = client.post("/scans/", json={"target": "example.com", "ports": [22]}).json()["id"]
    session.add(ScanResult(scan_id=sid, port=22, state="open"))
    session.commit()
    session.add(ScanResult(scan_id=sid, port=22, state="closed"))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
