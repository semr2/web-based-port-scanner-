from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user
from backend.database.session import get_db
from backend.models.scan import Scan, ScanStatus
from backend.models.user import User
from backend.scanner.dns_resolver import resolve_approved_hostname
from backend.services.quota_service import MAX_PORTS_PER_SCAN, QuotaExceeded, check_quota

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(min_length=1, max_length=MAX_PORTS_PER_SCAN)

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, ports: list[int]) -> list[int]:
        if not ports:
            raise ValueError("ports must not be empty")
        deduped = sorted(set(ports))
        if len(deduped) > MAX_PORTS_PER_SCAN:
            raise ValueError(f"port_count exceeds the maximum of {MAX_PORTS_PER_SCAN}")
        for p in deduped:
            if not (1 <= p <= 65535):
                raise ValueError(f"port {p} out of range 1-65535")
        return deduped


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    status: str
    port_count: int
    created_at: datetime


@router.post("/", status_code=202, response_model=ScanOut)
def create_scan(
    body: ScanRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. Quota first: cheap, local, no network call. Rejects before we ever touch DNS.
    try:
        check_quota(db, user.id, port_count=len(body.ports))
    except QuotaExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    # 2. DNS / scope gate: resolves and validates the hostname is an authorized target.
    #    resolve_approved_hostname raises on any disallowed or unresolved hostname
    #    (fails closed) and returns the approved, pinned IP list on success.
    try:
        approved_ips = resolve_approved_hostname(body.target)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Target rejected: {exc}")

    if not approved_ips:
        raise HTTPException(status_code=400, detail="Target rejected: no approved IPs")

    # 3. Create the record. Actual scanning is queued separately (T007/T008); this
    #    endpoint only validates and records the request.
    scan = Scan(
        owner_id=user.id,
        status=ScanStatus.QUEUED,
        port_count=len(body.ports),
        target=body.target.strip().lower(),
        ports=list(body.ports),
        resolved_ips=[str(ip) for ip in approved_ips],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan
