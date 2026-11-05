from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models.scan import Scan, ScanStatus

MAX_CONCURRENT_SCANS = 2
MAX_SCANS_PER_DAY = 20
MAX_PORTS_PER_SCAN = 1024

_ACTIVE_STATUSES = (ScanStatus.QUEUED, ScanStatus.RUNNING)


class QuotaExceeded(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class QuotaStatus:
    concurrent_scans: int
    scans_today: int
    concurrent_limit: int = MAX_CONCURRENT_SCANS
    daily_limit: int = MAX_SCANS_PER_DAY


def _count(db: Session, owner_id: int, *, statuses: tuple[str, ...] | None = None,
           since: datetime | None = None) -> int:
    stmt = select(func.count()).select_from(Scan).where(Scan.owner_id == owner_id)
    if statuses:
        stmt = stmt.where(Scan.status.in_(statuses))
    if since:
        stmt = stmt.where(Scan.created_at >= since)
    return db.scalar(stmt) or 0


def get_quota_status(db: Session, owner_id: int) -> QuotaStatus:
    since = datetime.now(timezone.utc) - timedelta(days=1)
    return QuotaStatus(
        concurrent_scans=_count(db, owner_id, statuses=_ACTIVE_STATUSES),
        scans_today=_count(db, owner_id, since=since),
    )


def check_quota(db: Session, owner_id: int, *, port_count: int) -> None:
    """Raise QuotaExceeded if a new scan would violate any limit. Does not create anything."""
    if port_count > MAX_PORTS_PER_SCAN:
        raise QuotaExceeded(f"port_count exceeds the maximum of {MAX_PORTS_PER_SCAN}")
    if port_count < 1:
        raise QuotaExceeded("port_count must be at least 1")

    status = get_quota_status(db, owner_id)
    if status.concurrent_scans >= MAX_CONCURRENT_SCANS:
        raise QuotaExceeded(f"{MAX_CONCURRENT_SCANS} concurrent scans already running")
    if status.scans_today >= MAX_SCANS_PER_DAY:
        raise QuotaExceeded(f"daily limit of {MAX_SCANS_PER_DAY} scans reached")