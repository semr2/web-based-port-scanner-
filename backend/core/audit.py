from __future__ import annotations

import logging
from typing import Any

audit_log = logging.getLogger("audit")


def _event(action: str, *, user_id: int | None, outcome: str, **fields: Any) -> None:
    # Never pass a password, token, or hash into fields. Reviewed at call sites.
    payload = {"action": action, "user_id": user_id, "outcome": outcome, **fields}
    audit_log.info("audit_event", extra={"audit": payload})


def log_registration(user_id: int, username: str) -> None:
    _event("register", user_id=user_id, outcome="success", username=username)


def log_login_success(user_id: int, username: str) -> None:
    _event("login", user_id=user_id, outcome="success", username=username)


def log_login_failure(username: str) -> None:
    # No user_id: the username may not correspond to a real account.
    _event("login", user_id=None, outcome="failure", attempted_username=username)


def log_quota_rejected(user_id: int, reason: str) -> None:
    _event("scan_quota_rejected", user_id=user_id, outcome="rejected", reason=reason)