"""The audit log's integrity status, for the Activity page (app/core/audit_integrity.py).

    GET /activity/integrity    the chain's head (the line to keep somewhere else), how far the hours are
                               sealed, the last check's time and outcome, and every failure and warning not
                               yet acknowledged.

The status is read from the head record and the verified view, never from the audit rows that announce a
failure: those land in hours not yet sealed, where whoever caused the failure could delete them. Only an
interactive administrator reaches it. A plain ``def``: it reads a small file and memory, no database.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.user_management_api import require_interactive_admin
from app.core import audit_integrity
from app.core.models import User

router = APIRouter(tags=["Audit log integrity"])

# What the page says the chain does, and does not, give.
CLAIM = ("Tamper-evident against changes made in the database without the server's key; not against the "
         "server's operator.")


def _entries(table: dict) -> list:
    return [{"kind": kind, "message": e.get("message", ""), "first_seen": e.get("first_seen"),
             "last_seen": e.get("last_seen")} for kind, e in sorted((table or {}).items())]


@router.get("/activity/integrity")
def get_integrity(current_user: User = Depends(require_interactive_admin)):
    """The integrity status of the audit log."""
    status = audit_integrity.status()
    return {"head": status.get("head"), "sealed_through": status.get("sealed_through"),
            "key_id": status.get("key_id"), "key_shared": bool(status.get("key_shared")),
            "outcome": status.get("outcome"), "checked_at": (status.get("check") or {}).get("daily_at"),
            "failures": _entries(status.get("failures")), "warnings": _entries(status.get("warnings")),
            "stopped": status.get("stopped"), "claim": CLAIM}
