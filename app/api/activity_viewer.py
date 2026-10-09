"""Who may read the Activity page's log: an administrator, or an auditor whose right is in force.

An auditor reads what log review needs: the catalog, the events and one event, the usernames typeahead, the
summary (without what is happening now), their own saved searches and the export (recorded, and with no name the
auditor could not read anyway). Live sessions and transfers (/activity/now), the temporary-credential typeahead,
the vault-password unlock of the Activity page, Blocks and Settings stay an administrator's.

The right is computed on every request (app/core/auditor_rights.py, auditor_live): a right revoked, suspended,
expired or turned off (COMPLIANCE_ACCESS=disabled) ends access at once. A temporary credential never reads the log
this way, and no endpoint group or permission grants it: endpoint groups have an administrator bypass, so they can
never carry a compliance capability.

An auditor's reading is recorded (``auditor_events_viewed``), by the server, at most once in ten minutes: every
committed row signals the open page, which then fetches it, and a row per fetch would feed itself. When the row
cannot be written the read is refused (503): no read of the log by the right without its record.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.user_management_api import get_current_user
from app.core.database import get_db
from app.core.models import RoleEnum, User

QUIET = timedelta(minutes=10)
VIEWED = "auditor_events_viewed"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def is_admin(user) -> bool:
    return getattr(user, "role", None) == RoleEnum.ADMIN


def reads_by_right(db, user, now: Optional[datetime] = None) -> bool:
    """Whether ``user`` reads the log through the auditor right (not as an administrator), with it in force."""
    from app.core import auditor_rights
    return not is_admin(user) and auditor_rights.auditor_live(db, user, now).live


def note_events_viewed(db, user, now: Optional[datetime] = None) -> bool:
    """Record that the auditor ``user`` read the log, unless that was recorded in the last ten minutes. Returns
    whether a row was written. Raises HTTPException(503) when it cannot be written."""
    from app.core import case_access
    from app.core.models import AuditLog
    now = now or utcnow()
    recent = db.query(AuditLog.id).filter(AuditLog.user_id == user.id, AuditLog.action == VIEWED,
                                          AuditLog.status == "success", AuditLog.timestamp >= now - QUIET).first()
    if recent is not None:
        return False
    try:
        case_access.record(db, None, user, VIEWED, resource_type="audit_log", resource_id=None, details={})
    except case_access.Refused:
        raise HTTPException(status_code=503, detail=(
            "Reading the activity log could not be recorded, so it was not shown. Try again shortly."))
    return True


def require_activity_viewer(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    """An administrator's or a live auditor's own interactive session; refused (403, recorded as a denial)
    otherwise. An auditor's read is recorded at most once in ten minutes."""
    from app.api.api_server import _audit_admin_denial
    if getattr(current_user, "_is_temp_session", False):
        _audit_admin_denial(db, current_user, "interactive session required (temp credential rejected)")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="This needs an interactive session, not a temporary credential.")
    if is_admin(current_user):
        return current_user
    if reads_by_right(db, current_user):
        note_events_viewed(db, current_user)
        return current_user
    _audit_admin_denial(db, current_user, "administrator or auditor required")
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                        detail="Only an administrator or an auditor can read the activity log.")
