"""Single sign-on, for administrators: the held administrator requests a provider group raises
(app/services/sso_groups.py). A sign-in never grants the administrator role; it opens a request here, and another
administrator approves or denies it under the fixed step-up every sign-in setting is written under, judged by the
approver rules of the credential changes with no requester. The provider pages themselves land with their item.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import fixed_step_up
from app.core.database import get_db
from app.core.models import SsoAdminRequest, SsoProvider, User
from app.services import sso_groups

router = APIRouter(tags=["Single sign-on administration"])
log = logging.getLogger("dockvault.sso")

STEP_UP_ACTION = "admin.auth_policy.write"
_step_up = fixed_step_up.guard(STEP_UP_ACTION)


def _api():
    from app.api import api_server
    return api_server


def _audit(db, action: str, *, user=None, ip, details: dict, status_: str = "success", resource_type=None,
           resource_id=None) -> None:
    try:
        from app.services.audit_logger import AuditLogger
        AuditLogger(db).log_action(action=action, status=status_, user=user, ip_address=ip, details=details,
                                   resource_type=resource_type, resource_id=resource_id)
    except Exception:      # noqa: BLE001 -- the decision stands without its row
        pass


def _request_or_404(db, request_id) -> SsoAdminRequest:
    try:
        rid = uuid.UUID(str(request_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such request.")
    row = db.query(SsoAdminRequest).filter(SsoAdminRequest.id == rid).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No such request.")
    return row


def _public(db, row: SsoAdminRequest, approver) -> dict:
    user = db.query(User).filter(User.id == row.user_id).first()
    provider = db.query(SsoProvider).filter(SsoProvider.id == row.provider_id).first()

    def _t(value):
        return value.isoformat() + "Z" if value else None
    refusal: Optional[str] = None
    if row.state == sso_groups.HELD:
        conflict = sso_groups.decision_refusal(db, row, approver)
        refusal = conflict.message if conflict is not None else None
    return {"id": str(row.id), "username": user.username if user is not None else None,
            "provider_id": str(row.provider_id),
            "provider": (provider.label or provider.name) if provider is not None else "a removed provider",
            "provider_group": row.provider_group, "requested_at": _t(row.requested_at), "expires_at": _t(row.expires_at),
            "state": row.state, "decided_by": row.decided_by_name, "decided_at": _t(row.decided_at),
            "you_may_decide": row.state == sso_groups.HELD and refusal is None, "refusal": refusal}


@router.get("/admin/sso/admin-requests")
def list_admin_requests(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """The requests waiting (with whether the caller may decide each, and why not), and the decided ones (the
    last fifty). A held request past its seven days is marked expired as it is read."""
    held, decided = sso_groups.requests(db)
    db.commit()
    return {"held": [_public(db, r, current_user) for r in held],
            "decided": [_public(db, r, current_user) for r in decided[:50]]}


def _decide(db, request_id, current_user, request: Request, *, approve: bool):
    api = _api()
    client_ip = api.get_client_ip(request)
    row = _request_or_404(db, request_id)
    conflict = sso_groups.decision_refusal(db, row, current_user)
    if conflict is not None:
        _decision_audit(db, approve, user=current_user, ip=client_ip, status_="failure", row=row,
                        details={"user_id": str(row.user_id), "reason": conflict.code})
        raise HTTPException(status_code=409, detail={"reason": conflict.code, "message": conflict.message})
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    row = _request_or_404(db, request_id)
    if sso_groups.decision_refusal(db, row, current_user) is not None:
        raise HTTPException(status_code=409, detail={"reason": "changed", "message": "The request changed meanwhile; look again."})
    if approve:
        outcome = sso_groups.approve(db, row, current_user, http_request=request)
    else:
        sso_groups.deny(db, row, current_user)
        outcome = {}
    _decision_audit(db, approve, user=current_user, ip=client_ip, status_="success", row=row,
                    details={"user_id": str(row.user_id), "provider_id": str(row.provider_id)})
    return {"request": _public(db, row, current_user), **outcome}


def _decision_audit(db, approve: bool, *, user, ip, status_: str, row, details: dict) -> None:
    if approve:
        _audit(db, "sso_admin_approved", user=user, ip=ip, status_=status_, resource_type="sso_admin_request",
               resource_id=str(row.id), details=details)
    else:
        _audit(db, "sso_admin_denied", user=user, ip=ip, status_=status_, resource_type="sso_admin_request",
               resource_id=str(row.id), details=details)


@router.post("/admin/sso/admin-requests/{request_id}/approve")
def approve_admin_request(request_id: str, request: Request, current_user: User = Depends(require_interactive_admin),
                          db: Session = Depends(get_db)):
    """Grant the administrator role the request asks for, as a promotion by the approver."""
    return _decide(db, request_id, current_user, request, approve=True)


@router.post("/admin/sso/admin-requests/{request_id}/deny")
def deny_admin_request(request_id: str, request: Request, current_user: User = Depends(require_interactive_admin),
                       db: Session = Depends(get_db)):
    """Refuse the request; the account is unchanged and the person is told."""
    return _decide(db, request_id, current_user, request, approve=False)
