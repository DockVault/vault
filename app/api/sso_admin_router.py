"""Single sign-on, for administrators: the held administrator requests a provider group raises
(app/services/sso_groups.py). A sign-in never grants the administrator role; it opens a request here, and another
administrator approves or denies it under the fixed step-up every sign-in setting is written under, judged by the
approver rules of the credential changes with no requester. The provider pages themselves land with their item.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
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


def _request_or_404(db, request_id, *, lock: bool = False) -> SsoAdminRequest:
    try:
        rid = uuid.UUID(str(request_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such request.")
    query = db.query(SsoAdminRequest).filter(SsoAdminRequest.id == rid)
    if lock:
        query = query.populate_existing().with_for_update()     # one decision at a time, read as it stands
    row = query.first()
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
    row = _request_or_404(db, request_id, lock=True)
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


# --------------------------------------------------------------------------- a provider's refusal, cleared

def _identity_or_404(db, identity_id, *, lock: bool = False):
    from app.core.models import ExternalIdentity
    try:
        iid = uuid.UUID(str(identity_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such identity.")
    query = db.query(ExternalIdentity).filter(ExternalIdentity.id == iid)
    if lock:
        query = query.populate_existing().with_for_update()
    identity = query.first()
    if identity is None:
        raise HTTPException(status_code=404, detail="No such identity.")
    return identity


@router.post("/admin/sso/identities/{identity_id}/clear-refusal")
def clear_identity_refusal(identity_id: str, request: Request, current_user: User = Depends(require_interactive_admin),
                           db: Session = Depends(get_db)):
    """Lift a refusal the identity's provider recorded (its verified token excluded the person, so their SSH keys,
    temporary credentials and devices paused): for a refusal that was a mistake the provider cannot answer, such as
    one recorded before the provider was disabled. Never an administrator's own: another administrator clears that.
    Under the administrators' sign-in policy step-up, recorded, and the person is told. The provider's freshness
    window, when it asks one, still applies."""
    api = _api()
    client_ip = api.get_client_ip(request)
    identity = _identity_or_404(db, identity_id)
    from app.services import sso_freshness
    if not sso_freshness.refusal_in_force(identity):       # none, or one the person has answered since
        raise HTTPException(status_code=409, detail={"reason": "not_refused",
                                                     "message": "No refusal holds this identity."})
    if str(identity.user_id) == str(current_user.id):
        raise HTTPException(status_code=409, detail={"reason": "own_identity", "message": (
            "Another administrator must clear a refusal of your own identity.")})
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    identity = _identity_or_404(db, identity_id, lock=True)
    if not sso_freshness.refusal_in_force(identity):
        raise HTTPException(status_code=409, detail={"reason": "changed", "message": "The identity changed meanwhile."})
    identity.refused_at = None
    user = db.query(User).filter(User.id == identity.user_id).first()
    provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
    label = ((provider.name or provider.label) if provider is not None else None) or "an identity provider"
    try:
        from app.core import owner_notices
        if user is not None:
            owner_notices.notify_in_transaction(
                db, [user.id], title="An administrator lifted a sign-in refusal",
                body=(f"{current_user.username} lifted the refusal {label} recorded for your account; your SSH keys, "
                      "temporary credentials and devices work again unless another rule pauses them."),
                ntype="sso_refusal_cleared", target="#profile")
    except Exception as exc:  # noqa: BLE001 -- the clearing stands without its notice
        log.info("sso refusal-cleared notice skipped: %s", type(exc).__name__)
    db.commit()
    _audit(db, "sso_refusal_cleared", user=current_user, ip=client_ip, resource_type="user",
           resource_id=str(identity.user_id),
           details={"user_id": str(identity.user_id), "provider_id": str(identity.provider_id),
                    "identity_id": str(identity.id)})
    # Lifting a refusal hands a person their keys back: the other administrators are told, as of every change to
    # the providers.
    try:
        from app.api import sso_providers_router
        sso_providers_router._tell_administrators(
            current_user.username, "A single sign-on refusal was lifted",
            f"{current_user.username} lifted the refusal {label} recorded for "
            f"{user.username if user is not None else 'an account'}: its SSH keys, temporary credentials and devices "
            "work again unless another rule pauses them.")
    except Exception as exc:  # noqa: BLE001 -- the clearing stands without its notice
        log.info("sso refusal-cleared notice to administrators skipped: %s", type(exc).__name__)
    return {"cleared": True}


@router.delete("/admin/sso/identities/{identity_id}")
def unlink_identity(identity_id: str, request: Request, current_user: User = Depends(require_interactive_admin),
                    db: Session = Depends(get_db)):
    """An administrator removes one identity from somebody's account: for a person whose provider cannot confirm
    their own unlink (it is off, or no longer signs them in), and for a link that should not be there. Never the
    administrator's own (that is unlinked under Your account). Under the administrators' sign-in policy step-up,
    recorded, and the person and the other administrators are told.

    What the owner's unlink does, it does: the account's flag follows the providers it is still linked to (one
    held to no password by this identity alone may hold a password again, and nothing is minted), and the
    sessions that came through the identity end with it. A hold the identity's provider had on the account (a
    refusal, days run out) ends with the identity: that is this administrator's decision, and is said so."""
    api = _api()
    client_ip = api.get_client_ip(request)
    identity = _identity_or_404(db, identity_id)
    if str(identity.user_id) == str(current_user.id):
        raise HTTPException(status_code=409, detail={"reason": "own_identity", "message": (
            "Unlink your own identity under Your account.")})
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    from app.api import sso_router
    from app.core import sso_only
    from app.services import sso_freshness
    # The account's turn at its sessions before any of its rows (the order of the locks), then the identity as it
    # stands, locked: one unlink at a time.
    api._sessions_turn(db, identity.user_id)
    identity = _identity_or_404(db, identity_id, lock=True)
    user = db.query(User).filter(User.id == identity.user_id).populate_existing().first()
    if user is None:
        raise HTTPException(status_code=404, detail="No such identity.")
    provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
    label = ((provider.label or provider.name) if provider is not None else None) or "an identity provider"
    standing = sso_freshness.deadline_of(identity, provider)
    held = standing is not None and (standing.refused or standing.due <= datetime.utcnow())
    settled = sso_only.settle(db, user, without=identity)
    ended = sso_router._end_what_came_through(db, user, identity)
    details = {"user_id": str(identity.user_id), "provider_id": str(identity.provider_id),
               "identity_id": str(identity.id), "linked_by": identity.linked_by, "sessions": ended}
    db.delete(identity)
    db.commit()
    _audit(db, "sso_identity_unlinked", user=current_user, ip=client_ip, resource_type="user",
           resource_id=details["user_id"], details=details)
    may_set_password = settled == sso_only.RESTORED
    try:
        from app.api import sso_providers_router
        sso_router._tell_owner(
            db, user, provider, "A sign-in method was removed from your account",
            f"{current_user.username} unlinked your account from {label}: it can no longer sign in through it."
            + (" " + sso_providers_router.SET_A_PASSWORD if may_set_password else ""))
        sso_providers_router._tell_administrators(
            current_user.username, "An identity was unlinked by an administrator",
            f"{current_user.username} unlinked {user.username} from {label}."
            + (f" {label} held that account to its own sign-in (a refusal, or days without a sign-in there): "
               "the hold ended with the identity." if held else "")
            + (" The account may hold a password again." if may_set_password else ""))
    except Exception as exc:  # noqa: BLE001 -- the unlink stands without its notices
        log.info("sso unlink notices skipped: %s", type(exc).__name__)
    answer = {"removed": True, "sessions_ended": ended, "held": bool(held)}
    if may_set_password:
        answer["may_set_password"] = True
    return answer
