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
            "you_may_decide": row.state == sso_groups.HELD and refusal is None, "refusal": refusal,
            # A request that can no longer be approved (its provider off, its group mapped to the role no more)
            # can still be denied by an administrator who may decide it.
            "you_may_deny": row.state == sso_groups.HELD and sso_groups.denial_refusal(db, row, approver) is None}


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
    refusal = sso_groups.decision_refusal if approve else sso_groups.denial_refusal
    conflict = refusal(db, row, current_user)
    if conflict is not None:
        _decision_audit(db, approve, user=current_user, ip=client_ip, status_="failure", row=row,
                        details={"user_id": str(row.user_id), "reason": conflict.code})
        raise HTTPException(status_code=409, detail={"reason": conflict.code, "message": conflict.message})
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    row = _request_or_404(db, request_id, lock=True)
    if refusal(db, row, current_user) is not None:
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
    sso_freshness.note_the_lift(identity, provider)       # the lift counts for a removal that asked for it
    label = ((provider.name or provider.label) if provider is not None else None) or "an identity provider"
    # What the lifting gives back, said as it is: the provider's days may have run out under the hold.
    to_the_person = sso_freshness.after_a_hold_is_lifted(db, user, identity, provider, whose="your")
    to_the_administrators = sso_freshness.after_a_hold_is_lifted(db, user, identity, provider, whose="its")
    try:
        from app.core import owner_notices
        if user is not None:
            owner_notices.notify_in_transaction(
                db, [user.id], title="An administrator lifted a sign-in refusal",
                body=(f"{current_user.username} lifted the refusal {label} recorded for your account: "
                      + to_the_person),
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
            f"{user.username if user is not None else 'an account'}: " + to_the_administrators)
    except Exception as exc:  # noqa: BLE001 -- the clearing stands without its notice
        log.info("sso refusal-cleared notice to administrators skipped: %s", type(exc).__name__)
    return {"cleared": True}


NO_WAY_IN_LEFT = "no_way_in_left"


def no_way_in_left(db, user, identity, settled=None) -> Optional[str]:
    """Why an administrator's unlink of ``identity`` would leave ``user`` with no way in, in words that say what
    to do first, or None. Asked after the account's flag was settled for the unlink (``settled``), in its
    transaction: no password anybody can type, and no other identity on a provider that is on and has not
    refused the person.

    Not refused where the unlink itself is what lets the account hold a password again (this identity alone held
    it to none): nothing could be done first, since no reset link is made for an account held to no password.
    The person and the administrators are told that it sets one now."""
    from app.core import sso_only
    from app.services import sign_in
    if settled == sso_only.RESTORED:
        return None
    if sign_in.has_a_password_it_can_type(user) or sso_only.another_way_in(db, user, without=identity):
        return None
    if getattr(user, "sso_only", False):
        # Another provider still holds the account to no password, and is not a way in now (off, or it refused
        # the person): a reset link would be refused for it.
        return (f"This is the only way {user.username} can sign in now: the account signs in only through its "
                "providers, and no other provider it is linked to is on. Turn that provider on, or "
                f"{sso_only.password_remedy(db, user)}, first. To take the account's access away, turn the account "
                "off or delete it.")
    return (f"This is the only way {user.username} can sign in: the account has no password anybody can type. "
            "Make a reset link for it first (Users), so that it can set a password, then unlink. To take the "
            "account's access away, turn the account off or delete it.")


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
    refusal, days run out) ends with the identity: that is this administrator's decision, and is said so.

    Refused, as the owner's own unlink is, where it would leave the account with no way in: no password anybody
    can type and no other identity on a provider that is on. The sentence says what to do first. An account that
    is to have no way in is turned off or deleted, which says so; an unlink that did it said nothing."""
    api = _api()
    client_ip = api.get_client_ip(request)
    identity = _identity_or_404(db, identity_id)
    if str(identity.user_id) == str(current_user.id):
        raise HTTPException(status_code=409, detail={"reason": "own_identity", "message": (
            "Unlink your own identity under Your account.")})
    # Whose account it is, kept before the step-up: that may commit, and what was loaded is read again
    # afterwards. An identity its owner unlinked, or its provider's removal took, in that moment has no row to
    # read again; asked of the loaded one then, the answer was an error and not "no such identity".
    target_id = identity.user_id
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    from app.api import sso_router
    from app.core import sso_only
    from app.services import sso_freshness
    # The account's turn at its sessions before any of its rows (the order of the locks), then the identity as it
    # stands, locked: one unlink at a time.
    api._sessions_turn(db, target_id)
    identity = _identity_or_404(db, identity_id, lock=True)
    user = db.query(User).filter(User.id == identity.user_id).populate_existing().first()
    if user is None:
        raise HTTPException(status_code=404, detail="No such identity.")
    provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
    label = ((provider.label or provider.name) if provider is not None else None) or "an identity provider"
    standing = sso_freshness.deadline_of(identity, provider)
    now = datetime.utcnow()
    # What the provider had on the account, said as it was. Missed (a refusal, or days run out), its keys were
    # paused. Held to the provider's own sign-in only where the hold applied: the provider closes the other
    # ways in, was turned on when the days ran out (or refused the person), and the account is one a hold
    # reaches (sso_freshness.closes_now, may_be_held: the hold's own rules).
    missed = standing is not None and (standing.refused or standing.due <= now)
    held = bool(missed and sso_freshness.closes_now(standing, now) and sso_freshness.may_be_held(db, user))
    paused = bool(missed and not held)
    settled = sso_only.settle(db, user, without=identity)
    why_not = no_way_in_left(db, user, identity, settled)
    if why_not is not None:
        db.rollback()
        raise HTTPException(status_code=409, detail={"reason": NO_WAY_IN_LEFT, "message": why_not})
    ended = sso_router._end_what_came_through(db, user, identity)
    details = {"user_id": str(identity.user_id), "provider_id": str(identity.provider_id),
               "identity_id": str(identity.id), "linked_by": identity.linked_by, "unlinked_by": "administrator",
               "sessions": ended, "held": held, "keys_paused": paused,
               "due": standing.due.isoformat() + "Z" if standing is not None and standing.due else None,
               "restored": settled == sso_only.RESTORED}
    refused_by_the_provider = bool(standing is not None and standing.refused)
    db.delete(identity)
    db.commit()
    _audit(db, "sso_identity_unlinked", user=current_user, ip=client_ip, resource_type="user",
           resource_id=details["user_id"], details=details)
    if refused_by_the_provider:
        # The provider's refusal ended with the identity: recorded as a refusal lifted, by way of the unlink,
        # so that whoever looks for the refusals an administrator lifted finds this one too.
        _audit(db, "sso_refusal_cleared", user=current_user, ip=client_ip, resource_type="user",
               resource_id=details["user_id"],
               details={"user_id": details["user_id"], "provider_id": details["provider_id"],
                        "identity_id": details["identity_id"], "via": "unlink"})
    may_set_password = settled == sso_only.RESTORED
    try:
        from app.api import sso_providers_router
        sso_router._tell_owner(
            db, user, provider, "A sign-in method was removed from your account",
            f"{current_user.username} unlinked your account from {label}: it can no longer sign in through it."
            + (" " + sso_providers_router.SET_A_PASSWORD if may_set_password else ""),
            advice=sso_router.BY_AN_ADMINISTRATOR)
        sso_providers_router._tell_administrators(
            current_user.username, "An identity was unlinked by an administrator",
            f"{current_user.username} unlinked {user.username} from {label}."
            + (f" {label} held that account to its own sign-in (a refusal, or days without a sign-in there): "
               "the hold ended with the identity." if held else "")
            + (f" {label} had paused that account's SSH keys, temporary credentials and devices (a refusal, or "
               "days without a sign-in there): the pause ended with the identity." if paused else "")
            + (" The account may hold a password again. It has none anybody can type until it sets one: it "
               "asks for a reset link on the sign-in page, or you make one for it (Users)." if may_set_password
               else ""))
    except Exception as exc:  # noqa: BLE001 -- the unlink stands without its notices
        log.info("sso unlink notices skipped: %s", type(exc).__name__)
    answer = {"removed": True, "sessions_ended": ended, "held": held, "keys_paused": paused}
    if may_set_password:
        answer["may_set_password"] = True
    return answer
