"""Compliance access: the auditor right, cases, legal holds.

Every step that grants or uses the power to read someone else's vault (proposing and approving an auditor
grant, reconfirming one, requesting, approving or extending a case, exporting from it, placing a legal hold and
confirming or releasing it) asks for the compliance step-up: the password and a TOTP or recovery code, every
time, whatever the admin's step-up matrix says (app/core/fixed_step_up.py, compliance_step_up). The check is
called inside the route's body, which lets a plain ``def`` route use it, and is made here, at import, so the
boot contract sees each of these actions guarded.

Routes here never use endpoint groups (whose administrator bypass would let any administrator through) and
never name a permission: authorization does not know about compliance access. Each is a plain ``def`` with a
statement timeout, refuses a temporary credential, and reads the grant again on every call.

The auditor right (app/core/auditor_rights.py has the rules):

    GET    /compliance/auditors                         every grant, open first, with its state; administrators
    GET    /compliance/auditor-grants/{id}              one grant, with where the account came from
    POST   /compliance/auditor-grants                   propose: {user_id, note?}; an administrator
    POST   /compliance/auditor-grants/{id}/approve      an independent administrator
    POST   /compliance/auditor-grants/{id}/reject       {reason}: an administrator other than the proposer
    POST   /compliance/auditor-grants/{id}/reconfirm    the holder, after a suspension
    DELETE /users/{user_id}/auditor                     revoke (a proposal too): {reason?}; any administrator
    GET    /compliance/me                               the caller's own right, as it stands now

Whether the right is in force is computed on every request (auditor_rights.auditor_live): a route an auditor
uses depends on require_live_auditor, which refuses (403) a right that is not, whatever the stored state says.
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.user_management_api import get_current_user, require_interactive_admin
from app.core import auditor_rights as rights
from app.core import fixed_step_up
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Compliance"])

STEP_UP_GRANT_PROPOSE = fixed_step_up.compliance_step_up("compliance.grant.propose")
STEP_UP_GRANT_APPROVE = fixed_step_up.compliance_step_up("compliance.grant.approve")
STEP_UP_GRANT_RECONFIRM = fixed_step_up.compliance_step_up("compliance.grant.reconfirm")
STEP_UP_CASE_REQUEST = fixed_step_up.compliance_step_up("compliance.case.request")
STEP_UP_CASE_APPROVE = fixed_step_up.compliance_step_up("compliance.case.approve")
STEP_UP_CASE_EXPORT = fixed_step_up.compliance_step_up("compliance.case.export")
STEP_UP_HOLD_PLACE = fixed_step_up.compliance_step_up("compliance.hold.place")
STEP_UP_HOLD_DECIDE = fixed_step_up.compliance_step_up("compliance.hold.decide")

STATEMENT_TIMEOUT_MS = 5000
# The most ended grants the list shows, newest first, after every open one.
ENDED_SHOWN = 200
NOTE_MAX = 2000

ACCESS_OFF = ("Compliance access is turned off on this deployment (COMPLIANCE_ACCESS=disabled): no auditor right "
              "can be proposed or approved.")


def limit_statements(db: Session) -> None:
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(sql_text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


async def require_interactive_account(current_user: User = Depends(get_current_user)) -> User:
    """A signed-in account in a session of its own: a temporary credential is refused."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="A temporary credential cannot do this.")
    return current_user


def require_live_auditor(current_user: User = Depends(require_interactive_account),
                         db: Session = Depends(get_db)) -> User:
    """An account whose auditor right is in force now, computed from the grant and the account as they stand
    (app/core/auditor_rights.py, auditor_live): 403 otherwise, with the reason."""
    standing = rights.auditor_live(db, current_user)
    if not standing.live:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"reason": standing.reason, "text": rights.text(standing.reason)})
    current_user._auditor_grant_id = standing.grant.id
    return current_user


class Proposal(BaseModel):
    user_id: uuid.UUID
    note: Optional[str] = Field(default=None, max_length=NOTE_MAX)


class Reason(BaseModel):
    reason: str = Field(..., min_length=1, max_length=NOTE_MAX)


class OptionalReason(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=NOTE_MAX)


def _refuse(db, actor, step, reason, *, code, user=None, grant=None, reasons=None):
    """Record the refused step and raise its answer: the first reason, and every reason, in plain words."""
    rights.record_refusal(db, actor=actor, step=step, reason=reason, user=user, grant=grant, reasons=reasons)
    raise HTTPException(status_code=code, detail={
        "reason": reason, "text": rights.text(reason),
        "reasons": [{"reason": r, "text": rights.text(r)} for r in (reasons or [reason])]})


def _grant_or_404(db, grant_id, *, lock=False):
    grant = rights.grant_by_id(db, grant_id, lock=lock)
    if grant is None:
        raise HTTPException(status_code=404, detail="No such auditor grant.")
    return grant


# --------------------------------------------------------------------------- reading

@router.get("/compliance/auditors")
def list_auditor_grants(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Every open grant, then the most recent ended ones: who holds or held the right, since when, until when,
    and in which state. For a proposal, whether the caller may approve it, and why not."""
    from app.core.models import AUDITOR_GRANT_OPEN, AuditorGrant
    limit_statements(db)
    now = rights.utcnow()
    open_rows = (db.query(AuditorGrant).filter(AuditorGrant.status.in_(AUDITOR_GRANT_OPEN))
                 .order_by(AuditorGrant.proposed_at.desc()).all())
    ended = (db.query(AuditorGrant).filter(AuditorGrant.status.notin_(AUDITOR_GRANT_OPEN))
             .order_by(AuditorGrant.updated_at.desc()).limit(ENDED_SHOWN).all())
    return {"grants": [rights.grant_dict(db, g, viewer=current_user, now=now) for g in open_rows + ended],
            "grant_days": rights.grant_days(), "proposal_days": rights.PROPOSAL_DAYS,
            "admin_may_hold": not rights.admin_not_allowed(), "access_enabled": rights.access_enabled()}


@router.get("/compliance/auditor-grants/{grant_id}")
def get_auditor_grant(grant_id: uuid.UUID, current_user: User = Depends(require_interactive_admin),
                      db: Session = Depends(get_db)):
    """One grant, with where its account came from and the reasons given."""
    limit_statements(db)
    grant = _grant_or_404(db, grant_id)
    out = rights.grant_dict(db, grant, viewer=current_user, detail=True)
    if "provenance" not in out:
        holder = db.get(User, grant.user_id) if grant.user_id is not None else None
        out["provenance"] = rights.provenance(db, holder)
    return out


@router.get("/compliance/me")
def my_auditor_right(current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """The caller's own auditor right, as it stands now: none, waiting for approval, in force, or suspended."""
    limit_statements(db)
    grant = rights.open_grant(db, current_user.id)
    if grant is None:
        return {"grant": None}
    standing = rights.auditor_live(db, current_user)
    reconfirm = rights.reconfirm_problem(db, grant, current_user) if grant.status == "suspended" else None
    return {"grant": {"id": str(grant.id), "status": rights.shown_status(grant),
                      "proposed_by": grant.proposed_by_username, "approved_by": grant.approved_by_username,
                      "approved_at": rights._iso(grant.approved_at),
                      "expires_at": rights._iso(rights.effective_expiry(grant)),
                      "suspend_reason": grant.suspend_reason if grant.status == "suspended" else None,
                      "live": standing.live, "reason": standing.reason, "reason_text": rights.text(standing.reason),
                      "may_reconfirm": grant.status == "suspended" and reconfirm is None,
                      "reconfirm_problem": ({"reason": reconfirm, "text": rights.text(reconfirm)}
                                            if reconfirm is not None else None)}}


# --------------------------------------------------------------------------- the steps

def _proposal_problems(db, user) -> list:
    problems = rights.preconditions(db, user)
    if rights.open_grant(db, user.id) is not None:
        problems.insert(0, rights.OPEN_GRANT)
    return problems


@router.post("/compliance/auditor-grants", status_code=201)
def propose_auditor_grant(body: Proposal, request: Request,
                          current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Propose the auditor right for an account. A second, independent administrator approves it."""
    from app.core import credential_changes as cc
    limit_statements(db)
    if not rights.access_enabled():
        raise HTTPException(status_code=409, detail=ACCESS_OFF)
    user = db.get(User, body.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No such account.")
    problems = _proposal_problems(db, user)
    if problems:
        _refuse(db, current_user, "propose", problems[0], code=409, user=user, reasons=problems)
    STEP_UP_GRANT_PROPOSE(db, current_user, request)
    limit_statements(db)
    # Read again under the account's lock: a change may have landed while the step-up was given.
    cc._lock_account(db, body.user_id)
    db.refresh(user)
    problems = _proposal_problems(db, user)
    if problems:
        _refuse(db, current_user, "propose", problems[0], code=409, user=user, reasons=problems)
    try:
        grant = rights.propose(db, user, proposer=current_user, note=(body.note or "").strip() or None)
        db.commit()
    except IntegrityError:
        _refuse(db, current_user, "propose", rights.OPEN_GRANT, code=409, user=user)
    return rights.grant_dict(db, grant, viewer=current_user)


def _check_approval(db, grant, approver) -> None:
    """Refuse (recorded) what may not be approved: not a proposal, lapsed, an approver who is not independent,
    an account that no longer meets the preconditions."""
    if grant.status != "proposed":
        _refuse(db, approver, "approve", rights.NOT_PROPOSED, code=409, grant=grant)
    if rights.is_lapsed(grant):
        _refuse(db, approver, "approve", rights.LAPSED, code=409, grant=grant)
    why = rights.approver_refusal(db, grant, approver)
    if why is not None:
        _refuse(db, approver, "approve", why, code=403, grant=grant)
    problems = rights.preconditions(db, db.get(User, grant.user_id) if grant.user_id is not None else None)
    if problems:
        _refuse(db, approver, "approve", problems[0], code=409, grant=grant, reasons=problems)


@router.post("/compliance/auditor-grants/{grant_id}/approve")
def approve_auditor_grant(grant_id: uuid.UUID, request: Request,
                          current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Approve a proposal, as the independent second administrator. The grant is bound to the account's
    authenticator as it is now, and lasts COMPLIANCE_AUDITOR_GRANT_DAYS."""
    from app.core import credential_changes as cc
    limit_statements(db)
    if not rights.access_enabled():
        raise HTTPException(status_code=409, detail=ACCESS_OFF)
    grant = _grant_or_404(db, grant_id)
    _check_approval(db, grant, current_user)
    STEP_UP_GRANT_APPROVE(db, current_user, request)
    limit_statements(db)
    if grant.user_id is not None:
        cc._lock_account(db, grant.user_id)
    grant = _grant_or_404(db, grant_id, lock=True)
    _check_approval(db, grant, current_user)
    rights.approve(db, grant, approver=current_user)
    db.commit()
    return rights.grant_dict(db, grant, viewer=current_user)


@router.post("/compliance/auditor-grants/{grant_id}/reject")
def reject_auditor_grant(grant_id: uuid.UUID, body: Reason, request: Request,
                         current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Turn a proposal down, with a reason: an administrator other than the one who proposed it and the
    account it is for."""
    limit_statements(db)

    def check(g):
        if g.status != "proposed" or rights.is_lapsed(g):
            _refuse(db, current_user, "reject", rights.NOT_PROPOSED, code=409, grant=g)
        why = rights.rejecter_refusal(g, current_user)
        if why is not None:
            _refuse(db, current_user, "reject", why, code=403, grant=g)

    check(_grant_or_404(db, grant_id))
    STEP_UP_GRANT_APPROVE(db, current_user, request)
    limit_statements(db)
    grant = _grant_or_404(db, grant_id, lock=True)
    check(grant)
    rights.reject(db, grant, rejecter=current_user, reason=body.reason.strip() or "-")
    db.commit()
    return rights.grant_dict(db, grant, viewer=current_user)


@router.post("/compliance/auditor-grants/{grant_id}/reconfirm")
def reconfirm_auditor_grant(grant_id: uuid.UUID, request: Request,
                            current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """The holder confirms their suspended right again, with their password and a code from the authenticator
    the right is bound to. After an administrator set their password, they set one of their own first; after a
    second-factor reset or removal the right has ended, and only a new grant gives it."""
    limit_statements(db)
    grant = rights.grant_by_id(db, grant_id)
    if grant is None or grant.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="No such auditor grant.")

    def check(g):
        problem = rights.reconfirm_problem(db, g, current_user)
        if problem is not None:
            _refuse(db, current_user, "reconfirm", problem, code=409, grant=g)

    check(grant)
    STEP_UP_GRANT_RECONFIRM(db, current_user, request)
    limit_statements(db)
    grant = _grant_or_404(db, grant_id, lock=True)
    check(grant)
    rights.reconfirm(db, grant, current_user)
    db.commit()
    return {"id": str(grant.id), "status": grant.status, "reconfirmed_at": rights._iso(grant.reconfirmed_at)}


@router.delete("/users/{user_id}/auditor")
def revoke_auditor_right(user_id: uuid.UUID, body: Optional[OptionalReason] = Body(default=None),
                         current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Take back an account's auditor right, or withdraw its proposal. One administrator is enough: it only
    removes power. Works while compliance access is turned off."""
    limit_statements(db)
    grant = rights.open_grant(db, user_id, lock=True)
    if grant is None:
        raise HTTPException(status_code=404, detail="That account holds no auditor right and none is proposed.")
    reason = ((body.reason if body is not None else None) or "").strip() or None
    rights.revoke(db, grant, actor=current_user, reason=reason)
    db.commit()
    return rights.grant_dict(db, grant, viewer=current_user)
