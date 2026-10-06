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

Legal holds (app/core/legal_holds.py has the rules): placing one, as a hold-only case, and confirming, reviewing,
releasing and undoing the release of a case's holds. Their routes are at the end of this module.
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
from app.core import legal_holds  # noqa: F401 -- registers the host's confirm-hold step
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


# --------------------------------------------------------------------------- legal holds
# (app/core/legal_holds.py has the rules; a hold-only case shows counts and sizes, never names or content)
#
#     GET  /compliance/holds                              the cases whose holds the caller may see
#     POST /compliance/holds                              place: a hold-only case; a live auditor or an administrator
#     POST /compliance/cases/{id}/hold/confirm            an independent administrator, not the one who placed it
#     POST /compliance/cases/{id}/hold/review             the case's auditor or an independent administrator
#     POST /compliance/cases/{id}/hold/release            {reason}: the case's auditor or an independent administrator
#     POST /compliance/cases/{id}/hold/undo-release       an independent administrator, before the purge

class HoldPlacement(BaseModel):
    vault_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=1000)
    purpose: str = Field(..., max_length=32)
    legal_basis: str = Field(..., max_length=32)
    lia_reference: Optional[str] = Field(default=None, max_length=255)
    justification: str = Field(..., max_length=4000)
    owner_note: str = Field(..., max_length=4000)


def _hold_refused(db, action: str, case, actor, refused) -> None:
    """Record a refused hold step and raise its answer."""
    from app.core import legal_holds as holds
    holds.record_refusal(db, action, case, actor=actor, reason=refused.reason)
    raise HTTPException(status_code=refused.code, detail={
        "reason": refused.reason, "text": refused.detail or holds.text(refused.reason)})


def _case_or_404(db, case_id, *, lock: bool = False):
    from app.core.models import ComplianceCase
    q = db.query(ComplianceCase).filter(ComplianceCase.id == case_id)
    case = (q.with_for_update() if lock else q).first()
    if case is None:
        raise HTTPException(status_code=404, detail="No such case.")
    return case


def _is_admin(user) -> bool:
    from app.core.models import RoleEnum
    return getattr(user, "role", None) == RoleEnum.ADMIN


def _hold_view(db, case, viewer, now) -> dict:
    """A case's holds, counts and sizes only: per vault its id and the hold's dates and people; what the hold keeps
    of all its vaults; and what ``viewer`` may do now (with why not)."""
    from sqlalchemy import func
    from app.core import legal_holds as holds
    from app.core.models import HeldFile, HeldFolder, LegalHoldVault
    rows = (db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case.id)
            .order_by(LegalHoldVault.vault_id).all())
    vault_ids = [r.vault_id for r in rows]
    kept_files, kept_bytes = (db.query(func.count(HeldFile.id), func.coalesce(func.sum(HeldFile.size_bytes), 0))
                              .filter(HeldFile.vault_id.in_(vault_ids)).one()) if vault_ids else (0, 0)
    kept_folders = (db.query(func.count(HeldFolder.id)).filter(HeldFolder.vault_id.in_(vault_ids)).scalar()
                    if vault_ids else 0)

    def may(refusal):
        why = refusal(db, case, viewer, now)
        return {"may": why is None, "why_not": None if why is None else {"reason": why, "text": holds.text(why)}}

    return {
        "id": str(case.id), "number": case.number, "status": case.status, "purpose": case.purpose,
        "legal_basis": case.legal_basis, "started_by": case.auditor_username,
        "started_at": rights._iso(case.requested_at), "closed_at": rights._iso(case.closed_at),
        "holds": [{"vault_id": str(r.vault_id), "placed_by": r.placed_by_username, "placed_at": rights._iso(r.placed_at),
                   "confirm_by": rights._iso(holds.confirm_deadline(r, case)) if r.confirmed_at is None else None,
                   "confirmed_by": r.confirmed_by_username, "confirmed_at": rights._iso(r.confirmed_at),
                   "lapsed_at": rights._iso(r.lapsed_at), "released_at": rights._iso(r.released_at),
                   "released_by": r.released_by_username, "purge_after": rights._iso(r.purge_after),
                   "last_reviewed_at": rights._iso(r.last_reviewed_at),
                   "review_asked_at": rights._iso(r.review_prompted_at),
                   "standing": r.released_at is None} for r in rows],
        "kept": {"files": int(kept_files or 0), "bytes": int(kept_bytes or 0), "folders": int(kept_folders or 0)},
        "you_may": {"confirm": may(_confirm_refusal), "review": may(_review_refusal),
                    "release": may(_release_refusal), "undo_release": may(_undo_refusal)},
    }


# Who may take each step (a refusal reason, or None). Only an administrator confirms or undoes a release; the
# case's own auditor (or the administrator who placed a hold-only case) may also review and release it, while
# they still stand as they did when they started it (legal_holds.starter_refusal).

def _confirm_refusal(db, case, person, now=None):
    from app.core import legal_holds as holds
    return holds.confirm_refusal(db, case, person, now) if _is_admin(person) else holds.NOT_ALLOWED


def _review_refusal(db, case, person, now=None):
    from app.core import legal_holds as holds
    if not _is_admin(person) and not holds.is_case_auditor(case, person):
        return holds.NOT_ALLOWED
    return holds.review_refusal(db, case, person, now)


def _release_refusal(db, case, person, now=None):
    from app.core import legal_holds as holds
    if not _is_admin(person) and not holds.is_case_auditor(case, person):
        return holds.NOT_ALLOWED
    return holds.release_refusal(db, case, person, now)


def _undo_refusal(db, case, person, now=None):
    from app.core import legal_holds as holds
    return holds.undo_refusal(db, case, person, now) if _is_admin(person) else holds.NOT_ALLOWED


@router.get("/compliance/holds")
def list_holds(current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """The cases with legal holds the caller may see: every one for an administrator, the ones they started for an
    auditor. Newest first."""
    from app.core import legal_holds as holds
    from app.core.models import ComplianceCase, LegalHoldVault
    limit_statements(db)
    if not _is_admin(current_user) and not rights.auditor_live(db, current_user).live:
        raise HTTPException(status_code=403, detail="Only an administrator or an auditor can see legal holds.")
    q = db.query(ComplianceCase).filter(ComplianceCase.id.in_(db.query(LegalHoldVault.case_id)))
    if not _is_admin(current_user):
        q = q.filter(ComplianceCase.auditor_id == current_user.id)
    now = holds.utcnow()
    cases = q.order_by(ComplianceCase.requested_at.desc()).limit(ENDED_SHOWN).all()
    return {"cases": [_hold_view(db, c, current_user, now) for c in cases],
            "purposes": list(holds.PURPOSES), "legal_bases": list(holds.LEGAL_BASES),
            "access_enabled": rights.access_enabled()}


@router.post("/compliance/holds", status_code=201)
def place_hold(body: HoldPlacement, request: Request, current_user: User = Depends(require_interactive_account),
               db: Session = Depends(get_db)):
    """Place a legal hold on vaults, as a hold-only case: what is deleted from them is kept from now on. A live
    auditor or an administrator the vaults do not concern; another administrator confirms it, or it lapses."""
    from app.core import legal_holds as holds
    limit_statements(db)
    why = holds.may_place(db, current_user)
    if why is not None:
        _hold_refused(db, "hold_placed", None, current_user,
                      holds.HoldRefused(why, code=403 if why == holds.NOT_ALLOWED else 409))
    try:
        holds.check_case_text(body.purpose, body.legal_basis, body.lia_reference, body.justification,
                              body.owner_note)
    except holds.HoldRefused as refused:
        raise HTTPException(status_code=refused.code, detail={"reason": refused.reason,
                                                              "text": holds.text(refused.reason)})
    STEP_UP_HOLD_PLACE(db, current_user, request)
    limit_statements(db)
    try:
        case = holds.place_hold_only(db, current_user, body.vault_ids, purpose=body.purpose,
                                     legal_basis=body.legal_basis, lia_reference=body.lia_reference,
                                     justification=body.justification, owner_note=body.owner_note)
        db.commit()
    except holds.HoldRefused as refused:
        _hold_refused(db, "hold_placed", None, current_user, refused)
    return _hold_view(db, case, current_user, holds.utcnow())


_NOTHING = ("nothing_to_confirm", "confirm_too_late", "nothing_to_release", "nothing_to_review", "nothing_to_undo",
            "undo_too_late")


def _check_decision(case_id, current_user, db, *, action: str, refusal, lock: bool = False):
    """The case, once ``refusal`` lets ``current_user`` take the step (recorded and refused otherwise); under the
    case's lock with ``lock``. A case the caller may not see is not found."""
    from app.core import legal_holds as holds
    limit_statements(db)
    case = _case_or_404(db, case_id, lock=lock)
    if not _is_admin(current_user) and str(case.auditor_id) != str(current_user.id):
        raise HTTPException(status_code=404, detail="No such case.")
    why = refusal(db, case, current_user)
    if why is not None:
        _hold_refused(db, action, case, current_user,
                      holds.HoldRefused(why, code=409 if why in _NOTHING else 403))
    return case


def _take_decision(case_id, current_user, db, *, action: str, refusal, step, guard: bool = False):
    """Under the case's lock, the refusal checked again, then the step taken and committed (the SFTP guard first
    with ``guard``). Every refusal is recorded."""
    from app.core import legal_holds as holds
    case = _check_decision(case_id, current_user, db, action=action, refusal=refusal, lock=True)
    try:
        if guard:
            holds.sftp_guard(db)
        step(case)
        db.commit()
    except holds.HoldRefused as refused:
        _hold_refused(db, action, case, current_user, refused)
    return _hold_view(db, case, current_user, holds.utcnow())


@router.post("/compliance/cases/{case_id}/hold/confirm")
def confirm_hold(case_id: uuid.UUID, request: Request, current_user: User = Depends(require_interactive_admin),
                 db: Session = Depends(get_db)):
    """Confirm a case's legal hold, as an administrator independent of whoever placed it."""
    from app.core import legal_holds as holds
    _check_decision(case_id, current_user, db, action="hold_confirmed", refusal=_confirm_refusal)
    STEP_UP_HOLD_DECIDE(db, current_user, request)
    return _take_decision(case_id, current_user, db, action="hold_confirmed", refusal=_confirm_refusal,
                          step=lambda case: holds.confirm(db, case, by=current_user))


@router.post("/compliance/cases/{case_id}/hold/review")
def review_hold(case_id: uuid.UUID, current_user: User = Depends(require_interactive_account),
                db: Session = Depends(get_db)):
    """Say that a case's legal hold is still needed: its auditor, or an independent administrator. It only
    records the answer, so it asks for no code."""
    from app.core import legal_holds as holds
    return _take_decision(case_id, current_user, db, action="hold_reviewed", refusal=_review_refusal,
                          step=lambda case: holds.review(db, case, by=current_user))


@router.post("/compliance/cases/{case_id}/hold/release")
def release_hold(case_id: uuid.UUID, body: Reason, request: Request,
                 current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """Release a case's legal hold, with a reason: its auditor, or an independent administrator. What it kept is
    purged after COMPLIANCE_HOLD_PURGE_DELAY_DAYS, unless the release is undone first."""
    from app.core import legal_holds as holds
    _check_decision(case_id, current_user, db, action="hold_released", refusal=_release_refusal)
    STEP_UP_HOLD_DECIDE(db, current_user, request)
    return _take_decision(case_id, current_user, db, action="hold_released", refusal=_release_refusal,
                          step=lambda case: holds.release(db, case, by=current_user,
                                                          reason=body.reason.strip() or "-"))


@router.post("/compliance/cases/{case_id}/hold/undo-release")
def undo_hold_release(case_id: uuid.UUID, request: Request, current_user: User = Depends(require_interactive_admin),
                      db: Session = Depends(get_db)):
    """Undo the release of a case's legal hold before what it kept is purged: the same holds stand again, with
    their confirmation. An independent administrator. Refused while an SFTP server of another version may run."""
    from app.core import legal_holds as holds
    _check_decision(case_id, current_user, db, action="hold_release_undone", refusal=_undo_refusal)
    STEP_UP_HOLD_DECIDE(db, current_user, request)
    return _take_decision(case_id, current_user, db, action="hold_release_undone", refusal=_undo_refusal,
                          guard=True, step=lambda case: holds.undo_release(db, case, by=current_user))
