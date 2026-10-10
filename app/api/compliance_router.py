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
releasing and undoing the release of a case's holds. Their routes follow the auditor right's.

Cases (app/core/cases.py has the steps, app/core/case_rules.py the rules): asking for one, approving and turning it
down, withdrawing, extending, closing, narrowing, recording an objection, and the vault picker. Their routes follow
the holds'.

A vault's owner (app/core/owner_access.py): Access to my vaults, the banner's "I've read it", and unlocking a
password-protected vault's names on that page. Their routes follow the cases'.

Reading a case (app/core/case_access.py, the only code that opens a file for a case): its vaults and folders, a
file's metadata, content and rendered preview, unlocking a password-protected vault with its password, and
searching file names; and exporting its files (app/core/case_export.py), prepared with the step-up and fetched
once as a streamed archive. Their routes are at the end of this module; each asks for no endpoint group and no
permission, and records what it reads and every refusal.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import anyio
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import event
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.user_management_api import get_current_user, require_interactive_admin
from app.core import auditor_rights as rights
from app.core import fixed_step_up
from app.core import cases as _cases  # noqa: F401 -- registers the host's approve and reject steps
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


_STATEMENT_LIMIT = f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"
_LIMITED = "compliance_statement_limit"


def _limit_again(session, transaction, connection) -> None:
    connection.exec_driver_sql(_STATEMENT_LIMIT)


def limit_statements(db: Session) -> None:
    """Every statement of the request's session runs under STATEMENT_TIMEOUT_MS: the transaction under way now, and
    each one the session begins after a commit (a read commits its own record and goes on reading: a folder's names,
    the vault's entry, the file to send), from its start. SET LOCAL ends with its transaction, so the session sets
    it again as each one begins."""
    bind = db.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    db.execute(sql_text(_STATEMENT_LIMIT))
    if not db.info.get(_LIMITED):
        db.info[_LIMITED] = True
        event.listen(db, "after_begin", _limit_again)


async def require_interactive_account(current_user: User = Depends(get_current_user)) -> User:
    """A signed-in account in a session of its own: a temporary credential is refused."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="A temporary credential cannot do this.")
    return current_user


def require_live_auditor_or_admin(current_user: User = Depends(require_interactive_account),
                                  db: Session = Depends(get_db)) -> User:
    """An administrator in their own session, or an account whose auditor right is in force: who may place a legal
    hold, and so look up an owner's vaults for one."""
    if _is_admin(current_user):
        return current_user
    return require_live_auditor(current_user=current_user, db=db)


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


def _seen_by(db, q, viewer):
    """``q`` (cases) narrowed to those ``viewer`` may see (cases.may_see): an administrator every case that does not
    concern them, anyone else the cases they started."""
    from sqlalchemy import and_, or_
    from app.core.models import ComplianceCase, ComplianceCasePerson, ComplianceCaseVault, Vault
    if not _is_admin(viewer):
        return q.filter(ComplianceCase.auditor_id == viewer.id)
    named = db.query(ComplianceCasePerson.case_id).filter(ComplianceCasePerson.user_id == viewer.id)
    owning = (db.query(ComplianceCaseVault.case_id).join(Vault, Vault.id == ComplianceCaseVault.vault_id)
              .filter(Vault.owner_id == viewer.id))
    return q.filter(or_(ComplianceCase.auditor_id == viewer.id,
                        and_(ComplianceCase.id.notin_(named), ComplianceCase.id.notin_(owning))))


def _kept_by(model, rows, viewer):
    """Which rows of the kept table ``model`` a case's view counts. An administrator sees every case, so every row
    kept on its vaults; anyone else (the case's auditor) only what was kept while the case's own hold stood on each
    vault: rows another case kept before it, or after it ended, are another investigation's."""
    from sqlalchemy import and_, or_
    if _is_admin(viewer):
        return model.vault_id.in_([r.vault_id for r in rows])
    return or_(*[and_(model.vault_id == r.vault_id, model.kept_at >= r.placed_at,
                      *([model.kept_at <= r.released_at] if r.released_at is not None else []))
                 for r in rows])


def _hold_view(db, case, viewer, now) -> dict:
    """A case's holds, counts and sizes only: per vault its id and the hold's dates and people; what the hold keeps
    of all its vaults (for its auditor, only what it kept itself); and what ``viewer`` may do now (with why not)."""
    from sqlalchemy import func
    from app.core import legal_holds as holds
    from app.core.models import HeldFile, HeldFolder, LegalHoldVault
    rows = (db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case.id)
            .order_by(LegalHoldVault.vault_id).all())
    kept_files, kept_bytes = (db.query(func.count(HeldFile.id), func.coalesce(func.sum(HeldFile.size_bytes), 0))
                              .filter(_kept_by(HeldFile, rows, viewer)).one()) if rows else (0, 0)
    kept_folders = (db.query(func.count(HeldFolder.id)).filter(_kept_by(HeldFolder, rows, viewer)).scalar()
                    if rows else 0)

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
    """The cases with legal holds the caller may see: for an administrator every one that does not concern them, the
    ones they started for an auditor. Newest first."""
    from app.core import legal_holds as holds
    from app.core.models import ComplianceCase, LegalHoldVault
    limit_statements(db)
    if not _is_admin(current_user) and not rights.auditor_live(db, current_user).live:
        raise HTTPException(status_code=403, detail="Only an administrator or an auditor can see legal holds.")
    q = _seen_by(db, db.query(ComplianceCase).filter(ComplianceCase.id.in_(db.query(LegalHoldVault.case_id))),
                 current_user)
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
    from app.core import cases
    from app.core import legal_holds as holds
    limit_statements(db)
    case = _case_or_404(db, case_id, lock=lock)
    if not cases.may_see(db, case, current_user):
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
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=422, detail={"reason": holds.NO_REASON, "text": holds.text(holds.NO_REASON)})
    _check_decision(case_id, current_user, db, action="hold_released", refusal=_release_refusal)
    STEP_UP_HOLD_DECIDE(db, current_user, request)
    return _take_decision(case_id, current_user, db, action="hold_released", refusal=_release_refusal,
                          step=lambda case: holds.release(db, case, by=current_user, reason=reason))


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


# --------------------------------------------------------------------------- cases
# (app/core/cases.py has the steps, app/core/case_rules.py the rules; reading a case is at the end of this module)
#
#     GET   /compliance/cases                         the caller's cases (an auditor's own; every case for an admin)
#     POST  /compliance/cases                         ask for one: a live auditor, with the step-up
#     GET   /compliance/cases/{id}                    one case, as the caller may see it; its version in ETag
#     POST  /compliance/cases/{id}/approve            an independent administrator, step-up, If-Match: version
#     POST  /compliance/cases/{id}/reject             {reason}: as for approving
#     POST  /compliance/cases/{id}/withdraw           the auditor, while it waits
#     POST  /compliance/cases/{id}/extend             {days}: an independent administrator, step-up, If-Match
#     POST  /compliance/cases/{id}/close              {reason}: the auditor or an independent administrator
#     POST  /compliance/cases/{id}/objection          {text}: an owner of one of its vaults, or an administrator
#     PATCH /compliance/cases/{id}/scope              narrow only: the auditor or an independent administrator
#     GET   /compliance/vault-picker?owner=           one owner's vaults, names only where already readable

class ScopeItemIn(BaseModel):
    kind: str = Field(..., max_length=16)
    target_id: uuid.UUID


class CaseRequest(BaseModel):
    purpose: str = Field(..., max_length=32)
    legal_basis: str = Field(..., max_length=32)
    lia_reference: Optional[str] = Field(default=None, max_length=255)
    special_category: bool = False
    art9_condition: Optional[str] = Field(default=None, max_length=32)
    criminal_offence: bool = False
    justification: str = Field(..., max_length=4000)
    owner_note: str = Field(..., max_length=4000)
    named_user_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    # The people named, by username (the screen's way: an auditor cannot browse the directory). Each must name one
    # account exactly (case aside); one that does not is refused as an unknown person is, and recorded.
    named_usernames: list[str] = Field(default_factory=list, max_length=100)
    scope: list[ScopeItemIn] = Field(..., min_length=1, max_length=1000)
    files_from: Optional[datetime] = None
    files_to: Optional[datetime] = None
    access_days: Optional[int] = None
    can_export: bool = False
    password_override: bool = False
    hold: Optional[bool] = None


class Extension(BaseModel):
    days: int


class ObjectionIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000)


class Narrowing(BaseModel):
    scope: list[ScopeItemIn] = Field(..., min_length=1, max_length=1000)
    files_from: Optional[datetime] = None
    files_to: Optional[datetime] = None


def _naive(value: Optional[datetime]) -> Optional[datetime]:
    """A time as the database keeps it: UTC, without a zone."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _case_refused(db, action: str, case, actor, refused, *, record: bool = True):
    """Record a refused case step (unless the request was only malformed or out of date) and raise its answer."""
    from app.core import cases
    if record:
        cases.record_refusal(db, action, case, actor=actor, reason=refused.reason)
    raise HTTPException(status_code=refused.code, detail={
        "reason": refused.reason, "text": refused.detail or cases.text(refused.reason)})


def _visible_case(db, case_id, viewer, *, lock: bool = False):
    """The case, when ``viewer`` may see it (its auditor, or an administrator it does not concern); not found
    otherwise, as for anyone else: an administrator a case concerns sees it only as an owner does, on Access to my
    vaults."""
    from app.core import cases
    case = _case_or_404(db, case_id, lock=lock)
    if not cases.may_see(db, case, viewer):
        raise HTTPException(status_code=404, detail="No such case.")
    return case


@router.get("/compliance/cases")
def list_cases(current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """The cases with access the caller may see, newest first: for an administrator every one that does not concern
    them, the ones they asked for otherwise (an empty list for anyone else). Hold-only cases are listed with the
    holds."""
    from app.core import cases
    from app.core.models import ComplianceCase
    limit_statements(db)
    q = _seen_by(db, db.query(ComplianceCase).filter(ComplianceCase.access_days > 0), current_user)
    now = cases.utcnow()
    rows = q.order_by(ComplianceCase.requested_at.desc()).limit(ENDED_SHOWN).all()
    counts = _case_counts(db, [c.id for c in rows])
    out = []
    for c in rows:
        view = cases.case_view(db, c, current_user, now=now, light=True)
        view["files_opened"], view["exports"] = counts.get(c.id, (0, 0))
        # What the list's "Waiting for my approval" and the sidebar's count read: a pending case this administrator
        # may decide.
        if c.status == cases.rules.PENDING and _is_admin(current_user):
            view["you_may_approve"] = cases.decision_refusal(db, c, current_user, now) is None
        out.append(view)
    return {"cases": out, "access_enabled": rights.access_enabled(), "max_open_cases": cases.rules.MAX_OPEN_CASES}


def _case_counts(db, case_ids) -> dict:
    """{case id: (files opened, exports)} under each case, as its owners' summary counts them, in one query: the
    distinct files of its case_file_viewed rows and its case_export_completed rows."""
    from sqlalchemy import func
    from app.core.models import AuditLog
    if not case_ids:
        return {}
    out = {}
    rows = (db.query(AuditLog.case_id, AuditLog.action, func.count(func.distinct(AuditLog.resource_id)),
                     func.count(AuditLog.id))
            .filter(AuditLog.case_id.in_(list(case_ids)),
                    AuditLog.action.in_(("case_file_viewed", "case_export_completed")), AuditLog.status == "success")
            .group_by(AuditLog.case_id, AuditLog.action).all())
    for case_id, action, distinct, total in rows:
        opened, exports = out.get(case_id, (0, 0))
        if action == "case_file_viewed":
            opened = int(distinct or 0)
        else:
            exports = int(total or 0)
        out[case_id] = (opened, exports)
    return out


def _named_by_username(db, usernames) -> Optional[list]:
    """The ids of the accounts ``usernames`` name (each exactly, case aside), or None when one names no account or
    several."""
    from sqlalchemy import func
    ids = []
    for name in usernames:
        name = (name or "").strip()
        if not name:
            continue
        found = db.query(User.id).filter(func.lower(User.username) == name.lower()).limit(2).all()
        if len(found) != 1:
            return None
        ids.append(found[0][0])
    return ids


@router.post("/compliance/cases", status_code=201)
def request_case(body: CaseRequest, request: Request, current_user: User = Depends(require_live_auditor),
                 db: Session = Depends(get_db)):
    """Ask for a case: what it is for and why, what it covers, for how long. An independent administrator
    approves it; until then nothing is readable and the owners are not told."""
    from app.core import cases
    limit_statements(db)
    named = list(body.named_user_ids)
    if body.named_usernames:
        by_name = _named_by_username(db, body.named_usernames)
        if by_name is None:
            _case_refused(db, "case_requested", None, current_user,
                          cases.CaseRefused(cases.rules.NO_SUCH_PERSON, code=404))
        named += by_name                # request_case keeps each person once
    args = dict(purpose=body.purpose, legal_basis=body.legal_basis, lia_reference=body.lia_reference,
                special_category=body.special_category, art9_condition=body.art9_condition,
                criminal_offence=body.criminal_offence, justification=body.justification,
                owner_note=body.owner_note, named_user_ids=named,
                scope=[{"kind": s.kind, "target_id": s.target_id} for s in body.scope],
                files_from=_naive(body.files_from), files_to=_naive(body.files_to), access_days=body.access_days,
                can_export=body.can_export, password_override=body.password_override, hold=body.hold)
    # Checked before the code is asked for (a request that cannot be made costs no code), and again after.
    try:
        cases.request_case(db, current_user, **args)
    except cases.CaseRefused as refused:
        _case_refused(db, "case_requested", None, current_user, refused, record=refused.code != 422)
    db.rollback()
    STEP_UP_CASE_REQUEST(db, current_user, request)
    limit_statements(db)
    try:
        case = cases.request_case(db, current_user, **args)
        db.commit()
    except cases.CaseRefused as refused:
        _case_refused(db, "case_requested", None, current_user, refused, record=refused.code != 422)
    return cases.case_view(db, case, current_user)


@router.get("/compliance/cases/{case_id}")
def get_case(case_id: uuid.UUID, response: Response, current_user: User = Depends(require_interactive_account),
             db: Session = Depends(get_db)):
    """One case as the caller may see it, with where the auditor's account came from for an administrator. Its
    version is the ETag an approval or an extension sends back in If-Match."""
    from app.core import cases
    limit_statements(db)
    case = _visible_case(db, case_id, current_user)
    response.headers["ETag"] = f'"{case.version}"'
    return cases.case_view(db, case, current_user, detail=True)


# Refusals about the case's state (409); the others are about the person (403).
_CASE_STATE = ("not_now", "expired_unapproved", "access_ended", "compliance_disabled", "independent_admin")


def _case_check(db, case, current_user, *, action: str, refusal, versioned: bool = False, if_match=None) -> None:
    """Refuse (recorded, but for an out-of-date or missing version) what ``refusal`` refuses, and with
    ``versioned`` a case that changed since the caller read it."""
    from app.core import cases
    try:
        if versioned:
            cases.check_version(case, if_match)
        why = refusal(db, case, current_user)
        if why is not None:
            raise cases.CaseRefused(why, code=409 if why in _CASE_STATE else 403)
    except cases.CaseRefused as refused:
        _case_refused(db, action, case, current_user, refused, record=refused.code not in (412, 428))


def _check_case(case_id, current_user, db, **kw):
    """The case, once the step is allowed (before the step-up is asked for)."""
    limit_statements(db)
    case = _visible_case(db, case_id, current_user)
    _case_check(db, case, current_user, **kw)
    return case


def _take_case_step(case_id, current_user, db, *, step, **kw):
    """Under the case's lock, the step checked again, taken and committed (every refusal recorded); the case as the
    caller now sees it."""
    from app.core import cases
    limit_statements(db)
    case = _visible_case(db, case_id, current_user, lock=True)
    _case_check(db, case, current_user, **kw)
    try:
        step(case)
        db.commit()
    except cases.CaseRefused as refused:
        _case_refused(db, kw["action"], case, current_user, refused, record=refused.code not in (412, 428))
    db.refresh(case)
    return cases.case_view(db, case, current_user, detail=True)


@router.post("/compliance/cases/{case_id}/approve")
def approve_case(case_id: uuid.UUID, request: Request, if_match: Optional[str] = Header(default=None),
                 current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Approve a case, as an administrator independent of its auditor, with the step-up and the version read
    (If-Match). The access, the hold and every owner's notice commit together, or nothing does."""
    from app.core import cases

    def refusal(db_, case, person, now=None):
        return cases.rules.ACCESS_OFF if not cases.access_enabled() else cases.decision_refusal(db_, case, person, now)
    kw = dict(action="case_approved", refusal=refusal, versioned=True, if_match=if_match)
    _check_case(case_id, current_user, db, **kw)
    STEP_UP_CASE_APPROVE(db, current_user, request)
    return _take_case_step(case_id, current_user, db, step=lambda case: cases.approve(db, case, approver=current_user),
                           **kw)


@router.post("/compliance/cases/{case_id}/reject")
def reject_case(case_id: uuid.UUID, body: Reason, request: Request,
                current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Turn a case down, with a reason its auditor reads: the administrators who could approve it."""
    from app.core import cases
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=422, detail={"reason": cases.NO_REASON, "text": cases.text(cases.NO_REASON)})
    kw = dict(action="case_rejected", refusal=cases.decision_refusal)
    _check_case(case_id, current_user, db, **kw)
    STEP_UP_CASE_APPROVE(db, current_user, request)
    return _take_case_step(case_id, current_user, db,
                           step=lambda case: cases.reject(db, case, by=current_user, reason=reason), **kw)


@router.post("/compliance/cases/{case_id}/withdraw")
def withdraw_case(case_id: uuid.UUID, current_user: User = Depends(require_interactive_account),
                  db: Session = Depends(get_db)):
    """The auditor withdraws their case while it waits for approval. It only removes power: no code."""
    from app.core import cases

    def refusal(db_, case, person, now=None):
        if not cases.is_auditor_of(case, person):
            return cases.NOT_ALLOWED
        return cases.rules.step_refusal(case.status, cases.rules.WITHDRAW)
    return _take_case_step(case_id, current_user, db, action="case_withdrawn", refusal=refusal,
                           step=lambda case: cases.withdraw(db, case, by=current_user))


@router.post("/compliance/cases/{case_id}/extend")
def extend_case(case_id: uuid.UUID, body: Extension, request: Request,
                if_match: Optional[str] = Header(default=None),
                current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Extend a case's access by ``days``, as an independent administrator, with the step-up and the version read.
    Its owners are told."""
    from app.core import cases
    kw = dict(action="case_extended", refusal=cases.extend_refusal, versioned=True, if_match=if_match)
    _check_case(case_id, current_user, db, **kw)
    STEP_UP_CASE_APPROVE(db, current_user, request)
    return _take_case_step(case_id, current_user, db,
                           step=lambda case: cases.extend(db, case, by=current_user, days=body.days), **kw)


@router.post("/compliance/cases/{case_id}/close")
def close_case(case_id: uuid.UUID, body: Reason, request: Request,
               current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """Close a case with a reason: its auditor or an independent administrator. Its legal holds are released (with
    the step-up a release asks for); the owners are told with a summary."""
    from app.core import cases
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=422, detail={"reason": cases.NO_REASON, "text": cases.text(cases.NO_REASON)})
    kw = dict(action="case_closed", refusal=cases.close_refusal)
    case = _check_case(case_id, current_user, db, **kw)
    code_asked = bool(legal_holds.standing(db, case.id))
    if code_asked:
        STEP_UP_HOLD_DECIDE(db, current_user, request)

    def step(c):
        # Under the case's lock: a release undone since the code was (not) asked for would otherwise be released
        # again here without it.
        if not code_asked and legal_holds.standing(db, c.id):
            raise cases.CaseRefused(cases.HOLD_STANDS_AGAIN)
        cases.close(db, c, by=current_user, reason=reason)
    return _take_case_step(case_id, current_user, db, step=step, **kw)


@router.post("/compliance/cases/{case_id}/objection")
def record_case_objection(case_id: uuid.UUID, body: ObjectionIn,
                          current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """Record an owner's objection on a case (the owner, or an administrator for them). Kept sealed; whoever extends
    the case reads it."""
    from app.core import cases
    limit_statements(db)
    case = _case_or_404(db, case_id, lock=True)
    if not (cases.may_see(db, case, current_user) or cases.owns_a_vault_in(db, case, current_user)):
        raise HTTPException(status_code=404, detail="No such case.")
    try:
        cases.record_objection(db, case, by=current_user, text_=body.text)
        db.commit()
    except cases.CaseRefused as refused:
        _case_refused(db, "case_objection_recorded", case, current_user, refused, record=refused.code != 422)
    return {"id": str(case.id), "objections": len(cases.objections(case))}


@router.patch("/compliance/cases/{case_id}/scope")
def narrow_case(case_id: uuid.UUID, body: Narrowing, current_user: User = Depends(require_interactive_account),
                db: Session = Depends(get_db)):
    """Narrow a case: its auditor or an independent administrator, no approval. Anything wider is refused (409):
    it needs a new case."""
    from app.core import cases
    fields = body.model_fields_set
    scope = [{"kind": s.kind, "target_id": s.target_id} for s in body.scope]
    return _take_case_step(case_id, current_user, db, action="case_scope_narrowed", refusal=cases.narrow_refusal,
                           step=lambda case: cases.narrow(db, case, by=current_user, scope=scope,
                                                          files_from=_naive(body.files_from),
                                                          files_to=_naive(body.files_to),
                                                          keep_range=not ({"files_from", "files_to"} & fields)))


@router.get("/compliance/vault-picker")
def vault_picker(owner: str = Query(..., min_length=1, max_length=255),
                 current_user: User = Depends(require_live_auditor_or_admin), db: Session = Depends(get_db)):
    """One owner's vaults for a case or a legal hold (by account id or username): type, size, file count, creation
    date and id; a name only where the caller can already read the vault. A live auditor, or an administrator (who
    places holds). Each query is recorded."""
    from app.core import cases
    from app.core.authorization import PermissionService
    from app.core.models import Vault
    from app.services.audit_logger import AuditLogger
    limit_statements(db)
    person_id = cases.rules.as_id(owner)
    person = db.get(User, person_id) if person_id is not None else (
        db.query(User).filter(User.username == owner.strip()).first())
    if person is None:
        raise HTTPException(status_code=404, detail="No such account.")
    permissions = PermissionService(db)
    out = []
    for v in db.query(Vault).filter(Vault.owner_id == person.id).order_by(Vault.created_at, Vault.id).all():
        readable = (v.type != "zero_knowledge" and v.password_hash is None
                    and permissions.get_vault_permissions(current_user, v.id) is not None)
        out.append({"id": str(v.id), "type": v.type or "standard", "has_password": v.password_hash is not None,
                    "file_count": int(v.file_count or 0), "bytes": int(v.total_size_bytes or 0),
                    "created_at": rights._iso(v.created_at), "name": v.name if readable else None})
    db.add(AuditLogger(db).build_row(action="case_picker_viewed", status="success", user=current_user,
                                     resource_type="user", resource_id=str(person.id), details={"vaults": len(out)}))
    db.commit()
    return {"owner": {"id": str(person.id), "username": person.username}, "vaults": out}


# --------------------------------------------------------------------------- a vault's owner
# (app/core/owner_access.py)
#
#     GET  /me/compliance-access                          the cases on the caller's vaults; X-Owner-Unlock: vault=receipt,...
#     POST /me/compliance-access/seen                     "I've read it" for the banner after sign-in
#     POST /me/compliance-access/vaults/{id}/unlock       {password}: a 15-minute receipt for that vault's names here

class SeenThrough(BaseModel):
    through: Optional[datetime] = None


class OwnerUnlock(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)


def _owner_receipts(header: Optional[str]) -> dict:
    """{vault id: receipt} of an X-Owner-Unlock header ("vault=receipt", comma-separated)."""
    out = {}
    for part in (header or "").split(",")[:100]:
        vid, _, receipt = part.strip().partition("=")
        if vid and receipt:
            out[vid] = receipt
    return out


@router.get("/me/compliance-access")
def my_compliance_access(request: Request, x_owner_unlock: Optional[str] = Header(default=None),
                         current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """Access to my vaults: every case that told the caller about one of their vaults, what it covers of them, the
    files it opened there (names read now, as the caller could read them in the vault), its exports, and the notices
    not yet read. Never the justification, the people named, or another owner's vaults."""
    from app.api.api_server import _current_session_hash
    from app.core import owner_access
    limit_statements(db)
    unlocked = owner_access.unlocked_vaults(db, current_user, _current_session_hash(request),
                                            _owner_receipts(x_owner_unlock))
    return owner_access.page(db, current_user, unlocked=unlocked)


@router.post("/me/compliance-access/seen")
def my_compliance_notices_seen(body: Optional[SeenThrough] = Body(default=None),
                               current_user: User = Depends(require_interactive_account),
                               db: Session = Depends(get_db)):
    """The caller has read their notices (up to ``through``): the banner goes; the notices and the page stay."""
    from app.core import owner_access
    limit_statements(db)
    count = owner_access.mark_seen(db, current_user, through=_naive(body.through) if body is not None else None)
    db.commit()
    return {"seen": count}


@router.post("/me/compliance-access/vaults/{vault_id}/unlock")
def unlock_my_vault_names(vault_id: uuid.UUID, body: OwnerUnlock, request: Request,
                          current_user: User = Depends(require_interactive_account), db: Session = Depends(get_db)):
    """A receipt that shows, for 15 minutes, the names of the files a case opened in one of the caller's own
    password-protected vaults. The password counts on the vault-password throttle every check of it by the caller
    uses, and is never recorded."""
    from app.api.api_server import _current_session_hash
    from app.core import owner_access
    from app.core import vault_unlock_receipts as receipts
    from app.core.models import Vault
    from app.services.audit_logger import AuditLogger
    limit_statements(db)
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    problem = owner_access.unlock_problem(db, current_user, vault)
    if problem is not None:
        raise HTTPException(status_code=problem[0], detail=problem[1])
    session_hash = _current_session_hash(request)
    if not session_hash:
        raise HTTPException(status_code=403, detail="A receipt is given only to a signed-in session.")

    def record(status_: str, details: dict) -> None:
        db.add(AuditLogger(db).build_row(action="owner_access_unlocked", status=status_, user=current_user,
                                         resource_type="vault", resource_id=str(vault.id),
                                         details={"vault_id": str(vault.id), **details}))
        db.commit()

    try:
        receipts.check_password(current_user, vault, body.password)
    except receipts.UnlockRefused as refused:
        if refused.status == 403:
            try:
                record("failure", {"reason": "wrong password"})
            except Exception:  # noqa: BLE001 -- the refusal stands without its row
                db.rollback()
        raise HTTPException(status_code=refused.status, detail=refused.detail)
    receipt, expires = receipts.issue(purpose=receipts.PURPOSE_OWNER, session_hash=session_hash, vault_id=vault.id,
                                      user_id=current_user.id, credential=receipts.credential_digest(vault.password_hash))
    try:
        record("success", {"expires_at": expires.isoformat() + "Z"})
    except Exception:  # noqa: BLE001 -- no receipt without its audit row
        db.rollback()
        raise HTTPException(status_code=503, detail="The names were not unlocked: the audit record could not be "
                                                    "written.")
    return {"vault_id": str(vault.id), "receipt": receipt, "expires_at": expires.isoformat() + "Z"}


# --------------------------------------------------------------------------- reading a case
# (app/core/case_access.py checks every read, records it, and is the only code that opens a file for a case)
#
#     GET  /compliance/cases/{id}/tree?vault_id=&folder_id=     without vault_id: the case's vaults; else one folder
#     GET  /compliance/cases/{id}/files/{file_id}               one file's metadata
#     GET  /compliance/cases/{id}/files/{file_id}/content       its bytes: Range, Cache-Control: no-store
#     GET  /compliance/cases/{id}/files/{file_id}/preview-render  Markdown, HTML or code, rendered and sanitised
#     POST /compliance/cases/{id}/vaults/{vault_id}/unlock      {password}: a 15-minute receipt for that vault
#     POST /compliance/cases/{id}/search                        {q, mode?, vault_id?}: file names
#
# The receipts of unlocked vaults come back in X-Case-Unlock ("<vault id>=<receipt>", comma-separated). Every
# refusal is recorded (case_access_refused) and answered with its reason: 404 where the answer would say whether
# something exists that the caller may not see, 403 otherwise, 429 past the view rate.

# Types a browser would run if one were ever opened as a page: their bytes are sent as text.
_ACTIVE_TYPES = ("text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml",
                 "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript")
_CONTENT_CSP = "default-src 'none'; sandbox"


class CaseUnlock(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)


class CaseSearch(BaseModel):
    q: str = Field(..., min_length=1, max_length=255)
    mode: str = Field(default="prefix", max_length=8)
    vault_id: Optional[uuid.UUID] = None


def _read_refused(db, case_id, current_user, refused, *, resource_type=None, resource_id=None):
    """Record a refused read (unless only malformed) and raise its answer."""
    from app.core import case_access
    if refused.record:
        case_access.record_refused(db, case_id, current_user, refused, resource_type=resource_type,
                                   resource_id=resource_id)
    raise HTTPException(status_code=refused.status, detail={"reason": refused.reason, "text": refused.text})


def _reader(case_id, current_user, db, request, x_case_unlock):
    """(case, the vaults its receipts unlock) for a read, after check 1."""
    from app.api.api_server import _current_session_hash
    from app.core import case_access
    case = case_access.case_for(db, case_id, current_user)
    unlocked = case_access.unlocked_vaults(db, case, current_user, _current_session_hash(request),
                                           case_access.parse_unlock_header(x_case_unlock))
    return case, unlocked


@router.get("/compliance/cases/{case_id}/tree")
def case_tree(case_id: uuid.UUID, request: Request, vault_id: Optional[uuid.UUID] = None,
              folder_id: Optional[uuid.UUID] = None, offset: int = Query(0, ge=0, le=10_000_000),
              limit: int = Query(500, ge=1, le=2000), x_case_unlock: Optional[str] = Header(default=None),
              current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The case's vaults, or one folder of one of them (its root without folder_id): folders and files, live and
    kept, with their status; names only where the case may read them. Recorded once per folder in ten minutes."""
    from app.core import case_access
    limit_statements(db)
    try:
        case, unlocked = _reader(case_id, current_user, db, request, x_case_unlock)
        if vault_id is None:
            return case_access.vaults(db, case, current_user, unlocked=unlocked)
        return case_access.tree(db, case, current_user, vault_id, folder_id, unlocked=unlocked, offset=offset,
                                limit=limit)
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="folder" if folder_id else "vault",
                      resource_id=folder_id or vault_id)


@router.get("/compliance/cases/{case_id}/files/{file_id}")
def case_file_info(case_id: uuid.UUID, file_id: uuid.UUID, request: Request,
                   x_case_unlock: Optional[str] = Header(default=None),
                   current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """One file of the case: as a listing shows it, with its folder path. Never its stored checksum."""
    from app.core import case_access
    limit_statements(db)
    try:
        case, unlocked = _reader(case_id, current_user, db, request, x_case_unlock)
        return case_access.file_info(db, case, current_user, file_id, unlocked=unlocked)
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="file", resource_id=file_id)


def _content_type(mime: Optional[str]) -> str:
    from app.api.api_server import _safe_media_type
    safe = _safe_media_type(mime)
    if safe.split(";")[0].strip().lower() in _ACTIVE_TYPES:
        return "text/plain; charset=utf-8"
    return safe


def _inline(name: Optional[str]) -> str:
    from app.api.api_server import _content_disposition
    value = _content_disposition(name or "file")
    return "inline" + value[len("attachment"):] if value.startswith("attachment") else value


def _open(db, case_id, file_id, current_user, request, x_case_unlock, *, preview=False):
    """Checks 1 to 4 and the stored file opened (case_access.open_file), every refusal recorded and answered."""
    from app.api.api_server import _current_session_hash
    from app.core import case_access
    from app.services.vault_service import FileNotFoundError as StoredFileMissing, FileServiceError
    try:
        return case_access.open_file(db, case_id, file_id, current_user,
                                     unlocked_given=case_access.parse_unlock_header(x_case_unlock),
                                     session_hash=_current_session_hash(request), preview=preview)
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="file", resource_id=file_id)
    except StoredFileMissing:
        raise HTTPException(status_code=404, detail={"reason": "content_missing",
                                                     "text": "The stored content of this file is missing."})
    except FileServiceError:
        raise HTTPException(status_code=500, detail={"reason": "content_unreadable",
                                                     "text": "The stored content of this file could not be read."})


_INTEGRITY = {"reason": "integrity", "text": "This file does not match the checksum stored for it."}


@router.get("/compliance/cases/{case_id}/files/{file_id}/content")
def case_file_content(case_id: uuid.UUID, file_id: uuid.UUID, request: Request,
                      x_case_unlock: Optional[str] = Header(default=None),
                      current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A file's bytes, to be shown (never a download of its own: copies leave only through an export). A byte
    range adds no record; the first view of the file in ten minutes is recorded before the first byte."""
    from fastapi.responses import StreamingResponse
    from app.api.api_server import _RANGE_WINDOW
    from app.services.download_stream import UNSATISFIABLE, ChecksumMismatch, parse_byte_range
    limit_statements(db)
    _case, found, download = _open(db, case_id, file_id, current_user, request, x_case_unlock)
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
               "Content-Security-Policy": _CONTENT_CSP,
               "Content-Disposition": _inline(found.item.original_name or found.item.name)}
    media = _content_type(download.mime_type)
    try:
        if download.total_length == 0:
            download.verify_now()
        etag = f'"{download.content_mac}"' if download.content_mac else None
        wanted = None
        if download.read_range is not None:
            headers["Accept-Ranges"] = "bytes"
            if etag:
                headers["ETag"] = etag
            if_range = request.headers.get("if-range")
            if if_range is None or (etag is not None and if_range.strip() == etag):
                wanted = parse_byte_range(request.headers.get("range"), download.total_length)
        if wanted is UNSATISFIABLE:
            raise HTTPException(status_code=416, detail="Requested range not satisfiable",
                                headers={"Content-Range": f"bytes */{download.total_length}"})
        if wanted is not None and wanted.start == 0 and wanted.last == download.total_length - 1:
            wanted = None
    except ChecksumMismatch:
        download.close()
        raise HTTPException(status_code=500, detail=_INTEGRITY)
    except BaseException:
        download.close()
        raise

    if wanted is not None:
        span = wanted

        def ranged():
            try:
                at = span.start
                while at <= span.last:
                    piece = download.read_range(at, min(_RANGE_WINDOW, span.last - at + 1))
                    if not piece:
                        break
                    yield piece
                    at += len(piece)
            finally:
                download.close()
        return StreamingResponse(ranged(), status_code=206, media_type=media,
                                 headers={**headers, "Content-Length": str(span.length),
                                          "Content-Range": span.content_range()})

    def whole():
        try:
            for piece in download.chunks():
                yield piece
        finally:
            download.close()
    return StreamingResponse(whole(), media_type=media,
                             headers={**headers, "Content-Length": str(download.total_length)})


# A rendered preview is for readable text: the same ceiling as the vault's own preview.
PREVIEW_MAX_BYTES = 2 * 1024 * 1024


@router.get("/compliance/cases/{case_id}/files/{file_id}/preview-render")
def case_file_preview(case_id: uuid.UUID, file_id: uuid.UUID, request: Request, kind: Optional[str] = None,
                      x_case_unlock: Optional[str] = Header(default=None),
                      current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Markdown, HTML or source of a file of the case, rendered and sanitised for the sandboxed preview
    (app/core/preview_render.py, as the vault's own preview). Recorded as a view."""
    from fastapi.responses import JSONResponse
    from app.core import case_access
    from app.core.preview_render import render_preview_document
    from app.services.download_stream import ChecksumMismatch
    limit_statements(db)
    try:
        case = case_access.case_for(db, case_id, current_user)
        found = case_access.file_for(db, case, file_id)
        if int(found.item.size_bytes or 0) > PREVIEW_MAX_BYTES:
            raise case_access.Refused(case_access.TOO_LARGE, record=False)
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="file", resource_id=file_id)
    _case, found, download = _open(db, case_id, file_id, current_user, request, x_case_unlock, preview=True)
    try:
        with download:
            content = b"".join(download.chunks())
    except ChecksumMismatch:
        raise HTTPException(status_code=500, detail=_INTEGRITY)
    if kind not in ("markdown", "html", "code", "text", None):
        kind = None
    document, resolved = render_preview_document(content.decode("utf-8", errors="replace"),
                                                 found.item.original_name or found.item.name or "file.txt", kind)
    resp = JSONResponse({"html": document, "kind": resolved})
    resp.headers["Content-Security-Policy"] = _CONTENT_CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.post("/compliance/cases/{case_id}/vaults/{vault_id}/unlock")
def unlock_case_vault(case_id: uuid.UUID, vault_id: uuid.UUID, body: CaseUnlock, request: Request,
                      current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A receipt that opens one password-protected vault of the case for 15 minutes, for this session, case and
    auditor (app/core/vault_unlock_receipts.py). The password is checked once, on the vault-password throttle every
    check of that vault's password by this account counts in (so a new case does not reset it), and never recorded.
    Only where the case opens password vaults with their password."""
    from app.api.api_server import _current_session_hash
    from app.core import case_access
    from app.core import compliance_settings as cs
    from app.core import vault_unlock_receipts as receipts
    from app.core.models import Vault
    limit_statements(db)
    try:
        case = case_access.case_for(db, case_id, current_user)
        row = case_access.covering_rows(db, case).get(vault_id)
        vault = db.get(Vault, vault_id) if row is not None else None
        if vault is None:
            raise case_access.Refused(case_access.NO_SUCH_VAULT)
        if case_access.is_zero_knowledge(vault, row):
            raise case_access.Refused(case_access.ZERO_KNOWLEDGE)
        if not vault.password_hash:
            raise case_access.Refused("no_password", status=400, record=False)
        rule = case_access.policy(case)
        if rule == cs.REFUSE:
            raise case_access.Refused(case_access.PASSWORD_REFUSED)
        if rule == cs.OVERRIDE:
            raise case_access.Refused("opens_without_password", status=400, record=False)
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="vault", resource_id=vault_id)
    session_hash = _current_session_hash(request)
    if not session_hash:
        raise HTTPException(status_code=403, detail="A receipt is given only to a signed-in session.")
    try:
        receipts.check_password(current_user, vault, body.password)
    except receipts.UnlockRefused as refused:
        try:
            case_access.record(db, case, current_user, "case_vault_unlocked", resource_type="vault",
                               resource_id=vault.id, status="failure", details={"vault_id": str(vault.id), "reason": (
                                   "wrong_password" if refused.status == 403 else "throttled")})
        except case_access.Refused:
            pass
        raise HTTPException(status_code=refused.status, detail=refused.detail)
    receipt, expires = receipts.issue(purpose=receipts.PURPOSE_CASE, session_hash=session_hash, case_id=case.id,
                                      vault_id=vault.id, user_id=current_user.id,
                                      credential=receipts.credential_digest(vault.password_hash))
    try:
        case_access.record(db, case, current_user, "case_vault_unlocked", resource_type="vault", resource_id=vault.id,
                           details={"vault_id": str(vault.id), "expires_at": expires.isoformat() + "Z"})
    except case_access.Refused:
        raise HTTPException(status_code=503, detail="The vault was not unlocked: the record could not be written.")
    return {"vault_id": str(vault.id), "receipt": receipt, "expires_at": expires.isoformat() + "Z"}


@router.post("/compliance/cases/{case_id}/search")
def search_case(case_id: uuid.UUID, body: CaseSearch, request: Request,
                x_case_unlock: Optional[str] = Header(default=None),
                current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """File names of the case that are the query, or start with it (``mode`` exact or prefix), ignoring case, at most
    2,000 names read per query. The query travels in the body and is never recorded: the record keeps its length
    and the number of matches."""
    from app.core import case_access
    limit_statements(db)
    try:
        case, unlocked = _reader(case_id, current_user, db, request, x_case_unlock)
        return case_access.search(db, case, current_user, body.q, mode=body.mode, vault_id=body.vault_id,
                                  unlocked=unlocked)
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="case", resource_id=case_id)


# --------------------------------------------------------------------------- exporting from a case
# (app/core/case_export.py)
#
#     POST /compliance/cases/{id}/exports                {file_ids} or {all: true}, with the step-up: an export id
#     GET  /compliance/cases/{id}/exports/{export_id}    the archive, streamed, once, by the auditor who made it


class ExportRequest(BaseModel):
    file_ids: Optional[list[uuid.UUID]] = Field(default=None, max_length=10_000)
    all: bool = False


@router.post("/compliance/cases/{case_id}/exports", status_code=201)
def prepare_case_export(case_id: uuid.UUID, body: ExportRequest, request: Request,
                        x_case_unlock: Optional[str] = Header(default=None),
                        current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Prepare an export of the case's files (or of the ones named), with the compliance step-up: checked as reading
    each one is, before the code is asked for (a refused export costs no code) and again after. Returns the id to
    fetch it with, once."""
    from app.core import case_access
    from app.core import case_export

    def chosen():
        case, unlocked = _reader(case_id, current_user, db, request, x_case_unlock)
        case_export.check(case)
        return case, unlocked, case_export.choose(db, case, file_ids=body.file_ids, every=body.all,
                                                  unlocked=unlocked)

    limit_statements(db)
    try:
        chosen()
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="case", resource_id=case_id)
    db.rollback()
    STEP_UP_CASE_EXPORT(db, current_user, request)
    limit_statements(db)
    try:
        case, unlocked, found = chosen()
        export = case_export.prepare(db, case, current_user, found, unlocked=unlocked)
        db.commit()
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="case", resource_id=case_id)
    return {"export_id": str(export.id), "files": export.file_count, "bytes": export.total_bytes,
            "expires_at": export.expires_at.isoformat() + "Z"}


def _stream_sessions(db: Session):
    """New sessions on the request's database, each with the statement timeout: what an export's stream reads with
    while the request's own session may be gone."""
    from sqlalchemy.orm import sessionmaker
    make = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)

    def session():
        s = make()
        limit_statements(s)
        return s
    return session


@router.get("/compliance/cases/{case_id}/exports/{export_id}")
def fetch_case_export(case_id: uuid.UUID, export_id: uuid.UUID, request: Request,
                      x_case_unlock: Optional[str] = Header(default=None),
                      current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The export's archive, streamed as it is built (ZIP64): once, by the auditor who prepared it, with their own
    session (no link to leak). Each owner is told before the first byte; the end, or a stop before it, is
    recorded."""
    from starlette.concurrency import iterate_in_threadpool
    from app.api.api_server import _current_session_hash
    from app.core import case_access
    from app.core import case_export
    limit_statements(db)
    try:
        case, export, entries = case_export.claim(db, case_id, export_id, current_user,
                                                  unlocked_given=case_access.parse_unlock_header(x_case_unlock),
                                                  session_hash=_current_session_hash(request))
    except case_access.Refused as refused:
        _read_refused(db, case_id, current_user, refused, resource_type="case", resource_id=case_id)
    name = f"case-{case.number or 'export'}-{str(export.id)[:8]}.zip"
    parts = case_export.ExportStream(_stream_sessions(db), case.id, export.id, current_user.id, entries)

    async def body():
        try:
            async for piece in iterate_in_threadpool(parts):
                if piece:
                    yield piece
        finally:
            # A stream stopped by the client, or never started, ends here too: recorded, off the event loop (the
            # response closes this body under a shield: see _ClosingStreamingResponse).
            await anyio.to_thread.run_sync(parts.close)

    return _ClosingStreamingResponse(body(), media_type="application/zip",
                                     headers={"Content-Disposition": f'attachment; filename="{name}"',
                                              "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


class _ClosingStreamingResponse(StreamingResponse):
    """A streamed response that closes its body when it ends, whatever ended it: a client gone leaves the body
    suspended mid-stream (the server stops reading it, sending fails, or the request's task is cancelled), and only
    closing it runs its ``finally`` (for an export: the record of its abort) now rather than when it is collected.
    The close is shielded from a cancellation in progress, which would otherwise stop it at its first await."""

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            closer = getattr(self.body_iterator, "aclose", None)
            if closer is not None:
                with anyio.CancelScope(shield=True):
                    await closer()


# --------------------------------------------------------------------------- revealing a recorded name, outside a case
# (app/core/name_reveal.py)
#
#     POST /activity/events/{event_id}/reveal    {reason_category, reason_text}: the names the event recorded in full


class RevealIn(BaseModel):
    reason_category: str = Field(..., min_length=1, max_length=32)
    # The reason is sealed whole: a longer one is refused (422), never cut short. Room for surrounding spaces,
    # which check_reason strips before it counts.
    reason_text: str = Field(..., min_length=1, max_length=4000)


@router.post("/activity/events/{event_id}/reveal")
def reveal_event_names(event_id: uuid.UUID, body: RevealIn, current_user: User = Depends(require_live_auditor),
                       db: Session = Depends(get_db)):
    """An event's names as the recording levels kept them in full, to an auditor whose right is in force, with a
    reason: never of a vault with a password or a zero-knowledge one, never a fingerprint turned into a value. The
    reveal, its sealed reason and, once a day per auditor and vault, the owner's notice commit before the names are
    sent; a refusal is recorded."""
    from app.core import name_reveal
    limit_statements(db)
    try:
        out = name_reveal.reveal(db, current_user, event_id, reason_category=body.reason_category,
                                 reason_text=body.reason_text)
        db.commit()
    except name_reveal.RevealRefused as refused:
        db.rollback()
        if refused.record:
            name_reveal.record_refused(db, current_user, event_id, refused.reason)
        raise HTTPException(status_code=refused.status, detail={"reason": refused.reason, "text": refused.text})
    return out
