"""The auditor right: who may hold it, who may grant it, and what follows when it is granted or taken back.

The right is a row in ``auditor_grants`` (app/core/models.py, AuditorGrant), held in addition to the account's
role (an ordinary user or an administrator). It is never a role or a permission: authorization never reads
that table. The routes are in app/api/compliance_router.py; the server's operator acts on the host through
app/core/host_compliance.py.

Two people grant it:
  * an administrator proposes it for an account (they may propose themselves);
  * an independent administrator approves it within PROPOSAL_DAYS, or it lapses. Independent is the one rule
    every two-person approval uses (app/core/independence.py, compliance_refusal_reason), with the proposer as
    the one who asked and the auditor as the account it is about, read against the records as they stand and
    against what they were when it was proposed (the proposal's snapshot). The proposer must still be an
    administrator who can act. When nobody independent with an authenticator exists, the server's operator
    approves on the host, and only then.

Who may hold it (checked at the proposal and again at the approval): an active account, not locked by an
administrator, whose role is user or administrator (an administrator only while
COMPLIANCE_AUDITOR_NOT_ADMIN is off), with an active TOTP enrollment (an email code never counts: an
administrator can change the address it goes to), a password the holder set themselves (an administrator
knows the first password of an account they created), and no change to its sign-in details made by someone
else in the last 14 days (no takeover in progress).

The approval binds the grant to the TOTP enrollment active then: the right is in force only while that same
enrollment is. It lasts COMPLIANCE_AUDITOR_GRANT_DAYS from the approval; renewing it is a new grant by two
people. Revoking takes one administrator (it only removes power). Each step writes its audit row in its own
transaction, and a refused step writes ``auditor_grant_refused``. Every administrator and the account are
told of each step, in the app and by email, after the commit (deliver()).
"""
from __future__ import annotations

import uuid
import weakref
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from app.core import after_commit
from app.core import compliance_settings as cs
from app.core import credential_changes as cc
from app.core import independence as ind

# How long a proposal waits for its second administrator.
PROPOSAL_DAYS = 7
PROPOSAL_LAPSES = timedelta(days=PROPOSAL_DAYS)
# No change to the account's sign-in details by someone else within this before a grant.
QUIET = cc.WINDOW
# The roles that may hold the right (the role's value).
ROLES = ("user", "admin")
HOST_OPERATOR = cc.HOST_OPERATOR
NOTICE_TYPE = "auditor_right"
EMAIL_ACTION = "auditor_right"

# Why an account may not be given the right (preconditions), in the order they are checked.
NO_ACCOUNT = "no_account"
INACTIVE = "inactive"
LOCKED = "locked"
ROLE = "role"
ADMIN_NOT_ALLOWED = "admin_not_allowed"
NO_TOTP = "no_totp"
PASSWORD_NOT_OWN = "password_not_own"
RECENT_CHANGE = "recent_change"
OPEN_GRANT = "open_grant"

# Why a step on a grant is refused besides (the independence rule's own reasons are in app/core/independence.py).
NOT_PROPOSED = "not_proposed"
LAPSED = "lapsed"
PROPOSER_GONE = "proposer_gone"
NOT_ABLE = "not_able"

TEXTS = {
    NO_ACCOUNT: "the account no longer exists",
    INACTIVE: "the account is deactivated",
    LOCKED: "the account is locked by an administrator",
    ROLE: "only an ordinary user or an administrator can hold the auditor right",
    ADMIN_NOT_ALLOWED: "this deployment does not let an administrator hold the auditor right "
                       "(COMPLIANCE_AUDITOR_NOT_ADMIN)",
    NO_TOTP: "the account has no authenticator app set up (an email code does not count)",
    PASSWORD_NOT_OWN: "the account's password was set by someone else: its holder must set their own first",
    RECENT_CHANGE: "someone else changed the account's sign-in details in the last 14 days",
    OPEN_GRANT: "the account already holds the auditor right, or a proposal for it is waiting",
    NOT_PROPOSED: "the grant is not waiting for approval",
    LAPSED: f"the proposal was not approved within {PROPOSAL_DAYS} days",
    PROPOSER_GONE: "the administrator who proposed it can no longer act",
    NOT_ABLE: "only an active administrator who is not locked can approve",
    ind.ASKED: "you proposed it",
    ind.OWN_ACCOUNT: "it is your own account",
    ind.MADE_BY_REQUESTER: "the administrator who proposed it made you an administrator",
    ind.MADE_REQUESTER: "you made the administrator who proposed it an administrator",
    ind.CHANGED_ACCOUNT: "you changed the account's sign-in details in the 14 days before the proposal, or since",
    ind.BECAME_ADMIN_AFTER: "you became an administrator after it was proposed",
    ind.NEW_ADMIN: "you had been an administrator for less than 14 days when it was proposed",
    ind.PASSWORD_NOT_OWN: "your own password was set by someone else",
    ind.MADE_BY_SUBJECT: "the account made you an administrator",
    ind.MADE_SUBJECT: "you made the account an administrator",
    ind.CREATED_SUBJECT: "you created the account, so you knew its first password",
    ind.MADE_BY_CREATOR: "whoever created the account made you an administrator",
    ind.MADE_CREATOR: "you made whoever created the account an administrator",
    ind.CHANGED_SUBJECT: "you changed the account's sign-in details while it held the right",
    ind.CONCERNED: "the case concerns you",
    ind.PROPOSED: "you proposed the account's auditor right",
}


def text(reason: Optional[str]) -> str:
    """A reason in plain words."""
    return TEXTS.get(reason, reason or "")


def utcnow() -> datetime:
    """Now as these columns store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


def _role(user) -> Optional[str]:
    role = getattr(user, "role", None)
    return getattr(role, "value", role)


# --------------------------------------------------------------------------- reading

def active_totp(db, user_id):
    """The account's active TOTP enrollment, or None. An email enrollment is not one."""
    from app.core.models import SecondFactorEnrollment
    if user_id is None:
        return None
    return db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.user_id == user_id, SecondFactorEnrollment.status == "active",
        SecondFactorEnrollment.method == "totp").first()


def open_grant(db, user_id, *, lock: bool = False):
    """The account's open grant (proposed, active or suspended), or None. ``lock``: take its row lock."""
    from app.core.models import AUDITOR_GRANT_OPEN, AuditorGrant
    if user_id is None:
        return None
    q = db.query(AuditorGrant).filter(AuditorGrant.user_id == user_id, AuditorGrant.status.in_(AUDITOR_GRANT_OPEN))
    if lock:
        # Locked, and read as it stands now, not as this session last saw it.
        q = q.with_for_update().populate_existing()
    return q.first()


def grant_by_id(db, grant_id, *, lock: bool = False):
    from app.core.models import AuditorGrant
    q = db.query(AuditorGrant).filter(AuditorGrant.id == grant_id)
    if lock:
        q = q.with_for_update().populate_existing()
    return q.first()


def grant_days() -> int:
    return int(cs.current(cs.AUDITOR_GRANT_DAYS))


def admin_not_allowed() -> bool:
    return bool(cs.current(cs.AUDITOR_NOT_ADMIN))


def access_enabled() -> bool:
    return cs.current(cs.ACCESS) != cs.DISABLED


def effective_expiry(grant) -> Optional[datetime]:
    """When the grant ends: the end recorded at its approval, or sooner when COMPLIANCE_AUDITOR_GRANT_DAYS has
    been lowered since (a grant never outlasts the setting in force). None before the approval."""
    if grant.approved_at is None:
        return None
    by_setting = grant.approved_at + timedelta(days=grant_days())
    return min(grant.expires_at, by_setting) if grant.expires_at is not None else by_setting


def lapses_at(grant) -> Optional[datetime]:
    return grant.proposed_at + PROPOSAL_LAPSES if grant.proposed_at is not None else None


def is_lapsed(grant, now: Optional[datetime] = None) -> bool:
    """A proposal nobody approved within PROPOSAL_DAYS."""
    now = now or utcnow()
    return grant.status == "proposed" and grant.proposed_at is not None and now >= lapses_at(grant)


def is_expired(grant, now: Optional[datetime] = None) -> bool:
    now = now or utcnow()
    end = effective_expiry(grant)
    return grant.status in ("active", "suspended") and end is not None and now >= end


# --------------------------------------------------------------------------- who may hold it

def preconditions(db, user, now: Optional[datetime] = None) -> List[str]:
    """Why ``user`` may not be given the auditor right now, in the order checked; [] when they may."""
    from app.core import password_origin
    from app.services.auth_service import admin_locked
    now = now or utcnow()
    if user is None:
        return [NO_ACCOUNT]
    problems = []
    if user.is_active is False:
        problems.append(INACTIVE)
    if admin_locked(user):
        problems.append(LOCKED)
    role = _role(user)
    if role not in ROLES:
        problems.append(ROLE)
    elif role == "admin" and admin_not_allowed():
        problems.append(ADMIN_NOT_ALLOWED)
    if active_totp(db, user.id) is None:
        problems.append(NO_TOTP)
    if password_origin.is_set_by_other(user):
        problems.append(PASSWORD_NOT_OWN)
    if cc.last_applied(db, user.id, now) is not None:
        problems.append(RECENT_CHANGE)
    return problems


# --------------------------------------------------------------------------- who may approve

def proposal_snapshot(db, *, proposer_id, subject_id, at: datetime) -> dict:
    """What the independence rule reads about a proposal, as it stands when it is made (the module docstring): the
    proposer's lineage and the account's recent changers (credential_changes.snapshot), and who created the
    account with that creator's lineage. Deleting the creator clears users.created_by, and demoting them deletes
    their lineage; the rule reads both the records then and these."""
    from app.core import admin_grants
    from app.core.models import User
    kept = cc.snapshot(db, requester_id=proposer_id, target_id=subject_id, requested_at=at)
    subject = db.get(User, subject_id) if subject_id is not None else None
    creator = subject.created_by if subject is not None else None
    record = admin_grants.of(db, [creator]).get(creator) if creator is not None else None
    kept["creator"] = str(creator) if creator is not None else None
    kept["creator_lineage"] = [str(x) for x in ((record.lineage or []) if record is not None else [])]
    return kept


def creator_of(db, user):
    """(who created ``user``'s account, that creator's admin_grants record): the independence rule refuses the
    creator and an administrator in the creator's lineage either way. (None, None) for an account the server's
    operator created, or whose creator was deleted."""
    from app.core import admin_grants
    creator = user.created_by if user is not None else None
    return creator, (admin_grants.of(db, [creator]).get(creator) if creator is not None else None)


def approver_refusal(db, grant, approver, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``approver`` (an account) may not approve ``grant`` as the independent second administrator, or None
    when they may."""
    from app.core import admin_grants, password_origin
    from app.core.models import User
    now = now or utcnow()
    if not cc.can_approve(approver):
        return NOT_ABLE
    proposer = db.get(User, grant.proposed_by) if grant.proposed_by is not None else None
    if proposer is None or not cc.can_approve(proposer):
        return PROPOSER_GONE
    subject = db.get(User, grant.user_id) if grant.user_id is not None else None
    records = admin_grants.of(db, [approver.id, grant.proposed_by, grant.user_id])
    requested_at = grant.proposed_at or now
    changed = cc.changers(db, grant.user_id, min(requested_at, now) - cc.WINDOW) if grant.user_id else set()
    creator, creator_grant = creator_of(db, subject)
    kept = grant.proposal_snapshot or {}
    reason = ind.compliance_refusal_reason(
        approver.id, requester_id=grant.proposed_by, subject_id=grant.user_id,
        approver_grant=records.get(approver.id), requester_grant=records.get(grant.proposed_by),
        subject_grant=records.get(grant.user_id), changed=changed, requested_at=requested_at,
        approver_password_set_by_other=password_origin.is_set_by_other(approver),
        subject_created_by=creator, creator_grant=creator_grant, kept_creator=kept.get("creator"),
        kept_creator_lineage=kept.get("creator_lineage") or [],
        credential_changers=grant.credential_changers or [], proposer_id=grant.proposed_by)
    if reason is not None:
        return reason
    # What was kept when it was proposed: demoting or deleting the proposer since deletes their lineage.
    who = ind._as_text(approver.id)
    if who in {ind._as_text(x) for x in (kept.get("lineage") or [])}:
        return ind.MADE_REQUESTER
    if who in {ind._as_text(x) for x in (kept.get("changed") or [])}:
        return ind.CHANGED_ACCOUNT
    return None


def independent_approvers(db, grant, now: Optional[datetime] = None) -> list:
    """The administrators who could approve ``grant`` now: able to act, independent of it, and with an
    authenticator set up (the approval asks for its code). None of them: the server's operator approves on
    the host."""
    from app.core.models import RoleEnum, User
    now = now or utcnow()
    admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
    return [a for a in admins
            if active_totp(db, a.id) is not None and approver_refusal(db, grant, a, now) is None]


def rejecter_refusal(grant, rejecter) -> Optional[str]:
    """Why ``rejecter`` may not turn ``grant`` down: only an administrator other than its proposer and its
    account may (turning a proposal down gives no power, so the rest of the rule does not apply)."""
    if not cc.can_approve(rejecter):
        return NOT_ABLE
    if rejecter.id == grant.proposed_by:
        return ind.ASKED
    if rejecter.id == grant.user_id:
        return ind.OWN_ACCOUNT
    return None


# --------------------------------------------------------------------------- what an approver sees

def provenance(db, user) -> dict:
    """Where the account came from, for the approver: when and by whom it was created, whether its password
    was set by someone else, its role, its authenticator, when it became an administrator and by whom, and the
    last change someone else made to its sign-in details."""
    from app.core import admin_grants, password_origin
    from app.core.models import User
    if user is None:
        return {}
    names = {}
    for uid in (user.created_by, user.password_set_by):
        if uid is not None and uid not in names:
            names[uid] = db.query(User.username).filter(User.id == uid).scalar()
    totp = active_totp(db, user.id)
    record = admin_grants.of(db, [user.id]).get(user.id)
    last = cc.last_applied(db, user.id)
    return {
        "username": user.username,
        "role": _role(user),
        "active": user.is_active is not False,
        "created_at": _iso(user.created_at),
        # None: not recorded (signed up on their own, made before this was recorded, or its maker was deleted).
        "created_by": names.get(user.created_by) if user.created_by is not None else None,
        "password_set_by_other": password_origin.is_set_by_other(user),
        "password_set_by": names.get(user.password_set_by) if user.password_set_by is not None else (
            HOST_OPERATOR if password_origin.is_set_by_other(user) else None),
        "password_set_at": _iso(user.password_set_by_other_at),
        "authenticator": ({"since": _iso(totp.confirmed_at or totp.created_at), "enrollment_id": str(totp.id)}
                          if totp is not None else None),
        "administrator_since": _iso(record.granted_at) if record is not None else None,
        "made_administrator_by": record.granted_by_name if record is not None else None,
        "last_change_by_someone_else": ({"kind": last.kind, "at": _iso(last.applied_at),
                                         "by": last.requested_by_name} if last is not None else None),
    }


def _changers_view(entries) -> list:
    return [{"name": e.get("name"), "kind": e.get("kind"), "at": e.get("at")}
            for e in (entries or []) if isinstance(e, dict)]


def _open_text(grant, column: str, field: str) -> Optional[str]:
    from app.core.security import is_case_sealed, open_case_field
    value = getattr(grant, column, None)
    if not is_case_sealed(value):
        return None
    try:
        return open_case_field(grant.id, value, field)
    except Exception:  # noqa: BLE001 -- a value that does not open is shown as missing, never as text
        return None


def shown_status(grant, now: Optional[datetime] = None) -> str:
    """The grant's state as it stands now: a proposal past its time reads lapsed, and a grant past its end
    expired, before the periodic job writes it."""
    now = now or utcnow()
    if is_lapsed(grant, now):
        return "lapsed"
    if is_expired(grant, now):
        return "expired"
    return grant.status


def grant_dict(db, grant, *, viewer=None, now: Optional[datetime] = None, detail: bool = False) -> dict:
    """A grant as an administrator sees it. For a proposal, also whether ``viewer`` may approve it and why
    not, and whether only the server's operator can (nobody independent with an authenticator)."""
    from app.core.models import User
    now = now or utcnow()
    holder = db.get(User, grant.user_id) if grant.user_id is not None else None
    status = shown_status(grant, now)
    out = {
        "id": str(grant.id),
        "user_id": str(grant.user_id) if grant.user_id is not None else None,
        "username": holder.username if holder is not None else grant.username_at_grant,
        "username_at_grant": grant.username_at_grant,
        "role": _role(holder) if holder is not None else None,
        "status": status,
        "proposed_by": grant.proposed_by_username,
        "proposed_at": _iso(grant.proposed_at),
        "lapses_at": _iso(lapses_at(grant)) if grant.status == "proposed" else None,
        "approved_by": grant.approved_by_username,
        "approved_by_operator": bool(grant.approved_by_operator),
        "approved_at": _iso(grant.approved_at),
        "expires_at": _iso(effective_expiry(grant)),
        "age_days": (now - grant.approved_at).days if grant.approved_at is not None else None,
        "suspended_at": _iso(grant.suspended_at) if grant.status == "suspended" else None,
        "suspend_reason": grant.suspend_reason,
        "reconfirmed_at": _iso(grant.reconfirmed_at),
        "rejected_by": grant.rejected_by_username,
        "revoked_by": grant.revoked_by_username,
        "ended_at": _iso(grant.ended_at),
        "credential_changers": _changers_view(grant.credential_changers),
        "note": _open_text(grant, "note_enc", "grant_note"),
    }
    if detail:
        out["reject_reason"] = _open_text(grant, "reject_reason_enc", "grant_reject_reason")
        out["revoke_reason"] = _open_text(grant, "revoke_reason_enc", "revoke_reason")
    if grant.status == "proposed" and status == "proposed":
        out["provenance"] = provenance(db, holder)
        out["problems"] = [{"reason": p, "text": text(p)} for p in preconditions(db, holder, now)]
        if viewer is not None:
            why = approver_refusal(db, grant, viewer, now)
            out["you_may_approve"] = why is None
            out["why_not"] = {"reason": why, "text": text(why)} if why is not None else None
            out["you_may_reject"] = rejecter_refusal(grant, viewer) is None
        out["host_approval"] = not independent_approvers(db, grant, now)
    return out


# --------------------------------------------------------------------------- the steps

def _audit(db, action: str, grant, *, actor=None, username=None, details: Optional[dict] = None, status="success"):
    """The step's audit row, in the caller's transaction."""
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(
        action=action, status=status, user=actor, username=None if actor is not None else username,
        resource_type="user", resource_id=str(grant.user_id) if grant.user_id is not None else None,
        details={"grant_id": str(grant.id), "target_username": grant.username_at_grant, **(details or {})}))


def record_refusal(db, *, actor, step: str, reason: str, user=None, grant=None, reasons=None) -> None:
    """Record a refused step (``auditor_grant_refused``) on its own: the caller's work is rolled back first, so
    nothing it changed is kept. Never raises: the refusal stands without its row."""
    from app.services.audit_logger import AuditLogger
    target_id = getattr(grant, "user_id", None) or getattr(user, "id", None)
    target_name = getattr(grant, "username_at_grant", None) or getattr(user, "username", None)
    actor_id = getattr(actor, "id", None)
    try:
        db.rollback()
        details = {"action": step, "reason": reason, "target_username": target_name}
        if grant is not None:
            details["grant_id"] = str(grant.id)
        if reasons:
            details["reasons"] = list(reasons)
        db.add(AuditLogger(db).build_row(
            action="auditor_grant_refused", status="failure", user=actor if actor_id is not None else None,
            username=None if actor_id is not None else HOST_OPERATOR, resource_type="user",
            resource_id=str(target_id) if target_id is not None else None, details=details))
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


def propose(db, user, *, proposer, note: Optional[str] = None, now: Optional[datetime] = None):
    """Propose the auditor right for ``user``, by the administrator ``proposer``, in the caller's transaction.
    The caller has checked the preconditions; the one-open-grant index refuses a second open grant."""
    from app.core.models import AuditorGrant
    from app.core.security import seal_case_field
    now = now or utcnow()
    grant = AuditorGrant(id=uuid.uuid4(), user_id=user.id, username_at_grant=user.username, status="proposed",
                         proposed_by=proposer.id, proposed_by_username=proposer.username, proposed_at=now,
                         credential_changers=[],
                         proposal_snapshot=proposal_snapshot(db, proposer_id=proposer.id, subject_id=user.id, at=now))
    if note:
        grant.note_enc = seal_case_field(grant.id, note, "grant_note")
    db.add(grant)
    db.flush()
    _audit(db, "auditor_grant_proposed", grant, actor=proposer, details={"role": _role(user)})
    queue(db, {"event": "proposed", "grant_id": str(grant.id), "holder_id": str(user.id), "holder": user.username,
               "by": proposer.username, "lapses_at": _iso(lapses_at(grant))})
    return grant


def approve(db, grant, *, approver=None, now: Optional[datetime] = None):
    """Approve ``grant`` (locked by the caller, checked by the caller), by ``approver`` or, with None, the
    server's operator on the host: bind it to the account's TOTP enrollment active now, and start its time."""
    from app.core.models import User
    now = now or utcnow()
    holder = db.get(User, grant.user_id)
    totp = active_totp(db, grant.user_id)
    grant.status = "active"
    grant.second_factor_enrollment_id = totp.id
    grant.confirmed_role = _role(holder)
    grant.approved_at = now
    grant.expires_at = now + timedelta(days=grant_days())
    if approver is not None:
        grant.approved_by, grant.approved_by_username, grant.approved_by_operator = approver.id, approver.username, False
    else:
        grant.approved_by, grant.approved_by_username, grant.approved_by_operator = None, HOST_OPERATOR, True
    grant.updated_at = now
    details = {"proposed_by": grant.proposed_by_username, "expires_at": _iso(grant.expires_at)}
    if approver is None:
        details["by"] = "host operator"
    _audit(db, "auditor_granted", grant, actor=approver, username=HOST_OPERATOR, details=details)
    queue(db, {"event": "granted", "grant_id": str(grant.id), "holder_id": str(grant.user_id),
               "holder": holder.username, "by": grant.approved_by_username, "proposed_by": grant.proposed_by_username,
               "expires_at": _iso(grant.expires_at)})
    return grant


def reject(db, grant, *, rejecter, reason: str, now: Optional[datetime] = None):
    """Turn the proposal ``grant`` down (locked and checked by the caller)."""
    from app.core.security import seal_case_field
    now = now or utcnow()
    grant.status = "rejected"
    grant.rejected_by, grant.rejected_by_username, grant.rejected_at = rejecter.id, rejecter.username, now
    grant.reject_reason_enc = seal_case_field(grant.id, reason, "grant_reject_reason")
    grant.ended_at = grant.updated_at = now
    _audit(db, "auditor_grant_rejected", grant, actor=rejecter, details={"proposed_by": grant.proposed_by_username})
    queue(db, {"event": "rejected", "grant_id": str(grant.id), "holder_id": str(grant.user_id),
               "holder": grant.username_at_grant, "by": rejecter.username, "proposed_by": grant.proposed_by_username})
    return grant


def revoke(db, grant, *, actor=None, reason: Optional[str] = None, because: Optional[str] = None,
           now: Optional[datetime] = None):
    """Take back the open ``grant`` (a proposal too), by ``actor`` or, with None, the server's operator.
    ``because``: the proposal is withdrawn because its proposer lost their standing (demoted, deactivated,
    locked or deleted)."""
    from app.core.security import seal_case_field
    now = now or utcnow()
    before = grant.status
    grant.status = "revoked"
    grant.revoked_at = grant.ended_at = grant.updated_at = now
    grant.revoked_by = actor.id if actor is not None else None
    grant.revoked_by_username = actor.username if actor is not None else HOST_OPERATOR
    if reason:
        grant.revoke_reason_enc = seal_case_field(grant.id, reason, "revoke_reason")
    details = {"status": before}
    if because:
        details["withdrawn_because"] = because
    if actor is None:
        details["by"] = "host operator"
    _audit(db, "auditor_revoked", grant, actor=actor, username=HOST_OPERATOR, details=details)
    queue(db, {"event": "revoked", "grant_id": str(grant.id), "holder_id": str(grant.user_id) if grant.user_id else None,
               "holder": grant.username_at_grant, "by": grant.revoked_by_username, "was": before,
               "because": because})
    return grant


def end_due(db, now: Optional[datetime] = None) -> int:
    """Write what time did: proposals past PROPOSAL_DAYS lapse, grants past their end expire, each with its
    audit row (written by the server, with no person acting). In the caller's transaction; returns how many."""
    from app.core.models import AuditorGrant
    now = now or utcnow()
    count = 0
    rows = (db.query(AuditorGrant).filter(AuditorGrant.status.in_(("proposed", "active", "suspended")))
            .with_for_update(skip_locked=True).all())
    for grant in rows:
        if is_lapsed(grant, now):
            grant.status, grant.ended_at, grant.updated_at = "lapsed", now, now
            _audit(db, "auditor_grant_lapsed", grant, details={"proposed_by": grant.proposed_by_username})
            queue(db, {"event": "lapsed", "grant_id": str(grant.id),
                       "holder_id": str(grant.user_id) if grant.user_id else None, "holder": grant.username_at_grant,
                       "proposed_by": grant.proposed_by_username})
            count += 1
        elif is_expired(grant, now):
            before = grant.status
            grant.status, grant.ended_at, grant.updated_at = "expired", now, now
            _audit(db, "auditor_grant_expired", grant, details={"status": before,
                                                                "expires_at": _iso(effective_expiry(grant))})
            queue(db, {"event": "expired", "grant_id": str(grant.id),
                       "holder_id": str(grant.user_id) if grant.user_id else None, "holder": grant.username_at_grant})
            count += 1
    return count


# --------------------------------------------------------------------------- whether it is in force now

# Why the right is not in force for an account now (auditor_live()), besides the preconditions' INACTIVE,
# LOCKED, ROLE, ADMIN_NOT_ALLOWED and PASSWORD_NOT_OWN.
TEMPORARY = "temporary"
NO_GRANT = "no_grant"
NOT_APPROVED = "not_approved"
SUSPENDED = "suspended"
EXPIRED = "expired"
DISABLED = "compliance_disabled"
DEMOTED = "demoted"
SECOND_FACTOR = "second_factor"
CREDENTIAL_CHANGE = "credential_change"
SSH_KEY = "ssh_key"
NOT_SUSPENDED = "not_suspended"
# Why a grant ended for good: the second factor it is bound to was reset or removed, or the account deleted.
FACTOR_RESET = "second_factor_reset"
FACTOR_REMOVED = "second_factor_removed"
DELETED = "deleted"
ENDS = (FACTOR_RESET, FACTOR_REMOVED, SECOND_FACTOR, DELETED)

TEXTS.update({
    TEMPORARY: "a temporary credential holds no auditor right",
    NO_GRANT: "the account holds no auditor right",
    NOT_APPROVED: "the auditor right is waiting for its approval",
    SUSPENDED: "the auditor right is suspended until its holder reconfirms it",
    EXPIRED: "the auditor right reached its end",
    DISABLED: "compliance access is turned off on this deployment (COMPLIANCE_ACCESS=disabled)",
    DEMOTED: "the account is no longer an administrator, as it was when the right was confirmed",
    SECOND_FACTOR: "the authenticator the right is bound to is no longer the account's: only a new grant gives it",
    CREDENTIAL_CHANGE: "someone else changed the account's sign-in details since the right was confirmed",
    SSH_KEY: "someone else added an SSH key to the account since the right was confirmed",
    NOT_SUSPENDED: "the auditor right is not suspended",
    FACTOR_RESET: "an administrator reset the authenticator the right is bound to",
    FACTOR_REMOVED: "the holder removed the authenticator the right is bound to",
    DELETED: "the account was deleted",
    cc.PASSWORD: "someone else set the account's password",
    cc.RESET_LINK: "someone else made a password reset link for the account",
    cc.EMAIL: "someone else changed the account's email address",
    cc.SSH_KEY: "someone else added an SSH key to the account",
    "deactivated": "the account was deactivated",
    "demoted": "the account was demoted from administrator",
    "locked": "the account was locked by an administrator",
})


@dataclass(frozen=True)
class Standing:
    """Whether an account's auditor right is in force now, and if not, why (a reason of TEXTS)."""
    live: bool
    reason: Optional[str] = None
    grant: object = None


def confirmed_at(grant) -> Optional[datetime]:
    """When the right was last confirmed: its approval, or its holder's last reconfirmation."""
    times = [t for t in (grant.approved_at, grant.reconfirmed_at) if t is not None]
    return max(times) if times else None


def _changed_since(db, user, since: Optional[datetime]) -> Optional[str]:
    """CREDENTIAL_CHANGE when someone else's change to the account's sign-in details was applied after
    ``since`` (the records of the 14 days after a change), SSH_KEY when someone else added an SSH key to it
    after ``since`` (kept as long as the key), else None."""
    from sqlalchemy import or_
    from app.core.models import CredentialChange, UserSSHKey
    if since is None:
        return None
    if db.query(CredentialChange.id).filter(
            CredentialChange.target_user_id == user.id, CredentialChange.status.in_(cc.APPLIED),
            CredentialChange.applied_at.isnot(None), CredentialChange.applied_at > since).first() is not None:
        return CREDENTIAL_CHANGE
    if db.query(UserSSHKey.id).filter(
            UserSSHKey.user_id == user.id, UserSSHKey.created_at > since,
            or_(UserSSHKey.created_by.is_(None), UserSSHKey.created_by != user.id)).first() is not None:
        return SSH_KEY
    return None


def standing_problem(db, user, grant, *, reconfirming: bool = False) -> Optional[str]:
    """Why ``user``'s account no longer stands as ``grant`` requires, or None. Read from the account and its
    records on every call, so a hook that missed a change still refuses. ``reconfirming``: what a holder's
    reconfirmation may not fix (a demotion and a change by someone else are what it confirms afresh)."""
    from app.core import password_origin
    from app.services.auth_service import admin_locked
    if user.is_active is False:
        return INACTIVE
    if admin_locked(user):
        return LOCKED
    role = _role(user)
    if role not in ROLES:
        return ROLE
    if role == "admin" and admin_not_allowed():
        return ADMIN_NOT_ALLOWED
    if not reconfirming and grant.confirmed_role == "admin" and role != "admin":
        return DEMOTED
    totp = active_totp(db, user.id)
    if totp is None or grant.second_factor_enrollment_id is None or totp.id != grant.second_factor_enrollment_id:
        return SECOND_FACTOR
    if password_origin.is_set_by_other(user):
        return PASSWORD_NOT_OWN
    if not reconfirming:
        return _changed_since(db, user, confirmed_at(grant))
    return None


def auditor_live(db, user, now: Optional[datetime] = None) -> Standing:
    """Whether ``user`` holds the auditor right in force now, computed from the grant, the deployment's
    settings and the account as they stand: an approved grant, not suspended, before its end, compliance
    access on, and the account as it was when the right was confirmed (active, not locked by an administrator,
    an allowed role and not demoted, the same authenticator, its own password, no change to its sign-in details
    by someone else since). Every compliance request asks this; nothing is cached."""
    now = now or utcnow()
    if user is None or getattr(user, "_is_temp_session", False):
        return Standing(False, TEMPORARY)
    grant = open_grant(db, user.id)
    if grant is None:
        return Standing(False, NO_GRANT)
    if grant.status == "proposed":
        return Standing(False, NOT_APPROVED, grant)
    if grant.status == "suspended":
        return Standing(False, SUSPENDED, grant)
    if is_expired(grant, now):
        return Standing(False, EXPIRED, grant)
    if not access_enabled():
        return Standing(False, DISABLED, grant)
    problem = standing_problem(db, user, grant)
    if problem is not None:
        return Standing(False, problem, grant)
    return Standing(True, None, grant)


# --------------------------------------------------------------------------- suspending, ending, reconfirming

def suspend(db, grant, reason: str, *, by_id=None, by_name: Optional[str] = None, now: Optional[datetime] = None):
    """Suspend the grant in force (``reason``: what happened to the account), in the caller's transaction, with
    its audit row; the holder and every administrator are told after the commit. A grant already suspended
    keeps its first suspension and records the new reason. ``by_*``: who made the change that caused it (None
    and None: the server, on its own)."""
    if grant.status not in ("active", "suspended"):
        return grant
    now = now or utcnow()
    if grant.status == "active":
        grant.status, grant.suspended_at = "suspended", now
    grant.suspend_reason, grant.updated_at = reason, now
    _audit_by(db, "auditor_suspended", grant, by_id, by_name, {"reason": reason, "outcome": "suspended"})
    queue(db, {"event": "suspended", "grant_id": str(grant.id), "holder_id": _id_text(grant.user_id),
               "holder": grant.username_at_grant, "by": by_name, "why": text(reason),
               "next": RECONFIRM_PASSWORD if reason in (PASSWORD_NOT_OWN, cc.PASSWORD) else RECONFIRM_HOW})
    return grant


def end(db, grant, reason: str, *, by_id=None, by_name: Optional[str] = None, now: Optional[datetime] = None):
    """End the open grant for good (``reason`` in ENDS): only a new grant, by two people, gives the right again.
    In the caller's transaction, with its audit row; told after the commit."""
    from app.core.models import AUDITOR_GRANT_OPEN
    if grant.status not in AUDITOR_GRANT_OPEN:
        return grant
    now = now or utcnow()
    before = grant.status
    grant.status, grant.suspend_reason = "ended", reason
    grant.ended_at = grant.updated_at = now
    _audit_by(db, "auditor_suspended", grant, by_id, by_name, {"reason": reason, "outcome": "ended", "status": before})
    queue(db, {"event": "ended", "grant_id": str(grant.id), "holder_id": _id_text(grant.user_id),
               "holder": grant.username_at_grant, "by": by_name, "why": text(reason)})
    return grant


RECONFIRM_HOW = ("Its holder reconfirms it on the Compliance page with their password and their authenticator "
                 "code.")
RECONFIRM_PASSWORD = ("Its holder first sets a password of their own, then reconfirms it on the Compliance page "
                      "with that password and their authenticator code.")


def _id_text(value) -> Optional[str]:
    return str(value) if value is not None else None


def _audit_by(db, action, grant, by_id, by_name, details):
    """The audit row of a change to a grant that another change caused, by whoever made that one."""
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(
        action=action, status="success", user_id=by_id, username=by_name, resource_type="user",
        resource_id=_id_text(grant.user_id),
        details={"grant_id": str(grant.id), "target_username": grant.username_at_grant, **details}))


def reconfirm_problem(db, grant, holder, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``holder`` may not reconfirm ``grant`` now, or None. Only a suspended grant before its end, whose
    account stands again as the grant requires, with the authenticator it is bound to; the step itself asks
    for the password and a code from that authenticator."""
    now = now or utcnow()
    if grant.status != "suspended":
        return NOT_SUSPENDED
    if is_expired(grant, now):
        return EXPIRED
    return standing_problem(db, holder, grant, reconfirming=True)


def reconfirm(db, grant, holder, now: Optional[datetime] = None):
    """The holder confirms the right again (checked by the caller), in the caller's transaction."""
    now = now or utcnow()
    before = grant.suspend_reason
    grant.status, grant.reconfirmed_at, grant.updated_at = "active", now, now
    grant.suspended_at, grant.suspend_reason = None, None
    grant.confirmed_role = _role(holder)
    _audit(db, "auditor_reconfirmed", grant, actor=holder, details={"reason": before})
    queue(db, {"event": "reconfirmed", "grant_id": str(grant.id), "holder_id": str(holder.id),
               "holder": holder.username, "by": holder.username})
    return grant


# --------------------------------------------------------------------------- what follows from a change

_TABLE = "auditor_grants"
_HAS_TABLE = weakref.WeakSet()


def _has_grants(db) -> bool:
    """Whether the database has the grants table (a database built only with the tables a test needs may not,
    and a stand-in for a session has no database at all; neither holds a grant). Remembered for the engine once
    found."""
    get_bind = getattr(db, "get_bind", None)
    if get_bind is None:
        return False
    bind = get_bind()
    engine = getattr(bind, "engine", bind)
    if engine in _HAS_TABLE:
        return True
    from sqlalchemy import inspect
    if inspect(bind).has_table(_TABLE):
        _HAS_TABLE.add(engine)
        return True
    return False


def after_credential_change(db, target, kind: str, *, actor_id, actor_name: str, someone_else: bool,
                            approved: bool = False, approver_id=None) -> None:
    """A change to ``target``'s sign-in details was just applied, in the caller's transaction (``kind`` is a
    credential change's kind; ``someone_else`` False when the account changed its own through an
    administrator's route; ``approved``: a held change ``approver_id`` approved, None for the server's
    operator). Whoever made it (the one who asked, and the approver) joins the open grant's list of changers,
    which the independence rule reads for as long as the grant stands. A second-factor reset ends the grant;
    any other change by someone else suspends it."""
    if not _has_grants(db):
        return
    grant = open_grant(db, target.id, lock=True)
    if grant is None:
        return
    now = utcnow()
    if someone_else:
        joined = list(grant.credential_changers or [])
        joined.append({"id": _id_text(actor_id), "name": actor_name, "kind": kind, "at": _iso(now)})
        if approved:
            from app.core.models import User
            name = (db.query(User.username).filter(User.id == approver_id).scalar() if approver_id is not None
                    else HOST_OPERATOR)
            joined.append({"id": _id_text(approver_id), "name": name, "kind": kind, "at": _iso(now)})
        grant.credential_changers = joined
    if grant.status == "proposed":
        return          # its approval checks the account again
    if kind == cc.SECOND_FACTOR:
        end(db, grant, FACTOR_RESET if someone_else else FACTOR_REMOVED, by_id=actor_id, by_name=actor_name, now=now)
    elif someone_else:
        suspend(db, grant, kind, by_id=actor_id, by_name=actor_name, now=now)


def after_lost_standing(db, user, *, actor, because: str) -> None:
    """``user`` is about to be demoted, deactivated, locked by an administrator or deleted (``because``), by
    ``actor`` (None: the server's operator), in the caller's transaction. Their right in force is suspended
    (ended, when the account is deleted), and the proposals they made are withdrawn: a proposal whose proposer
    can no longer act is never approved."""
    from app.core.models import AuditorGrant
    if not _has_grants(db) or user is None or user.id is None:
        return
    by_id = actor.id if actor is not None else None
    by_name = actor.username if actor is not None else HOST_OPERATOR
    for proposal in (db.query(AuditorGrant).filter(AuditorGrant.proposed_by == user.id,
                                                   AuditorGrant.status == "proposed").with_for_update().all()):
        revoke(db, proposal, actor=actor, because=because)
    grant = open_grant(db, user.id, lock=True)
    if grant is None:
        return
    if because == DELETED:
        end(db, grant, DELETED, by_id=by_id, by_name=by_name)
    else:
        suspend(db, grant, because, by_id=by_id, by_name=by_name)


def after_own_factor_removed(db, user) -> None:
    """The holder removed their own second factor, in the caller's transaction: the grant bound to it ends."""
    if not _has_grants(db):
        return
    grant = open_grant(db, user.id, lock=True)
    if grant is not None and grant.status != "proposed":
        end(db, grant, FACTOR_REMOVED, by_id=user.id, by_name=user.username)


def promotion_refusal(db, user) -> Optional[str]:
    """Why ``user`` may not be made an administrator now, or None: while COMPLIANCE_AUDITOR_NOT_ADMIN is on, an
    account with an open grant (or a proposal) is not promoted until the right is revoked."""
    if not admin_not_allowed() or user is None or user.id is None or not _has_grants(db):
        return None
    if open_grant(db, user.id) is None:
        return None
    return (f"{user.username} holds the auditor right, or a proposal for it is waiting, and this deployment does "
            "not let an administrator hold it (COMPLIANCE_AUDITOR_NOT_ADMIN). Revoke the right first.")


def settle(db, now: Optional[datetime] = None) -> int:
    """What the periodic job writes: end_due(), then what the hooks may have missed. A grant in force whose
    account no longer stands as it requires is suspended (ended, when its authenticator is not the one it is
    bound to, or the account is gone); a suspended grant whose account is gone, or whose authenticator is
    gone, ends. Compliance access turned off is never written: it is computed on each request. In the
    caller's transaction; returns how many grants changed."""
    from app.core.models import AuditorGrant, User
    now = now or utcnow()
    count = end_due(db, now)
    db.flush()
    for grant in (db.query(AuditorGrant).filter(AuditorGrant.status.in_(("active", "suspended")))
                  .with_for_update(skip_locked=True).all()):
        user = db.get(User, grant.user_id) if grant.user_id is not None else None
        if user is None:
            end(db, grant, DELETED, now=now)
            count += 1
            continue
        problem = standing_problem(db, user, grant)
        if problem == SECOND_FACTOR:
            end(db, grant, SECOND_FACTOR, now=now)
            count += 1
        elif problem is not None and grant.status == "active":
            suspend(db, grant, problem, now=now)
            count += 1
    return count


# --------------------------------------------------------------------------- telling people

# What is told after a commit goes through the one after-commit dispatcher (app/core/after_commit.py), never
# through a listener of this module's own: a listener added while a commit runs its listeners breaks that commit.
_NOTICES = "auditor_right_notices"


def queue(db, notice: dict) -> None:
    """Tell of ``notice`` once the caller's transaction commits (deliver()); nothing when it rolls back."""
    after_commit.later(db, _NOTICES, notice)


def _deliver_notices(notices) -> None:
    try:
        deliver(notices)
    except Exception as exc:  # noqa: BLE001 -- a notice never undoes the change
        print(f"Warning: an auditor right notice was not sent ({type(exc).__name__})")


after_commit.handler(_NOTICES, _deliver_notices)


def _who(name: Optional[str]) -> str:
    return "the server's operator, on the host" if name == HOST_OPERATOR else (name or "an administrator")


def notice_text(notice: dict) -> tuple:
    """(title, body) of a notice, in plain words. Never a vault, file or folder name: it is about an account."""
    event, holder, by = notice.get("event"), notice.get("holder") or "an account", _who(notice.get("by"))
    if event == "proposed":
        return ("Auditor right proposed",
                f"{by} proposed the auditor right for {holder}. An independent administrator can approve it until "
                f"{(notice.get('lapses_at') or '')[:10]}; after that it lapses.")
    if event == "granted":
        return ("Auditor right granted",
                f"{holder} now holds the auditor right, proposed by {_who(notice.get('proposed_by'))} and approved "
                f"by {by}, until {(notice.get('expires_at') or '')[:10]}. An auditor can review the activity log and "
                "open vaults in a case another administrator approves; the owners of those vaults are told who "
                "opened them.")
    if event == "rejected":
        return ("Auditor right turned down",
                f"{by} turned down the auditor right proposed for {holder} by {_who(notice.get('proposed_by'))}.")
    if event == "revoked":
        if notice.get("because"):
            return ("Auditor right proposal withdrawn",
                    f"The proposal of the auditor right for {holder} was withdrawn: the administrator who proposed it "
                    f"was {notice.get('because')}.")
        return ("Auditor right revoked", f"{by} revoked the auditor right of {holder}.")
    if event == "lapsed":
        return ("Auditor right proposal lapsed",
                f"Nobody approved the auditor right proposed for {holder} within {PROPOSAL_DAYS} days, so it lapsed.")
    if event == "expired":
        return ("Auditor right expired",
                f"The auditor right of {holder} reached its end. Renewing it takes a new proposal and approval.")
    if event == "suspended":
        return ("Auditor right suspended",
                f"The auditor right of {holder} is suspended: {notice.get('why') or 'its account changed'}. "
                + notice.get("next", ""))
    if event == "ended":
        return ("Auditor right ended",
                f"The auditor right of {holder} ended: {notice.get('why') or 'its account changed'}. Only a new "
                "proposal and approval, by two people, gives it again.")
    if event == "reconfirmed":
        return ("Auditor right reconfirmed",
                f"{holder} reconfirmed their auditor right with their password and their authenticator.")
    return ("Auditor right", f"The auditor right of {holder} changed.")


def deliver(notices: Iterable[dict]) -> None:
    """Tell every active administrator and the account of each notice, in the app and by email. After the
    commit, best-effort: a notice never undoes the change."""
    from app.api import api_server as api
    from app.core.database import get_db_context
    from app.core.models import RoleEnum, User
    with get_db_context() as db:
        admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
        for notice in notices:
            title, body = notice_text(notice)
            people = {str(a.id): a for a in admins}
            holder_id = notice.get("holder_id")
            if holder_id:
                holder = db.query(User).filter(User.id == uuid.UUID(str(holder_id))).first()
                if holder is not None:
                    people.setdefault(str(holder.id), holder)
            api._notify_users(list(people), NOTICE_TYPE, title=title, body=body, target="#compliance")
            api._fire_action_email_bulk(db, EMAIL_ACTION, [(p.email, p.username) for p in people.values()],
                                        {"change": body, "by": _who(notice.get("by")),
                                         "when": api._change_time_text()})
