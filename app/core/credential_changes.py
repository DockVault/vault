"""Changes an administrator makes to someone else's sign-in credentials, and the rule on them.

These changes count, each as one change:
  * a password set by the administrator;
  * a password reset link, copied or emailed;
  * a second-factor reset;
  * an email address change;
  * an SSH key added to the account.

One such change may be made to an account within 14 days. A second change in that window, by the same
administrator or any other, is not made: it is held as a request that a DIFFERENT administrator must
approve, and it expires after 7 days. With no other administrator who could approve it, the second
change is refused, and the person who runs the server can make it on the host (``dockvault.py
accounts``), where it is recorded as the host operator's.

A different administrator means one independent of the change (refusal_reason, with the records in
app/core/admin_grants.py). The approver:
  1. is not the administrator who asked;
  2. made no credential change to that account (asked for one that was made, or approved one) in the
     14 days before the request, or since. Otherwise the administrator who made the first change could
     approve the second through someone else's request: make an administrator account, ask as it, and
     approve as themselves;
  3. is not in the lineage of the one who asked, and the one who asked is not in theirs: neither made
     the other an administrator, directly or through administrators they made;
  4. had been an administrator for at least 14 days when the request was made. An administrator from
     before these records existed, and the first one the server set up, count as long-standing. This
     closes what the lineage alone cannot: two accounts one administrator made for the purpose (neither
     in the other's lineage), and an administrator whose maker was demoted or deleted.

The residual, accepted: someone who creates several administrator accounts and waits 14 days can then
approve their own changes through them. Every step of that is visible: every administrator is told when
an administrator is created or promoted, and the user is told of every change to their sign-in
details, held or made. A stricter rule (no maker in common) would leave a deployment whose first
administrator made all the others with no approver but the host tool.

Why: taking over an account takes two credential changes (move its email, then reset its password;
reset its password, then its second factor). One administrator acting alone, or one whose session was
stolen, can no longer make both. A lock is deliberately not part of it: the account keeps working while
a request waits, because a hostile administrator could otherwise lock anyone out by asking.

A person changing their own credentials is not affected, and nothing here is consulted for it.

This module holds the rule and the records. It never commits: each caller adds what it builds to its
own transaction, so a change and its record land together or not at all. The routes that apply a
change (and the approval that applies a held one) live in app/api/api_server.py and call
:func:`decide` first.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Set

from app.core.models import CredentialChange, RoleEnum, User

WINDOW = timedelta(days=14)
HOLD = timedelta(days=7)
# How long an approver must have been an administrator before the request was made.
TENURE = timedelta(days=14)

# The name the records, the audit log and the notifications use for whoever runs the server, acting
# through `dockvault.py accounts`. A username may not contain '@', so no account can carry it.
HOST_OPERATOR = "operator@host"

PASSWORD = "password"
RESET_LINK = "reset_link"
SECOND_FACTOR = "second_factor"
EMAIL = "email"
SSH_KEY = "ssh_key"

# What each kind is called in a list, and the verb phrase a sentence uses ("alice asked to ...").
KIND_LABELS = {
    PASSWORD: "New password",
    RESET_LINK: "Password reset link",
    SECOND_FACTOR: "Second factor reset",
    EMAIL: "Email address change",
    SSH_KEY: "SSH key added",
}
KIND_PHRASES = {
    PASSWORD: "set a new password",
    RESET_LINK: "create a password reset link",
    SECOND_FACTOR: "reset the second factor",
    EMAIL: "change the email address",
    SSH_KEY: "add an SSH key",
}

MADE = "made"            # applied at once: the first change in the window
HELD = "held"            # waiting for another administrator
APPROVED = "approved"    # held, then approved and applied
DENIED = "denied"        # held, then turned down by another administrator
WITHDRAWN = "withdrawn"  # held, then taken back by the administrator who asked
EXPIRED = "expired"      # held, and nobody decided within HOLD
APPLIED = (MADE, APPROVED)


class NoApprover(Exception):
    """A second change in the window, and no administrator other than the one asking could approve
    it. Carries the change that opened the window, and why each other administrator who can sign in
    may not approve: ``refusals`` is [(username, reason)], empty when there is no such administrator."""

    def __init__(self, last_change: CredentialChange, refusals=None):
        super().__init__("no other administrator can approve")
        self.last_change = last_change
        self.refusals = list(refusals or [])


def utcnow() -> datetime:
    """Now as these columns store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def label(kind: str) -> str:
    return KIND_LABELS.get(kind, kind)


def phrase(kind: str) -> str:
    return KIND_PHRASES.get(kind, "change sign-in details")


def request_label(kind: str) -> str:
    """What a request waiting for approval asks for, as a heading: "Add an SSH key". A change that
    was made is named by label() instead ("SSH key added")."""
    text = phrase(kind)
    return text[:1].upper() + text[1:]


def last_applied(db, target_id, now: Optional[datetime] = None) -> Optional[CredentialChange]:
    """The newest change applied to this account within the window, or None."""
    now = now or utcnow()
    return (db.query(CredentialChange)
            .filter(CredentialChange.target_user_id == target_id,
                    CredentialChange.status.in_(APPLIED),
                    CredentialChange.applied_at.isnot(None),
                    CredentialChange.applied_at > now - WINDOW)
            .order_by(CredentialChange.applied_at.desc())
            .first())


def email_changes_in_window(db, target_id, now: Optional[datetime] = None) -> List[CredentialChange]:
    """The email address changes an administrator (or the host operator) applied to this account within
    the window, oldest first. Their ``payload`` keeps the address before and after (see
    applied_email_payload), which a self-service reset link reads: within the window it goes to the
    address the account had before (app/api/api_server.py, _self_service_reset_destination)."""
    now = now or utcnow()
    return (db.query(CredentialChange)
            .filter(CredentialChange.target_user_id == target_id,
                    CredentialChange.kind == EMAIL,
                    CredentialChange.status.in_(APPLIED),
                    CredentialChange.applied_at > now - WINDOW)
            .order_by(CredentialChange.applied_at.asc())
            .all())


def applied_email_payload(result: dict) -> dict:
    """What an applied email change keeps, from what applying it returned: the address before and the
    address after. Kept for the window only; the periodic prune deletes the row after it."""
    result = result or {}
    return {"previous_email": result.get("old_email"), "new_email": result.get("new_email")}


def window_ends(change: CredentialChange) -> Optional[datetime]:
    """When a further change to that account stops needing approval."""
    return change.applied_at + WINDOW if change.applied_at else None


def can_approve(admin) -> bool:
    """An administrator who could sign in and approve: active, and not locked by an administrator.
    A lock that wrong passwords armed runs out by itself, so it does not count here."""
    from app.services.auth_service import admin_locked
    return (getattr(admin, "role", None) == RoleEnum.ADMIN
            and getattr(admin, "is_active", None) is not False
            and not admin_locked(admin))


# Why an administrator may not approve a held request (refusal_reason), in the order they are checked.
# Each is said in plain words on the Users page, in the refusal of an approval (403), and in the refusal
# of a second change nobody may approve (409): see app/api/api_server.py.
ASKED = "asked"                  # the administrator who asked
MADE_BY_REQUESTER = "made"       # the one who asked made them an administrator (rule 3)
MADE_REQUESTER = "maker"         # they made the one who asked an administrator (rule 3, the other way)
CHANGED_ACCOUNT = "changed"      # they made or approved a change to that account (rule 2)
BECAME_ADMIN_AFTER = "after"     # they became an administrator after the request was made (rule 4)
NEW_ADMIN = "new"                # they had been one for less than TENURE when it was made (rule 4)


def changers(db, target_id, since: datetime) -> Set:
    """The administrators who made a credential change to ``target_id`` applied after ``since``: who
    asked for it, and, for a held change that was approved, who approved it. Either one made it happen."""
    rows = (db.query(CredentialChange.requested_by_id, CredentialChange.decided_by_id, CredentialChange.status)
            .filter(CredentialChange.target_user_id == target_id,
                    CredentialChange.status.in_(APPLIED),
                    CredentialChange.applied_at.isnot(None),
                    CredentialChange.applied_at > since)
            .all())
    out = set()
    for requested_by, decided_by, status in rows:
        if requested_by is not None:
            out.add(requested_by)
        if status == APPROVED and decided_by is not None:
            out.add(decided_by)
    return out


def refusal_reason(approver_id, *, requester_id, approver_grant, requester_grant, changed: Set,
                   requested_at: datetime) -> Optional[str]:
    """Why ``approver_id`` may not approve a change ``requester_id`` asked for at ``requested_at``, or
    None when they may (the module docstring has the four rules). ``approver_grant`` and
    ``requester_grant`` are their admin_grants records (None: none); ``changed`` is changers() for the
    account since 14 days before the request."""
    from app.core import admin_grants
    if approver_id == requester_id:
        return ASKED
    if admin_grants.made_by(approver_grant, requester_id):
        return MADE_BY_REQUESTER
    if admin_grants.made_by(requester_grant, approver_id):
        return MADE_REQUESTER
    if approver_id in changed:
        return CHANGED_ACCOUNT
    if admin_grants.granted_after(approver_grant, requested_at):
        return BECAME_ADMIN_AFTER
    if admin_grants.granted_after(approver_grant, requested_at - TENURE):
        return NEW_ADMIN
    return None


def refusals(db, requester_id, *, target_id=None, requested_at: Optional[datetime] = None,
             now: Optional[datetime] = None) -> Dict:
    """{administrator: why they may not approve, or None when they may} for every administrator other
    than ``requester_id`` who could sign in, for a change to ``target_id`` asked for at ``requested_at``
    (default now). Without ``target_id`` the changes already made to an account are not looked at."""
    from app.core import admin_grants
    now = now or utcnow()
    requested_at = requested_at or now
    admins = [a for a in db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
              if a.id != requester_id and can_approve(a)]
    grants = admin_grants.of(db, [a.id for a in admins] + [requester_id])
    changed = changers(db, target_id, min(requested_at, now) - WINDOW) if target_id is not None else set()
    return {a: refusal_reason(a.id, requester_id=requester_id, approver_grant=grants.get(a.id),
                              requester_grant=grants.get(requester_id), changed=changed,
                              requested_at=requested_at)
            for a in admins}


def approvers(db, requester_id, change: Optional[CredentialChange] = None, *, target_id=None,
              now: Optional[datetime] = None) -> List[User]:
    """The administrators who could approve a change asked for by ``requester_id``: able to sign in,
    and independent of it (the module docstring's four rules). With ``change``, the change held; with
    ``target_id``, a change to that account asked for now."""
    if change is not None:
        found = refusals(db, requester_id, target_id=change.target_user_id,
                         requested_at=change.requested_at, now=now)
    else:
        found = refusals(db, requester_id, target_id=target_id, now=now)
    return [a for a, reason in found.items() if reason is None]


def _lock_account(db, target_id) -> None:
    """Take the account's row lock, so two administrators changing it at the same moment are counted
    one after the other: the second waits for the first to commit, then finds its change."""
    db.query(User.id).filter(User.id == target_id).with_for_update().first()


def decide(db, *, requester_id, target_id, now: Optional[datetime] = None) -> Optional[CredentialChange]:
    """Whether a change to ``target_id`` asked for by ``requester_id`` (None: the host operator) may
    be made now.

    Returns None when it may: no change was applied to the account within the window. Returns the
    change that opened the window when this one must be held instead. Raises :class:`NoApprover`, with
    why each other administrator may not approve, when it would have to be held but nobody could
    approve it. The host operator is the way round the rule, so a change it asks for is never held.

    Call it before applying anything, in the transaction that will apply or hold the change."""
    now = now or utcnow()
    _lock_account(db, target_id)
    if requester_id is None:
        return None
    last = last_applied(db, target_id, now)
    if last is None:
        return None
    found = refusals(db, requester_id, target_id=target_id, requested_at=now, now=now)
    if not any(reason is None for reason in found.values()):
        raise NoApprover(last, sorted((a.username, reason) for a, reason in found.items()))
    return last


def record_made(db, *, kind, target_id, requester_id, requester_name, summary=None,
                now: Optional[datetime] = None) -> CredentialChange:
    """Record a change that is applied at once, in the caller's transaction."""
    now = now or utcnow()
    row = CredentialChange(target_user_id=target_id, kind=kind, status=MADE,
                           requested_by_id=requester_id, requested_by_name=requester_name,
                           requested_at=now, applied_at=now, summary=summary)
    db.add(row)
    # Written now, so a second change in the same request (an address and a password in one save)
    # finds this one: the application's sessions do not flush before a query on their own.
    db.flush()
    return row


def hold(db, *, kind, target_id, requester_id, requester_name, summary, payload,
         now: Optional[datetime] = None) -> CredentialChange:
    """Record a change as a request waiting for approval, in the caller's transaction."""
    now = now or utcnow()
    row = CredentialChange(target_user_id=target_id, kind=kind, status=HELD,
                           requested_by_id=requester_id, requested_by_name=requester_name,
                           requested_at=now, expires_at=now + HOLD, summary=summary,
                           payload=payload or {})
    db.add(row)
    db.flush()
    return row


def is_open(change: CredentialChange, now: Optional[datetime] = None) -> bool:
    """A held request nobody has decided and whose time has not run out."""
    now = now or utcnow()
    return change.status == HELD and (change.expires_at is None or change.expires_at > now)


def may_approve(change: CredentialChange, approver_id) -> bool:
    """Anyone but the administrator who asked, on the request alone. None is the host operator, who may
    approve any. approval_refusal adds what the administrator records say."""
    return approver_id is None or approver_id != change.requested_by_id


def approval_refusal(db, change: CredentialChange, approver_id, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``approver_id`` may not approve ``change`` (one of the reasons above, see refusal_reason),
    or None when they may. None is the host operator, who may approve any request."""
    from app.core import admin_grants
    if approver_id is None:
        return None
    if approver_id == change.requested_by_id:
        return ASKED
    now = now or utcnow()
    requested_at = change.requested_at or now
    grants = admin_grants.of(db, [approver_id, change.requested_by_id])
    return refusal_reason(approver_id, requester_id=change.requested_by_id,
                          approver_grant=grants.get(approver_id),
                          requester_grant=grants.get(change.requested_by_id),
                          changed=changers(db, change.target_user_id, min(requested_at, now) - WINDOW),
                          requested_at=requested_at)


def _decide(change, status, decider_id, decider_name, now):
    change.status = status
    change.decided_by_id = decider_id
    change.decided_by_name = decider_name
    change.decided_at = now
    change.payload = None   # nothing a decided request held is needed any more


def approve(change: CredentialChange, *, approver_id, approver_name, now: Optional[datetime] = None) -> None:
    """Mark a held request approved and applied. The caller has applied it and commits both."""
    now = now or utcnow()
    _decide(change, APPROVED, approver_id, approver_name, now)
    change.applied_at = now


def claim_approval(db, change: CredentialChange, *, approver_id, approver_name,
                   now: Optional[datetime] = None) -> bool:
    """Mark a held request approved in ONE guarded statement, before anything is applied, in the
    caller's transaction. Returns False, changing nothing, when the request is no longer held and open
    in the database: another administrator (or the expiry sweep) decided it first.

    Why a guarded statement and not the row lock alone: applying a reset link commits part-way (the
    token is minted and committed on its own), which releases the lock the approval took. A second
    approval waiting on that lock would then read the row, find it still held, and apply the change a
    second time. Claimed here first, the row is already approved by the time anything commits, and only
    one approval can ever match ``status = 'held'``."""
    from sqlalchemy import null, or_, update
    now = now or utcnow()
    tbl = CredentialChange.__table__
    claimed = db.execute(
        update(tbl)
        .where(tbl.c.id == change.id, tbl.c.status == HELD,
               or_(tbl.c.expires_at.is_(None), tbl.c.expires_at > now))
        .values(status=APPROVED, decided_by_id=approver_id, decided_by_name=approver_name,
                decided_at=now, applied_at=now, payload=null())
    ).rowcount
    if claimed != 1:
        return False
    # The statement went straight to the table: bring the caller's copy into step without marking it
    # changed.
    from sqlalchemy.orm.attributes import set_committed_value
    for key, value in (("status", APPROVED), ("decided_by_id", approver_id), ("decided_by_name", approver_name),
                       ("decided_at", now), ("applied_at", now), ("payload", None)):
        set_committed_value(change, key, value)
    return True


def deny(change: CredentialChange, *, decider_id, decider_name, now: Optional[datetime] = None) -> str:
    """Turn a held request down. The administrator who asked withdraws it; anyone else denies it.
    Returns the status set."""
    now = now or utcnow()
    status = WITHDRAWN if (decider_id is not None and decider_id == change.requested_by_id) else DENIED
    _decide(change, status, decider_id, decider_name, now)
    return status


def expire_due(db, now: Optional[datetime] = None) -> List[CredentialChange]:
    """Mark every held request whose time ran out as expired, in the caller's transaction, and return
    them. Rows are claimed FOR UPDATE SKIP LOCKED, so an approval in progress keeps its row and two
    sweeps never both expire one."""
    now = now or utcnow()
    due = (db.query(CredentialChange)
           .filter(CredentialChange.status == HELD, CredentialChange.expires_at <= now)
           .with_for_update(skip_locked=True).all())
    for change in due:
        _decide(change, EXPIRED, None, None, now)
    return due


def prune_done(db, now: Optional[datetime] = None) -> int:
    """Delete, in the caller's transaction, the records nothing reads any more: a change applied more
    than 14 days ago (it no longer holds the window open), and a request denied, withdrawn or expired
    more than 14 days ago. Held requests still open are kept. Their summary names an email address or
    a key that may never have been applied, so they are not kept for as long as the account lives; the
    audit log keeps the history. Run by the periodic cleanup. Returns how many were deleted."""
    now = now or utcnow()
    cutoff = now - WINDOW
    applied = (db.query(CredentialChange)
               .filter(CredentialChange.status.in_(APPLIED), CredentialChange.applied_at < cutoff)
               .delete(synchronize_session=False))
    decided = (db.query(CredentialChange)
               .filter(CredentialChange.status.in_((DENIED, WITHDRAWN, EXPIRED)),
                       CredentialChange.decided_at < cutoff)
               .delete(synchronize_session=False))
    return applied + decided


def open_requests(db, now: Optional[datetime] = None, target_ids: Optional[Iterable] = None) -> List[CredentialChange]:
    """Held requests nobody has decided yet, oldest first."""
    now = now or utcnow()
    q = db.query(CredentialChange).filter(CredentialChange.status == HELD,
                                          CredentialChange.expires_at > now)
    if target_ids is not None:
        q = q.filter(CredentialChange.target_user_id.in_(list(target_ids)))
    return q.order_by(CredentialChange.requested_at).all()


def recent_by_account(db, target_ids: Iterable, now: Optional[datetime] = None) -> dict:
    """{account id: the newest change applied to it within the window} for the given accounts, in
    one query: what the Users page shows beside each account."""
    ids = list(target_ids)
    if not ids:
        return {}
    now = now or utcnow()
    rows = (db.query(CredentialChange)
            .filter(CredentialChange.target_user_id.in_(ids),
                    CredentialChange.status.in_(APPLIED),
                    CredentialChange.applied_at > now - WINDOW)
            .order_by(CredentialChange.applied_at.desc()).all())
    out = {}
    for r in rows:
        out.setdefault(r.target_user_id, r)
    return out
