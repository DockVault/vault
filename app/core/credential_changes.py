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
from typing import Iterable, List, Optional

from app.core.models import CredentialChange, RoleEnum, User

WINDOW = timedelta(days=14)
HOLD = timedelta(days=7)

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
    it. Carries the change that opened the window."""

    def __init__(self, last_change: CredentialChange):
        super().__init__("no other administrator can approve")
        self.last_change = last_change


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


def approvers(db, requester_id) -> List[User]:
    """The administrators, other than the one asking, who could approve a held change."""
    admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
    return [a for a in admins if a.id != requester_id and can_approve(a)]


def _lock_account(db, target_id) -> None:
    """Take the account's row lock, so two administrators changing it at the same moment are counted
    one after the other: the second waits for the first to commit, then finds its change."""
    db.query(User.id).filter(User.id == target_id).with_for_update().first()


def decide(db, *, requester_id, target_id, now: Optional[datetime] = None) -> Optional[CredentialChange]:
    """Whether a change to ``target_id`` asked for by ``requester_id`` (None: the host operator) may
    be made now.

    Returns None when it may: no change was applied to the account within the window. Returns the
    change that opened the window when this one must be held instead. Raises :class:`NoApprover` when
    it would have to be held but nobody could approve it. The host operator is the way round the rule,
    so a change it asks for is never held.

    Call it before applying anything, in the transaction that will apply or hold the change."""
    now = now or utcnow()
    _lock_account(db, target_id)
    if requester_id is None:
        return None
    last = last_applied(db, target_id, now)
    if last is None:
        return None
    if not approvers(db, requester_id):
        raise NoApprover(last)
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
    """Anyone but the administrator who asked. None is the host operator, who may approve any."""
    return approver_id is None or approver_id != change.requested_by_id


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
