"""Whether an account's current password is its own, or one someone else set.

Someone who set another person's password knows it, and keeps knowing it after that person is made an
administrator: they could sign in as the new administrator and, after 14 days, approve their own held
changes to someone's sign-in details (app/core/credential_changes.py). So the account records when its
current password was set by someone else, and by whom:

  * ``users.password_set_by_other_at``: when, or NULL when the password is the person's own (or nothing
    says otherwise: an account from before these columns whose history the audit log does not show);
  * ``users.password_set_by``: the account that set it, NULL for the server's operator on the host or
    once that account is deleted.

Set (someone else): an administrator, a user who manages users, or the host operator setting a
password (an approved held change counts as the one who asked for it); a reset link another account made
being used (whoever uses it, its maker could have); an administrator creating an account with a password.

Cleared (the person's own): the person changing their password themselves, to a different one (the same
password again is no change of hands); a reset link the person asked for, or one the server's operator
made on the host; accepting an invitation or signing up (new accounts start clear). The administrator
account the server creates from its .env at first start starts clear too: whoever runs the server
chose it for themselves.

What follows from it: when such an account is made an administrator, the password becomes unusable, its
sessions end, and the person sets a new one through a link to their own inbox (app/api/api_server.py,
_take_back_password_at_promotion); and an administrator whose current password someone else set may
not approve a held change (credential_changes.refusal_reason).

This module never commits: each caller changes the account in its own transaction.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

# Added on an existing deployment (a fresh one gets them from the model), with the audit-log backfill in
# the same transaction: add_columns_once.
COLUMNS_DDL = ("ALTER TABLE users"
               " ADD COLUMN IF NOT EXISTS password_set_by UUID REFERENCES users(id) ON DELETE SET NULL,"
               " ADD COLUMN IF NOT EXISTS password_set_by_other_at TIMESTAMP")

HOST_OPERATOR = "operator@host"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def set_by_other(user, setter_id, now: Optional[datetime] = None) -> None:
    """Someone other than the person (``setter_id``, None for the host operator) set ``user``'s password."""
    user.password_set_by = setter_id
    user.password_set_by_other_at = now or _now()


def set_by_self(user) -> None:
    """The person set their own password."""
    user.password_set_by = None
    user.password_set_by_other_at = None


def is_set_by_other(user) -> bool:
    return getattr(user, "password_set_by_other_at", None) is not None


# --------------------------------------------------------------------------- the backfill

# The audit rows that say who set an account's password, and the reset links it was set with.
_ACTIONS = ("user_created", "user_updated", "USER_UPDATED", "credential_change_approved", "self_account_update",
            "password_reset_link_minted", "password_reset_link_sent", "password_reset_completed")


def _is_host(row) -> bool:
    return row.user_id is None and row.username == HOST_OPERATOR


def _other_than(row, account: str):
    """(True, setter id or None) when the row's actor is someone other than ``account``, (False, None) when it
    is the account itself, None when the row names no actor."""
    if _is_host(row):
        return True, None
    if row.user_id is None:
        return None
    return (str(row.user_id) != account, row.user_id if str(row.user_id) != account else None)


def _link_maker(row, account: str):
    """(made by another account, its id) for a reset link the row records as made. One the host operator
    made counts as the person's own, as when it is used (api_server.do_reset); so does one whose maker the
    row does not name."""
    who = _other_than(row, account)
    if who is None or _is_host(row):
        return False, None
    return who


def derive_from_audit(db) -> dict:
    """{account id (str): (setter id or None, when)} for every account whose current password the audit log
    says someone else set, reading the rows oldest first so the newest event decides. An account the log
    says nothing about is not in it (its password counts as its own). A reset link used is judged by the
    newest link made for that account before it: made by another account, the password counts as that
    account's; asked for by the person, or made on the host, as the person's own."""
    from app.core.models import AuditLog
    names = None
    state = {}        # account -> (setter id or None, when) when someone else set it; None when its own
    links = {}        # account -> the maker of the newest reset link for it: (made by another, maker id)
    rows = (db.query(AuditLog.action, AuditLog.user_id, AuditLog.username, AuditLog.resource_id,
                     AuditLog.details, AuditLog.timestamp)
            .filter(AuditLog.action.in_(_ACTIONS), AuditLog.status == "success")
            .order_by(AuditLog.timestamp, AuditLog.id)
            .yield_per(2000))
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        action = row.action
        if action == "user_created":
            account = row.resource_id
            who = _other_than(row, account) if account else None
            if who is not None:
                state[account] = (who[1], row.timestamp) if who[0] else None
        elif action in ("user_updated", "USER_UPDATED"):
            changes = details.get("changes")
            account = row.resource_id
            if not (account and isinstance(changes, dict) and "password" in changes):
                continue
            who = _other_than(row, account)
            if who is not None:
                state[account] = (who[1], row.timestamp) if who[0] else None
        elif action == "credential_change_approved":
            account = row.resource_id
            if not account:
                continue
            if details.get("kind") == "password":
                # Set as the one who asked for it chose it.
                if names is None:
                    from app.core.models import User
                    names = {n: i for i, n in db.query(User.id, User.username).all()}
                state[account] = (names.get(details.get("requested_by")), row.timestamp)
            elif details.get("kind") == "reset_link":
                # Its maker is the administrator who approved it (or the host operator).
                links[account] = _link_maker(row, account)
        elif action in ("password_reset_link_minted", "password_reset_link_sent"):
            account = details.get("target_user_id")
            if account:
                links[account] = _link_maker(row, account)
        elif action == "password_reset_completed":
            if row.user_id is None:
                continue
            account = str(row.user_id)
            made_by_other, maker = links.pop(account, (False, None))
            state[account] = (maker, row.timestamp) if made_by_other else None
        elif action == "self_account_update":
            if row.user_id is not None and "password" in (details.get("fields") or []):
                state[str(row.user_id)] = None
    # An account that joined by invitation or signed up chose its first password, and no row before that
    # can name it, so those rows are not read.
    return {account: value for account, value in state.items() if value is not None}


def backfill_from_audit(db) -> int:
    """Record, from the audit log, whose password each existing account holds (derive_from_audit), in the
    caller's transaction. A setter whose account is gone is recorded as NULL. Returns how many accounts
    were marked as holding a password someone else set."""
    from app.core.models import User
    found = derive_from_audit(db)
    if not found:
        return 0
    existing = {str(i): i for (i,) in db.query(User.id).all()}
    marked = 0
    for account, (setter, when) in found.items():
        user_id = existing.get(account)
        if user_id is None:
            continue
        setter_id = setter if setter is not None and str(setter) in existing else None
        db.query(User).filter(User.id == user_id).update(
            {User.password_set_by: setter_id, User.password_set_by_other_at: when}, synchronize_session=False)
        marked += 1
    return marked


def columns_exist(db) -> bool:
    return db.execute(text(
        "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
        "AND table_name = 'users' AND column_name = 'password_set_by_other_at'")).first() is not None


def add_columns_once(db) -> Optional[int]:
    """On a deployment whose ``users`` table has no such columns yet (upgraded from an earlier release),
    add them and fill them from the audit log, in the caller's transaction, and return how many accounts
    were marked. None when they were there already: filled once, when they are added. A password set
    while an older release ran afterwards is not recorded, and counts as the person's own."""
    if columns_exist(db):
        return None
    db.execute(text("SET LOCAL lock_timeout = 0"))
    db.execute(text(COLUMNS_DDL))
    return backfill_from_audit(db)
