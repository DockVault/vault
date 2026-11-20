"""Whether the vault itself confirmed that an account's email address belongs to the account.

An address reaches an account in several ways, and only some of them are a proof: an administrator set it (at
creation, or through a credential change), an invitation carried it (an administrator wrote it), or the person
proved it by typing the code the vault sent there. An address a person typed at self sign-up, or changed to with
the current password alone, is their own claim: nothing says the mailbox is theirs. An address a provider vouched
for at a first sign-in is the provider's word, not the vault's.

``users.email_confirmed_at`` holds the difference. It is cleared by every change of the address (a listener on the
column, app/core/models.py, so a path written later cannot forget) and set here by the paths that confirm.
Linking a provider identity to an account by its email address reads it: an account whose address nobody
confirmed is never linked by that address, because anyone could have written it there and so taken the sign-ins
of the person the address really belongs to.

The mark names the address it was given for (``users.email_confirmed_for``, a digest of the address in lower case:
the row needs no second copy of it), and counts only while the account holds that address. The listener is not the
only guard, then: an address changed where no listener runs (a statement over many rows, or an earlier release of
the vault, run for a while after going back to it, which knows neither column) leaves a mark that no longer fits
and is not one.

Accounts from before the column start unconfirmed. One case is proved by what is stored and is confirmed at start:
an account made from an invitation that carried the address the account still holds (``BACKFILL``).
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional

# Run once, at the first start after the columns exist (:func:`backfill_once`). An administrator wrote the address
# into the invitation this account was made from, and the account holds that address now: confirmed, as of the
# acceptance. Once only: run at every start, it would confirm again an address the account lost and its owner then
# typed back with the password alone.
# The digest is the one :func:`mark_for` makes; where the database and Python would lower-case an address
# differently the two do not match, and the address reads as unconfirmed.
BACKFILL = (
    "UPDATE users SET email_confirmed_at = i.accepted_at, "
    "email_confirmed_for = encode(sha256(convert_to(lower(btrim(users.email)), 'UTF8')), 'hex') "
    "FROM account_invitations i "
    "WHERE (users.email_confirmed_at IS NULL OR users.email_confirmed_for IS NULL) AND users.email IS NOT NULL "
    "AND i.accepted_user_id = users.id "
    "AND i.accepted_at IS NOT NULL AND i.email IS NOT NULL AND lower(i.email) = lower(users.email)"
)


BACKFILL_MARKER = "email_confirmation_backfill_v1"


def backfill_once(db) -> int:
    """Run :data:`BACKFILL` if it never ran on this database, and note that it did. Returns the accounts confirmed."""
    from sqlalchemy import text
    from app.core.models import SystemSetting
    if db.query(SystemSetting).filter(SystemSetting.key == BACKFILL_MARKER).first() is not None:
        return 0
    confirmed = db.execute(text(BACKFILL)).rowcount or 0
    db.add(SystemSetting(key=BACKFILL_MARKER, value={"rows": confirmed}))
    db.commit()
    return confirmed


def _folded(address) -> str:
    """The address as the vault compares addresses (app/core/email_identity.py): trimmed, ASCII letters lowered."""
    from app.core.email_identity import normalize_email
    return normalize_email(address) or ""


def mark_for(address: str) -> str:
    """What a mark is given for: the address as the vault compares addresses, as a digest."""
    return hashlib.sha256(_folded(address).encode("utf-8")).hexdigest()


def confirm(user, *, now: Optional[datetime] = None) -> None:
    """Mark ``user``'s address as confirmed by the vault, as of now. Call it after the address is set (setting an
    address clears the mark). An account without an address has nothing to confirm."""
    address = (getattr(user, "email", None) or "").strip()
    user.email_confirmed_at = (now or datetime.utcnow()) if address else None
    user.email_confirmed_for = mark_for(address) if address else None


def confirmed(user) -> bool:
    """Whether the vault confirmed the address ``user`` holds now: a mark, given for this very address."""
    address = (getattr(user, "email", None) or "").strip()
    if not address or getattr(user, "email_confirmed_at", None) is None:
        return False
    return getattr(user, "email_confirmed_for", None) == mark_for(address)


def address_changed(target, value, oldvalue, initiator) -> None:
    """The column's listener: an address that changed is unconfirmed, whoever changed it and however. A change of
    letter case alone is the same address. The paths that confirm call :func:`confirm` afterwards."""
    old = oldvalue if isinstance(oldvalue, str) else ""
    new = value if isinstance(value, str) else ""
    if _folded(new) != _folded(old):
        target.email_confirmed_at = None
        target.email_confirmed_for = None
