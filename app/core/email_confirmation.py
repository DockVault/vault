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

Accounts from before the column start unconfirmed. One case is proved by what is stored and is confirmed at start:
an account made from an invitation that carried the address the account still holds (``BACKFILL``).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

# Run at start, after the column exists; harmless to run again. An administrator wrote the address into the
# invitation this account was made from, and the account holds that address now: confirmed, as of the acceptance.
BACKFILL = (
    "UPDATE users SET email_confirmed_at = i.accepted_at FROM account_invitations i "
    "WHERE users.email_confirmed_at IS NULL AND users.email IS NOT NULL AND i.accepted_user_id = users.id "
    "AND i.accepted_at IS NOT NULL AND i.email IS NOT NULL AND lower(i.email) = lower(users.email)"
)


def confirm(user, *, now: Optional[datetime] = None) -> None:
    """Mark ``user``'s address as confirmed by the vault, as of now. Call it after the address is set (setting an
    address clears the mark). An account without an address has nothing to confirm."""
    user.email_confirmed_at = (now or datetime.utcnow()) if (getattr(user, "email", None) or "").strip() else None


def confirmed(user) -> bool:
    """Whether the vault confirmed the address ``user`` holds now."""
    return bool((getattr(user, "email", None) or "").strip()) and getattr(user, "email_confirmed_at", None) is not None


def address_changed(target, value, oldvalue, initiator) -> None:
    """The column's listener: an address that changed is unconfirmed, whoever changed it and however. A change of
    letter case alone is the same address. The paths that confirm call :func:`confirm` afterwards."""
    old = oldvalue if isinstance(oldvalue, str) else ""
    new = value if isinstance(value, str) else ""
    if new.strip().lower() != old.strip().lower():
        target.email_confirmed_at = None
