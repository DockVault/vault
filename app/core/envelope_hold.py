"""The hold on an account's zero-knowledge key envelope after an administrator changed its sign-in details.

An account's private key lives on the server only as an envelope sealed under the person's zero-knowledge
passphrase, and GET /ecc/keys/private hands it to the account's sessions so a browser can unlock it. The
passphrase is the one low-entropy secret in the design: whoever holds the envelope can guess it offline, and
a guessed passphrase makes the guesser that member. Proof of the key stops an administrator who took over an
account from changing its vaults' keys, but not from downloading the envelope and guessing.

So for ``ZK_ENVELOPE_HOLD_DAYS`` (default 14, 0 turns it off, at most 14) after an administrator -- or the
server's operator -- changed an account's sign-in details (app/core/credential_changes.py: a password, a
reset link, a second factor, an email address, an SSH key), the envelope is released to a session only once
that session has entered a code sent by email. The code goes to the address the account had just before the
first of the changes that hold it was applied (code_destination): for an email change, the address it
replaced. Never to the address the account has now: whoever made the change can sign in with the password
they set and move the address through the account's own settings, and the code would follow them. The
person's own sessions are held too: the server cannot tell them apart from the administrator's, and the
mailbox is what does. A deployment without mail, an account that had no address, and a change recorded
before 0.34.0 that kept none (only an email change did) need the host operator: ``dockvault.py accounts``
releases the hold (``release-key-hold``).

What it reads: the applied changes to the account within the hold, from credential_changes, whose rows are
pruned 14 days after they apply; that is why the hold cannot be longer. A session's release is kept on its
own row (active_sessions.zk_envelope_released_at) and covers the changes made before it; a later change
holds that session again. The host operator's release is kept on the change it releases
(credential_changes.envelope_released_at).

A release older than 0.34.0 ignores both columns and does not hold the envelope.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

MAX_DAYS = 14
# The one-time code's purpose (app/core/otp_service.py), and how long it lives.
OTP_PURPOSE = "zk_envelope_release"
CODE_TTL_MINUTES = 15
EMAIL_ACTION = "encryption_key_release_code"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hold_days() -> int:
    """The configured hold, clamped to 0..14 (the setting is refused at start outside that)."""
    from app.core.config import settings
    try:
        days = int(getattr(settings, "zk_envelope_hold_days", MAX_DAYS))
    except (TypeError, ValueError):
        days = MAX_DAYS
    return max(0, min(MAX_DAYS, days))


def holding_changes(db, user_id, now: Optional[datetime] = None) -> list:
    """The changes to this account that hold its envelope now: applied within the hold, and not released by
    the host operator. Newest first."""
    from app.core.credential_changes import APPLIED
    from app.core.models import CredentialChange
    days = hold_days()
    if days <= 0:
        return []
    now = now or utcnow()
    return (db.query(CredentialChange)
            .filter(CredentialChange.target_user_id == user_id,
                    CredentialChange.status.in_(APPLIED),
                    CredentialChange.applied_at.isnot(None),
                    CredentialChange.applied_at > now - timedelta(days=days),
                    CredentialChange.envelope_released_at.is_(None))
            .order_by(CredentialChange.applied_at.desc()).all())


def code_destination(db, user, now: Optional[datetime] = None) -> Optional[str]:
    """Where the code that releases this account's envelope goes: the address the account had just before
    the earliest change that holds it was applied (credential_changes.address_before). None when nothing
    holds it, when the account had no address then, or when the change's record does not say."""
    from app.core.credential_changes import address_before
    changes = holding_changes(db, user.id, now)
    if not changes:
        return None
    return address_before(changes[-1]) or None


def held_until(db, user, now: Optional[datetime] = None) -> Optional[datetime]:
    """When the hold on this request's session ends, or None when the envelope may be released to it."""
    from app.core.models import ActiveSession
    changes = holding_changes(db, user.id, now)
    if not changes:
        return None
    latest = changes[0].applied_at
    from app.core.session_hash_utils import hash_session_token
    token = getattr(user, "_session_token", None)
    if token:
        released = db.query(ActiveSession.zk_envelope_released_at).filter(
            ActiveSession.session_token == hash_session_token(token)).scalar()
        if released is not None and released >= latest:
            return None
    return latest + timedelta(days=hold_days())


def release_session(db, user, now: Optional[datetime] = None) -> bool:
    """Record that this request's session entered the code. The caller commits. False when the request has
    no session row to record it on (nothing is released then)."""
    from app.core.models import ActiveSession
    from app.core.session_hash_utils import hash_session_token
    token = getattr(user, "_session_token", None)
    if not token:
        return False
    updated = db.query(ActiveSession).filter(
        ActiveSession.session_token == hash_session_token(token), ActiveSession.user_id == user.id,
    ).update({"zk_envelope_released_at": now or utcnow()}, synchronize_session=False)
    return bool(updated)


def release_by_host(db, user_id, now: Optional[datetime] = None) -> int:
    """The host operator's release: every change holding the account's envelope now is marked released. The
    caller commits. Returns how many were."""
    now = now or utcnow()
    changes = holding_changes(db, user_id, now)
    for change in changes:
        change.envelope_released_at = now
    return len(changes)


def report_at_startup(log=print) -> None:
    """Say at start when the hold is off. Never raises."""
    try:
        if hold_days() == 0:
            log("⚠ The zero-knowledge key envelope is not held after an administrator changes an account's "
                "sign-in details (ZK_ENVELOPE_HOLD_DAYS=0)")
    except Exception:  # noqa: BLE001 -- a report must never stop the server starting
        pass
