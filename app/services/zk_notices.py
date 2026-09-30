"""Notices about zero-knowledge encryption keys, told to the people concerned.

* **A refused key change without the account's own key.** A request that changes a zero-knowledge vault's
  keys carries a proof that the account's encryption key is at hand (app/services/zk_key_proof.py). When that
  part fails, the request came from a session for the account without the account's key, which almost always
  means someone else is signed in as them. The account's user is told in the app and by email, at most once
  an hour, so a burst of attempts is one notice and a client fault cannot flood a mailbox.
* **An owner's reset of a vault's key.** Every other manager of the vault is told, in the app and by email: a
  reset makes a new key without proof of the old one, so it is worth knowing about when it was not expected.
* **An encryption key set up for an account.** Its user is told, in the app and by email. Whoever sets up an
  account's key first owns it, and receives what is shared with that account; a key the user did not set up
  themselves means someone else did.
* **A member's report that their key does not match** (POST /ecc/vaults/{id}/key-proof/report). The vault's
  owner is told in the app, at most once a day for each vault.

Each notice is best-effort: it runs after what it tells about, in its own session, and never raises, so a
notice that cannot be delivered never undoes or holds up the change. No notice names a vault: a
zero-knowledge vault's name is sealed, and the server does not know it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

# The in-app notice type these share, and the automated email that carries them.
NOTICE_TYPE = "encryption_key"
EMAIL_ACTION = "encryption_key_notice"

# How often, at most, each kind of notice reaches one person (or one vault's owner).
FAILED_PROOF_EVERY = timedelta(hours=1)

FAILED_PROOF_TITLE = "A change to a vault's key was refused"
FAILED_PROOF_TEXT = (
    "Someone signed in to your account tried to change a zero-knowledge vault's key without your "
    "encryption key, and it was refused; nothing was changed. If this was not you, someone else may be "
    "signed in as you: change your sign-in details and tell your administrators at once."
)
OWNER_RESET_TITLE = "A vault's key was reset by its owner"
KEY_REGISTERED_TITLE = "An encryption key was set up for your account"
KEY_REGISTERED_TEXT = (
    "An encryption key was set up for your account, and zero-knowledge vaults are shared with you under it "
    "from now on. If you did not set it up yourself, tell your administrators at once: whoever set it up "
    "can open what is shared with you."
)
MISMATCH_TITLE = "A member's key for one of your vaults does not match"
# What a report is about, as a sentence can name it.
FINDINGS = {
    "dek_check": "the key a member was given",
    "seal": "the key check material a manager opened",
    "team_key": "the team key a member was given",
    "lineage": "the record that the current key was made by someone who held the one before",
}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _when() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _told_recently(user_id, title: str, since: datetime) -> bool:
    """Was this person given this notice after `since`? Read in a session of its own."""
    from app.core.database import get_db_context
    from app.core.models import Notification
    with get_db_context() as s:
        return s.query(Notification.id).filter(
            Notification.user_id == user_id, Notification.type == NOTICE_TYPE,
            Notification.title == title, Notification.created_at > since,
        ).first() is not None


def _tell(db, users, *, title: str, text: str, target: str, dedup: Optional[str] = None,
          email: bool = True) -> list:
    """The in-app notice, and the email to each person the notice reached. Returns the ids told."""
    from app.api.api_server import _fire_action_email, _notify_users
    users = [u for u in users if u is not None]
    told = _notify_users([str(u.id) for u in users], NOTICE_TYPE, title=title, body=text, target=target,
                         dedup_prefix=dedup) or []
    if email:
        for u in users:
            if str(u.id) in told:
                _fire_action_email(db, EMAIL_ACTION, email=getattr(u, "email", None),
                                   username=getattr(u, "username", None),
                                   action_context={"change": text, "when": _when()})
    return told


def failed_identity_proof(db, user) -> None:
    """Tell an account's user that a key change was refused for want of their own encryption key: at most
    once an hour. Never raises."""
    try:
        now = _now()
        if _told_recently(user.id, FAILED_PROOF_TITLE, now - FAILED_PROOF_EVERY):
            return
        _tell(db, [user], title=FAILED_PROOF_TITLE, text=FAILED_PROOF_TEXT, target="#profile",
              dedup="zk-proof-failed:" + now.strftime("%Y-%m-%dT%H"))
    except Exception as exc:  # noqa: BLE001 -- a notice must never surface anywhere
        print(f"⚠ key-proof notice skipped: {type(exc).__name__}")


def owner_reset(db, owner, vault) -> None:
    """Tell every manager of a vault other than its owner that the owner reset its key. Never raises."""
    try:
        from sqlalchemy import select
        from app.core.models import User, vault_members
        ids = [row[0] for row in db.execute(select(vault_members.c.user_id).where(
            vault_members.c.vault_id == vault.id,
            vault_members.c.manage_permission == True,  # noqa: E712
        )).all() if str(row[0]) != str(owner.id)]
        if not ids:
            return
        managers = db.query(User).filter(User.id.in_(ids)).all()
        text = (f"{owner.username}, the owner of a zero-knowledge vault you manage, reset its key because "
                "the key's check was damaged. A new key was made and given to every remaining member; the "
                "files already in the vault stay readable. If you did not expect this, ask the owner.")
        _tell(db, managers, title=OWNER_RESET_TITLE, text=text, target="#vaults")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠ owner-reset notice skipped: {type(exc).__name__}")


def key_registered(db, user) -> None:
    """Tell an account's user that an encryption key was set up for it. Never raises."""
    try:
        _tell(db, [user], title=KEY_REGISTERED_TITLE, text=KEY_REGISTERED_TEXT, target="#profile")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠ key-registration notice skipped: {type(exc).__name__}")


ENVELOPE_RELEASED_TITLE = "Your encryption key can be opened again"
ENVELOPE_RELEASED_TEXT = (
    "The person who runs the server let your encryption key be opened without the code that is sent by email "
    "for a while after an administrator changes your sign-in details. If you did not ask for this, contact "
    "your administrators at once."
)


def envelope_released_by_host(db, user) -> None:
    """Tell an account's user that the host operator released the hold on their encryption key. Never
    raises."""
    try:
        _tell(db, [user], title=ENVELOPE_RELEASED_TITLE, text=ENVELOPE_RELEASED_TEXT, target="#profile")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠ key-release notice skipped: {type(exc).__name__}")


def key_check_mismatch(db, vault, finding: str) -> None:
    """Tell a vault's owner that a member's app found a key that does not match: in the app, at most once
    a day for each vault. Never raises."""
    try:
        from app.core.models import User
        owner = db.query(User).filter(User.id == vault.owner_id).first()
        if owner is None:
            return
        now = _now()
        what = FINDINGS.get(finding, "a key")
        text = (f"A member's app found that {what} for a zero-knowledge vault you own does not match the "
                "vault's key, and it stops writing to the vault with it. As the owner you can reset the "
                "vault's key from its key details.")
        # Once a day for each vault: the key names the vault and the day, so another vault's report still
        # reaches the owner the same day.
        _tell(db, [owner], title=MISMATCH_TITLE, text=text, target="#vaults", email=False,
              dedup=f"zk-key-mismatch:{vault.id}:{now.strftime('%Y-%m-%d')}")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠ key-mismatch notice skipped: {type(exc).__name__}")
