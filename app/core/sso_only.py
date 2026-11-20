"""Accounts that sign in only through their identity provider (``users.sso_only``).

A provider whose ``sso_password_login`` is ``disabled`` makes every account linked to it SSO-only: the password hash
is replaced by a real hash of 32 random bytes thrown away (the column stays NOT NULL, an older release refuses a
password sign-in cleanly, and nothing can be timed), SFTP password sign-in is turned off, the password door refuses
the account after the hash check, reset links are not minted or honoured for it, and it cannot set a password.
The setting is refused while a linked account is privileged (app/core/privileged_accounts.py): those need a local
password for the fixed step-ups. Setting the provider back to ``allowed`` clears the flag and mints nothing: each
person sets a password by a reset link made the ordinary way (their own request from the sign-in page, or an
administrator's for that one account), so no change of a provider's setting hands anyone a link to many accounts and
every link stays under the rules of the route that makes it. Nothing here commits.
"""
from __future__ import annotations

import secrets
from typing import List, Optional

from app.core import privileged_accounts


class Privileged(ValueError):
    """The account cannot be made SSO-only: it is privileged (the message names why)."""


def make_sso_only(db, user) -> None:
    """Make ``user`` sign in only through its provider, in the caller's transaction."""
    from app.core.security import hash_password
    kind = privileged_accounts.kind(db, user)
    if kind is not None:
        raise Privileged(f"{user.username} is {privileged_accounts.TEXTS[kind]} and keeps a local password")
    user.sso_only = True
    user.password_hash = hash_password(secrets.token_urlsafe(32))     # nobody knows it; a reset sets a real one
    user.sftp_password_auth = False


def allow_password_sign_in(db, user) -> None:
    """Let ``user`` hold a password again, in the caller's transaction: the flag cleared, so a reset link can be made
    for the account and it may set a password. The hash stays one nobody knows until such a link is used (whatever
    was written to it meanwhile is not a password), and nothing is minted here."""
    from app.core.security import hash_password
    user.sso_only = False
    user.password_hash = hash_password(secrets.token_urlsafe(32))


def provider_only_message(db, user) -> str:
    """What a person is told when they try to sign in to an account that signs in only through its provider some
    other way (a passkey): the organisation's provider by name and the button to use, or the link when the provider
    is not on the sign-in page; when no provider of the account is enabled, to ask an administrator."""
    from app.core.models import ExternalIdentity, SsoProvider
    names, buttons = [], []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        row = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if row is None or getattr(row, "state", None) != "enabled":
            continue
        name = (getattr(row, "name", None) or "").strip()
        label = (getattr(row, "label", None) or "").strip() or name       # the button shows the name when no label
        if name and name not in names:
            names.append(name)
        if getattr(row, "show_on_sign_in", True):
            if label and label not in buttons:
                buttons.append(label)
    if not names:
        return ("Your organisation signs this account in through its own sign-in, which is not available on this vault "
                "right now. Ask your administrator.")
    through = " or ".join(names)
    if buttons:
        return (f"Your organisation signs this account in through {through}. Use the "
                + " or ".join(f"“{b}”" for b in buttons) + " button on the sign-in page.")
    return (f"Your organisation signs this account in through {through}. Use the sign-in link your organisation "
            "gave you.")


def passkey_note(db, user) -> Optional[str]:
    """What the passkey section tells an account that signs in only through its provider, or None for any other
    account: a passkey there confirms the person after the provider's sign-in and never stands in for it."""
    if not getattr(user, "sso_only", False):
        return None
    from app.core.models import ExternalIdentity, SsoProvider
    names = []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        row = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if row is None or getattr(row, "state", None) != "enabled":
            continue
        name = (getattr(row, "label", None) or "").strip() or (getattr(row, "name", None) or "").strip()
        if name and name not in names:
            names.append(name)
    through = " or ".join(names) if names else "its own sign-in"
    return (f"Your organisation signs you in through {through}; this passkey confirms it's you after that, it does "
            "not replace it.")


def linked_accounts(db, provider) -> List:
    from app.core.models import ExternalIdentity, User
    ids = [row.user_id for row in db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == provider.id).all()]
    return [u for u in (db.query(User).filter(User.id == uid).first() for uid in ids) if u is not None]


def disabled_refusal(db, provider) -> Optional[str]:
    """Why ``sso_password_login`` may not be set to ``disabled`` for ``provider``: the linked accounts that must keep a
    local password, named, or None."""
    named = []
    for user in linked_accounts(db, provider):
        kind = privileged_accounts.kind(db, user)
        if kind is not None:
            named.append(f"{user.username} ({privileged_accounts.TEXTS[kind]})")
    if not named:
        return None
    return ("Password sign-in cannot be turned off for this provider while accounts that need a local password are "
            f"linked to it: {', '.join(sorted(named))}. Unlink them, or leave password sign-in allowed.")


def apply_password_login(db, provider, value: str) -> dict:
    """Apply a saved ``sso_password_login`` to the provider's linked accounts: ``disabled`` makes each SSO-only;
    ``allowed`` lets each SSO-only one hold a password again (:func:`allow_password_sign_in`: no link is minted).
    Returns the usernames changed: ``{"made_sso_only": [...], "restored": [...]}``, each sorted. Call
    :func:`disabled_refusal` first for ``disabled``."""
    made, restored = [], []
    for user in linked_accounts(db, provider):
        if value == "disabled" and not getattr(user, "sso_only", False):
            make_sso_only(db, user)
            made.append(user.username)
        elif value == "allowed" and getattr(user, "sso_only", False):
            allow_password_sign_in(db, user)
            restored.append(user.username)
    return {"made_sso_only": sorted(made), "restored": sorted(restored)}
