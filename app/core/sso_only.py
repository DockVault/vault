"""Accounts that sign in only through their identity provider (``users.sso_only``).

A provider whose ``sso_password_login`` is ``disabled`` makes every account linked to it SSO-only: the password hash
is replaced by a real hash of 32 random bytes thrown away (the column stays NOT NULL, an older release refuses a
password sign-in cleanly, and nothing can be timed), SFTP password sign-in is turned off, the password door refuses
the account after the hash check, reset links are not minted or honoured for it, and it cannot set a password.
The setting is refused while a linked account is privileged (app/core/privileged_accounts.py): those need a local
password for the fixed step-ups. Setting the provider back to ``allowed``, or an administrator's unlink, clears the
flag and mints the reset link the person sets a password with. Nothing here commits.
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


def restore_password_sign_in(db, user, *, base_url: str, created_by_id) -> Optional[str]:
    """Let ``user`` sign in with a password again: the flag cleared and a reset link minted for them to set one (the
    hash stays unusable until then). Returns the link, or None when no link can be minted (the reset pepper is not
    configured). ``_mint_reset_link`` commits on its own."""
    from app.api import api_server as api
    from app.core.security import hash_password
    user.sso_only = False
    user.password_hash = hash_password(secrets.token_urlsafe(32))     # whatever was set meanwhile is not a password
    return api._mint_reset_link(db, user, base_url, created_by_id=created_by_id, made_by_other=True)


def provider_only_message(db, user) -> str:
    """What a person is told when they try to sign in to an account that signs in only through its provider some
    other way (a passkey): the organisation's provider by name and the button to use, or the link when the provider
    is not on the sign-in page; when no provider of the account is enabled, to ask an administrator."""
    from app.core.models import ExternalIdentity, SsoProvider
    names, buttons, hidden = [], [], False
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        row = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if row is None or getattr(row, "state", None) != "enabled":
            continue
        name = (getattr(row, "name", None) or "").strip()
        label = (getattr(row, "label", None) or "").strip()
        if name and name not in names:
            names.append(name)
        if getattr(row, "show_on_sign_in", True) and label:
            if label not in buttons:
                buttons.append(label)
        else:
            hidden = True
    if not names:
        return ("Your organisation signs this account in through its own sign-in, which is not available on this vault "
                "right now. Ask your administrator.")
    through = " or ".join(names)
    if buttons:
        return (f"Your organisation signs this account in through {through}. Use the "
                + " or ".join(f"“{b}”" for b in buttons) + " button on the sign-in page.")
    assert hidden
    return (f"Your organisation signs this account in through {through}. Use the sign-in link your organisation "
            "gave you.")


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


def apply_password_login(db, provider, value: str, *, base_url: str, created_by_id) -> dict:
    """Apply a saved ``sso_password_login`` to the provider's linked accounts: ``disabled`` makes each SSO-only;
    ``allowed`` restores each SSO-only one with a reset link. Returns what changed: ``{"made_sso_only": [usernames],
    "restored": [(username, link or None)]}``. Call :func:`disabled_refusal` first for ``disabled``."""
    made, restored = [], []
    for user in linked_accounts(db, provider):
        if value == "disabled" and not getattr(user, "sso_only", False):
            make_sso_only(db, user)
            made.append(user.username)
        elif value == "allowed" and getattr(user, "sso_only", False):
            restored.append((user.username, restore_password_sign_in(db, user, base_url=base_url, created_by_id=created_by_id)))
    return {"made_sso_only": made, "restored": restored}
