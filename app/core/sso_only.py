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

The flag follows the providers, and is never set on its own: an account signs in only through its providers exactly
while it is linked to at least one provider whose people hold no password (:func:`should_be_sso_only`), whatever
that provider's state. :func:`settle` brings one account in line and is called wherever the answer can change: a
link (by the person, by email, at a first sign-in, through an invitation), an unlink, a change of a provider's
setting and a provider's removal. So a provider set to "no password" also covers the accounts linked after the
setting was saved, and an account that unlinked the provider that made it password-less is not left without one.
"""
from __future__ import annotations

import secrets
from typing import List, Optional

from app.core import privileged_accounts


class Privileged(ValueError):
    """The account cannot be made SSO-only: it is privileged (the message names why)."""


def _password_is_nobodys(user) -> None:
    """The hash now holds random bytes: a password that is not its owner's. Marked as one somebody else set
    (app/core/password_origin.py), so the rules for such a password apply to it: made an administrator later,
    the account is sent a link to choose one; and until the person has chosen one, it approves no held change.
    The mark goes when the person sets a password of their own."""
    from app.core import password_origin
    password_origin.set_by_other(user, None)
    password_origin.mark_nobody_knows(user)


def make_sso_only(db, user, *, keep_session=None) -> None:
    """Make ``user`` sign in only through its provider, in the caller's transaction. The web sessions a password
    made end with the password (:func:`end_sessions_no_provider_made`); ``keep_session`` is the id of the session
    the request itself came through, where the person has just proved themselves at the provider in it."""
    from app.core.security import hash_password
    kind = privileged_accounts.kind(db, user)
    if kind is not None:
        raise Privileged(f"{user.username} is {privileged_accounts.TEXTS[kind]} and keeps a local password")
    user.sso_only = True
    user.password_hash = hash_password(secrets.token_urlsafe(32))     # nobody knows it; a reset sets a real one
    user.sftp_password_auth = False
    _password_is_nobodys(user)
    end_sessions_no_provider_made(db, user, keep=keep_session)


def end_sessions_no_provider_made(db, user, *, keep=None) -> int:
    """End the account's web sessions that did not come through a provider, in the caller's transaction. They
    were made with the password that has just stopped working (alone, or with a second factor), and whoever
    holds one would otherwise stay signed in until it expires. Sessions that came through a provider stay, and
    so do a temporary credential's (not the account's own sign-in) and SFTP's (a key made them; SFTP password
    sign-in is off from now). Returns how many ended."""
    from app.core.models import ActiveSession, SsoSession
    from app.core.table_presence import has_table
    if not has_table(db, ActiveSession.__tablename__):
        return 0
    rows = db.query(ActiveSession).filter(ActiveSession.user_id == user.id, ActiveSession.is_active.is_(True)).all()
    mine = [r for r in rows if getattr(r, "temp_credential_id", None) is None
            and getattr(r, "channel", None) in (None, "web") and r.id != keep]
    if not mine:
        return 0
    through = set()
    if has_table(db, SsoSession.__tablename__):
        through = {s.session_id for s in
                   db.query(SsoSession).filter(SsoSession.session_id.in_([r.id for r in mine])).all()}
    ending = [r.id for r in mine if r.id not in through]
    if not ending:
        return 0
    from app.api import api_server as api
    return int(api._revoke_sessions(db, session_ids=ending, actor_username="system", durable=True) or 0)


def allow_password_sign_in(db, user, *, keep_password: bool = False) -> None:
    """Let ``user`` hold a password again, in the caller's transaction: the flag cleared, so a reset link can be made
    for the account and it may set a password. The hash stays one nobody knows until such a link is used (whatever
    was written to it meanwhile is not a password), and nothing is minted here.

    ``keep_password``: for a privileged account met flagged. The flag on such an account comes from a release that
    knew nothing of it, run for a while after going back to it, and that release may also have given the account a
    real password (it had to, for the account to act as an administrator there): the hash is left as it is. Where
    it is still the one nobody knows, its mark still says so."""
    from app.core.security import hash_password
    user.sso_only = False
    if keep_password:
        return
    user.password_hash = hash_password(secrets.token_urlsafe(32))
    _password_is_nobodys(user)


def password_less(provider) -> bool:
    """Whether ``provider``'s people hold no password (its ``sso_password_login`` is ``disabled``)."""
    from app.core import sso_policy
    return sso_policy.effective(getattr(provider, "policy", None))["sso_password_login"] == "disabled"


def should_be_sso_only(db, user, *, also=None, without=None) -> bool:
    """The rule the flag follows: linked to at least one provider whose people hold no password, and not an
    account that must keep a password of its own (an administrator, a holder of the auditor right), whatever it
    is linked to. ``also`` is a provider being linked in this transaction, ``without`` an identity being removed
    in it.

    The links and settings that would put a privileged account on such a provider are refused where they are
    made. The state exists all the same: an account that signs in only through its provider was made an
    administrator, or given the auditor right, by an earlier release run for a while after going back to it,
    which knows nothing of the flag. Such an account is never flagged here, so settling it gives it its password
    back and never fails the request that met it."""
    from app.core.models import ExternalIdentity, SsoProvider
    if privileged_accounts.kind(db, user) is not None:
        return False
    if also is not None and password_less(also):
        return True
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        if without is not None and identity.id == without.id:
            continue
        provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if provider is not None and password_less(provider):
            return True
    return False


MADE, RESTORED = "made_sso_only", "restored"


def settle(db, user, *, also=None, without=None, keep_session=None) -> Optional[str]:
    """Bring ``user``'s flag in line with the providers it is linked to, in the caller's transaction: ``MADE`` when
    the account now signs in only through its providers (its password replaced, SFTP password sign-in off),
    ``RESTORED`` when it may hold a password again (nothing is minted), None when nothing changed. An account
    that must keep a password of its own is never made provider-only and is given its password back when it is
    met flagged (:func:`should_be_sso_only`); nothing is raised for it."""
    should = should_be_sso_only(db, user, also=also, without=without)
    flagged = bool(getattr(user, "sso_only", False))
    if should and not flagged:
        make_sso_only(db, user, keep_session=keep_session)
        return MADE
    if flagged and not should:
        allow_password_sign_in(db, user, keep_password=privileged_accounts.kind(db, user) is not None)
        return RESTORED
    return None


def settle_privileged(db) -> list:
    """Give every privileged account that is flagged as signing in only through its provider its password back,
    in the caller's transaction, and return them as (id, username, email, what it is). Run at start: the state
    comes from a release that knew nothing of the flag, and such an account could neither type a password at the
    step an administrator always meets nor be sent a reset link while flagged."""
    from app.core.models import User
    restored = []
    for user in db.query(User).filter(User.sso_only.is_(True)).all():
        kind = privileged_accounts.kind(db, user)
        if kind is None:
            continue
        allow_password_sign_in(db, user, keep_password=True)
        restored.append((user.id, user.username, user.email, privileged_accounts.TEXTS[kind]))
    return restored


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


def apply_password_login(db, provider) -> dict:
    """After ``provider``'s ``sso_password_login`` was written: settle each account linked to it. ``disabled`` makes
    each SSO-only; ``allowed`` lets each hold a password again unless another provider it is linked to still holds
    its people to none (no link is minted). Returns the usernames changed: ``{"made_sso_only": [...], "restored":
    [...]}``, each sorted. Call :func:`disabled_refusal` first for ``disabled``."""
    changed = {MADE: [], RESTORED: []}
    for user in linked_accounts(db, provider):
        outcome = settle(db, user)
        if outcome is not None:
            changed[outcome].append(user.username)
    return {MADE: sorted(changed[MADE]), RESTORED: sorted(changed[RESTORED])}
