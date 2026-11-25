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
while it is linked to at least one provider that holds it to no password (:func:`should_be_sso_only`), whatever
that provider's state. :func:`settle` brings one account in line and is called wherever the answer can change: a
link (by the person, by email, at a first sign-in, through an invitation), an unlink, a change of a provider's
setting and a provider's removal. So a provider set to "no password" also covers the accounts linked after the
setting was saved, and an account that unlinked the provider that made it password-less is not left without one.

A provider holds an account to no password in two ways (:func:`holds_to_no_password`). Its people hold none
(``sso_password_login`` is ``disabled``): every account linked to it. Or the account was made at its first sign-in
through the provider and has never had a password of its own, and the provider does not let such accounts set one
(``sso_jit_password``, off unless an administrator turns it on): nobody at the vault ever met that person, so the
provider stays the one way in, and a person the provider has stopped vouching for cannot make themselves a
password with a reset link and stay. Such an account gets a password of its own only by an administrator's act:
the option turned on, or the account made an administrator (the promotion ends the flag and sends the person a
link to choose a password). A password it has once set is its own from then on, whatever the option says later,
and the rule is over for the account for good: also when that password is replaced later by one nobody knows (a
provider whose people hold no password, linked for a while or set so for a while), the account is let go with
the others when that ends. The account remembers that it has had a password (``users.had_a_password_at``,
app/core/password_origin.note_it_was_known), written where a password somebody knew is replaced.
"""
from __future__ import annotations

import secrets
from typing import List, Optional

from app.core import after_commit, privileged_accounts


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


def a_password_nobody_knows() -> str:
    """The hash of random bytes that are thrown away: a password nobody, the account's owner included, can type.

    Hashing is slow on purpose. What settles many accounts under a lock (a provider's save, its removal) makes
    one before it takes the lock and hands it to each (``unknown_hash``): the lock is then held for what is
    written, not for one hashing per account. One hash on several accounts tells nothing: the bytes behind it are
    gone, and each account's mark (app/core/password_origin.py) is of its own row."""
    from app.core.security import hash_password
    return hash_password(secrets.token_urlsafe(32))


def make_sso_only(db, user, *, keep_session=None, unknown_hash=None) -> None:
    """Make ``user`` sign in only through its provider, in the caller's transaction. The sessions a password made
    end with the password (:func:`end_sessions_no_provider_made`); ``keep_session`` is the id of the session the
    request itself came through, where the person has just proved themselves at the provider in it.
    ``unknown_hash``: a hash from :func:`a_password_nobody_knows` made beforehand; one is made here without it."""
    kind = privileged_accounts.kind(db, user)
    if kind is not None:
        raise Privileged(f"{user.username} is {privileged_accounts.TEXTS[kind]} and keeps a local password")
    from app.core import password_origin
    user.sso_only = True
    password_origin.note_it_was_known(user)          # a password of its own goes: that it had one is kept
    user.password_hash = unknown_hash or a_password_nobody_knows()     # a reset sets a real one
    user.sftp_password_auth = False
    _password_is_nobodys(user)
    end_sessions_no_provider_made(db, user, keep=keep_session)


def end_sessions_no_provider_made(db, user, *, keep=None) -> int:
    """End the account's sessions that a password made, in the caller's transaction: the password has just stopped
    working, and whoever holds one of them (a thief of the password among them) would otherwise stay signed in
    until it expires.

    Every session that is not revoked is looked at, not only the active ones: a web session a later sign-in
    replaced is marked inactive and never revoked, and its token goes on working until it expires. Ended are the
    web sessions that did not come through a provider, and the SFTP sessions a password made (they carry an end;
    a key's session carries none, and the key goes on working). What came through a provider stays, and so do a
    temporary credential's sessions (not the account's own sign-in) and ``keep``: the session the request itself
    came through, where the person has just proved themselves at the provider in it. The account's turn at its
    sessions is taken first, so a renewal under way comes wholly before or wholly after. Returns how many ended."""
    from app.core.models import ActiveSession, SsoSession
    from app.core.table_presence import has_table
    if not has_table(db, ActiveSession.__tablename__):
        return 0
    from app.api import api_server as api
    api._sessions_turn(db, user.id)
    rows = db.query(ActiveSession).filter(ActiveSession.user_id == user.id, ActiveSession.revoked.is_(False)).all()

    def a_password_made(row) -> bool:
        if getattr(row, "temp_credential_id", None) is not None or row.id == keep:
            return False
        if getattr(row, "channel", None) in (None, "web"):
            return True
        return getattr(row, "expires_at", None) is not None        # SFTP: a password's session has an end

    mine = [r for r in rows if a_password_made(r)]
    if not mine:
        return 0
    through = set()
    if has_table(db, SsoSession.__tablename__):
        through = {s.session_id for s in
                   db.query(SsoSession).filter(SsoSession.session_id.in_([r.id for r in mine])).all()}
    ending = [r.id for r in mine if r.id not in through]
    if not ending:
        return 0
    return int(api._revoke_sessions(db, session_ids=ending, actor_username="system", durable=True) or 0)


def allow_password_sign_in(db, user, *, keep_password: bool = False, unknown_hash=None) -> None:
    """Let ``user`` hold a password again, in the caller's transaction: the flag cleared, so a reset link can be made
    for the account and it may set a password. The hash stays one nobody knows until such a link is used (whatever
    was written to it meanwhile is not a password), and nothing is minted here.

    ``keep_password``: for a privileged account met flagged. The flag on such an account comes from a release that
    knew nothing of it, run for a while after going back to it, and that release may also have given the account a
    real password (it had to, for the account to act as an administrator there): the hash is left as it is. Where
    it is still the one nobody knows, its mark still says so.

    ``unknown_hash``: as for :func:`make_sso_only`."""
    from app.core import password_origin
    user.sso_only = False
    if keep_password:
        return
    password_origin.note_it_was_known(user)
    user.password_hash = unknown_hash or a_password_nobody_knows()
    _password_is_nobodys(user)


def password_less(provider) -> bool:
    """Whether ``provider``'s people hold no password (its ``sso_password_login`` is ``disabled``)."""
    from app.core import sso_policy
    return sso_policy.effective(getattr(provider, "policy", None))["sso_password_login"] == "disabled"


MADE_AT_A_FIRST_SIGN_IN = "jit"       # external_identities.linked_by of the identity such an account was made with


def made_here_holds_no_password(provider) -> bool:
    """Whether an account made at its first sign-in through ``provider`` is held to no password (the provider's
    ``sso_jit_password`` is off, as it is unless an administrator turned it on)."""
    from app.core import sso_policy
    return not sso_policy.effective(getattr(provider, "policy", None))["sso_jit_password"]


def holds_to_no_password(provider, user, linked_by) -> bool:
    """Whether ``provider`` holds ``user``, linked to it in the way ``linked_by`` says, to no password: its people
    hold none; or the account was made at its first sign-in there, the provider does not let such accounts set a
    password, and the account has never had a password somebody could type: the one it holds is one nobody knows,
    and none was replaced by such a one before (app/core/password_origin.py)."""
    if password_less(provider):
        return True
    if linked_by != MADE_AT_A_FIRST_SIGN_IN or not made_here_holds_no_password(provider):
        return False
    from app.core import password_origin
    return password_origin.nobody_knows(user) and not password_origin.has_had_one(user)


def held_by_a_password_less_provider(db, user) -> bool:
    """Whether ``user`` is linked to a provider whose people hold no password at all: the one case in which an
    account that signs in only through its provider cannot be given a standing that needs a password."""
    from app.core.models import ExternalIdentity, SsoProvider
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if provider is not None and password_less(provider):
            return True
    return False


def should_be_sso_only(db, user, *, also=None, also_by=None, without=None) -> bool:
    """The rule the flag follows: linked to at least one provider that holds the account to no password
    (:func:`holds_to_no_password`), and not an account that must keep a password of its own (an administrator, a
    holder of the auditor right), whatever it is linked to. ``also`` is a provider being linked in this
    transaction (``also_by``: how), ``without`` an identity being removed in it.

    The links and settings that would put a privileged account on such a provider are refused where they are
    made. The state exists all the same: an account that signs in only through its provider was made an
    administrator, or given the auditor right, by an earlier release run for a while after going back to it,
    which knows nothing of the flag. Such an account is never flagged here, so settling it gives it its password
    back and never fails the request that met it."""
    from app.core.models import ExternalIdentity, SsoProvider
    if privileged_accounts.kind(db, user) is not None:
        return False
    if also is not None and holds_to_no_password(also, user, also_by):
        return True
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        if without is not None and identity.id == without.id:
            continue
        provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if provider is not None and holds_to_no_password(provider, user, getattr(identity, "linked_by", None)):
            return True
    return False


MADE, RESTORED = "made_sso_only", "restored"


def read_again(db, user, names) -> None:
    """Read ``names`` of ``user`` again as they are committed, each unless the caller has set it on the account
    and not written it yet (the role of a demotion that is being made, a password that is being set). Read
    again, such a value would be put back to what the database still holds: the caller's change undone without a
    word, while everything it did beside it stands (a demotion whose grant record and permissions were already
    dropped left an administrator with a user's permissions)."""
    refresh = getattr(db, "refresh", None)
    if refresh is None or getattr(user, "_sa_instance_state", None) is None:
        return
    from sqlalchemy import inspect
    state = inspect(user)
    written = [name for name in names if not state.attrs[name].history.has_changes()]
    if written:
        refresh(user, attribute_names=written)


def settle(db, user, *, also=None, also_by=None, without=None, keep_session=None,
           unknown_hash=None) -> Optional[str]:
    """Bring ``user``'s flag in line with the providers it is linked to, in the caller's transaction: ``MADE`` when
    the account now signs in only through its providers (its password replaced, SFTP password sign-in off),
    ``RESTORED`` when it may hold a password again (nothing is minted), None when nothing changed. An account
    that must keep a password of its own is never made provider-only and is given its password back when it is
    met flagged (:func:`should_be_sso_only`); nothing is raised for it. ``unknown_hash``: the hash to write where
    a password is replaced, made beforehand by a caller that settles many accounts under a lock."""
    should = should_be_sso_only(db, user, also=also, also_by=also_by, without=without)
    flagged = bool(getattr(user, "sso_only", False))
    if should == flagged:
        # Nothing to change, and no turn is taken here: a save or a removal settles every account linked to its
        # provider, and takes a turn only for those it changes. What settles one account because its links
        # change holds that account's turn before it calls this (a link:
        # app/services/sso_sign_in.decide_in_the_accounts_turn; an unlink: its route), so its decision is made on
        # the flag as committed. Known, and left: two saves that let two providers' people hold a password again
        # at one moment each still see the other provider holding an account linked to both, and both leave it
        # held. It signs in through either meanwhile, and the next settling of the account lets it go.
        return None
    if getattr(user, "id", None) is not None:
        # A change is to be made: the account's turn at its sessions, and the decision made again in it. What
        # unlinks an identity, and what links one, hold the turn too, so the change is decided on the links, the
        # flag and the role as they are, not as they were a moment before a change that is being made (decided on
        # the old ones, it left an account held to no password with no provider). Only what is read again is
        # read again: nothing else the caller set on the account is touched. The password is among it: whether
        # it is still the one nobody knows decides for an account made at a first sign-in, and a password set a
        # moment ago (a reset link used) is written in this same turn.
        from app.api import api_server as api
        api._sessions_turn(db, user.id)
        read_again(db, user, ["sso_only", "role", "password_hash", "password_nobody_knows", "had_a_password_at"])
        should = should_be_sso_only(db, user, also=also, also_by=also_by, without=without)
        flagged = bool(getattr(user, "sso_only", False))
    if should and not flagged:
        make_sso_only(db, user, keep_session=keep_session, unknown_hash=unknown_hash)
        return MADE
    if flagged and not should:
        allow_password_sign_in(db, user, keep_password=privileged_accounts.kind(db, user) is not None,
                               unknown_hash=unknown_hash)
        return RESTORED
    return None


# What an account stopped being, for the sentence it is told.
WAS_AN_ADMINISTRATOR = "is no longer an administrator"
HELD_THE_AUDITOR_RIGHT = "no longer holds the auditor right"

# Work for after a commit (app/core/after_commit.py): the notice to an account held to its provider again, and the
# settling of an account whose auditor grant has ended.
_HELD_AGAIN = "sso_only.held_again"
_GRANT_ENDED = "sso_only.grant_ended"


def settle_when_a_privilege_ends(db, user, *, standing: str) -> Optional[str]:
    """``user`` has just stopped being an administrator, or holding the auditor right, in the caller's
    transaction (``standing``: which). An account with that standing keeps a password of its own whatever its
    providers say; without it the account's flag follows its providers again (:func:`settle`). So an account
    made at its first sign-in that was promoted and is demoted before the person chose a password signs in only
    through its provider again, as before the promotion: left as it was, it held no flag and a password nobody
    knew, and a reset link gave whoever asked a password, for good. The promotion's own link is refused from
    here on (the account is flagged). The person is told once the transaction commits.

    The account's turn is the caller's to hold before it changes the account (every demotion takes it). What the
    caller has set and not written (the new role) is decided on as set, and stays (:func:`read_again`)."""
    from app.core.models import ExternalIdentity
    from app.core.table_presence import has_table
    if not has_table(db, ExternalIdentity.__tablename__):
        return None                 # a database built without the identity tables links nobody to a provider
    outcome = settle(db, user)
    if outcome == MADE and getattr(db, "info", None) is not None:
        names, _buttons = _providers_to_name(db, user)
        through = " or ".join(names) or "your organisation's sign-in"
        after_commit.later(db, _HELD_AGAIN, (user.id, user.username, user.email, (
            f"Your account signs in only through {through}"), (
            f"Your account {standing}. It signs in only through {through} from now on: its password and its "
            "SFTP password sign-in no longer work.")))
    return outcome


def after_a_grant_ended(db, user_id) -> None:
    """An auditor grant of ``user_id`` has just stopped being open, in the caller's transaction. Once that
    transaction commits, the account's password rule is settled in a transaction of its own
    (:func:`settle_when_a_privilege_ends`).

    Not in the caller's: what ends a grant holds the grant's row, and the settling takes the account's turn at
    its sessions. A change of the account's sign-in details takes the turn first and the grant's row after it,
    so the two orders in one transaction each would wait for each other."""
    if user_id is not None and getattr(db, "info", None) is not None:
        after_commit.later(db, _GRANT_ENDED, str(user_id))


def _settle_after_a_grant_ended(user_ids) -> None:
    import logging
    import uuid
    from app.core.database import get_db_context
    from app.core.models import User
    for user_id in dict.fromkeys(user_ids):
        try:
            with get_db_context() as db:
                user = db.get(User, uuid.UUID(str(user_id)))
                if user is not None:
                    settle_when_a_privilege_ends(db, user, standing=HELD_THE_AUDITOR_RIGHT)
        except Exception as exc:  # noqa: BLE001 -- the grant's end is committed; the account's next settling decides
            logging.getLogger(__name__).warning("an account was not settled after its auditor grant ended: %s",
                                                type(exc).__name__)


def _tell_held_again(notices) -> None:
    from app.api import sso_providers_router
    for user_id, username, email, title, change in notices:
        sso_providers_router._tell_accounts([(user_id, username, email)], title, change)


after_commit.handler(_GRANT_ENDED, _settle_after_a_grant_ended)
after_commit.handler(_HELD_AGAIN, _tell_held_again)


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
    names, buttons = _providers_to_name(db, user)
    if not names:
        return NO_PROVIDER_ON
    through = " or ".join(names)
    if buttons:
        return (f"Your organisation signs this account in through {through}. Use the "
                + " or ".join(f"“{b}”" for b in buttons) + " button on the sign-in page.")
    return (f"Your organisation signs this account in through {through}. Use the sign-in link your organisation "
            "gave you.")


# What an account that signs in only through its provider is told where no provider it is linked to is on.
NO_PROVIDER_ON = ("Your organisation signs this account in through its own sign-in, which is not available on this "
                  "vault right now. Ask your administrator.")


def another_way_in(db, user, *, without) -> bool:
    """Whether ``user`` is linked to a provider that is on by an identity other than ``without``, one its provider
    has not refused: a way to sign in once ``without`` is gone, for an account that has no password it can type.
    A refusal in force lets nobody in through that identity until the provider admits the person again or an
    administrator clears it, so it is no way in to count on."""
    from app.core.models import ExternalIdentity, SsoProvider
    from app.services import sso_freshness
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        if identity.id == getattr(without, "id", None) or sso_freshness.refusal_in_force(identity):
            continue
        row = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if row is not None and getattr(row, "state", None) == "enabled":
            return True
    return False


def _providers_to_name(db, user) -> tuple:
    """(the names, the button labels) of the enabled providers ``user`` is linked to, each once, in the order found."""
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
    return names, buttons


def passkey_after_the_provider_message(db, user) -> str:
    """What a person is told when a passkey by itself would sign in an account whose password nobody knows: where
    the account signs in, that the passkey confirms them after that sign-in, and what makes the passkey a sign-in
    of its own. An account no enabled provider vouches for (its password was taken back when it was made an
    administrator, say, and it is linked to none) is not sent to an organisation's sign-in it does not have: what
    it needs is a password of its own. Neither is an account whose standing asks for the password at every
    sign-in (an administrator, a holder of the auditor right): through its provider it would be asked for that
    password, and its passkey never signs in by itself."""
    from app.core import privileged_accounts
    if privileged_accounts.kind(db, user) is not None or not _providers_to_name(db, user)[0]:
        return ("Your account has no password of its own yet, and your passkey signs you in by itself only once it "
                "has one. Use the password reset link you were given, or ask an administrator for one.")
    return (provider_only_message(db, user) + " Your passkey confirms it is you after that sign-in. It signs you "
            "in by itself once your account has a password of its own: ask for a password reset link.")


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
    """The accounts linked to ``provider``, by the account's id: the one order in which several accounts' turns
    are taken, so two changes that settle the same accounts never wait for each other's turn."""
    from app.core.models import ExternalIdentity, User
    ids = sorted({row.user_id for row in db.query(ExternalIdentity).filter(
        ExternalIdentity.provider_id == provider.id).all()}, key=str)
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


def apply_password_login(db, provider, *, unknown_hash=None) -> dict:
    """After ``provider``'s ``sso_password_login`` or ``sso_jit_password`` was written: settle each account linked
    to it. ``disabled`` makes each SSO-only; ``allowed`` lets each hold a password again unless a provider it is
    linked to still holds it to none (no link is minted); the second setting does the same for the accounts made
    at a first sign-in through the provider that have no password of their own. Returns the usernames changed:
    ``{"made_sso_only": [...], "restored": [...]}``, each sorted. Call :func:`disabled_refusal` first for
    ``disabled``. ``unknown_hash``: made by the caller before it took the provider's row, and written to each
    account whose password is replaced."""
    changed = {MADE: [], RESTORED: []}
    for user in linked_accounts(db, provider):
        outcome = settle(db, user, unknown_hash=unknown_hash)
        if outcome is not None:
            changed[outcome].append(user.username)
    return {MADE: sorted(changed[MADE]), RESTORED: sorted(changed[RESTORED])}
