"""Whose account a caller may change: never one whose role is above the caller's own.

An administrator can give a person who is not one the permission to manage users. That permission
reaches a few routes that change someone else's account (a password reset link, copied or emailed).
Without a check on WHOSE account, such a person could make a reset link for an administrator, set the
administrator's password with it and sign in as them: a way from managing users to administering the
whole deployment that nobody granted.

So a caller who is not an interactive administrator may change only an account whose role is not
above theirs, and never an administrator's. Roles rank administrator above user above external. An
interactive administrator (not a temporary credential) may change any account, as before; the other
rules on each route still apply to them (the last administrator, the two-administrator rule on
credential changes).

What counts as changing an account: its sign-in credentials (a password, a reset link, a second factor,
an email address, an SSH key), its identity, its role, whether it is active or locked, its sessions,
and deleting it. Every route that does one of those to someone else's account either requires an
interactive administrator outright or asks :func:`refusal` first
(tests/test_account_authority.py holds the list).

A password reset link is used later, by whoever holds it, and the account it is for may have changed
by then (made an administrator), or its maker may have (demoted, deactivated, locked, deleted, the
permission taken away). So a link made for someone else's account is judged again when it is used
(:func:`link_refusal`), by the same rule, as its maker and the account stand then.

Nothing here touches the database.
"""
from typing import Optional

from app.core.models import RoleEnum

# Why a caller may not change an account (refusal).
ADMINISTRATOR = "administrator"   # the account is an administrator's, and the caller is not one
HIGHER_ROLE = "higher_role"       # the account's role is above the caller's

_RANK = {RoleEnum.EXTERNAL: 0, RoleEnum.USER: 1, RoleEnum.ADMIN: 2}

# Why a link made for someone else's account no longer stands (link_refusal), besides the two above.
MAKER_DELETED = "maker_deleted"            # the account that made it no longer exists
MAKER_INACTIVE = "maker_inactive"          # it was deactivated
MAKER_LOCKED = "maker_locked"              # an administrator locked it
MAKER_WITHOUT_PERMISSION = "maker_without_permission"   # it may no longer manage users

DETAILS = {
    ADMINISTRATOR: "Only an administrator can change an administrator's account.",
    HIGHER_ROLE: "You cannot change the account of someone whose role is above yours.",
}


def _role(value):
    """A role as RoleEnum, from the enum or its stored text; None when it is neither."""
    if isinstance(value, RoleEnum):
        return value
    try:
        return RoleEnum(str(value))
    except ValueError:
        return None


def rank(role) -> int:
    """Where a role stands: external 0, user 1, administrator 2. An unknown role ranks lowest."""
    return _RANK.get(_role(role), -1)


def acts_as_administrator(caller) -> bool:
    """An administrator signed in as themselves. A temporary credential keeps its maker's role, but
    never acts as an administrator here."""
    return _role(getattr(caller, "role", None)) == RoleEnum.ADMIN and not getattr(caller, "_is_temp_session", False)


def refusal(caller, target) -> Optional[str]:
    """Why ``caller`` may not change ``target``'s account (ADMINISTRATOR or HIGHER_ROLE), or None when
    they may. ``caller`` None is the server's operator on the host, who may. A person's own account is
    theirs to change as far as this rule goes; the routes send them to their own settings."""
    if caller is None or acts_as_administrator(caller):
        return None
    if getattr(caller, "id", None) is not None and getattr(caller, "id", None) == getattr(target, "id", None):
        return None
    # An administrator's account first: a temporary credential keeps its maker's role, and would
    # otherwise rank as one.
    if _role(getattr(target, "role", None)) == RoleEnum.ADMIN:
        return ADMINISTRATOR
    if rank(getattr(target, "role", None)) > rank(getattr(caller, "role", None)):
        return HIGHER_ROLE
    return None


def link_refusal(maker, target, *, maker_may_manage_users: bool) -> Optional[str]:
    """Why a password reset link that ``maker`` made for ``target``'s account may not be used now, or
    None when it may. ``maker`` is the account that made it as it stands now, or None when that account
    was deleted; ``maker_may_manage_users`` whether it holds the permission to manage users now (an
    administrator always does). Only for a link someone made for another person's account: one a person
    asked for themselves, or the server's operator made on the host, is not judged here.

    Authority is judged when the link is made, and again here when it is used: the maker must still be
    able to make it (an account that exists, is active, is not locked by an administrator, and may manage
    users) for the account as it is now (:func:`refusal`, so a user who manages users never for an
    administrator, even one promoted after the link was made). A lock that wrong passwords armed pauses
    only new sign-ins, and does not count."""
    from app.services.auth_service import admin_locked
    if maker is None:
        return MAKER_DELETED
    if getattr(maker, "is_active", None) is False:
        return MAKER_INACTIVE
    if admin_locked(maker):
        return MAKER_LOCKED
    if not maker_may_manage_users:
        return MAKER_WITHOUT_PERMISSION
    return refusal(maker, target)
