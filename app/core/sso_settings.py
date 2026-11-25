"""Single sign-on in the settings registry.

The providers keep a table of their own (``sso_providers``), with each provider's policy on its row, so the
registry lists them as a group the deployment may lock: with ``SETTINGS_LOCKED_KEYS`` naming ``sso`` (or ``*``),
the providers are kept as they are: nothing is added, changed, turned on or off, or removed through the panel or
its routes. Nothing in a deployment's .env sets a provider, so the lock only keeps the rows the database holds;
whoever runs the vault lifts it to change them. The Settings page lists the group among the locked entries and keeps
the providers' card, read-only. Reading the providers and running a test sign-in stay open to an administrator.
Sign-ins go on as before.
"""
from __future__ import annotations

from app.core import settings_registry as registry

LOCK_GROUP = "sso"
PAGE = "signin"
SINCE = "0.36.0"
LOCKED_TEXT = ("Single sign-on is locked in this deployment (SETTINGS_LOCKED_KEYS): the providers are kept as they "
               "are and nothing can be changed here. Whoever runs the vault lifts the lock to change them.")


def locked(settings=None) -> bool:
    """Whether the deployment has locked the single sign-on providers."""
    return registry.group_locked(LOCK_GROUP, settings)


def _in_words() -> str:
    """What a locked group shows on the Settings pages: what the lock keeps, and what stays open."""
    return ("The providers are kept as they are: none can be added, changed, turned on or off, or removed here. "
            "Reading them and running a test sign-in stay open.")


def _register() -> None:
    registry.register_lock_group(
        LOCK_GROUP, label="Single sign-on providers", level=registry.ESSENTIAL, since=SINCE, page=PAGE,
        help="The identity providers people may sign in through, and each provider's rules: who it admits, "
             "whether it makes accounts, its groups, its sessions.",
        shown=_in_words)


_register()
