"""Single sign-on in the settings registry.

The providers keep a table of their own (``sso_providers``), with each provider's policy on its row, so the
registry lists them as a group the deployment may lock: with ``SETTINGS_LOCKED_KEYS`` naming ``sso`` (or ``*``),
the providers are the deployment's, and the panel adds, changes, turns on or off and removes nothing; it still
lists them, runs a test sign-in and shows who is linked. Sign-ins go on as before.

The group joins the registry with the page that shows it (:func:`_register`).
"""
from __future__ import annotations

from app.core import settings_registry as registry

LOCK_GROUP = "sso"
PAGE = "signin"
SINCE = "0.36.0"
LOCKED_TEXT = "Single sign-on is set by your provider on this deployment: nothing can be changed here."


def locked(settings=None) -> bool:
    """Whether the deployment has locked the single sign-on providers."""
    return registry.group_locked(LOCK_GROUP, settings)


def _in_words() -> str:
    """What a locked group shows on the Settings pages: who sets the providers."""
    return "The providers and their rules are set in the deployment."


def _register() -> None:
    registry.register_lock_group(
        LOCK_GROUP, label="Single sign-on providers", level=registry.ESSENTIAL, since=SINCE, page=PAGE,
        help="The identity providers people may sign in through, and each provider's rules: who it admits, "
             "whether it makes accounts, its groups, its sessions.",
        shown=_in_words)
