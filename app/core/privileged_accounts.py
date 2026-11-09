"""Accounts that reach other people's vaults by their standing: an administrator, or one with an open auditor grant
(proposed, active or suspended). In this vault only an administrator can approve a compliance case, so the case
approvers are the administrators. Such an account is never linked or made through a provider's verified-email path
(a provider-side takeover of an address must not reach it silently; it links only from its own signed-in profile
under step-up), and never made SSO-only (it needs a local password for the fixed step-ups).
"""
from __future__ import annotations

from typing import Optional

ADMINISTRATOR = "administrator"
AUDITOR_RIGHT = "auditor_right"
TEXTS = {ADMINISTRATOR: "an administrator", AUDITOR_RIGHT: "holding the auditor right, or a proposal for it"}


def kind(db, user) -> Optional[str]:
    """``ADMINISTRATOR``, ``AUDITOR_RIGHT`` or None for an account with no such standing."""
    from app.core import auditor_rights
    from app.core.models import RoleEnum
    if user is None:
        return None
    if getattr(user, "role", None) == RoleEnum.ADMIN:
        return ADMINISTRATOR
    if getattr(db, "get_bind", None) is not None and not auditor_rights._has_grants(db):
        return None            # a database without the grants table holds no grant
    if auditor_rights.open_grant(db, getattr(user, "id", None)) is not None:
        return AUDITOR_RIGHT
    return None
