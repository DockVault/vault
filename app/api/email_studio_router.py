"""Email Studio router — admin-authored SMTP profiles, HTML templates, and image resources.

All routes are gated by ``require_interactive_admin`` (the same surface as Settings): an admin-minted
temporary credential must not manage sending identities, templates, or the private resource folder.
Kept in its own module so the bulk of this feature stays out of api_server.py.

This module currently registers the router with the shared dynamic-action catalog; the profile,
template, resource, and sending endpoints fill in the rest of the CRUD.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.models import RoleEnum, User
from app.core import email_sanitize

security_scheme = HTTPBearer()


# --------------------------------------------------------------------------------------------------
# Auth dependencies (mirrors user_management_api: lazy-import the hardened chain to avoid a cycle —
# api_server imports THIS module at load time to mount the router). Defined BEFORE the router so it
# can carry a router-level dependency: every route on this router is then admin-gated by default,
# and no future CRUD/send route can accidentally ship unguarded.
# --------------------------------------------------------------------------------------------------

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    from app.api.api_server import get_current_user as _hardened_get_current_user
    return await _hardened_get_current_user(credentials, db)


async def require_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    if current_user.role != RoleEnum.ADMIN:
        from app.api.api_server import _audit_admin_denial
        _audit_admin_denial(db, current_user, "admin role required")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


async def require_interactive_admin(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    """Admin, and NOT a temporary-credential session — the Email Studio is an org-policy surface."""
    if getattr(current_user, "_is_temp_session", False):
        from app.api.api_server import _audit_admin_denial
        _audit_admin_denial(db, current_user,
                            "interactive admin session required (temp credential rejected)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an interactive admin session, not a temporary credential.",
        )
    return current_user


# Router-level gate: EVERY route below requires an interactive admin session. Individual routes that
# need the admin User object still add `Depends(require_interactive_admin)` as a parameter.
router = APIRouter(tags=["Email Studio"], dependencies=[Depends(require_interactive_admin)])


# --------------------------------------------------------------------------------------------------
# Shared catalog
# --------------------------------------------------------------------------------------------------

@router.get("/dynamic-actions")
async def list_dynamic_actions(
    _admin: User = Depends(require_interactive_admin),
):
    """The personalization tokens the template editor's 'Add Dynamic Action' dropdown offers.

    Server-owned so the accepted set and the UI list can never drift. Values are substituted per
    recipient at send time (see app.core.email_sanitize)."""
    return {
        "actions": [
            {"token": a.token, "label": a.label, "sample": a.sample}
            for a in email_sanitize.DYNAMIC_ACTIONS
        ]
    }
