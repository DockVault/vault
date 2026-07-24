"""
Dashboard API endpoints for role-based dashboard views.
Provides real-time statistics, recent events, and system status.

Performance: All endpoints support ETag-based conditional responses
to reduce network traffic and latency for frequently-polled data.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, select

from app.core.database import get_db
from app.core.models import User, Vault, vault_members, TemporaryCredential, AuditLog, ActiveSession, RoleEnum
from app.core.endpoint_permissions import require_endpoint_permission
from app.core.response_hash_utils import handle_conditional_response

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
security_scheme = HTTPBearer()


# =============================================================================
# Dependencies
# =============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to get the current authenticated user for the /api/dashboard plane.

    Delegates to the ONE hardened dependency (api_server.get_current_user) so there is a single
    source of truth for authentication: the token denylist + durable ActiveSession.revoked check,
    temp-session is_active/grace/lifetime validation, account_locked, and attach_scope (which sets
    _is_temp_session — read by _is_interactive_admin below). The previous bespoke copy OMITTED the
    temp-session lifetime + account_locked checks, so a deactivated/locked temp credential kept
    reading the dashboard aggregates until its token expired.

    The import is LAZY (inside the body): api_server imports this module at load time to mount the
    router, so a module-level import would be circular. By request time api_server is fully loaded.
    """
    from app.api.api_server import get_current_user as _hardened_get_current_user
    return await _hardened_get_current_user(credentials, db)


def _is_interactive_admin(user) -> bool:
    """A real admin session, excluding admin-minted temporary credentials (a temp cred is a scoped
    delegation, not a full interactive admin)."""
    return user.role == RoleEnum.ADMIN and not getattr(user, "_is_temp_session", False)


@router.get("/stats")
@require_endpoint_permission("DASHBOARD_VIEW")
async def get_dashboard_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Response:
    """
    Get dashboard statistics based on user role.
    - Admin: System-wide statistics
    - User: Personal statistics
    - External: Limited statistics (accessible vaults only)
    
    Performance: Supports ETag caching (polled every 30s).
    Returns 304 Not Modified if data unchanged, reducing traffic by ~70%.
    """
    stats = {}
    
    if _is_interactive_admin(current_user):
        # Admin sees everything
        stats["vaults"] = db.query(Vault).count()
        stats["users"] = db.query(User).filter(User.is_active == True).count()
        stats["temp_creds"] = db.query(TemporaryCredential).filter(
            TemporaryCredential.is_active == True,
            TemporaryCredential.expires_at > datetime.now(timezone.utc)
        ).count()
        stats["active_sessions"] = db.query(ActiveSession).count()
        
        # Calculate total storage (sum of all vault total_size_bytes)
        total_storage = db.query(func.sum(Vault.total_size_bytes)).scalar() or 0
        stats["storage_mb"] = round(total_storage / (1024 * 1024), 2)
        
    elif current_user.role in (RoleEnum.USER, RoleEnum.ADMIN) and not getattr(current_user, "_is_temp_session", False):
        # A regular USER sees only their OWN statistics — never deployment-wide.
        # A temporary credential is EXCLUDED here even though it carries the minting admin's ADMIN
        # role + user_id: the owner-aggregate storage/file-count below is keyed on that shared
        # user_id, so a scoped credential would learn the admin's whole-deployment file count and
        # storage (an out-of-scope aggregate leak). It falls through to the minimal branch instead.
        # Vaults they own
        owned_vaults = db.query(Vault).filter(Vault.owner_id == current_user.id).count()
        
        # Vaults they have access to (as member) - query the association table
        member_vaults = db.execute(
            select(func.count()).select_from(vault_members).where(
                vault_members.c.user_id == current_user.id
            )
        ).scalar() or 0
        
        stats["vaults"] = owned_vaults
        stats["accessible_vaults"] = owned_vaults + member_vaults
        
        # Their temp credentials
        stats["temp_creds"] = db.query(TemporaryCredential).filter(
            TemporaryCredential.user_id == current_user.id,
            TemporaryCredential.is_active == True,
            TemporaryCredential.expires_at > datetime.now(timezone.utc)
        ).count()
        
        # Their storage usage (only owned vaults)
        user_storage = db.query(func.sum(Vault.total_size_bytes)).filter(
            Vault.owner_id == current_user.id
        ).scalar() or 0
        stats["storage_mb"] = round(user_storage / (1024 * 1024), 2)
        
        # Their files count (across owned vaults)
        stats["files"] = db.query(func.sum(Vault.file_count)).filter(
            Vault.owner_id == current_user.id
        ).scalar() or 0
        
    else:  # EXTERNAL
        # External users see minimal stats
        # Vaults they have access to (as member only, cannot own) - query the association table
        member_vaults = db.execute(
            select(func.count()).select_from(vault_members).where(
                vault_members.c.user_id == current_user.id
            )
        ).scalar() or 0
        
        stats["accessible_vaults"] = member_vaults
        
        # Their temp credentials
        stats["temp_creds"] = db.query(TemporaryCredential).filter(
            TemporaryCredential.user_id == current_user.id,
            TemporaryCredential.is_active == True,
            TemporaryCredential.expires_at > datetime.now(timezone.utc)
        ).count()
    
    stats["role"] = current_user.role.value
    
    # Use conditional response with ETag to reduce traffic
    return handle_conditional_response(request, stats)


@router.get("/recent-events")
@require_endpoint_permission("DASHBOARD_VIEW")
async def get_recent_events(
    request: Request,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Response:
    """
    Get recent events from audit logs based on user role.
    - Admin: All system events
    - User/External: Only their own events
    
    Performance: Supports ETag caching to reduce redundant event data transfer.
    """
    # Clamp the client-supplied limit: an unbounded value over-fetches + serializes an arbitrarily
    # large result set (memory/CPU/response-size DoS), and a negative value errors. Mirror the
    # bounded audit-search sibling.
    limit = max(1, min(limit, 100))

    # A temporary credential is a scoped share, not an operator, and it carries the minting admin's
    # shared user_id — so "its own events" would resolve to the admin's deployment-wide audit trail
    # (resource ids, actions, and — for renames — cleartext names, across every vault/folder). It
    # must see no audit feed, consistent with the interactive-admin-only /audit/events sibling.
    if getattr(current_user, "_is_temp_session", False):
        return handle_conditional_response(request, [])

    query = db.query(AuditLog).order_by(desc(AuditLog.timestamp))

    if not _is_interactive_admin(current_user):
        # Non-admin interactive users only see their own events, never the deployment-wide trail.
        query = query.filter(AuditLog.user_id == current_user.id)

    events = query.limit(limit).all()
    
    events_data = [
        {
            "id": str(event.id),
            "action": event.action,
            "username": event.username,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "status": event.status,
            "details": event.details,
            "ip_address": event.ip_address
        }
        for event in events
    ]
    
    # Use conditional response with ETag to reduce traffic
    return handle_conditional_response(request, events_data)


@router.get("/active-connections")
@require_endpoint_permission("DASHBOARD_VIEW")
async def get_active_connections(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Response:
    """
    Get active SFTP connections.
    Only available to admins.
    
    Performance: Supports ETag caching for connection list.
    """
    if not _is_interactive_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view active connections"
        )
    
    # Get only ACTIVE sessions (is_active == True)
    # Sessions are marked inactive by the cleanup task if last_activity is too old
    sessions = db.query(ActiveSession).filter(
        ActiveSession.is_active == True
    ).order_by(desc(ActiveSession.last_activity)).limit(10).all()
    
    connections = []
    for session in sessions:
        user = db.query(User).filter(User.id == session.user_id).first()
        
        # Calculate session duration, handling both timezone-aware and naive datetimes
        session_duration = 0
        if session.started_at:
            now = datetime.now(timezone.utc)
            # Make started_at timezone-aware if it isn't already
            started_at = session.started_at if session.started_at.tzinfo else session.started_at.replace(tzinfo=timezone.utc)
            session_duration = round((now - started_at).total_seconds() / 60)
        
        connections.append({
            "id": str(session.id),
            "username": user.username if user else "Unknown",
            "is_temporary": session.temp_credential_id is not None,
            "ip_address": session.ip_address,
            "created_at": session.started_at.isoformat() if session.started_at else None,
            "last_activity": session.last_activity.isoformat() if session.last_activity else None,
            "session_duration_minutes": session_duration
        })
    
    # Use conditional response with ETag to reduce traffic
    return handle_conditional_response(request, connections)
