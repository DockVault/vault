"""
Enhanced User Management API Endpoints
Provides comprehensive user management with temp credentials, roles, and activity logging
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import uuid
import os
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from pydantic import BaseModel, EmailStr, Field

from app.core.database import get_db
from app.core.auth_offload import auth_offload_slot, run_offloaded
from app.core.email_identity import email_in_use, normalize_email
from app.core.last_admin import LAST_ADMIN_DETAIL, removes_last_admin
from app.core.models import User, TemporaryCredential, RoleEnum, AuditLog, ActiveSession
from app.services.auth_service import AuthService
from app.services.audit_logger import AuditLogger
from app.core.endpoint_permissions import require_endpoint_permission

security_scheme = HTTPBearer()

# =============================================================================
# Hash Utilities for Conditional Updates
# =============================================================================

def compute_response_hash(data: any) -> str:
    """
    Compute SHA-256 hash of response data for conditional updates.
    This allows client to skip DOM updates if data hasn't changed.
    """
    # Convert Pydantic models or lists to JSON string, converting UUIDs and dates to strings
    if hasattr(data, 'model_dump'):
        json_str = json.dumps(data.model_dump(mode='json'), default=str, sort_keys=True)
    elif isinstance(data, list):
        json_str = json.dumps([item.model_dump(mode='json') if hasattr(item, 'model_dump') else item for item in data], default=str, sort_keys=True)
    else:
        json_str = json.dumps(data, default=str, sort_keys=True)
    
    return hashlib.sha256(json_str.encode()).hexdigest()

def check_if_none_match(request: Request, current_hash: str) -> bool:
    """
    Check if client's If-None-Match header matches current hash.
    Returns True if content hasn't changed (should return 304).
    """
    if_none_match = request.headers.get('If-None-Match')
    if not if_none_match:
        return False
    # RFC 7232 §3.2: "*" matches any; otherwise a comma list of (weak-prefixed) quoted ETags.
    if if_none_match.strip() == '*':
        return True
    for tag in if_none_match.split(','):
        tag = tag.strip()
        if tag.startswith('W/'):
            tag = tag[2:].strip()
        if tag.strip('"') == current_hash:
            return True
    return False

# =============================================================================
# Dependencies
# =============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to get the current authenticated user for the user-management router.

    Delegates to the ONE hardened dependency (api_server.get_current_user) so there is a single
    source of truth for authentication: the token denylist + durable ActiveSession.revoked check,
    temp-session is_active/grace/lifetime validation, account_locked, and attach_scope (temp-cred
    least privilege / the _is_temp_session flag require_interactive_admin relies on). This replaces
    a hand-synced copy that had to be kept in lock-step by hand.

    The import is LAZY (inside the body): api_server imports this module at load time to mount the
    router, so a module-level import would be circular. By request time api_server is fully loaded.
    """
    from app.api.api_server import get_current_user as _hardened_get_current_user
    return await _hardened_get_current_user(credentials, db)


async def require_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Dependency to require admin role."""
    if current_user.role != RoleEnum.ADMIN:
        # Audit the denial via the single shared helper in api_server (lazy import avoids an
        # import cycle, matching this module's get_current_user delegation above), so the
        # /api/user-management/* admin routes are not audit-blind like the api_server ones were.
        from app.api.api_server import _audit_admin_denial
        _audit_admin_denial(db, current_user, "admin role required")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


async def require_interactive_admin(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    """Admin dependency that ALSO rejects temporary-credential sessions.

    An admin-minted temp credential keeps the admin ROLE (get_current_user returns the real
    admin User; attach_scope never downgrades role), so require_admin alone would let a
    tightly-scoped temp credential perform privilege-escalating admin-plane writes such as a
    role change. Those must come from a real interactive admin session."""
    if getattr(current_user, "_is_temp_session", False):
        from app.api.api_server import _audit_admin_denial
        _audit_admin_denial(db, current_user,
                            "interactive admin session required (temp credential rejected)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an interactive admin session, not a temporary credential.",
        )
    return current_user


def require_step_up(action: str):
    """Enforce the second-factor step-up policy for `action` on this router's routes, reusing the
    single enforcement + registry that lives in api_server (imported lazily to avoid a circular
    import — api_server includes this router at load). The FastAPI ``Request`` is located by TYPE,
    not by parameter name, so a route whose ``request`` parameter is a request BODY (e.g.
    change_user_role) still works as long as it also declares a ``Request`` parameter."""
    from functools import wraps

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            from app.api.api_server import _enforce_step_up, GUARDED_STEP_UP_ACTIONS
            GUARDED_STEP_UP_ACTIONS.add(action)
            user = kwargs.get("current_user")
            db = kwargs.get("db")
            req = next((v for v in kwargs.values() if isinstance(v, Request)), None)
            if user is not None and db is not None and req is not None:
                _enforce_step_up(db, user, req, action)
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# Pydantic Models
# =============================================================================

class UserMetrics(BaseModel):
    """User metrics for dashboard"""
    total_users: int
    active_users: int
    inactive_users: int
    locked_users: int
    new_this_month: int
    active_temp_credentials: int
    total_sessions: int

class UserListItem(BaseModel):
    """User list item with summary info"""
    id: uuid.UUID
    username: str
    email: Optional[str] = None
    role: RoleEnum
    is_active: bool
    is_locked: bool
    temp_credentials_count: int
    active_sessions_count: int
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserDetailResponse(BaseModel):
    """Detailed user information"""
    id: uuid.UUID
    username: str
    email: Optional[str] = None
    role: RoleEnum
    is_active: bool
    is_locked: bool
    failed_login_attempts: int
    last_login: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[uuid.UUID]
    
    # Counts
    temp_credentials_count: int
    active_sessions_count: int
    vaults_owned_count: int
    vaults_accessible_count: int
    
    class Config:
        from_attributes = True

class UserUpdateRequest(BaseModel):
    """User update request"""
    email: Optional[EmailStr] = None
    role: Optional[RoleEnum] = None
    is_active: Optional[bool] = None

class TempCredentialListItem(BaseModel):
    """Temp credential list item"""
    id: uuid.UUID
    temp_username: str
    created_at: datetime
    expires_at: datetime
    deactivate_at: datetime
    is_active: bool
    is_used: bool
    used_at: Optional[datetime]
    has_password: bool  # Indicates if password can be revealed
    
    class Config:
        from_attributes = True

class TempCredentialCreateRequest(BaseModel):
    """Admin creates temp credential for user"""
    user_id: uuid.UUID
    validity_minutes: Optional[int] = Field(default=65, ge=1, le=1440)  # Max 24 hours

class TempCredentialCreateResponse(BaseModel):
    """Response when admin creates temp credential"""
    id: uuid.UUID
    temp_username: str
    created_at: datetime
    expires_at: datetime
    deactivate_at: datetime
    message: str

# ❌ REMOVED: TempCredentialPasswordResponse (Security Enhancement)
# Passwords are no longer retrievable after creation

class UserActivityItem(BaseModel):
    """User activity log item"""
    id: uuid.UUID
    action: str
    details: Optional[str]
    ip_address: Optional[str]
    timestamp: datetime
    performed_by_username: Optional[str]
    
    class Config:
        from_attributes = True

# =============================================================================
# Router Setup
# =============================================================================

router = APIRouter(prefix="/api/user-management", tags=["user-management"])

# =============================================================================
# User Management Endpoints
# =============================================================================

@router.get("/metrics", response_model=UserMetrics)
@require_endpoint_permission("USER_VIEW")
async def get_user_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user metrics for dashboard"""
    
    # Total users
    total_users = db.query(func.count(User.id)).scalar()
    
    # Active/inactive users
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()
    inactive_users = db.query(func.count(User.id)).filter(User.is_active == False).scalar()
    
    # Locked users
    locked_users = db.query(func.count(User.id)).filter(User.is_locked == True).scalar()
    
    # New users this month
    month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    new_this_month = db.query(func.count(User.id)).filter(User.created_at >= month_start).scalar()
    
    # Active temp credentials
    active_temp_creds = db.query(func.count(TemporaryCredential.id)).filter(
        and_(
            TemporaryCredential.is_active == True,
            TemporaryCredential.expires_at > datetime.now(timezone.utc)
        )
    ).scalar()
    
    # Total active sessions
    total_sessions = db.query(func.count(ActiveSession.id)).filter(
        ActiveSession.is_active == True
    ).scalar()
    
    return UserMetrics(
        total_users=total_users or 0,
        active_users=active_users or 0,
        inactive_users=inactive_users or 0,
        locked_users=locked_users or 0,
        new_this_month=new_this_month or 0,
        active_temp_credentials=active_temp_creds or 0,
        total_sessions=total_sessions or 0
    )

def _like_escape(value: str) -> str:
    r"""Escape LIKE/ILIKE wildcards so a user-supplied filter matches its characters
    literally (use with ``.ilike(pattern, escape="\")``). Without it, ``%`` and ``_`` in
    the input silently become pattern metacharacters -- e.g. the ``_`` in a filter like
    "file_download" matches ANY character, returning actions the caller never asked for."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/users", response_model=List[UserListItem])
@require_endpoint_permission("USER_VIEW")
async def list_users(
    request: Request,
    search: Optional[str] = Query(None, description="Search by username or email", max_length=128),
    role: Optional[RoleEnum] = Query(None, description="Filter by role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_locked: Optional[bool] = Query(None, description="Filter by locked status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all users with filtering and search (supports ETag for conditional updates)"""

    # USER_VIEW is admin-only by default; a fleet-wide user listing has no "own" subset, so if an
    # operator grants USER_VIEW to a non-admin, restrict the listing to admins (mirrors the
    # own-or-admin guard on the per-user detail route).
    if current_user.role != RoleEnum.ADMIN:
        raise HTTPException(status_code=403, detail="Listing all users requires an administrator")
    
    query = db.query(User)
    
    # Apply filters
    if search:
        search_pattern = f"%{_like_escape(search)}%"
        query = query.filter(
            or_(
                User.username.ilike(search_pattern, escape="\\"),
                User.email.ilike(search_pattern, escape="\\")
            )
        )
    
    if role:
        query = query.filter(User.role == role)
    
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    if is_locked is not None:
        query = query.filter(User.is_locked == is_locked)
    
    # Order by creation date (newest first)
    query = query.order_by(User.created_at.desc())
    
    # Pagination
    users = query.offset(skip).limit(limit).all()
    
    # Build response with counts
    result = []
    for user in users:
        temp_creds_count = db.query(func.count(TemporaryCredential.id)).filter(
            TemporaryCredential.user_id == user.id
        ).scalar()
        
        sessions_count = db.query(func.count(ActiveSession.id)).filter(
            and_(
                ActiveSession.user_id == user.id,
                ActiveSession.is_active == True
            )
        ).scalar()
        
        result.append(UserListItem(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            is_locked=user.is_locked,
            temp_credentials_count=temp_creds_count or 0,
            active_sessions_count=sessions_count or 0,
            last_login=user.last_login,
            created_at=user.created_at
        ))
    
    # Compute hash of response data
    response_hash = compute_response_hash(result)
    
    # Check if client already has this data
    if check_if_none_match(request, response_hash):
        return Response(status_code=304)  # Not Modified
    
    # Convert to JSON-serializable format and return with ETag
    content = json.dumps([item.model_dump(mode='json') for item in result], default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"ETag": f'"{response_hash}"'}
    )

@router.get("/users/{user_id}", response_model=UserDetailResponse)
@require_endpoint_permission("USER_VIEW")
async def get_user_detail(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed user information (supports ETag for conditional updates)"""

    # Own-or-admin (checked BEFORE the existence lookup to avoid an enumeration oracle): USER_VIEW is
    # admin-only by default, but the catalog's requires_ownership flag is display-only and NOT enforced
    # by require_endpoint_permission — so if an operator grants USER_VIEW to a non-admin, enforce
    # ownership here, mirroring the temp-cred / activity siblings.
    if current_user.role != RoleEnum.ADMIN and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="You can only view your own user record")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get counts
    temp_creds_count = db.query(func.count(TemporaryCredential.id)).filter(
        TemporaryCredential.user_id == user.id
    ).scalar()
    
    sessions_count = db.query(func.count(ActiveSession.id)).filter(
        and_(
            ActiveSession.user_id == user.id,
            ActiveSession.is_active == True
        )
    ).scalar()
    
    vaults_owned_count = len(user.vaults_owned)
    vaults_accessible_count = len(user.vaults_accessible)
    
    result = UserDetailResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        is_locked=user.is_locked,
        failed_login_attempts=user.failed_login_attempts,
        last_login=user.last_login,
        created_at=user.created_at,
        updated_at=user.updated_at,
        created_by=user.created_by,
        temp_credentials_count=temp_creds_count or 0,
        active_sessions_count=sessions_count or 0,
        vaults_owned_count=vaults_owned_count,
        vaults_accessible_count=vaults_accessible_count
    )
    
    # Compute hash of response data
    response_hash = compute_response_hash(result)
    
    # Check if client already has this data
    if check_if_none_match(request, response_hash):
        return Response(status_code=304)  # Not Modified
    
    # Convert to JSON-serializable format and return with ETag
    content = json.dumps(result.model_dump(mode='json'), default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"ETag": f'"{response_hash}"'}
    )

def _blacklist_user_vault_keys(db: Session, user_id, revoked_by) -> int:
    """Offboarding: deactivate a user's active wrapped-DEK rows so the server can no longer hand
    them a zero-knowledge vault key. Called when a user is DEACTIVATED. Forward secrecy for NEW
    content still needs a manual manager rotation (the server holds no DEK) — the affected vaults
    surface as 'rekey owed' on the /ecc keys endpoint. Standard-vault access (the vault_members
    authz rows) is left untouched; this only removes ZK key access.

    OWNER CARVE-OUT: a user's key for a vault they OWN is never blacklisted — the same
    owner-protection every other ZK path enforces (revoke / rekey refuse the owner, the orphan
    reconciler skips owner rows). Blacklisting the owner's row would drop the vault's guaranteed
    key-holder — and for a sole-owner vault that is irreversible (no client left holds the DEK to
    re-wrap it), bricking the vault. A departing OWNER is an ownership-transfer problem, not a
    key-blacklist one, so their owned vaults are left intact. Returns the count blacklisted.

    LOCKING: each affected vault's row is locked (SELECT ... FOR UPDATE, in ascending id order)
    before that vault's keys are read and switched off. It is the lock a key rotation holds from its
    key-holder check to its commit, and that removing a member takes. Without it, a rotation in
    flight could commit an active key for this user at the new epoch just after the old ones were
    switched off here, and the vault would report no rotation owed. With it, a rotation in flight
    commits first and the key it wrote is switched off here with the rest; one that starts later
    finds this user's keys already off.

    Call this BEFORE anything in the same transaction locks a user row (the last-administrator
    check locks every administrator's). A path that holds a vault row lock may go on to wait for a
    user row -- writing a key row checks the users it names -- so vault rows are always locked
    first. Nothing is committed here; the caller commits."""
    from app.core.models import VaultMemberKey, Vault
    now = datetime.now(timezone.utc)
    owned_vault_ids = {vid for (vid,) in db.query(Vault.id).filter(Vault.owner_id == user_id).all()}

    def active_keys():
        # populate_existing: a row read before a lock is re-read as it stands after it.
        return db.query(VaultMemberKey).populate_existing().filter(
            VaultMemberKey.user_id == user_id,
            VaultMemberKey.is_active == True,  # noqa: E712
        ).all()

    locked = set()
    rows = active_keys()
    while True:
        # Every vault on the first pass. A later pass finds one only if the user was given a key
        # in another vault while this waited for a lock; it is locked then, after the others.
        waiting = {mk.vault_id for mk in rows} - owned_vault_ids - locked
        if not waiting:
            break
        db.query(Vault.id).filter(Vault.id.in_(waiting)).order_by(Vault.id).with_for_update().all()
        locked |= waiting
        rows = active_keys()   # read again under the locks: a rotation that held one has committed
    blacklisted = 0
    for mk in rows:
        if mk.vault_id in owned_vault_ids:
            continue  # never blacklist the owner's own key (would brick the vault)
        mk.is_active = False
        mk.revoked_at = now
        mk.revoked_by = revoked_by
        blacklisted += 1
    return blacklisted


@router.put("/users/{user_id}", response_model=UserDetailResponse)
@require_endpoint_permission("USER_MANAGE")
@require_step_up("admin.user.manage")
async def update_user(
    user_id: uuid.UUID,
    update_data: UserUpdateRequest,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Update user information (interactive admin only — sets role/is_active; a temp
    credential must not escalate roles)."""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # The same refusals as the dedicated role and activate endpoints, and PATCH /users/{id}: an
    # administrator cannot change their own role or deactivate themselves, and no change may leave
    # the deployment without an administrator who can act. Both are checked before any field is set,
    # because the second reloads the row under a lock. Resaving an unchanged role is not a change.
    changes_role = update_data.role is not None and update_data.role != user.role
    if current_user.id == user_id:
        if changes_role:
            raise HTTPException(status_code=400, detail="Cannot change your own role")
        if update_data.is_active is False:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    # Offboarding: deactivating a user switches off their zero-knowledge vault keys. That locks the
    # vaults the keys belong to, so it comes before the check below locks the administrator rows:
    # vault rows are always locked before user rows (see _blacklist_user_vault_keys). Nothing is
    # committed unless every check passes.
    if update_data.is_active is False and user.is_active:
        _blacklist_user_vault_keys(db, user.id, current_user.id)
    if user.role == RoleEnum.ADMIN and (changes_role or update_data.is_active is False):
        if removes_last_admin(db, user):
            raise HTTPException(status_code=400, detail=LAST_ADMIN_DETAIL)

    # Update fields
    held = []   # credential changes waiting for another administrator's approval
    made = []   # credential changes made, for the user's notice
    old_role, old_active = user.role.value if user.role is not None else None, user.is_active
    # Omitting "email" leaves the address alone; sending it as an explicit null clears it. The
    # previous `is not None` test collapsed those two into one, so an address could be replaced but
    # never removed.
    if "email" in update_data.model_fields_set:
        new_email = normalize_email(update_data.email)
        # Changing your OWN email is a self-service act that must re-prove the current password (and,
        # when the org requires it, an emailed code) — even for an admin. This management route only
        # sets another user's email; an admin editing their own address is redirected to account
        # settings, matching PATCH /users/{id}. A no-op resave of one's own address is not a change.
        if current_user.id == user_id and new_email != user.email:
            raise HTTPException(
                status_code=400,
                detail="Change your own email from account settings, which requires your "
                       "current password.")
        # Case-insensitive: the previous `==` let an admin store BOB@x.com beside bob@x.com.
        if new_email is not None and email_in_use(db, new_email, exclude_user_id=user_id):
            raise HTTPException(status_code=400, detail="Email already in use")
        # Someone else's address is a credential change: the second one within 14 days waits for
        # another administrator. The same rule and code as PATCH /users/{id}
        # (app/core/credential_changes.py). Resaving the same address is not a change.
        if new_email != user.email:
            from app.api.api_server import _credential_change
            outcome = _credential_change(
                db, current_user, user, "email",
                summary=f"Change the email address to {new_email}" if new_email else "Remove the email address",
                payload={"email": new_email}, request=request)
            if outcome.held:
                held.append(outcome)
            else:
                made.append(outcome)

    if update_data.role is not None:
        user.role = update_data.role
    
    if update_data.is_active is not None:
        was_active = user.is_active
        user.is_active = update_data.is_active
        # Offboarding also revokes the user's sessions durably (see toggle_user_active); their
        # zero-knowledge vault keys were switched off above.
        if was_active and not user.is_active:
            from app.api.api_server import _revoke_sessions
            _revoke_sessions(db, user_id=user.id, actor_username=current_user.username)

    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    
    # Log the action
    audit_logger = AuditLogger(db)
    audit_logger.log_custom_action(
        user=current_user,
        action="USER_UPDATED",
        details=f"Updated user {user.username}",
        ip_address=None
    )

    # The user hears of every change an administrator made to their address or standing.
    if current_user.id != user_id:
        from app.api.api_server import _notify_account_status_changes, _notify_credential_change
        for outcome in made:
            _notify_credential_change(db, "email", user, outcome.result, by_name=current_user.username)
        _notify_account_status_changes(
            db, user, by_name=current_user.username, active=(old_active, user.is_active),
            role=(old_role, user.role.value if user.role is not None else None))
    
    # Return updated details
    # Keyword args, not positional: get_user_detail is wrapped by require_endpoint_permission,
    # whose wrapper reads current_user and db out of **kwargs. Called positionally they arrive as
    # *args, the wrapper sees None for both, and every call returned 401 -- AFTER this function had
    # already committed the change. The caller saw a failure that had in fact succeeded.
    detail = await get_user_detail(
        user_id=user_id, request=request, current_user=current_user, db=db
    )
    if held:
        # The rest of the update was saved; the address change waits. 202 with the account as it now
        # stands, plus what is waiting and why.
        from app.api.api_server import _announce_held_change, _held_body
        for outcome in held:
            _announce_held_change(db, outcome.change, user)
        # get_user_detail answers with the JSON bytes (and an ETag), or 304 when they match.
        raw = getattr(detail, "body", b"") or b""
        body = json.loads(raw) if raw else {"id": str(user_id)}
        body["held_changes"] = [_held_body(o, user, current_user.id) for o in held]
        body["message"] = " ".join(h["message"] for h in body["held_changes"])
        return JSONResponse(status_code=202, content=body)
    return detail

@router.post("/users/{user_id}/toggle-active")
@require_endpoint_permission("USER_MANAGE")
@require_step_up("admin.user.manage")
async def toggle_user_active(
    user_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Toggle user active status (interactive admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deactivation
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    # Offboarding: deactivating a user switches off their zero-knowledge vault keys, locking the
    # vaults they belong to before the check below locks the administrator rows (see
    # _blacklist_user_vault_keys). Nothing is committed unless the check passes.
    if user.is_active:
        _blacklist_user_vault_keys(db, user.id, current_user.id)

    # Never deactivate the last administrator who can act (see app/core/last_admin.py).
    if user.is_active and user.role == RoleEnum.ADMIN and removes_last_admin(db, user):
        raise HTTPException(status_code=400, detail=LAST_ADMIN_DETAIL)

    # Reactivating a user consumes a seat, so enforce the plan's user cap on the
    # inactive->active transition here too (mirrors the PATCH /users/{id} path). create_user
    # and that PATCH are otherwise the only checkpoints, which an admin at the cap could
    # sidestep by deactivating a user, creating a replacement (allowed — a seat freed up),
    # then reactivating the original via this toggle to land above the cap.
    if not user.is_active:
        from app.api.api_server import _enforce_user_cap
        _enforce_user_cap(db)

    user.is_active = not user.is_active
    if not user.is_active:
        # Offboarding also revokes the user's sessions, durably, as PATCH /users/{id} does (their
        # zero-knowledge vault keys were switched off above). The per-request check refuses them
        # only while the account is off: a token that is not revoked works again the moment the
        # account is reactivated.
        from app.api.api_server import _revoke_sessions
        _revoke_sessions(db, user_id=user.id, actor_username=current_user.username)
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    # Log the action
    audit_logger = AuditLogger(db)
    audit_logger.log_custom_action(
        user=current_user,
        action="USER_STATUS_CHANGED",
        details=f"Set user {user.username} active status to {user.is_active}",
        ip_address=None
    )
    from app.api.api_server import _notify_account_status_changes
    _notify_account_status_changes(db, user, by_name=current_user.username,
                                   active=(not user.is_active, user.is_active))
    
    return {
        "message": f"User {'activated' if user.is_active else 'deactivated'} successfully",
        "user_id": str(user.id),
        "is_active": user.is_active
    }

@router.post("/users/{user_id}/toggle-locked")
@require_endpoint_permission("USER_MANAGE")
@require_step_up("admin.user.manage")
async def toggle_user_locked(
    user_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Toggle user locked status (interactive admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-locking
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot lock your own account")

    # Never lock the last administrator who can act (see app/core/last_admin.py).
    if not user.is_locked and user.role == RoleEnum.ADMIN and removes_last_admin(db, user):
        raise HTTPException(status_code=400, detail=LAST_ADMIN_DETAIL)

    new_locked = not user.is_locked
    user.is_locked = new_locked
    user.updated_at = datetime.now(timezone.utc)

    # Mirror the PATCH /users/{id} lock path exactly so the two admin-lock controls can't
    # diverge: an admin lock/unlock always clears locked_until (an ADMIN lock is PERMANENT —
    # locked_until NULL — never an auto-unlocking TTL; a stale past TTL must not silently
    # defeat the lock). Unlock also resets the failed-attempt counter.
    user.locked_until = None
    if not new_locked:
        user.failed_login_attempts = 0
    elif new_locked:
        # Locking revokes the user's live sessions immediately + durably (durable web-token
        # revocation + force-close of any live SFTP transport), matching the PATCH path.
        try:
            from app.api.api_server import _revoke_sessions
            _revoke_sessions(db, user_id=user.id, actor_username=current_user.username)
        except Exception as e:  # noqa: BLE001 — never let revoke break the lock
            print(f"⚠ toggle-lock session revoke failed: {e}")

    db.commit()
    
    # Log the action
    audit_logger = AuditLogger(db)
    audit_logger.log_custom_action(
        user=current_user,
        action="USER_LOCK_CHANGED",
        details=f"Set user {user.username} locked status to {user.is_locked}",
        ip_address=None
    )
    from app.api.api_server import _notify_account_status_changes
    _notify_account_status_changes(db, user, by_name=current_user.username,
                                   locked=(not user.is_locked, user.is_locked))
    
    return {
        "message": f"User {'locked' if user.is_locked else 'unlocked'} successfully",
        "user_id": str(user.id),
        "is_locked": user.is_locked
    }

# =============================================================================
# Temporary Credentials Management
# =============================================================================

@router.get("/users/{user_id}/temp-credentials", response_model=List[TempCredentialListItem])
@require_endpoint_permission("TEMP_CREDS_VIEW")
async def list_user_temp_credentials(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all temp credentials for a user (supports ETag for conditional updates)"""
    
    # Users can only view their own, admins can view any
    if current_user.role != RoleEnum.ADMIN and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # A temp session (scoped OR legacy NULL-scope) sees ONLY the credentials IT created — never
    # the target user's full listing (whose id UUIDs are exactly what the by-id deactivate/delete
    # endpoints consume). Mirrors app/api/api_server.py's /temp-creds/list; without it a legacy admin-minted
    # temp credential (role==ADMIN, _temp_scope==None) could enumerate any user's credential ids via
    # this parallel router. A degraded temp session with no cred id fails closed (empty).
    if getattr(current_user, '_is_temp_session', False):
        _my_cred_id = getattr(current_user, '_temp_cred_id', None)
        temp_creds = (
            db.query(TemporaryCredential).filter(
                TemporaryCredential.user_id == user_id,
                TemporaryCredential.created_by_temp_credential_id == _my_cred_id,
            ).order_by(TemporaryCredential.created_at.desc()).all()
            if _my_cred_id is not None else []
        )
    else:
        temp_creds = db.query(TemporaryCredential).filter(
            TemporaryCredential.user_id == user_id
        ).order_by(TemporaryCredential.created_at.desc()).all()
    
    result = []
    for cred in temp_creds:
        # The temp password is show-once at creation and never stored for re-reveal, so there is
        # never a retrievable password (the reveal endpoint always 404s).
        has_password = False
        
        result.append(TempCredentialListItem(
            id=cred.id,
            temp_username=cred.temp_username,
            created_at=cred.created_at,
            expires_at=cred.expires_at,
            deactivate_at=cred.deactivate_at,
            is_active=cred.is_active,
            is_used=cred.is_used,
            used_at=cred.used_at,
            has_password=has_password
        ))
    
    # Compute hash of response data
    response_hash = compute_response_hash(result)
    
    # Check if client already has this data
    if check_if_none_match(request, response_hash):
        return Response(status_code=304)  # Not Modified
    
    # Convert to JSON-serializable format and return with ETag
    content = json.dumps([item.model_dump(mode='json') for item in result], default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"ETag": f'"{response_hash}"'}
    )

@router.post("/users/{user_id}/temp-credentials", response_model=TempCredentialCreateResponse)
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def create_temp_credential_for_user(
    user_id: uuid.UUID,
    request_data: TempCredentialCreateRequest,
    # Declared BEFORE the admin resolver and get_db so the concurrency slot is held before any
    # database connection is checked out — this mint runs the same blocking credential generation as
    # its three sibling routes, so it takes a slot and runs off the loop too.
    _offload_slot: None = Depends(auth_offload_slot),
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Interactive admin creates a temp credential for a user (a temp session must not mint
    further unrestricted credentials). Password NOT shown to admin."""
    
    # Verify user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ZK-in-scope policy: this endpoint mints an UNRESTRICTED (whole-account) credential, which would
    # reach the target's zero-knowledge vaults. Under a deny policy that bypasses the ZK-in-scope
    # restriction, so refuse (fail-closed) when the target owns OR is a keyed member of any active ZK
    # vault — the target can mint a scoped credential for themselves instead. (Scoped/self-service +
    # delegated + all-vaults/unrestricted mints enforce this inside create_temporary_credential, using
    # the same user_reaches_active_zk_vault check.)
    from app.core import temp_passcode_policy
    from app.core.models import SystemSetting
    from app.services.auth_service import user_reaches_active_zk_vault
    _pol_row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
    # A malformed settings blob is read as an empty one rather than crashing the mint, matching
    # the other two "global" policy reads on this path. The documented default still applies.
    _pol_raw = _pol_row.value if _pol_row is not None else {}
    if not isinstance(_pol_raw, dict):
        _pol_raw = {}
    if (not temp_passcode_policy.allow_zk_vaults(_pol_raw)
            and user_reaches_active_zk_vault(db, user_id)):
        raise HTTPException(
            status_code=400,
            detail=("This user owns or is a member of zero-knowledge vaults, which organization policy "
                    "forbids in a temporary credential. Ask them to mint a scoped credential for themselves."))

    # Create the temp credential OFF the loop (bounded by the slot held above), like the sibling mints.
    auth_service = AuthService(db)
    result = await run_offloaded(auth_service.create_temporary_credential, user_id)
    
    # Log the action
    audit_logger = AuditLogger(db)
    audit_logger.log_custom_action(
        user=current_user,
        action="TEMP_CREDENTIAL_CREATED",
        details=f"Created temp credential {result['temp_username']} for user {user.username}",
        ip_address=None
    )
    
    # Return response WITHOUT password (admin doesn't see it)
    return TempCredentialCreateResponse(
        id=result['id'],
        temp_username=result['temp_username'],
        created_at=datetime.fromisoformat(result['created_at']),
        expires_at=datetime.fromisoformat(result['expires_at']),
        deactivate_at=datetime.fromisoformat(result['deactivate_at']),
        message="Temp credential created. User can view password after logging in."
    )

# ❌ REMOVED: reveal_temp_credential_password endpoint (Security Enhancement)
# Passwords are no longer retrievable after creation (one-way bcrypt hashing only)
# Users must copy password at creation time

@router.post("/temp-credentials/{temp_cred_id}/deactivate")
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def deactivate_temp_credential_by_id(
    temp_cred_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deactivate a temp credential"""
    
    temp_cred = db.query(TemporaryCredential).filter(
        TemporaryCredential.id == temp_cred_id
    ).first()
    
    if not temp_cred:
        raise HTTPException(status_code=404, detail="Temp credential not found")
    
    # Users can only deactivate their own, admins can deactivate any
    if current_user.role != RoleEnum.ADMIN and temp_cred.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    # Confine a scoped temp session to creds it created, matching the app/api/api_server.py
    # sibling (POST /temp-creds/{u}/deactivate). Without this, a scoped admin delegate
    # could deactivate the main account's or a sibling's credential via this parallel
    # router — the confinement is enforced on one router and absent on the other.
    from app.api.api_server import _guard_temp_session_cred_mutation, _revoke_sessions
    _guard_temp_session_cred_mutation(current_user, temp_cred, 'invalidate')

    temp_cred.is_active = False
    # Force-close any live session for this credential (parity with the api_server twin).
    _revoke_sessions(db, temp_credential_id=temp_cred.id, actor_username=current_user.username)
    db.commit()
    
    # Log the action
    audit_logger = AuditLogger(db)
    audit_logger.log_custom_action(
        user=current_user,
        action="TEMP_CREDENTIAL_DEACTIVATED",
        details=f"Deactivated temp credential {temp_cred.temp_username}",
        ip_address=None
    )
    
    return {
        "message": "Temp credential deactivated successfully",
        "temp_username": temp_cred.temp_username
    }

@router.delete("/temp-credentials/{temp_cred_id}")
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def delete_temp_credential_by_id(
    temp_cred_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a temp credential"""
    
    temp_cred = db.query(TemporaryCredential).filter(
        TemporaryCredential.id == temp_cred_id
    ).first()
    
    if not temp_cred:
        raise HTTPException(status_code=404, detail="Temp credential not found")
    
    # Users can only delete their own, admins can delete any
    if current_user.role != RoleEnum.ADMIN and temp_cred.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    # Confine a scoped temp session to creds it created, matching the app/api/api_server.py
    # sibling (POST /temp-creds/{u}/delete). Absent here, a scoped admin delegate could
    # destroy the main account's or a sibling's credential via this parallel router.
    from app.api.api_server import _guard_temp_session_cred_mutation, _revoke_sessions
    _guard_temp_session_cred_mutation(current_user, temp_cred, 'clear')

    temp_username = temp_cred.temp_username
    # Force-close any live session before the row (and its cascaded sessions) go.
    _revoke_sessions(db, temp_credential_id=temp_cred.id, actor_username=current_user.username)
    db.delete(temp_cred)
    db.commit()
    
    # Log the action
    audit_logger = AuditLogger(db)
    audit_logger.log_custom_action(
        user=current_user,
        action="TEMP_CREDENTIAL_DELETED",
        details=f"Deleted temp credential {temp_username}",
        ip_address=None
    )
    
    return {
        "message": "Temp credential deleted successfully",
        "temp_username": temp_username
    }

# =============================================================================
# User Activity Logging
# =============================================================================

@router.get("/users/{user_id}/activity", response_model=List[UserActivityItem])
@require_endpoint_permission("AUDIT_VIEW")
async def get_user_activity(
    user_id: uuid.UUID,
    request: Request,
    action_filter: Optional[str] = Query(None, description="Filter by action type", max_length=128),
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get activity log for a specific user (supports ETag for conditional updates)"""
    
    # Users can view their own activity, admins can view any
    if current_user.role != RoleEnum.ADMIN and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Calculate date threshold
    date_threshold = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Build query
    query = db.query(AuditLog).filter(
        and_(
            AuditLog.user_id == user_id,
            AuditLog.timestamp >= date_threshold
        )
    )
    
    # Apply action filter if provided
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{_like_escape(action_filter)}%", escape="\\"))
    
    # Order by timestamp (newest first)
    query = query.order_by(AuditLog.timestamp.desc())
    
    # Limit results
    logs = query.limit(limit).all()
    
    # Build response
    result = []
    for log in logs:
        # Use the username from the log (already stored)
        result.append(UserActivityItem(
            id=log.id,
            action=log.action,
            details=log.details if isinstance(log.details, str) else str(log.details) if log.details else None,
            ip_address=log.ip_address,
            timestamp=log.timestamp,
            performed_by_username=log.username  # Use the username field from AuditLog
        ))
    
    # Compute hash of response data
    response_hash = compute_response_hash(result)
    
    # Check if client already has this data
    if check_if_none_match(request, response_hash):
        return Response(status_code=304)  # Not Modified
    
    # Convert to JSON-serializable format and return with ETag
    content = json.dumps([item.model_dump(mode='json') for item in result], default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"ETag": f'"{response_hash}"'}
    )


# =============================================================================
# Role Management Endpoints
# =============================================================================

class RoleDefinition(BaseModel):
    """Role definition with permissions"""
    role: str
    display_name: str
    description: str
    permissions: List[str]
    icon: str
    color: str


class ChangeRoleRequest(BaseModel):
    """Request to change user role"""
    new_role: RoleEnum


class ChangeRoleResponse(BaseModel):
    """Response after changing user role"""
    message: str
    user_id: str
    username: str
    old_role: str
    new_role: str


@router.get("/roles", response_model=List[RoleDefinition])
async def get_role_definitions(
    current_user: User = Depends(get_current_user)
):
    """
    Get predefined role definitions with permissions matrix.
    Available to all authenticated users to understand the system.
    """
    roles = [
        RoleDefinition(
            role="admin",
            display_name="Administrator",
            description="Full system access with user and role management capabilities",
            permissions=[
                "Manage all users",
                "Change user roles",
                "View all vaults",
                "Create/delete any vault",
                "Access all files",
                "View audit logs",
                "Manage temporary credentials",
                "Access live monitoring",
                "Full dashboard access"
            ],
            icon="👑",
            color="#dc2626"  # Red
        ),
        RoleDefinition(
            role="user",
            display_name="User",
            description="Standard user with vault creation and file management capabilities",
            permissions=[
                "Create own vaults",
                "Manage owned vaults",
                "Access member vaults (read/write/delete based on vault permissions)",
                "Upload/download files in accessible vaults",
                "Generate temporary credentials",
                "View own activity logs",
                "Access personal dashboard"
            ],
            icon="👤",
            color="#2563eb"  # Blue
        ),
        RoleDefinition(
            role="external",
            display_name="External User",
            description="Limited access user for collaboration without vault ownership",
            permissions=[
                "Access member vaults only (read/write/delete based on vault permissions)",
                "Upload/download files in accessible vaults",
                "Generate temporary credentials",
                "View own activity logs",
                "Access personal dashboard",
                "❌ Cannot create vaults"
            ],
            icon="🌐",
            color="#16a34a"  # Green
        )
    ]
    
    return roles


@router.patch("/users/{user_id}/role", response_model=ChangeRoleResponse)
@require_step_up("admin.user.manage")
async def change_user_role(
    user_id: uuid.UUID,
    request: ChangeRoleRequest,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    http_request: Request = None,
):
    """
    Change a user's role. Only an interactive admin can perform this action (a temp
    credential must not escalate roles). Prevents admins changing their own role.
    """
    # Get target user
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent self-role change
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role"
        )

    # Never demote the last administrator who can act (see app/core/last_admin.py). Checked before
    # old_role is read, because the check reloads the row under a lock.
    if (target_user.role == RoleEnum.ADMIN and request.new_role != RoleEnum.ADMIN
            and removes_last_admin(db, target_user)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=LAST_ADMIN_DETAIL)

    old_role = target_user.role.value
    new_role = request.new_role.value
    
    # Check if role is actually changing
    if old_role == new_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User already has role '{new_role}'"
        )
    
    # Update role
    target_user.role = request.new_role
    target_user.updated_at = datetime.now(timezone.utc)
    
    # Recorded as the admin who made the change, with the account changed as the resource, like the
    # other account events. log_action's commit is the one commit for both, so a role change is never
    # saved without its record. (This row used to be built directly, under the changed account and
    # with "admin-action" where the address belongs.)
    AuditLogger(db).log_action(
        action="role_changed",
        status="success",
        user=current_user,
        resource_type="user",
        resource_id=str(target_user.id),
        details={"username": target_user.username, "old_role": old_role, "new_role": new_role},
    )
    from app.api.api_server import _notify_account_status_changes
    _notify_account_status_changes(db, target_user, by_name=current_user.username, role=(old_role, new_role))

    return ChangeRoleResponse(
        message=f"Role changed successfully from '{old_role}' to '{new_role}'",
        user_id=str(target_user.id),
        username=target_user.username,
        old_role=old_role,
        new_role=new_role
    )

