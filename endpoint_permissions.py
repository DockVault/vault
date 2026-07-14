"""
Endpoint Permission System for granular access control.
This module provides decorators and utilities for checking endpoint-level permissions.
Uses api_catalog.py for comprehensive endpoint definitions.
"""
from functools import wraps
from datetime import datetime, timezone
from typing import List, Optional, Callable
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from models import User, UserEndpointPermission, RoleEnum
from api_catalog import API_CATALOG


def require_endpoint_permission(group_name: str):
    """
    Decorator to require specific endpoint permission by group name.
    
    Usage:
        @app.get("/users")
        @require_endpoint_permission("users.list")
        async def list_users(current_user: User = Depends(get_current_user)):
            ...
    
    Args:
        group_name: The permission group name (e.g., "users.list", "vaults.create")
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user and db from kwargs
            current_user = kwargs.get('current_user')
            db = kwargs.get('db')
            
            if not current_user or not db:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            from models import UserEndpointPermission as UEP

            def _creator_has_group():
                return db.query(UEP).filter(
                    UEP.user_id == current_user.id,
                    UEP.endpoint_group == group_name
                ).first() is not None

            # Temporary-credential sessions are gated by their OWN scope and never
            # inherit the admin bypass (so an admin can mint a tightly-scoped temp
            # credential). A NULL scope is legacy and behaves as before.
            if getattr(current_user, '_is_temp_session', False):
                from temp_scope import temp_session_allows_group
                if not temp_session_allows_group(current_user, group_name, kwargs):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Temporary credential scope does not permit this action ({group_name})"
                    )
                # The credential can never exceed its creator: the creating user
                # must hold the group too (unless that user is an admin).
                if current_user.role != RoleEnum.ADMIN and not _creator_has_group():
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"You do not have permission to access this resource. Required permission: {group_name}"
                    )
                return await func(*args, **kwargs)

            # Admin bypass: admins have all permissions
            if current_user.role == RoleEnum.ADMIN:
                return await func(*args, **kwargs)

            if not _creator_has_group():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"You do not have permission to access this resource. Required permission: {group_name}"
                )

            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def grant_endpoint_permission(
    user_id: str,
    endpoint_group: str,
    db: Session,
    granted_by: Optional[str] = None
):
    """
    Grant an endpoint group permission to a user.
    
    Args:
        user_id: User UUID
        endpoint_group: Group name (e.g., 'TEMP_CREDS_VIEW', 'USER_MANAGE')
        db: Database session
        granted_by: Admin user ID who granted permission
    """
    if endpoint_group not in API_CATALOG:
        raise ValueError(f"Unknown endpoint group: {endpoint_group}")
    
    from datetime import datetime
    import uuid as uuid_module
    from models import UserEndpointPermission
    
    # Check if permission already exists
    existing = db.query(UserEndpointPermission).filter(
        UserEndpointPermission.user_id == uuid_module.UUID(user_id),
        UserEndpointPermission.endpoint_group == endpoint_group
    ).first()
    
    if not existing:
        # Create new permission
        perm = UserEndpointPermission(
            user_id=uuid_module.UUID(user_id),
            endpoint_group=endpoint_group,
            granted_at=datetime.now(timezone.utc),
            granted_by=uuid_module.UUID(granted_by) if granted_by else None
        )
        db.add(perm)
        db.commit()
    
    return True


def grant_default_permissions_for_role(
    user_id: str,
    role: str,
    db: Session
):
    """
    Grant default endpoint permissions based on user role.
    
    Args:
        user_id: User UUID string
        role: User role ('user' or 'admin')
        db: Database session
    """
    from api_catalog import API_CATALOG
    
    # Normalize role
    role_str = str(role).lower().replace('roleenum.', '').replace('role.', '')
    
    # Grant permissions for all groups that have this role in default_for_roles
    for group_name, group in API_CATALOG.items():
        if role_str in [r.lower() for r in group.default_for_roles]:
            try:
                grant_endpoint_permission(user_id, group_name, db, granted_by=None)
                print(f"  ✓ Granted {group_name} to {role_str} user")
            except Exception as e:
                print(f"  ✗ Failed to grant {group_name}: {e}")
    
    db.commit()


def revoke_endpoint_permission(
    user_id: str,
    endpoint_group: str,
    db: Session
):
    """
    Revoke an endpoint group permission from a user.
    
    Args:
        user_id: User UUID
        endpoint_group: Group name (e.g., 'TEMP_CREDS_VIEW')
        db: Database session
    """
    if endpoint_group not in API_CATALOG:
        raise ValueError(f"Unknown endpoint group: {endpoint_group}")
    
    import uuid as uuid_module
    from models import UserEndpointPermission
    
    # Delete the permission
    perm = db.query(UserEndpointPermission).filter(
        UserEndpointPermission.user_id == uuid_module.UUID(user_id),
        UserEndpointPermission.endpoint_group == endpoint_group
    ).first()
    
    if perm:
        db.delete(perm)
        db.commit()
    
    return True


def get_user_permissions(user_id: str, db: Session) -> List[dict]:
    """
    Get all endpoint permissions for a user.
    
    Returns:
        List of permission dicts with endpoint_group, granted_at, granted_by
    """
    from models import UserEndpointPermission
    import uuid
    
    # Query the new user_endpoint_permissions table
    permissions = db.query(UserEndpointPermission).filter(
        UserEndpointPermission.user_id == uuid.UUID(user_id)
    ).all()
    
    # For each permission, get the group details from API_CATALOG
    results = []
    for perm in permissions:
        endpoint_group = perm.endpoint_group
        # Get group details from API_CATALOG (it's a FunctionalityGroup object)
        group = API_CATALOG.get(endpoint_group)
        if not group:
            continue
            
        # Add one entry per endpoint in the group
        for endpoint in group.endpoints:
            granted_at_str = None
            granted_by_str = None
            
            if perm.granted_at is not None:
                granted_at_str = perm.granted_at.isoformat()
            if perm.granted_by is not None:
                granted_by_str = str(perm.granted_by)
                
            results.append({
                'endpoint_group': endpoint_group,
                'endpoint_pattern': endpoint.path,
                'method': endpoint.method,
                'is_allowed': True,
                'granted_at': granted_at_str,
                'granted_by': granted_by_str
            })
    
    return results
