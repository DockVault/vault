"""
Endpoint Permission System for granular access control.
This module provides decorators and utilities for checking endpoint-level permissions.
Uses api_catalog.py for comprehensive endpoint definitions.
"""
from functools import wraps
from datetime import datetime, timezone
from typing import List, Optional, Callable, Tuple
from fastapi import HTTPException, status, Depends
from sqlalchemy.orm import Session
from sqlalchemy import select, Table, MetaData
import re
import uuid as uuid_module

from database import get_db
from models import User, UserEndpointPermission, RoleEnum
from api_catalog import API_CATALOG, APIEndpoint, RoleRequirement


def get_endpoint_info(method: str, path: str) -> Optional[Tuple[str, APIEndpoint]]:
    """
    Find endpoint information from catalog.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: Endpoint path (e.g., '/vaults/123/files')
        
    Returns:
        Tuple of (group_name, APIEndpoint) if found, None otherwise
    """
    for group_name, group in API_CATALOG.items():
        for endpoint in group.endpoints:
            if endpoint.method != method.upper():
                continue
            
            # Convert path pattern to regex for matching
            # e.g., /vaults/{vault_id}/files -> /vaults/[^/]+/files
            pattern = endpoint.path
            pattern = re.sub(r'\{[^}]+\}', '[^/]+', pattern)
            pattern = f"^{pattern}$"
            
            if re.match(pattern, path):
                return (group_name, endpoint)
    
    return None


class EndpointPermissionChecker:
    """Check if user has permission to access an endpoint."""
    
    @staticmethod
    def check_role_requirement(user: User, requirement: RoleRequirement) -> bool:
        """Check if user meets role requirement"""
        if requirement == RoleRequirement.PUBLIC:
            return True
        
        if requirement == RoleRequirement.USER:
            return True  # Any authenticated user
        
        if requirement == RoleRequirement.ADMIN:
            # Check if user has admin role
            try:
                return str(user.role) == 'admin'
            except:
                return False
        
        return False
    
    @staticmethod
    def check_ownership(
        user: User,
        resource_type: str,
        resource_id: str,
        db: Session
    ) -> bool:
        """
        Check if user owns the resource.
        
        Args:
            user: User object
            resource_type: Type of resource ('vault', 'file', 'user')
            resource_id: UUID of the resource
            db: Database session
            
        Returns:
            True if user owns resource
        """
        try:
            if resource_type == 'user':
                # User owns their own account
                return str(user.id) == resource_id
            
            elif resource_type == 'vault':
                # Check vault ownership
                from models import Vault
                vault = db.query(Vault).filter(Vault.id == uuid_module.UUID(resource_id)).first()
                if vault:
                    return bool(vault.owner_id == user.id)
                return False
            
            elif resource_type == 'file':
                # Check file ownership via vault
                from models import File, Vault
                file = db.query(File).filter(File.id == uuid_module.UUID(resource_id)).first()
                if file:
                    vault = db.query(Vault).filter(Vault.id == file.vault_id).first()
                    if vault:
                        return bool(vault.owner_id == user.id)
                return False
            
        except Exception as e:
            print(f"Error checking ownership: {e}")
            return False
        
        return False
    
    @staticmethod
    def user_has_permission(
        user: User,
        endpoint: str,
        method: str,
        db: Session
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if user has permission to access endpoint.
        
        Args:
            user: User object
            endpoint: Endpoint path (e.g., '/users')
            method: HTTP method (e.g., 'GET')
            db: Database session
            
        Returns:
            Tuple of (has_permission, reason)
        """
        # Find endpoint in catalog
        endpoint_info = get_endpoint_info(method, endpoint)
        if not endpoint_info:
            # Endpoint not in catalog - allow (for backwards compatibility)
            return (True, "Endpoint not in catalog")
        
        group_name, endpoint_def = endpoint_info
        
        # Check role requirement
        if not EndpointPermissionChecker.check_role_requirement(user, endpoint_def.role_requirement):
            return (False, f"Requires {endpoint_def.role_requirement.value} role")
        
        # Check ownership if required
        if endpoint_def.requires_ownership and endpoint_def.resource_type:
            # Extract resource ID from path
            resource_id = EndpointPermissionChecker.extract_resource_id(
                endpoint,
                endpoint_def.path,
                endpoint_def.resource_type
            )
            
            if resource_id:
                if not EndpointPermissionChecker.check_ownership(
                    user, endpoint_def.resource_type, resource_id, db
                ):
                    return (False, f"You do not own this {endpoint_def.resource_type}")
        
        # Check if user has explicit endpoint permission in database
        if str(user.role) != 'admin':  # Admins bypass explicit permission checks
            has_explicit_permission = EndpointPermissionChecker.check_explicit_permission(
                user, endpoint, method, db
            )
            
            if has_explicit_permission is False:  # Explicitly denied
                return (False, "Permission explicitly denied")
        
        return (True, None)
    
    @staticmethod
    def extract_resource_id(actual_path: str, pattern_path: str, resource_type: str) -> Optional[str]:
        """
        Extract resource ID from actual path using pattern.
        
        Example:
            actual_path: '/vaults/123-456/files'
            pattern_path: '/vaults/{vault_id}/files'
            resource_type: 'vault'
            -> Returns: '123-456'
        """
        # Map resource type to pattern variable name
        type_to_param = {
            'vault': 'vault_id',
            'file': 'file_id',
            'user': 'user_id'
        }
        
        param_name = type_to_param.get(resource_type)
        if not param_name:
            return None
        
        # Create regex pattern
        pattern = pattern_path
        pattern = pattern.replace('{' + param_name + '}', f'(?P<{param_name}>[^/]+)')
        pattern = re.sub(r'\{[^}]+\}', '[^/]+', pattern)
        pattern = f"^{pattern}$"
        
        match = re.match(pattern, actual_path)
        if match:
            return match.group(param_name)
        
        return None
    
    @staticmethod
    def check_explicit_permission(user: User, endpoint: str, method: str, db: Session) -> Optional[bool]:
        """
        Check if user has explicit permission (granted/denied) in database.
        
        Returns:
            True if explicitly allowed
            False if explicitly denied
            None if no explicit permission set
        """
        try:
            metadata = MetaData()
            endpoint_perms = Table('endpoint_permissions', metadata, autoload_with=db.bind)
            
            # Query for matching permissions
            stmt = select(endpoint_perms).where(
                endpoint_perms.c.user_id == user.id,
                endpoint_perms.c.method == method.upper()
            )
            
            results = db.execute(stmt).fetchall()
            
            # Check if any permission matches this endpoint
            for perm in results:
                # Convert stored pattern to regex
                pattern = perm.endpoint_pattern
                pattern = re.sub(r'\{[^}]+\}', '[^/]+', pattern)
                pattern = f"^{pattern}$"
                
                if re.match(pattern, endpoint):
                    return perm.is_allowed
            
            return None  # No explicit permission
        except Exception as e:
            print(f"Error checking explicit permission: {e}")
            return None


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
