"""
Authorization and permission management system.
Implements Role-Based Access Control (RBAC) with fine-grained permissions.
"""
from typing import List, Optional, Set
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import and_, select

from models import (
    User, RoleEnum, PermissionEnum, user_permissions,
    Vault, vault_members, VaultPermissionEnum, vault_group_access, user_groups
)


class AuthorizationError(Exception):
    """Base exception for authorization errors."""
    pass


class PermissionDeniedError(AuthorizationError):
    """Raised when user lacks required permissions."""
    pass


class ResourceNotFoundError(AuthorizationError):
    """Raised when requested resource is not found."""
    pass


# Default role permissions mapping
DEFAULT_ROLE_PERMISSIONS = {
    RoleEnum.ADMIN: {
        # All permissions for admin
        PermissionEnum.USER_CREATE,
        PermissionEnum.USER_READ,
        PermissionEnum.USER_UPDATE,
        PermissionEnum.USER_DELETE,
        PermissionEnum.USER_LIST,
        PermissionEnum.VAULT_CREATE,
        PermissionEnum.VAULT_READ,
        PermissionEnum.VAULT_UPDATE,
        PermissionEnum.VAULT_DELETE,
        PermissionEnum.VAULT_LIST,
        PermissionEnum.FILE_UPLOAD,
        PermissionEnum.FILE_DOWNLOAD,
        PermissionEnum.FILE_DELETE,
        PermissionEnum.FILE_LIST,
        PermissionEnum.FOLDER_CREATE,
        PermissionEnum.FOLDER_DELETE,
        PermissionEnum.FOLDER_LIST,
        PermissionEnum.TEMP_CRED_CREATE,
        PermissionEnum.TEMP_CRED_LIST,
        PermissionEnum.TEMP_CRED_REVOKE,
        PermissionEnum.DASHBOARD_VIEW,
        PermissionEnum.DASHBOARD_ADMIN,
        PermissionEnum.AUDIT_VIEW,
    },
    RoleEnum.USER: {
        # Standard user permissions
        PermissionEnum.USER_READ,  # Can read own profile
        PermissionEnum.VAULT_CREATE,
        PermissionEnum.VAULT_READ,
        PermissionEnum.VAULT_UPDATE,  # Own vaults
        PermissionEnum.VAULT_LIST,
        PermissionEnum.FILE_UPLOAD,
        PermissionEnum.FILE_DOWNLOAD,
        PermissionEnum.FILE_DELETE,
        PermissionEnum.FILE_LIST,
        PermissionEnum.FOLDER_CREATE,
        PermissionEnum.FOLDER_DELETE,
        PermissionEnum.FOLDER_LIST,
        PermissionEnum.TEMP_CRED_CREATE,  # Own temp credentials
        PermissionEnum.TEMP_CRED_LIST,
        PermissionEnum.DASHBOARD_VIEW,
    },
    RoleEnum.EXTERNAL: {
        # Limited permissions for external users
        PermissionEnum.USER_READ,  # Own profile only
        PermissionEnum.VAULT_READ,
        PermissionEnum.FILE_DOWNLOAD,
        PermissionEnum.FILE_LIST,
        PermissionEnum.FOLDER_LIST,
        PermissionEnum.TEMP_CRED_CREATE,
    }
}


class PermissionService:
    """Service for managing permissions and authorization."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_user_permissions(self, user: User) -> Set[PermissionEnum]:
        """
        Get all permissions for a user (role + custom permissions).
        
        Args:
            user: User object
            
        Returns:
            Set of PermissionEnum values
        """
        # Start with default role permissions
        permissions = DEFAULT_ROLE_PERMISSIONS.get(user.role, set()).copy()
        
        # Add custom permissions from user_permissions table
        custom_perms = self.db.execute(
            user_permissions.select().where(
                user_permissions.c.user_id == user.id
            )
        ).fetchall()
        
        for perm_row in custom_perms:
            try:
                permissions.add(PermissionEnum(perm_row.permission))
            except ValueError:
                # Skip invalid permissions
                pass
        
        return permissions
    
    def has_permission(self, user: User, permission: PermissionEnum) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user: User object
            permission: Permission to check
            
        Returns:
            True if user has permission, False otherwise
        """
        user_permissions = self.get_user_permissions(user)
        return permission in user_permissions
    
    def require_permission(self, user: User, permission: PermissionEnum):
        """
        Require user to have a specific permission.
        
        Args:
            user: User object
            permission: Required permission
            
        Raises:
            PermissionDeniedError: If user lacks permission
        """
        if not self.has_permission(user, permission):
            raise PermissionDeniedError(
                f"User lacks required permission: {permission.value}"
            )
    
    def require_any_permission(self, user: User, permissions: List[PermissionEnum]):
        """
        Require user to have at least one of the specified permissions.
        
        Args:
            user: User object
            permissions: List of permissions (user needs at least one)
            
        Raises:
            PermissionDeniedError: If user lacks all permissions
        """
        user_perms = self.get_user_permissions(user)
        if not any(perm in user_perms for perm in permissions):
            raise PermissionDeniedError(
                f"User lacks required permissions: {[p.value for p in permissions]}"
            )
    
    def require_all_permissions(self, user: User, permissions: List[PermissionEnum]):
        """
        Require user to have all specified permissions.
        
        Args:
            user: User object
            permissions: List of permissions (user needs all)
            
        Raises:
            PermissionDeniedError: If user lacks any permission
        """
        user_perms = self.get_user_permissions(user)
        missing = [p for p in permissions if p not in user_perms]
        if missing:
            raise PermissionDeniedError(
                f"User lacks required permissions: {[p.value for p in missing]}"
            )
    
    def grant_permission(
        self,
        user_id: uuid.UUID,
        permission: PermissionEnum,
        granted_by: uuid.UUID
    ):
        """
        Grant a custom permission to a user.
        
        Args:
            user_id: User UUID
            permission: Permission to grant
            granted_by: UUID of user granting the permission
        """
        # Check if permission already exists
        existing = self.db.execute(
            user_permissions.select().where(
                and_(
                    user_permissions.c.user_id == user_id,
                    user_permissions.c.permission == permission.value
                )
            )
        ).fetchone()
        
        if not existing:
            self.db.execute(
                user_permissions.insert().values(
                    user_id=user_id,
                    permission=permission.value,
                    granted_by=granted_by
                )
            )
            self.db.commit()
    
    def revoke_permission(self, user_id: uuid.UUID, permission: PermissionEnum):
        """
        Revoke a custom permission from a user.
        
        Args:
            user_id: User UUID
            permission: Permission to revoke
        """
        self.db.execute(
            user_permissions.delete().where(
                and_(
                    user_permissions.c.user_id == user_id,
                    user_permissions.c.permission == permission.value
                )
            )
        )
        self.db.commit()
    
    def get_vault_permissions(
        self,
        user: User,
        vault_id: uuid.UUID
    ) -> Optional[dict]:
        """
        Get user's permissions for a specific vault.
        
        Args:
            user: User object
            vault_id: Vault UUID
            
        Returns:
            Dictionary with read, write, delete permissions or None if no access
        """
        # Check if user owns the vault
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            return None
        
        if vault.owner_id == user.id:
            # Owner has all permissions, including management.
            return {
                'read': True,
                'write': True,
                'delete': True,
                'manage': True
            }
        
        # Check if user is a member
        membership = self.db.execute(
            vault_members.select().where(
                and_(
                    vault_members.c.vault_id == vault_id,
                    vault_members.c.user_id == user.id
                )
            )
        ).fetchone()
        
        if not membership:
            # Zero-knowledge vaults are never shared via groups: a group has no
            # key, so a group member holds no wrapped DEK and "access" would only
            # leak metadata. The grant endpoint blocks creating such rows; this is
            # defense-in-depth for any row that predates that block. ZK sharing is
            # explicit per-user only (owner + direct members).
            if getattr(vault, 'type', 'standard') == 'zero_knowledge':
                return None
            # No direct membership — fall back to group-based access.
            return self._group_vault_permission(user, vault_id)

        return {
            'read': membership.read_permission,
            'write': membership.write_permission,
            'delete': membership.delete_permission,
            # A member granted manage_permission is a vault "Manager".
            'manage': bool(getattr(membership, 'manage_permission', False)),
        }

    def _group_vault_permission(self, user: User, vault_id: uuid.UUID) -> Optional[dict]:
        """Highest vault permission the user gets via any group that has been
        granted access to this vault. Returns None if none apply."""
        group_ids = [
            r[0] for r in self.db.execute(
                select(user_groups.c.group_id).where(user_groups.c.user_id == user.id)
            ).fetchall()
        ]
        if not group_ids:
            return None
        rows = self.db.execute(
            select(vault_group_access.c.permission).where(
                and_(
                    vault_group_access.c.vault_id == vault_id,
                    vault_group_access.c.group_id.in_(group_ids),
                )
            )
        ).fetchall()
        if not rows:
            return None
        write = any(r[0] == 'write' for r in rows)
        # Group access never grants delete or management (reserved for owner/admin/manager).
        return {'read': True, 'write': write, 'delete': False, 'manage': False}

    def can_manage_vault(self, user: User, vault_id: uuid.UUID) -> bool:
        """True if the user may manage this vault's membership/access: a global
        admin, the owner, or a member granted the 'manage' permission (Manager role).
        Does NOT cover destructive/ownership actions (delete vault, rotate keys,
        change password) — those stay owner-only at their endpoints."""
        if getattr(user, 'role', None) == RoleEnum.ADMIN:
            return True
        perms = self.get_vault_permissions(user, vault_id)
        return bool(perms and perms.get('manage'))
    
    def can_access_vault(
        self,
        user: User,
        vault_id: uuid.UUID,
        required_permission: VaultPermissionEnum = VaultPermissionEnum.READ
    ) -> bool:
        """
        Check if user can access a vault with specified permission.
        
        Args:
            user: User object
            vault_id: Vault UUID
            required_permission: Required vault permission
            
        Returns:
            True if user has access, False otherwise
        """
        perms = self.get_vault_permissions(user, vault_id)
        
        if not perms:
            return False
        
        permission_map = {
            VaultPermissionEnum.READ: perms['read'],
            VaultPermissionEnum.WRITE: perms['write'],
            VaultPermissionEnum.DELETE: perms['delete']
        }
        
        return permission_map.get(required_permission, False)
    
    def require_vault_permission(
        self,
        user: User,
        vault_id: uuid.UUID,
        required_permission: VaultPermissionEnum = VaultPermissionEnum.READ
    ):
        """
        Require user to have vault access permission.
        
        Args:
            user: User object
            vault_id: Vault UUID
            required_permission: Required vault permission
            
        Raises:
            ResourceNotFoundError: If vault not found
            PermissionDeniedError: If user lacks permission
        """
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        if not vault:
            raise ResourceNotFoundError(f"Vault not found: {vault_id}")
        
        if not self.can_access_vault(user, vault_id, required_permission):
            raise PermissionDeniedError(
                f"User lacks {required_permission.value} permission for vault {vault_id}"
            )
    
    def can_modify_user(self, actor: User, target_user_id: uuid.UUID) -> bool:
        """
        Check if actor can modify target user.
        
        Args:
            actor: User performing the action
            target_user_id: User being modified
            
        Returns:
            True if modification is allowed, False otherwise
        """
        # Admins can modify anyone
        if actor.role == RoleEnum.ADMIN:
            return True
        
        # Users can only modify themselves
        return actor.id == target_user_id
    
    def add_vault_member(
        self,
        vault_id: uuid.UUID,
        user_id: uuid.UUID,
        read: bool = True,
        write: bool = False,
        delete: bool = False,
        added_by: uuid.UUID = None
    ):
        """
        Add a member to a vault with specific permissions.
        
        Args:
            vault_id: Vault UUID
            user_id: User UUID to add
            read: Read permission
            write: Write permission
            delete: Delete permission
            added_by: UUID of user adding the member
        """
        # Check if already a member
        existing = self.db.execute(
            vault_members.select().where(
                and_(
                    vault_members.c.vault_id == vault_id,
                    vault_members.c.user_id == user_id
                )
            )
        ).fetchone()
        
        if existing:
            # Update permissions
            self.db.execute(
                vault_members.update().where(
                    and_(
                        vault_members.c.vault_id == vault_id,
                        vault_members.c.user_id == user_id
                    )
                ).values(
                    read_permission=read,
                    write_permission=write,
                    delete_permission=delete
                )
            )
        else:
            # Add new member
            self.db.execute(
                vault_members.insert().values(
                    vault_id=vault_id,
                    user_id=user_id,
                    read_permission=read,
                    write_permission=write,
                    delete_permission=delete,
                    added_by=added_by
                )
            )
        
        self.db.commit()
    
    def remove_vault_member(self, vault_id: uuid.UUID, user_id: uuid.UUID):
        """
        Remove a member from a vault.
        
        Args:
            vault_id: Vault UUID
            user_id: User UUID to remove
        """
        self.db.execute(
            vault_members.delete().where(
                and_(
                    vault_members.c.vault_id == vault_id,
                    vault_members.c.user_id == user_id
                )
            )
        )
        self.db.commit()
