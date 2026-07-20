"""
Authorization and permission management system.
Implements Role-Based Access Control (RBAC) with fine-grained permissions.
"""
from typing import List, Optional, Set
from datetime import datetime
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import and_, select, update

from app.core.models import (
    User, RoleEnum, PermissionEnum, user_permissions,
    Vault, vault_members, VaultPermissionEnum, vault_group_access, user_groups,
    Share, ShareClaim,
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
        vault_id: uuid.UUID,
        allow_share: bool = False,
    ) -> Optional[dict]:
        """
        Get user's permissions for a specific vault.

        Args:
            user: User object
            vault_id: Vault UUID
            allow_share: When True (opt-in at the recipient READ endpoints ONLY),
                a caller with no owner/member/group access may still be granted
                READ-ONLY access by an active share claim (a file/folder share is
                confined to its subtree by stamp_share_scope + the id-scope wrappers).
                Defaults to False, so every other caller — every write/delete path and
                ALL SFTP call sites — never sees a share grant (SFTP fail-closed).

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

        if membership:
            return {
                'read': membership.read_permission,
                'write': membership.write_permission,
                'delete': membership.delete_permission,
                # A member granted manage_permission is a vault "Manager".
                'manage': bool(getattr(membership, 'manage_permission', False)),
            }

        # No direct membership.
        if getattr(vault, 'type', 'standard') == 'zero_knowledge':
            # Zero-knowledge vaults are never shared via groups: a group has no
            # key, so a group member holds no wrapped DEK and "access" would only
            # leak metadata. The grant endpoint blocks creating such rows; this is
            # defense-in-depth for any row that predates that block. ZK sharing is
            # explicit per-user only (owner + direct members) — and a share claim
            # never opens a ZK vault either.
            return None

        # Fall back to group-based access.
        group_perms = self._group_vault_permission(user, vault_id)
        if group_perms is not None:
            return group_perms

        # No owner/member/group access. Only when the caller explicitly opted in
        # (a recipient READ endpoint), an active share claim may grant read-only
        # access. Fail-closed everywhere else.
        if allow_share:
            return self._share_vault_permission(user, vault)
        return None

    def _share_vault_permission(self, user: User, vault: Vault) -> Optional[dict]:
        """READ-ONLY vault access granted by an active share claim, or None.

        Fail-closed and intentionally NARROW: grants only for
          * a Standard, non-password vault (zero-knowledge + password-protected are
            refused; the vault could have gained a password after the claim);
          * an 'active', not-past-expiry share (INCLUDING view-only — a view-only share
            grants read so the recipient can open/list/preview; the download path denies
            file.download separately via the downloadable scope);
          * a caller holding a non-revoked ShareClaim on that share.
        Grants read (the download path re-checks READ) but never write/delete/manage. For a
        FILE/FOLDER-target share this read is SUBTREE-RESTRICTED by the id-scope wrappers once
        stamp_share_scope() has stamped the caller's share scope at the get_vault chokepoint — the
        read grant here and the scope stamp there select the SAME claim set. Only reached with
        allow_share=True, so a share claim confers nothing over SFTP."""
        # The deployment-wide sharing master switch is a LIVE kill-switch: disabling sharing
        # org-wide (e.g. on a suspected leak) stops existing claims from granting access at once,
        # mirroring how the temp-passcode master switch gates redemption at the vault chokepoint.
        # Fail-closed: an absent/unreadable setting or any error denies the share grant.
        if not self._sharing_enabled():
            return None
        if getattr(vault, 'type', 'standard') == 'zero_knowledge':
            return None
        if vault.password_hash:
            return None
        now = datetime.utcnow()
        claim = (
            self.db.query(ShareClaim)
            .join(Share, Share.id == ShareClaim.share_id)
            .filter(
                ShareClaim.user_id == user.id,
                ShareClaim.revoked.is_(False),
                Share.vault_id == vault.id,
                Share.status == 'active',
                Share.expires_at > now,
            )
            .first()
        )
        if claim is None:
            return None
        return {'read': True, 'write': False, 'delete': False, 'manage': False}

    def _sharing_enabled(self) -> bool:
        """The deployment-wide sharing master switch, read from SystemSetting('global'). Fail-closed:
        an absent/unreadable setting or any error returns False (no share access)."""
        from app.core import sharing_policy
        from app.core.models import SystemSetting
        try:
            row = self.db.query(SystemSetting).filter(SystemSetting.key == 'global').first()
            cfg = (row.value or {}) if (row and row.value) else {}
        except Exception:
            cfg = {}
        return sharing_policy.sharing_enabled(cfg)

    def stamp_share_scope(self, user: User, vault: Vault) -> None:
        """Stamp a share recipient's per-vault id-subtrees so the generalized id-scope wrappers
        (temp_scope.scope_ids + vault_service's listing filter / per-file gate) confine a file/folder
        share to its subtree. share-ONLY: an owner / member / group-member who ALSO holds a claim keeps
        full (unscoped) access — never downgraded.

        Stamps TWO scopes, each the UNION of the caller's active, non-revoked claims on this vault:
          * ``_share_vault_scope[vault_id]``  — the VISIBLE scope (ALL claims, incl. view-only): what
            the recipient may open/list. This is the SAME claim set _share_vault_permission grants
            read for.
          * ``_share_download_scope[vault_id]`` — the DOWNLOADABLE scope (NON-view-only claims only):
            what the recipient may download. A view-only share contributes to the visible scope but
            NOT the downloadable one, so it is see-but-not-download.
        For each scope: any qualifying whole-vault claim ⇒ None (no id restriction); otherwise
        ``{"files": [...], "folders": [...]}`` (empty ⇒ deny-all, fail-closed). If the claim set is
        unresolvable NOW — sharing just disabled, or the claim revoked/expired between the read-grant
        query and this one (a read-committed race) — BOTH scopes fail closed to deny-all rather than
        leaving the caller unstamped, which scope_ids would read as whole-vault (fail-open). No-op for
        a non-recipient (leaves the stamps untouched)."""
        if vault.owner_id == user.id:
            return
        # A member/group principal is NOT scope-restricted by a share; only a share-only caller is.
        if self.get_vault_permissions(user, vault.id) is not None:
            return
        visible = {"files": [], "folders": []}
        downloadable = {"files": [], "folders": []}
        if self._sharing_enabled():
            now = datetime.utcnow()
            rows = (
                self.db.query(Share.target_type, Share.target_folder_id,
                              Share.target_file_id, Share.view_only)
                .join(ShareClaim, ShareClaim.share_id == Share.id)
                .filter(
                    ShareClaim.user_id == user.id,
                    ShareClaim.revoked.is_(False),
                    Share.vault_id == vault.id,
                    Share.status == 'active',
                    Share.expires_at > now,
                )
                .all()
            )
            if rows:
                v_whole = d_whole = False
                v_files, v_folders = set(), set()
                d_files, d_folders = set(), set()
                for target_type, folder_id, file_id, view_only in rows:
                    # Every active claim contributes to the VISIBLE scope; only a non-view-only claim
                    # also contributes to the DOWNLOADABLE scope.
                    if target_type == 'vault':
                        v_whole = True
                        if not view_only:
                            d_whole = True
                    elif target_type == 'folder' and folder_id is not None:
                        v_folders.add(str(folder_id))
                        if not view_only:
                            d_folders.add(str(folder_id))
                    elif target_type == 'file' and file_id is not None:
                        v_files.add(str(file_id))
                        if not view_only:
                            d_files.add(str(file_id))
                visible = None if v_whole else {"files": sorted(v_files), "folders": sorted(v_folders)}
                downloadable = None if d_whole else {"files": sorted(d_files), "folders": sorted(d_folders)}
        self._stamp_scope(user, "_share_vault_scope", vault.id, visible)
        self._stamp_scope(user, "_share_download_scope", vault.id, downloadable)

    @staticmethod
    def _stamp_scope(user: User, attr: str, vault_id, scope) -> None:
        smap = getattr(user, attr, None)
        if smap is None:
            smap = {}
            setattr(user, attr, smap)
        smap[str(vault_id)] = scope

    def burn_share_download(self, user: User, vault: Vault, file, ancestor_folder_ids) -> bool:
        """Consume ONE download against the per-recipient ``max_downloads`` of the SHARE claims that
        cover this file (each recipient gets their own per-share download budget). Returns True to allow, False to deny
        (a covering LIMITED claim is exhausted). MUST be called only for a share recipient (the caller
        gates on the share-scope stamp); it independently re-resolves the covering claims.

        Coverage: a claim covers `file` if it is a whole-vault share, a folder share whose target
        folder is `file`'s own folder or an ancestor, or a file share of exactly this file. Only
        active, non-revoked, non-view-only claims count (a view-only claim can't download, so it can't
        consume a download). If ANY covering claim is UNLIMITED (max_downloads NULL) the download is
        unlimited and burns nothing. Otherwise EACH covering LIMITED claim is consumed via an ATOMIC
        conditional increment (``download_count < max_downloads`` in the WHERE — so concurrent GETs by
        the same recipient can never exceed the cap); if any is already at its cap the whole burn is
        rolled back and the download denied. No covering claim => allow (this gate enforces ONLY
        max_downloads; revoke/expiry is enforced at get_vault at request start, so a claim that
        vanished mid-request is a get_vault concern, not a limit to burn). The web download endpoint
        serves the full object (no Range/partial responses), so every successful GET counts once.

        TRANSACTION OWNERSHIP: this commits (on allow) or rolls back (on deny) the request session, so
        it must be called with NO unrelated pending writes — at the current call site (the download
        endpoint, after get_vault has committed and only reads follow) that holds."""
        now = datetime.utcnow()
        anc = {str(a) for a in (ancestor_folder_ids or [])}
        fid = str(file.id)
        rows = (
            self.db.query(ShareClaim.id, Share.max_downloads, Share.target_type,
                          Share.target_folder_id, Share.target_file_id)
            .join(Share, Share.id == ShareClaim.share_id)
            .filter(
                ShareClaim.user_id == user.id,
                ShareClaim.revoked.is_(False),
                Share.vault_id == vault.id,
                Share.view_only.is_(False),
                Share.status == 'active',
                Share.expires_at > now,
            )
            .all()
        )
        covering = []
        for claim_id, max_dl, ttype, tfolder, tfile in rows:
            covers = (
                ttype == 'vault'
                or (ttype == 'folder' and tfolder is not None and str(tfolder) in anc)
                or (ttype == 'file' and tfile is not None and str(tfile) == fid)
            )
            if covers:
                covering.append((claim_id, max_dl))
        if not covering:
            return True  # require_download_scope already gated visibility/download; defensive
        # An unlimited covering claim ⇒ unlimited downloads for this file (burn nothing).
        if any(max_dl is None for _, max_dl in covering):
            return True
        # All covering claims are limited: atomically consume one from EACH; deny (and roll back the
        # whole burn) if any is already at its cap. Consuming every covering limited claim keeps each
        # share's max_downloads a hard ceiling — the multi-claim keying is intentionally strict.
        for claim_id, max_dl in covering:
            res = self.db.execute(
                update(ShareClaim)
                .where(ShareClaim.id == claim_id, ShareClaim.download_count < max_dl)
                .values(download_count=ShareClaim.download_count + 1)
            )
            if res.rowcount == 0:
                self.db.rollback()
                return False
        self.db.commit()
        return True

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
        required_permission: VaultPermissionEnum = VaultPermissionEnum.READ,
        allow_share: bool = False,
    ) -> bool:
        """
        Check if user can access a vault with specified permission.

        Args:
            user: User object
            vault_id: Vault UUID
            required_permission: Required vault permission
            allow_share: opt-in to an active whole-vault share claim (see
                get_vault_permissions). Defaults False → SFTP/write paths fail-closed.

        Returns:
            True if user has access, False otherwise
        """
        perms = self.get_vault_permissions(user, vault_id, allow_share=allow_share)

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
        required_permission: VaultPermissionEnum = VaultPermissionEnum.READ,
        allow_share: bool = False,
    ):
        """
        Require user to have vault access permission.

        Args:
            user: User object
            vault_id: Vault UUID
            required_permission: Required vault permission
            allow_share: opt-in to an active whole-vault share claim (see
                get_vault_permissions). Defaults False → SFTP/write paths fail-closed.

        Raises:
            ResourceNotFoundError: If vault not found
            PermissionDeniedError: If user lacks permission
        """
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        if not vault:
            raise ResourceNotFoundError(f"Vault not found: {vault_id}")

        if not self.can_access_vault(user, vault_id, required_permission, allow_share=allow_share):
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
