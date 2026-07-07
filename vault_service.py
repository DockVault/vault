"""
File and vault management service.
Handles file encryption, storage, and hierarchical password protection.
"""
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, BinaryIO
import uuid
import mimetypes

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError

from models import User, Vault, Folder, File, VaultPermissionEnum
from security import (
    encrypt_file_content, decrypt_file_content,
    calculate_file_checksum, verify_file_integrity,
    hash_password, verify_password, sanitize_filename
)
from authorization import PermissionService
from config import settings
from database import redis_client
from encrypted_file_storage import EncryptedFileStorage


def _seal_named_object(vault, obj, is_file: bool) -> None:
    """Encrypt a File/Folder name (and a File's MIME) at rest for STANDARD vaults and set
    the per-vault blind index, then NULL the plaintext columns. No-op for zero-knowledge /
    non-standard vaults (their names are left as-is / handled client-side later).

    The object MUST already have its id assigned (the cipher key is per-(vault_id, id)).
    The plaintext is restored in-memory by the model's load/refresh decrypt events, so a
    caller that reads the name right after sealing must refresh() the object first.
    """
    if getattr(vault, 'type', 'standard') != 'standard':
        return
    from security import encrypt_object_field, name_blind_index
    if is_file:
        if obj.original_name is not None:
            obj.enc_name = encrypt_object_field(obj.vault_id, obj.id, obj.original_name, 'name')
            obj.name_bi = name_blind_index(obj.vault_id, obj.original_name)
        if obj.mime_type:
            obj.enc_mime = encrypt_object_field(obj.vault_id, obj.id, obj.mime_type, 'mime')
        obj.original_name = None
        obj.name = None
        obj.mime_type = None
    else:
        if obj.name is not None:
            obj.enc_name = encrypt_object_field(obj.vault_id, obj.id, obj.name, 'name')
            obj.name_bi = name_blind_index(obj.vault_id, obj.name)
        obj.name = None


def _name_match_filter(model, vault, name: str):
    """SQLAlchemy filter matching `model` (File|Folder) rows whose name equals `name`.

    STANDARD vaults store the plaintext name NULL and match on the per-vault blind index;
    we also OR the plaintext column so a not-yet-backfilled legacy row still matches.
    Non-standard (ZK/legacy) vaults match on the plaintext column directly."""
    plain_col = model.original_name if model is File else model.name
    if getattr(vault, 'type', 'standard') == 'standard':
        from security import name_blind_index
        return or_(model.name_bi == name_blind_index(vault.id, name), plain_col == name)
    return plain_col == name


def deployment_storage_used(db) -> int:
    """Total stored bytes across all active vaults in this deployment (one deployment =
    one customer org)."""
    from sqlalchemy import func as _f
    return int(db.query(_f.coalesce(_f.sum(Vault.total_size_bytes), 0)).filter(
        Vault.is_active == True  # noqa: E712
    ).scalar() or 0)


def would_exceed_deployment_storage(db, additional_bytes: int):
    """Whether adding `additional_bytes` would push the deployment past its PLAN storage
    ceiling (settings.plan_max_storage_gb, GB; -1/0 => unlimited). Returns
    (exceeds: bool, used_bytes: int, cap_bytes: int). Shared by the HTTP upload paths
    (api_server) and the SFTP write path (sftp_server) so both honor the aggregate cap;
    each caller turns a True into its own error (HTTP 413 / SFTP failure). A soft,
    deployment-wide ceiling — the per-vault size_limit reservation stays the atomic guard.
    cap_gb <= 0 (or None) means UNLIMITED: the plan layer coerces an absent/0 storage value
    to -1, so a non-positive cap reaching here is 'no limit', never 'block everything'.
    Under concurrency the cap is best-effort (a SUM, not a reservation): worst-case
    overshoot ≈ (concurrent finalizes) × (per-vault size_limit)."""
    cap_gb = settings.plan_max_storage_gb
    if cap_gb is None or cap_gb <= 0:
        return (False, 0, 0)
    cap_bytes = cap_gb * 1024 * 1024 * 1024
    used = deployment_storage_used(db)
    return (used + max(0, additional_bytes or 0) > cap_bytes, used, cap_bytes)


class FileServiceError(Exception):
    """Base exception for file service errors."""
    pass


class VaultNotFoundError(FileServiceError):
    """Raised when vault is not found."""
    pass


class FolderNotFoundError(FileServiceError):
    """Raised when folder is not found."""
    pass


class FileNotFoundError(FileServiceError):
    """Raised when file is not found."""
    pass


class PasswordRequiredError(FileServiceError):
    """Raised when password is required but not provided."""
    pass


class InvalidPasswordError(FileServiceError):
    """Raised when provided password is invalid."""
    pass


class RateLimitExceededError(FileServiceError):
    """Raised when too many vault access attempts."""
    pass


class FileTooLargeError(FileServiceError):
    """Raised when file exceeds size limit."""
    pass


class DuplicateNameError(FileServiceError):
    """Raised when a name uniqueness constraint rejects an insert — i.e. another row with
    the same (vault, folder, name_bi) already exists. In normal operation the replace-on-
    clash path deletes the prior row first; this surfaces only on a lost concurrent race
    (or a folder-create clash) and the API layer maps it to HTTP 409."""
    pass


def calculate_file_expiration(vault) -> Optional[datetime]:
    """Calculate file expiration datetime based on vault's expiration policy.
    
    Args:
        vault: Vault object with expire_files_after_days and expire_files_unit fields
        
    Returns:
        datetime: Expiration timestamp, or None if no expiration policy
    """
    if not vault.expire_files_after_days:
        return None
    
    now = datetime.now(timezone.utc)
    value = vault.expire_files_after_days
    unit = vault.expire_files_unit or 'days'
    
    if unit == 'minutes':
        return now + timedelta(minutes=value)
    elif unit == 'hours':
        return now + timedelta(hours=value)
    else:  # 'days' or any other value defaults to days
        return now + timedelta(days=value)


class VaultService:
    """Service for vault operations."""
    
    def __init__(self, db: Session, permission_service: PermissionService):
        self.db = db
        self.permission_service = permission_service
        self.storage_path = Path(settings.file_storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize encrypted file storage handler
        self.encrypted_storage = EncryptedFileStorage(self.storage_path)
    
    def create_vault(
        self,
        name: str,
        owner: User,
        description: Optional[str] = None,
        password: Optional[str] = None,
        expire_files_after_days: Optional[int] = None,
        vault_type: str = 'standard'
    ) -> Vault:
        """
        Create a new vault.
        
        Args:
            name: Vault name
            owner: Owner user
            description: Optional description
            password: Optional vault password
            expire_files_after_days: Optional file expiration policy
            
        Returns:
            Created Vault object
        """
        from vault_key_utils import generate_vault_key, encrypt_vault_key
        from config import settings
        import json
        
        # Hash password if provided
        password_hash = hash_password(password) if password else None
        
        # ✅ NEW: Generate unique vault encryption key
        vault_key = generate_vault_key()
        
        # ✅ NEW: Encrypt vault key (with password or master key)
        master_key = settings.encryption_key.encode()
        encrypted_key_data = encrypt_vault_key(
            vault_key,
            password=password,
            master_key=master_key
        )
        
        vault = Vault(
            name=name,
            description=description,
            owner_id=owner.id,
            password_hash=password_hash,
            type=vault_type,
            expire_files_after_days=expire_files_after_days,
            # ✅ NEW: Store encrypted vault key
            encrypted_vault_key=encrypted_key_data['encrypted_key'],
            key_salt=encrypted_key_data['salt'],
            key_version=encrypted_key_data['version'],
            key_encryption_metadata=json.dumps({
                'method': encrypted_key_data['method'],
                'iterations': encrypted_key_data['iterations']
            })
        )
        
        self.db.add(vault)
        self.db.commit()
        self.db.refresh(vault)
        
        # Create vault directory
        vault_dir = self._get_vault_path(vault.id)
        vault_dir.mkdir(parents=True, exist_ok=True)
        
        return vault
    
    def get_vault(
        self,
        vault_id: uuid.UUID,
        user: User,
        vault_password: Optional[str] = None,
        require_password: bool = False
    ) -> Vault:
        """
        Get a vault with access verification.
        
        Args:
            vault_id: Vault UUID
            user: User requesting access
            vault_password: Optional vault password
            require_password: If True, validates password even for metadata access.
                            If False, password only validated when provided.
            
        Returns:
            Vault object
            
        Raises:
            VaultNotFoundError: If vault not found
            PermissionDeniedError: If user lacks access
            PasswordRequiredError: If password required but not provided (when require_password=True)
            InvalidPasswordError: If provided password is invalid
        """
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise VaultNotFoundError(f"Vault not found: {vault_id}")
        
        # Check permissions
        self.permission_service.require_vault_permission(
            user, vault_id, VaultPermissionEnum.READ
        )

        # Least-privilege gate: a scoped temp credential may only reach vaults in
        # its scope. No-op for normal users / legacy creds. Covers web AND SFTP
        # because every per-vault operation funnels through get_vault().
        from temp_scope import enforce_vault
        enforce_vault(user, vault_id)

        # Rate limiting for password-protected vaults
        if vault.password_hash and require_password:
            # Check rate limit before attempting password verification
            rate_key = f"rate_limit:vault:{vault_id}:{user.id}"
            attempts = redis_client.get(rate_key)
            
            # Different limits based on role (admins get higher limit)
            from models import RoleEnum
            limit = settings.rate_limit_vault_attempts_admin if user.role == RoleEnum.ADMIN else settings.rate_limit_vault_attempts
            
            if attempts and int(attempts) >= limit:
                raise RateLimitExceededError(
                    f"Too many vault access attempts. Please try again later."
                )
        
        # Check vault password if set AND if we require password validation
        # For metadata-only access (like opening vault view), we don't require password
        # For file access, we do require password
        if vault.password_hash and require_password:
            if not vault_password:
                raise PasswordRequiredError("Vault password is required")
            
            # Verify password
            password_valid = verify_password(vault_password, vault.password_hash)
            
            # Record failed attempt for rate limiting
            if not password_valid:
                rate_key = f"rate_limit:vault:{vault_id}:{user.id}"
                pipe = redis_client.pipeline()
                pipe.incr(rate_key)
                pipe.expire(rate_key, settings.rate_limit_vault_window_seconds)
                pipe.execute()
                
                raise InvalidPasswordError("Invalid vault password")
        
        # If password was provided, validate it (even if not required)
        if vault.password_hash and vault_password and not require_password:
            if not verify_password(vault_password, vault.password_hash):
                raise InvalidPasswordError("Invalid vault password")
        
        # Update last accessed time
        vault.last_accessed = datetime.now(timezone.utc)
        self.db.commit()
        
        return vault
    
    def list_vaults(
        self,
        user: User,
        include_stats: bool = False
    ) -> List[Vault]:
        """
        List vaults accessible to user.
        
        Args:
            user: User object
            include_stats: Whether to include statistics
            
        Returns:
            List of Vault objects
        """
        # Get vaults owned by user
        owned_vaults = self.db.query(Vault).filter(
            Vault.owner_id == user.id
        ).all()
        
        # Get vaults where user is a member
        member_vaults = self.db.query(Vault).join(
            Vault.members
        ).filter(
            User.id == user.id
        ).all()

        # Get vaults accessible via the user's group memberships
        from models import vault_group_access, user_groups
        from sqlalchemy import select
        group_ids = [
            r[0] for r in self.db.execute(
                select(user_groups.c.group_id).where(user_groups.c.user_id == user.id)
            ).fetchall()
        ]
        group_vaults = []
        if group_ids:
            vids = [
                r[0] for r in self.db.execute(
                    select(vault_group_access.c.vault_id).where(vault_group_access.c.group_id.in_(group_ids))
                ).fetchall()
            ]
            if vids:
                # Zero-knowledge vaults are never reachable via a group (the grant
                # endpoint blocks it — a group has no wrapped DEK). Exclude any stale
                # group row defensively so a ZK vault the user can't open or decrypt
                # never surfaces in their list. Owned/member ZK vaults are unaffected.
                group_vaults = self.db.query(Vault).filter(
                    Vault.id.in_(vids),
                    Vault.type != 'zero_knowledge',
                ).all()

        # Combine and deduplicate
        all_vaults = list(set(owned_vaults + member_vaults + group_vaults))

        # Scoped temp credential in 'selected' mode: restrict to its granted set
        # (intersection enforces "restrict, never expand"). 'all' / legacy: no-op.
        from temp_scope import is_scoped
        if is_scoped(user) and getattr(user, '_temp_vault_mode', 'selected') == 'selected':
            allowed = set((getattr(user, '_temp_vault_caps', {}) or {}).keys())
            all_vaults = [v for v in all_vaults if str(v.id) in allowed]

        return all_vaults
    
    def update_vault(
        self,
        vault_id: uuid.UUID,
        user: User,
        name: Optional[str] = None,
        description: Optional[str] = None,
        password: Optional[str] = None,
        expire_files_after_days: Optional[int] = None
    ) -> Vault:
        """
        Update vault properties.
        
        Args:
            vault_id: Vault UUID
            user: User performing update
            name: New name
            description: New description
            password: New password (use empty string to remove)
            expire_files_after_days: New expiration policy
            
        Returns:
            Updated Vault object
        """
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise VaultNotFoundError(f"Vault not found: {vault_id}")
        
        # Only owner can update vault
        if vault.owner_id != user.id:
            from authorization import PermissionDeniedError
            raise PermissionDeniedError("Only vault owner can update vault")
        
        if name is not None:
            vault.name = name
        
        if description is not None:
            vault.description = description
        
        # ✅ NEW: Handle password changes that require re-encrypting vault key
        if password is not None:
            from vault_key_utils import decrypt_vault_key, encrypt_vault_key
            from config import settings
            import json
            
            master_key = settings.encryption_key.encode()
            
            # Only re-encrypt if vault has encryption key
            if vault.encrypted_vault_key:
                # Decrypt vault key with old method
                old_encrypted_data = {
                    'encrypted_key': vault.encrypted_vault_key,
                    'salt': vault.key_salt,
                    'method': json.loads(vault.key_encryption_metadata).get('method') if vault.key_encryption_metadata else 'master_key',
                    'iterations': json.loads(vault.key_encryption_metadata).get('iterations', 100000) if vault.key_encryption_metadata else None,
                    'version': vault.key_version or 1
                }
                
                # Decrypt with master key (works for both password and non-password vaults)
                vault_key = decrypt_vault_key(old_encrypted_data, master_key=master_key)
                
                # Re-encrypt with new password (or master key if removing password)
                if password == "":
                    # Removing password - encrypt with master key
                    new_encrypted_data = encrypt_vault_key(vault_key, master_key=master_key)
                    vault.password_hash = None
                else:
                    # Setting/changing password - encrypt with password
                    new_encrypted_data = encrypt_vault_key(vault_key, password=password, master_key=master_key)
                    vault.password_hash = hash_password(password)
                
                # Update vault key encryption
                vault.encrypted_vault_key = new_encrypted_data['encrypted_key']
                vault.key_salt = new_encrypted_data['salt']
                vault.key_encryption_metadata = json.dumps({
                    'method': new_encrypted_data['method'],
                    'iterations': new_encrypted_data['iterations']
                })
            else:
                # Legacy vault without encryption key - just update password
                if password == "":
                    vault.password_hash = None
                else:
                    vault.password_hash = hash_password(password)
        
        if expire_files_after_days is not None:
            vault.expire_files_after_days = expire_files_after_days
        
        vault.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(vault)
        
        return vault
    
    def delete_vault(self, vault_id: uuid.UUID, user: User):
        """
        Delete a vault and all its contents.
        
        Args:
            vault_id: Vault UUID
            user: User performing deletion
        """
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise VaultNotFoundError(f"Vault not found: {vault_id}")
        
        # Owner-or-admin deletion — a read-only / shared member must not delete. NOTE:
        # the sole caller (the delete route) runs get_vault() first, which gates READ with no
        # admin special-case, so a non-member admin is already blocked upstream; this admin arm
        # covers an admin who is a member. Fails closed.
        from models import RoleEnum
        if vault.owner_id != user.id and user.role != RoleEnum.ADMIN:
            from authorization import PermissionDeniedError
            raise PermissionDeniedError("Only the vault owner or an admin can delete this vault")
        
        # Delete physical files
        vault_dir = self._get_vault_path(vault_id)
        if vault_dir.exists():
            shutil.rmtree(vault_dir)
        
        # Database cascade will handle related records
        self.db.delete(vault)
        self.db.commit()
    
    def create_folder(
        self,
        vault_id: uuid.UUID,
        name: str,
        user: User,
        parent_folder_id: Optional[uuid.UUID] = None,
        password: Optional[str] = None,
        zk_enc_name: Optional[str] = None,
        zk_name_bi: Optional[str] = None,
        zk_name_key_version: Optional[int] = None,
        folder_id: Optional[uuid.UUID] = None,
    ) -> Folder:
        """
        Create a folder in a vault.

        Args:
            vault_id: Vault UUID
            name: Folder name (plaintext, Standard vaults; None for zero-knowledge)
            user: User creating folder
            parent_folder_id: Optional parent folder UUID
            password: Optional folder password
            zk_enc_name / zk_name_bi / zk_name_key_version: for ZERO-KNOWLEDGE vaults the
                folder name is encrypted IN THE BROWSER under the vault DEK; the server
                stores the opaque blob + client blind index + name epoch and the plaintext
                name column stays NULL (the server never sees the folder name).

        Returns:
            Created Folder object
        """
        # Verify vault access
        self.permission_service.require_vault_permission(
            user, vault_id, VaultPermissionEnum.WRITE
        )

        # Verify parent folder if specified
        if parent_folder_id:
            parent_folder = self.db.query(Folder).filter(
                Folder.id == parent_folder_id
            ).first()

            if not parent_folder or parent_folder.vault_id != vault_id:
                raise FolderNotFoundError("Parent folder not found or not in vault")

            # bound nesting depth so the tree can't grow deep enough to exhaust
            # rows/inodes or blow Python's recursion limit in the recursive folder delete.
            depth = 1
            ancestor = parent_folder
            while ancestor is not None and ancestor.parent_folder_id is not None:
                depth += 1
                if depth > 64:
                    raise ValueError("Folder nesting too deep (max depth 64)")
                ancestor = self.db.query(Folder).filter(
                    Folder.id == ancestor.parent_folder_id
                ).first()

        # Hash password if provided
        password_hash = hash_password(password) if password else None

        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        is_zk = getattr(vault, 'type', 'standard') == 'zero_knowledge'

        # Reject a duplicate name in the same parent (folders are NOT auto-replaced, unlike
        # files). This mirrors rename's uniqueness check and is enforced at rest by the
        # (vault, parent, name_bi) unique index; the pre-check turns the common case into a
        # clean 409 instead of relying on the IntegrityError path below.
        clash_name = zk_name_bi if is_zk else sanitize_filename(name)
        clash_match = (Folder.name_bi == zk_name_bi) if is_zk \
            else _name_match_filter(Folder, vault, clash_name)
        if self.db.query(Folder).filter(
            Folder.vault_id == vault_id,
            Folder.parent_folder_id == parent_folder_id,
            clash_match,
        ).first() is not None:
            raise DuplicateNameError("A folder with that name already exists in this location")

        # Folder ID: a CLIENT-supplied id (zero-knowledge v2 name binding — the browser seals
        # the name bound to this id) or a server-generated one; assigned now so the at-rest name
        # cipher key (per id) is available. The endpoint validates a client id is a fresh UUID.
        if folder_id is not None and self.db.query(Folder.id).filter(Folder.id == folder_id).first():
            raise ValueError("folder id already in use")
        folder = Folder(
            id=folder_id or uuid.uuid4(),
            # ZK: no plaintext name — store the browser-encrypted name + blind index + epoch.
            name=None if is_zk else sanitize_filename(name),
            vault_id=vault_id,
            parent_folder_id=parent_folder_id,
            password_hash=password_hash,
            created_by=user.id,
        )
        if is_zk:
            folder.enc_name = zk_enc_name
            folder.name_bi = zk_name_bi
            folder.name_key_version = int(zk_name_key_version) if zk_name_key_version else 1
        else:
            # Encrypt the folder name at rest (Standard vaults) before persisting.
            _seal_named_object(vault, folder, is_file=False)

        self.db.add(folder)
        try:
            self.db.commit()
        except IntegrityError:
            # Lost a concurrent same-name folder-create race against the unique index.
            self.db.rollback()
            raise DuplicateNameError("A folder with that name already exists in this location")
        self.db.refresh(folder)
        
        # Create physical directory
        folder_path = self._get_folder_path(vault_id, folder.id)
        folder_path.mkdir(parents=True, exist_ok=True)
        
        return folder
    
    def get_folder(
        self,
        folder_id: uuid.UUID,
        user: User,
        folder_password: Optional[str] = None
    ) -> Folder:
        """Get a folder with access verification."""
        folder = self.db.query(Folder).filter(Folder.id == folder_id).first()
        
        if not folder:
            raise FolderNotFoundError(f"Folder not found: {folder_id}")
        
        # Check vault access
        self.permission_service.require_vault_permission(
            user, folder.vault_id, VaultPermissionEnum.READ
        )
        
        # Check folder password if set
        if folder.password_hash:
            if not folder_password:
                raise PasswordRequiredError("Folder password is required")
            
            if not verify_password(folder_password, folder.password_hash):
                raise InvalidPasswordError("Invalid folder password")
        
        return folder
    
    def upload_file(
        self,
        vault_id: uuid.UUID,
        file_name: str,
        file_content: bytes,
        user: User,
        folder_id: Optional[uuid.UUID] = None,
        password: Optional[str] = None,
        mime_type: Optional[str] = None
    ) -> File:
        """
        Upload and encrypt a file.
        
        Args:
            vault_id: Vault UUID
            file_name: Original file name
            file_content: File content bytes
            user: User uploading file
            folder_id: Optional folder UUID
            password: Optional file password
            mime_type: Optional MIME type
            
        Returns:
            Created File object
        """
        # RETIRED: this whole-file AES-256-GCM writer is no longer used — every upload
        # goes through upload_file_streaming (the AES-GCM chunked stream that binds each
        # chunk's AAD to vault_id+file_id). It wrote a format (DockVault + 0x01) that
        # download_file no longer reads, so re-wiring it would silently create
        # undecryptable blobs. Guard it off rather than leave a latent foot-gun.
        raise NotImplementedError(
            "VaultService.upload_file is retired; use upload_file_streaming "
            "(the AES-GCM chunked at-rest stream)."
        )
        from vault_key_utils import get_vault_key_bytes
        from config import settings
        
        # Check file size
        file_size = len(file_content)
        max_size_bytes = settings.max_file_size_mb * 1024 * 1024
        
        if file_size > max_size_bytes:
            raise FileTooLargeError(
                f"File exceeds maximum size of {settings.max_file_size_mb}MB"
            )
        
        # Verify vault access
        self.permission_service.require_vault_permission(
            user, vault_id, VaultPermissionEnum.WRITE
        )
        
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        
        # Verify folder if specified
        if folder_id:
            folder = self.db.query(Folder).filter(Folder.id == folder_id).first()
            if not folder or folder.vault_id != vault_id:
                raise FolderNotFoundError("Folder not found or not in vault")
        
        # Calculate checksum before encryption
        checksum = calculate_file_checksum(file_content)
        
        # Generate unique file ID and storage path
        file_id = uuid.uuid4()
        storage_path = self._get_file_storage_path(vault_id, file_id, folder_id)
        
        # ✅ ENHANCED: Encrypt with AES-256-GCM and metadata
        master_key = settings.encryption_key.encode()
        try:
            # Get raw 32-byte vault key for AES-GCM
            vault_key = get_vault_key_bytes(vault, password=None, master_key=master_key)
            
            # Encrypt and save with metadata (key version, nonce, etc.)
            encrypted_size = self.encrypted_storage.encrypt_and_save(
                file_content=file_content,
                vault_key=vault_key,
                storage_path=storage_path,
                key_version=getattr(vault, 'key_version', 1)
            )
            
        except (ValueError, AttributeError) as e:
            # Fallback to old Fernet encryption for vaults without proper keys
            print(f"Warning: Using fallback Fernet encryption for vault {vault_id}: {e}")
            from vault_key_utils import get_vault_fernet
            vault_fernet = get_vault_fernet(vault, password=None, master_key=master_key)
            encrypted_content = vault_fernet.encrypt(file_content)
            
            # Save with old method
            storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(storage_path, 'wb') as f:
                f.write(encrypted_content)
        
        # Detect MIME type if not provided
        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_name)
        
        # Hash password if provided
        password_hash = hash_password(password) if password else None
        
        # Calculate expiration if vault has policy
        expires_at = calculate_file_expiration(vault)
        
        # Create file record
        file = File(
            id=file_id,
            name=sanitize_filename(file_name),
            original_name=file_name,
            vault_id=vault_id,
            folder_id=folder_id,
            size_bytes=file_size,
            mime_type=mime_type,
            checksum_sha256=checksum,
            storage_path=str(storage_path.relative_to(self.storage_path)),
            is_encrypted=True,
            password_hash=password_hash,
            expires_at=expires_at,
            uploaded_by=user.id
        )
        
        self.db.add(file)
        
        # Update vault statistics
        vault.total_size_bytes += file_size
        vault.file_count += 1
        
        self.db.commit()
        self.db.refresh(file)
        
        return file
    
    def upload_file_streaming(
        self,
        vault_id: uuid.UUID,
        file_name: str,
        user: User,
        folder_id: Optional[uuid.UUID] = None,
        password: Optional[str] = None,
        mime_type: Optional[str] = None,
        file_id: Optional[uuid.UUID] = None,
    ) -> tuple[File, object]:
        """
        Start a streaming file upload.
        Returns File object and a context manager for writing chunks.
        
        Args:
            vault_id: Vault UUID
            file_name: Original file name
            user: User uploading file
            folder_id: Optional folder UUID
            password: Optional file password
            mime_type: Optional MIME type
            
        Returns:
            Tuple of (File object, StreamingUploadContext)
        """
        from streaming_upload import StreamingUploadContext
        from security import GcmChunkStreamCodec, IdentityChunkCodec, calculate_file_checksum
        
        # Verify vault access
        self.permission_service.require_vault_permission(
            user, vault_id, VaultPermissionEnum.WRITE
        )
        
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        
        # Verify folder if specified
        if folder_id:
            folder = self.db.query(Folder).filter(Folder.id == folder_id).first()
            if not folder or folder.vault_id != vault_id:
                raise FolderNotFoundError("Folder not found or not in vault")

        # File ID: a CLIENT-supplied id (zero-knowledge v2 name binding — the browser seals the
        # name bound to this id before the row exists) or a server-generated one. The endpoint
        # validates a client id is a fresh UUID; this is belt-and-suspenders against a collision.
        if file_id is not None and self.db.query(File.id).filter(File.id == file_id).first():
            raise ValueError("file id already in use")
        file_id = file_id or uuid.uuid4()
        storage_path = self._get_file_storage_path(vault_id, file_id, folder_id)
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Detect MIME type if not provided
        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_name)
        
        # Hash password if provided
        password_hash = hash_password(password) if password else None
        
        # Calculate expiration if vault has policy
        expires_at = calculate_file_expiration(vault)
        
        # Zero-knowledge vaults store the CLIENT's ciphertext verbatim — the server
        # performs no encryption and cannot read the content. Standard vaults use the
        # AES-256-GCM chunked stream whose per-chunk AAD binds the blob to THIS
        # vault+file (so a stored blob can't be swapped between vaults/files).
        is_zk = getattr(vault, 'type', 'standard') == 'zero_knowledge'
        codec = IdentityChunkCodec() if is_zk else GcmChunkStreamCodec(vault_id, file_id)

        # Create streaming context
        context = StreamingUploadContext(
            file_id=file_id,
            storage_path=storage_path,
            codec=codec,
        )
        
        # File object will be created after upload completes with actual size
        file_info = {
            'id': file_id,
            'name': sanitize_filename(file_name),
            'original_name': file_name,
            'vault_id': vault_id,
            'folder_id': folder_id,
            'mime_type': mime_type,
            'storage_path': str(storage_path.relative_to(self.storage_path)),
            'is_encrypted': True,
            'password_hash': password_hash,
            'expires_at': expires_at,
            'uploaded_by': user.id,
            'vault': vault
        }
        
        return file_info, context
    
    def _stage_same_name_replacement(self, vault, vault_id, folder_id, *,
                                     filename: Optional[str] = None,
                                     name_bi: Optional[str] = None) -> List[str]:
        """Mark prior same-name File rows in (vault, folder) for deletion as part of the
        CALLER's open transaction (NO commit here) and return their on-disk blob paths,
        decrementing vault stats for each.

        This is the replace-on-clash step done BEFORE the replacement row is inserted, in
        the SAME transaction — so the old and new rows never coexist under the
        (vault_id, folder_id, name_bi) unique index, while a rollback still leaves the old
        file fully intact (its blob is only removed from disk by _remove_blobs AFTER the
        commit succeeds). Zero-knowledge matches on the client blind index; Standard matches
        the per-vault blind index OR the plaintext column (un-backfilled legacy rows)."""
        if name_bi is not None:
            match = (File.name_bi == name_bi)
        elif filename is not None:
            match = _name_match_filter(File, vault, filename)
        else:
            return []
        paths: List[str] = []
        for ex in self.db.query(File).filter(
            File.vault_id == vault_id,
            File.folder_id == folder_id,
            match,
        ).all():
            paths.append(ex.storage_path)
            vault.total_size_bytes = max(0, (vault.total_size_bytes or 0) - (ex.size_bytes or 0))
            vault.file_count = max(0, (vault.file_count or 0) - 1)
            self.db.delete(ex)
        if paths:
            # Force the DELETEs to hit the DB NOW, before the caller inserts the replacement
            # row. SQLAlchemy's unit-of-work otherwise orders INSERTs ahead of DELETEs within
            # a flush, which would momentarily put the new row alongside the old one and trip
            # the (vault_id, folder_id, name_bi) unique index. Same transaction, so a later
            # rollback still restores the old rows.
            self.db.flush()
        return paths

    def _remove_blobs(self, rel_paths: List[str]) -> None:
        """Securely remove on-disk encrypted blobs by storage_path (relative to the storage
        root). Best-effort: a failure here only orphans a blob, never the committed DB state."""
        for rel in rel_paths:
            try:
                p = self.storage_path / rel
                if p.exists():
                    self.encrypted_storage.secure_delete(p)
            except Exception as e:  # noqa: BLE001
                print(f"⚠️ replace: could not remove old blob {rel}: {e}")

    def finalize_streaming_upload(self, file_info: dict, total_size: int, checksum: str,
                                  zk_key_version: Optional[int] = None,
                                  zk_enc_name: Optional[str] = None,
                                  zk_enc_mime: Optional[str] = None,
                                  zk_name_bi: Optional[str] = None,
                                  replace_same_name: bool = False):
        """
        Finalize a streaming upload by creating the File database record.

        Args:
            file_info: File information dictionary from upload_file_streaming
            total_size: Total size of uploaded file in bytes
            checksum: SHA256 checksum of original file
            zk_key_version: for zero-knowledge vaults, the DEK epoch this file was
                encrypted under (stamped into File.encryption_metadata so a later read
                fetches the right wrapped DEK after a rotation). Defaults to the vault's
                current dek_version. Ignored for Standard vaults.
            zk_enc_name / zk_enc_mime / zk_name_bi: for zero-knowledge vaults the file
                name + MIME encrypted IN THE BROWSER under the vault DEK, plus the client
                blind index. Stored verbatim; the plaintext name columns stay NULL (the
                server never sees the name). Ignored for Standard vaults.
            replace_same_name: same-name policy = REPLACE. When True, any prior same-name
                file in the folder is deleted in the SAME transaction as this insert (so the
                two never coexist under the name unique index, and a rollback preserves the
                old file). The CALLER must pre-authorize replacement (the upload paths gate
                this on the principal's file.delete capability); when the principal cannot
                replace, pass False and a same-name clash surfaces as DuplicateNameError (409).
        """
        # Check file size
        max_size_bytes = settings.max_file_size_mb * 1024 * 1024
        if total_size > max_size_bytes:
            raise FileTooLargeError(
                f"File exceeds maximum size of {settings.max_file_size_mb}MB"
            )

        vault_obj = file_info['vault']
        is_zk = getattr(vault_obj, 'type', 'standard') == 'zero_knowledge'

        # Replace-on-clash: delete any prior same-name row BEFORE inserting the new one,
        # within this transaction (blobs removed only after a successful commit, below).
        stale_blobs: List[str] = []
        if replace_same_name:
            stale_blobs = self._stage_same_name_replacement(
                vault_obj, file_info['vault_id'], file_info['folder_id'],
                filename=None if is_zk else file_info['original_name'],
                name_bi=zk_name_bi if is_zk else None,
            )

        # Create file record
        file = File(
            id=file_info['id'],
            # ZK: no plaintext name/MIME at rest — set below from the client blobs.
            name=None if is_zk else file_info['name'],
            original_name=None if is_zk else file_info['original_name'],
            vault_id=file_info['vault_id'],
            folder_id=file_info['folder_id'],
            size_bytes=total_size,
            mime_type=None if is_zk else file_info['mime_type'],
            checksum_sha256=checksum,
            storage_path=file_info['storage_path'],
            is_encrypted=file_info['is_encrypted'],
            password_hash=file_info['password_hash'],
            expires_at=file_info['expires_at'],
            uploaded_by=file_info['uploaded_by']
        )

        if is_zk:
            # Tag the DEK epoch this ciphertext was encrypted under, so a read after a
            # rotation fetches the matching wrapped DEK (forward-only versioning). Non-secret
            # routing metadata. Absent => epoch 1 (legacy).
            version = zk_key_version if zk_key_version is not None else (getattr(vault_obj, 'dek_version', 1) or 1)
            file.encryption_metadata = {'key_version': int(version)}
            # Browser-encrypted name/MIME + client blind index. The server cannot read these.
            file.enc_name = zk_enc_name
            file.enc_mime = zk_enc_mime
            file.name_bi = zk_name_bi

        self.db.add(file)

        # Encrypt the filename/MIME at rest (Standard vaults) before persisting. No-op for ZK.
        _seal_named_object(file_info['vault'], file, is_file=True)

        # Update vault statistics
        vault = file_info['vault']
        vault.total_size_bytes += total_size
        vault.file_count += 1

        try:
            self.db.commit()
        except IntegrityError:
            # The (vault, folder, name_bi) unique index rejected the insert — a same-name
            # row already exists (a lost concurrent race, or a non-replacing principal hit a
            # clash that appeared after the open() pre-check). Roll back (the old file's row,
            # only marked-deleted in this txn, is restored intact) and remove just the new
            # blob already written during streaming, then surface a clean 409.
            self.db.rollback()
            self._remove_blobs([file_info['storage_path']])
            raise DuplicateNameError("A file with that name already exists in this folder.")
        self.db.refresh(file)
        # Commit succeeded: the prior same-name rows are gone, so it is now safe to remove
        # their on-disk blobs (deferred until here so a rollback never destroys the old file).
        self._remove_blobs(stale_blobs)

        return file
    
    def download_file(
        self,
        file_id: uuid.UUID,
        user: User,
        file_password: Optional[str] = None
    ) -> Tuple[bytes, str, str]:
        """
        Download and decrypt a file.
        
        Args:
            file_id: File UUID
            user: User downloading file
            file_password: Optional file password
            
        Returns:
            Tuple of (file_content, file_name, mime_type)
        """
        file = self.db.query(File).filter(File.id == file_id).first()
        
        if not file:
            raise FileNotFoundError(f"File not found: {file_id}")
        
        # Check vault access
        self.permission_service.require_vault_permission(
            user, file.vault_id, VaultPermissionEnum.READ
        )
        
        # Check file password if set
        if file.password_hash:
            if not file_password:
                raise PasswordRequiredError("File password is required")
            
            if not verify_password(file_password, file.password_hash):
                raise InvalidPasswordError("Invalid file password")
        
        # Get vault for decryption
        vault = self.db.query(Vault).filter(Vault.id == file.vault_id).first()
        
        # Get file storage path
        storage_path = self.storage_path / file.storage_path
        
        if not storage_path.exists():
            raise FileNotFoundError(f"File data not found on disk: {file_id}")

        # Zero-knowledge vault: the server stored the client's ciphertext verbatim
        # and has no key to read it — return the bytes AS-IS (the client decrypts).
        # Integrity here is over the stored ciphertext; plaintext integrity is the
        # client's responsibility via its own AEAD.
        if vault and getattr(vault, 'type', 'standard') == 'zero_knowledge':
            with open(storage_path, 'rb') as f:
                file_content = f.read()
            if not verify_file_integrity(file_content, file.checksum_sha256):
                raise FileServiceError("File integrity check failed")
            return file_content, file.original_name, file.mime_type or 'application/octet-stream'

        # Auto-detect the at-rest format and decrypt accordingly:
        #  - AES-256-GCM chunked stream (MAGIC + version 0x10): the current format; each
        #    chunk's AAD is bound to this file's vault_id + file_id, so a blob swapped in
        #    from another file/vault fails to decrypt.
        #  - otherwise: the legacy global-key Fernet chunk stream (length-prefixed tokens,
        #    no magic header).
        # NB: the old whole-file AES-GCM writer (upload_file + EncryptedFileStorage) is
        # never called, and its detector compared only header[:5] to a 9-byte magic so it
        # never matched — there are no such files to read.
        from security import (
            is_gcm_chunk_stream, decrypt_gcm_chunk_stream, decrypt_chunk_stream,
        )

        if is_gcm_chunk_stream(storage_path):
            try:
                with open(storage_path, 'rb') as f:
                    file_content = decrypt_gcm_chunk_stream(f, file.vault_id, file.id)
            except Exception as e:
                raise FileServiceError(f"Failed to decrypt file: {e}")
        else:
            # Legacy Fernet chunk stream (global key, length-prefixed tokens).
            file_content_chunks = []
            try:
                with open(storage_path, 'rb') as f:
                    for decrypted_chunk in decrypt_chunk_stream(f):
                        file_content_chunks.append(decrypted_chunk)
                file_content = b''.join(file_content_chunks)
            except Exception as e:
                raise FileServiceError(f"Failed to decrypt chunked file: {e}")
        
        # Verify integrity
        if not verify_file_integrity(file_content, file.checksum_sha256):
            raise FileServiceError("File integrity check failed")
        
        return file_content, file.original_name, file.mime_type or 'application/octet-stream'
    
    def delete_file(self, file_id: uuid.UUID, user: User):
        """
        Securely delete a file.
        
        Args:
            file_id: File UUID
            user: User deleting file
        """
        file = self.db.query(File).filter(File.id == file_id).first()
        
        if not file:
            raise FileNotFoundError(f"File not found: {file_id}")
        
        # Check vault access
        self.permission_service.require_vault_permission(
            user, file.vault_id, VaultPermissionEnum.DELETE
        )
        
        vault = file.vault
        
        # ✅ ENHANCED: Use EncryptedFileStorage secure deletion
        storage_path = self.storage_path / file.storage_path
        
        if storage_path.exists():
            try:
                # Secure delete with overwrite
                self.encrypted_storage.secure_delete(storage_path)
            except Exception as e:
                # Fallback to manual overwrite if secure delete fails
                print(f"Warning: EncryptedFileStorage.secure_delete() failed, using fallback: {e}")
                try:
                    file_size = storage_path.stat().st_size
                    with open(storage_path, 'wb') as f:
                        f.write(os.urandom(file_size))
                    storage_path.unlink()
                except Exception as fallback_error:
                    print(f"Warning: Fallback deletion also failed: {fallback_error}")
                    # Last resort: just delete
                    storage_path.unlink()
        
        # Update vault statistics
        vault.total_size_bytes -= file.size_bytes
        vault.file_count -= 1
        
        # Delete database record
        self.db.delete(file)
        self.db.commit()
    
    def rename_file(self, file_id: uuid.UUID, new_name: str, user: User,
                    vault_id: Optional[uuid.UUID] = None, *,
                    zk_enc_name: Optional[str] = None,
                    zk_name_bi: Optional[str] = None,
                    zk_name_key_version: Optional[int] = None):
        """
        Rename a file or folder.

        Args:
            file_id: File or Folder UUID
            new_name: New plaintext name (Standard vaults; None for zero-knowledge)
            user: User renaming the file
            zk_enc_name / zk_name_bi / zk_name_key_version: for ZERO-KNOWLEDGE vaults the new
                name is encrypted IN THE BROWSER under the vault DEK; the server stores the
                opaque blob + client blind index (+ epoch for folders) and the plaintext name
                column stays NULL. The server never sees the new name.

        Raises:
            FileNotFoundError: If file/folder doesn't exist
            ValueError: If new name is invalid or already exists
        """
        # Resolve the target (file first, then folder) and the cross-vault guard up front,
        # so we can branch on vault type before any plaintext-name validation (which can't
        # run for zero-knowledge renames — the server never receives the plaintext name).
        file = self.db.query(File).filter(File.id == file_id).first()
        folder = None if file else self.db.query(Folder).filter(Folder.id == file_id).first()
        if not file and not folder:
            raise FileNotFoundError("File or folder not found. It may have been deleted.")
        target = file or folder
        if vault_id is not None and target.vault_id != vault_id:
            raise FileNotFoundError("File or folder not found. It may have been deleted.")
        self.permission_service.require_vault_permission(
            user, target.vault_id, VaultPermissionEnum.WRITE
        )
        fvault = self.db.query(Vault).filter(Vault.id == target.vault_id).first()

        # Zero-knowledge rename: store the browser-encrypted name + blind index; the server
        # validates nothing about the name (the browser did) and learns nothing about it.
        if getattr(fvault, 'type', 'standard') == 'zero_knowledge':
            if not zk_enc_name or not zk_name_bi:
                raise ValueError("A zero-knowledge rename requires an encrypted name (enc_name + name_bi).")
            if folder is not None:
                clash = self.db.query(Folder).filter(and_(
                    Folder.vault_id == folder.vault_id,
                    Folder.parent_folder_id == folder.parent_folder_id,
                    Folder.name_bi == zk_name_bi,
                    Folder.id != file_id,
                )).first()
                if clash:
                    raise ValueError("A folder with that name already exists in this location")
                folder.enc_name = zk_enc_name
                folder.name_bi = zk_name_bi
                folder.name_key_version = int(zk_name_key_version) if zk_name_key_version else (folder.name_key_version or 1)
                folder.name = None
                folder.updated_at = datetime.now(timezone.utc)
                self.db.commit()
                return {'old_name': None, 'new_name': None, 'file_type': 'folder'}
            clash = self.db.query(File).filter(and_(
                File.vault_id == file.vault_id,
                File.folder_id == file.folder_id,
                File.name_bi == zk_name_bi,
                File.id != file_id,
            )).first()
            if clash:
                raise ValueError("A file with that name already exists in this location")
            # A file's name epoch follows its CONTENT epoch (encryption_metadata.key_version),
            # which a rename never changes — so we only swap the name blob + blind index.
            file.enc_name = zk_enc_name
            file.name_bi = zk_name_bi
            file.name = None
            file.original_name = None
            file.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            return {'old_name': None, 'new_name': None, 'file_type': 'file'}

        # ---- Standard / legacy plaintext rename ----
        # Validate new name
        new_name = (new_name or '').strip()
        # strip control chars (CR/LF etc.) so a renamed object's stored name can't
        # corrupt logs or inject into the download Content-Disposition header — the
        # invalid_chars list below omits them (the download-header sink is also defended).
        new_name = ''.join(c for c in new_name if ord(c) >= 32 and ord(c) != 127)
        if not new_name:
            raise ValueError("File name cannot be empty")

        if len(new_name) > 255:
            raise ValueError("File name is too long (max 255 characters)")

        # Check for invalid characters (path traversal prevention)
        invalid_chars = ['/', '\\', '\0', '<', '>', ':', '"', '|', '?', '*']
        if any(char in new_name for char in invalid_chars):
            raise ValueError(f"File name contains invalid characters: {', '.join(invalid_chars)}")

        # Renaming a folder (target resolved + access checked above).
        if not file:
            existing_folder = self.db.query(Folder).filter(
                and_(
                    Folder.vault_id == folder.vault_id,
                    Folder.parent_folder_id == folder.parent_folder_id,
                    _name_match_filter(Folder, fvault, new_name),
                    Folder.id != file_id
                )
            ).first()

            if existing_folder:
                raise ValueError(f"A folder named '{new_name}' already exists in this location")

            old_name = folder.name
            folder.name = new_name
            folder.updated_at = datetime.now(timezone.utc)
            # Re-encrypt the new name at rest (Standard vaults).
            _seal_named_object(fvault, folder, is_file=False)
            self.db.commit()
            self.db.refresh(folder)

            return {
                'old_name': old_name,
                'new_name': new_name,
                'file_type': 'folder'
            }

        # Renaming a file (target resolved + access checked above).
        # Check if new name already exists in the same folder
        existing_file = self.db.query(File).filter(
            and_(
                File.vault_id == file.vault_id,
                File.folder_id == file.folder_id,
                _name_match_filter(File, fvault, new_name),
                File.id != file_id  # Exclude current file
            )
        ).first()

        if existing_file:
            raise ValueError(f"A file or folder named '{new_name}' already exists in this location")

        # Capture the kind BEFORE sealing nulls the in-memory mime_type.
        is_folder_kind = (file.mime_type == 'folder')
        old_name = file.original_name

        # Update database record
        file.original_name = new_name

        # NOTE: the on-disk blob is named purely by the file UUID (no extension), so a
        # metadata rename does NOT touch the filesystem — and must NOT write the new
        # name's extension into storage_path, which is stored in cleartext at rest. The
        # extension is recoverable from the sealed enc_name/enc_mime at read time, so it
        # never needs to leak into the path. (Older rows whose storage_path already has an
        # extension keep working; we just stop adding one.)

        # Re-encrypt name/MIME at rest (Standard vaults) for the new name.
        _seal_named_object(fvault, file, is_file=True)
        self.db.commit()
        self.db.refresh(file)

        return {
            'old_name': old_name,
            'new_name': new_name,
            'file_type': 'folder' if is_folder_kind else 'file'
        }
    
    def cleanup_expired_files(self):
        """Clean up expired files."""
        now = datetime.now(timezone.utc)
        
        expired_files = self.db.query(File).filter(
            and_(
                File.expires_at.isnot(None),
                File.expires_at < now
            )
        ).all()
        
        for file in expired_files:
            try:
                # Securely delete physical file
                storage_path = self.storage_path / file.storage_path
                
                if storage_path.exists():
                    file_size = storage_path.stat().st_size
                    with open(storage_path, 'wb') as f:
                        f.write(os.urandom(file_size))
                    
                    storage_path.unlink()
                
                # Update vault statistics
                vault = file.vault
                if vault:
                    vault.total_size_bytes -= file.size_bytes
                    vault.file_count -= 1
                
                # Delete database record
                self.db.delete(file)
            
            except Exception as e:
                print(f"Error deleting expired file {file.id}: {e}")
                continue
        
        self.db.commit()
    
    def _get_vault_path(self, vault_id: uuid.UUID) -> Path:
        """Get physical path for vault directory."""
        return self.storage_path / str(vault_id)
    
    def _get_folder_path(self, vault_id: uuid.UUID, folder_id: uuid.UUID) -> Path:
        """Get physical path for folder directory."""
        return self._get_vault_path(vault_id) / "folders" / str(folder_id)
    
    def _get_file_storage_path(
        self,
        vault_id: uuid.UUID,
        file_id: uuid.UUID,
        folder_id: Optional[uuid.UUID] = None
    ) -> Path:
        """Get physical storage path for file."""
        if folder_id:
            return self._get_folder_path(vault_id, folder_id) / str(file_id)
        else:
            return self._get_vault_path(vault_id) / "files" / str(file_id)
