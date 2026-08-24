"""
File and vault management service.
Handles file encryption, storage, and hierarchical password protection.
"""
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, BinaryIO
import itertools
import uuid
import mimetypes

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import IntegrityError

from app.core.models import User, Vault, Folder, File, VaultPermissionEnum
from app.core.safe_log import safe_event
from app.core.security import (
    encrypt_file_content, decrypt_file_content,
    calculate_file_checksum, verify_file_integrity,
    hash_password, verify_password, sanitize_filename
)
from app.core.authorization import PermissionService, PermissionDeniedError
from app.core.config import settings
from app.core.database import redis_client
from app.services.encrypted_file_storage import EncryptedFileStorage

import contextvars

# The X-Vault-Passcode header value for the CURRENT HTTP request, captured by a pure-ASGI middleware
# (see api_server.VaultPasscodeMiddleware) and read by get_vault. A contextvar so a temp-credential
# passcode can be redeemed at the single get_vault chokepoint WITHOUT threading a second header through
# every file endpoint (the vault password is threaded explicitly; the passcode rides this instead).
# None for SFTP / requests without the header.
_vault_passcode_ctx = contextvars.ContextVar("vault_passcode", default=None)


def current_vault_passcode():
    """The X-Vault-Passcode for the current request, or None."""
    return _vault_passcode_ctx.get()


def set_current_vault_passcode(value):
    """Set the request's X-Vault-Passcode (middleware only); returns a token to reset with."""
    return _vault_passcode_ctx.set(value)


def reset_current_vault_passcode(token):
    _vault_passcode_ctx.reset(token)


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
    from app.core.security import encrypt_object_field, name_blind_index
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
        from app.core.security import name_blind_index
        return or_(model.name_bi == name_blind_index(vault.id, name), plain_col == name)
    return plain_col == name


def deployment_storage_used(db) -> int:
    """Total stored bytes across all active vaults in this deployment (one deployment =
    one customer org)."""
    from sqlalchemy import func as _f
    return int(db.query(_f.coalesce(_f.sum(Vault.total_size_bytes), 0)).filter(
        Vault.is_active == True  # noqa: E712
    ).scalar() or 0)


def deployment_storage_limit_bytes(db):
    """The EFFECTIVE deployment-wide limit on stored bytes, or None when unlimited.

    Two layers: MAX_STORAGE_GB is the deployment's hard ceiling, and an administrator may save
    a lower live limit ('deployment_storage_limit_gb' in the global settings blob) from the
    admin panel. A settings read that fails falls back to the env ceiling alone rather than to
    'unlimited' — a database hiccup must not quietly remove the storage limit."""
    from app.core import storage_quota
    from app.core.models import SystemSetting
    stored = None
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
        if row and row.value:
            stored = row.value.get("deployment_storage_limit_gb")
    except Exception:
        stored = None
    return storage_quota.deployment_limit_bytes(settings.max_storage_gb, stored)


def would_exceed_deployment_storage(db, additional_bytes: int):
    """Whether adding `additional_bytes` would push the deployment past its storage limit
    (see deployment_storage_limit_bytes). Returns (exceeds: bool, used_bytes: int,
    cap_bytes: int). Shared by the HTTP upload paths (api_server) and the SFTP write path
    (sftp_server) so both honor the aggregate limit; each caller turns a True into its own
    error (HTTP 413 / SFTP failure).

    This counts STORED bytes only — declaring a vault size allocates against the owner's own
    account budget, never against the deployment, so a thousand empty vaults leave this number
    untouched. The per-vault size_limit remains the atomic per-upload guard.

    Under concurrency the limit is best-effort (a SUM, not a reservation): worst-case overshoot
    ≈ (concurrent finalizes) × (per-vault size_limit)."""
    from app.core import storage_quota
    cap_bytes = deployment_storage_limit_bytes(db)
    if cap_bytes is None:
        return (False, 0, 0)
    used = deployment_storage_used(db)
    return (storage_quota.would_exceed_deployment(used, additional_bytes, cap_bytes), used, cap_bytes)


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


def is_refundable_serve_failure(exc) -> bool:
    """Does `exc` mean the server FAILED TO SERVE a file it should have been able to — such that a
    share download burned against it must be RETURNED?

    True for a server-side integrity failure on stored bytes: a rejected at-rest walk or a record
    that will not authenticate (``FileServiceError``/``EncryptionError``) and a whole-file checksum
    mismatch (``ChecksumMismatch``). A client cannot induce any of these, which is exactly why
    returning the burn cannot be used to uncap a capped share.

    False — deliberately, and each for its own reason — for four things that ARE (or subclass) the
    above but must never refund here:

    - ``ObjectChangedDuringRead`` — a delete or same-name replacement while the read is open. It
      subclasses ``EncryptionError`` (so it would slip through a bare isinstance), but it is a race a
      party with vault write access can trigger on demand; refunding it would turn the download cap
      into a counter an attacker holds down at will.
    - ``InvalidPasswordError`` / ``PasswordRequiredError`` — client/auth failures (they subclass
      ``FileServiceError``). The client caused them, so the burn stays spent.
    - ``FileNotFoundError`` — a missing blob is refunded, but on its own dedicated 404 path, not
      here; classifying it as a generic serve failure would double-count it.

    Self-contained (it does not rely on the caller having peeled these off first), so it is safe to
    reuse and can be unit-tested directly."""
    from app.core.security import EncryptionError, ObjectChangedDuringRead
    from app.services.download_stream import ChecksumMismatch
    if isinstance(exc, (ObjectChangedDuringRead, InvalidPasswordError,
                        PasswordRequiredError, FileNotFoundError)):
        return False
    return isinstance(exc, (FileServiceError, ChecksumMismatch, EncryptionError))


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


def folder_ancestry(db: Session, vault_id, folder_id) -> List[str]:
    """Folder-id chain from `folder_id` up to the vault root, INCLUSIVE:
    ``[str(folder_id), str(parent), ..., str(root)]``; ``[]`` when folder_id is None (vault root).
    Every hop is filtered by `vault_id` (a cross-vault folder stops the walk), and a visited-set
    guards against a cycle. Feeds the ID-based scope check (app/core/id_scope) and the delegation
    clamp; because it uses IDs, not names, it works for zero-knowledge vaults too."""
    chain: List[str] = []
    seen = set()
    cur = folder_id
    while cur is not None:
        cur_s = str(cur)
        if cur_s in seen:
            break  # cycle guard (defensive; the tree should never contain one)
        seen.add(cur_s)
        row = db.query(Folder.id, Folder.parent_folder_id).filter(
            Folder.id == cur, Folder.vault_id == vault_id).first()
        if row is None:
            break  # unknown / cross-vault folder -> stop (the caller fails closed)
        chain.append(str(row[0]))
        cur = row[1]
    return chain


def id_ancestry(db: Session, vault_id, obj_id) -> List[str]:
    """``[str(obj_id)] + containing-folder chain`` for a FILE or FOLDER id in `vault_id` -- what the
    delegation clamp (id_scope.intersect_id_scope) needs to test whether a child id falls within a
    parent folder. An unknown/cross-vault id resolves to just ``[str(obj_id)]`` (so it can only match
    a parent that granted exactly that id, never a broader parent folder -- fail closed)."""
    oid = str(obj_id)
    f = db.query(File.folder_id).filter(File.id == obj_id, File.vault_id == vault_id).first()
    if f is not None:
        return [oid] + folder_ancestry(db, vault_id, f[0])
    d = db.query(Folder.parent_folder_id).filter(Folder.id == obj_id, Folder.vault_id == vault_id).first()
    if d is not None:
        return [oid] + folder_ancestry(db, vault_id, d[0])
    return [oid]


# --- Per-file/folder scope enforcement wrappers ------------------------------------------------
# These are the ONLY way REST/SFTP surfaces should check a per-file/folder ID scope: they resolve
# the target within the vault and compute its folder ancestry INTERNALLY, so no call site ever
# hand-rolls (and risks mis-computing) the ancestry. Each gates on temp_scope.scope_ids(), which
# returns the effective id-scope for EITHER a temp credential OR a share recipient (None = a
# non-scoped principal or a whole-vault grant -> no-op). They raise PermissionDeniedError (handlers
# map it to 403; the SFTP layer catches it) for anything outside the scope -- failing CLOSED on an
# unresolved target.

def require_file_scope(db, user, vault_id, file_id) -> None:
    """A scoped principal (temp credential OR share recipient) may act on file `file_id` only if it
    (or a containing folder) is in its ID scope. Fails closed if the file doesn't exist in this vault."""
    from app.core.temp_scope import scope_ids, require_scope
    if scope_ids(user, vault_id) is None:
        return
    f = db.query(File.id, File.folder_id).filter(
        File.id == file_id, File.vault_id == vault_id).first()
    if f is None:
        raise PermissionDeniedError("Scope does not permit this file")
    require_scope(user, vault_id, f[0], folder_ancestry(db, vault_id, f[1]))


def require_download_scope(db, user, vault_id, file_id) -> None:
    """A SHARE recipient may DOWNLOAD file `file_id` only if it (or a containing folder) is in their
    DOWNLOADABLE scope. A view-only share grants VISIBILITY (require_file_scope passes) but NOT
    download — such a file lists fine yet is denied here. No-op for a non-share principal or a
    downloadable whole-vault share (download_scope_ids is None). Fails closed on an unknown file."""
    from app.core.temp_scope import download_scope_ids
    from app.core.id_scope import id_in_scope
    scope = download_scope_ids(user, vault_id)
    if scope is None:
        return
    f = db.query(File.id, File.folder_id).filter(
        File.id == file_id, File.vault_id == vault_id).first()
    if f is None:
        raise PermissionDeniedError("Scope does not permit downloading this file")
    if not id_in_scope(scope, str(f[0]), folder_ancestry(db, vault_id, f[1])):
        raise PermissionDeniedError("This share is view-only; downloading is not permitted.")


def require_folder_scope(db, user, vault_id, folder_id) -> None:
    """A scoped principal (temp credential OR share recipient) may act ON, or write INTO, folder
    `folder_id` only if it (or an ancestor) is in its ID scope. `folder_id` None = the vault ROOT,
    which no file/folder id-scope covers, so it is denied for a scoped principal. Fails closed on an
    unknown/cross-vault folder."""
    from app.core.temp_scope import scope_ids, require_scope
    if scope_ids(user, vault_id) is None:
        return
    if folder_id is None or str(folder_id) == "":
        raise PermissionDeniedError("Scope does not permit the vault root")
    try:
        folder_id = uuid.UUID(str(folder_id))  # callers may pass a str (upload/create) or a UUID
    except (ValueError, AttributeError, TypeError):
        raise PermissionDeniedError("Scope does not permit this folder")
    d = db.query(Folder.id, Folder.parent_folder_id).filter(
        Folder.id == folder_id, Folder.vault_id == vault_id).first()
    if d is None:
        raise PermissionDeniedError("Scope does not permit this folder")
    require_scope(user, vault_id, d[0], folder_ancestry(db, vault_id, d[1]))


def require_item_scope(db, user, vault_id, item_id) -> None:
    """`item_id` may identify a FILE or a FOLDER (e.g. the rename endpoint is id-polymorphic --
    it renames whichever the id resolves to). Enforce the scope on whichever it is; fail closed if
    it is neither. No-op for a non-scoped principal or a whole-vault grant (temp credential OR share)."""
    from app.core.temp_scope import scope_ids, require_scope
    if scope_ids(user, vault_id) is None:
        return
    f = db.query(File.id, File.folder_id).filter(
        File.id == item_id, File.vault_id == vault_id).first()
    if f is not None:
        require_scope(user, vault_id, f[0], folder_ancestry(db, vault_id, f[1]))
        return
    d = db.query(Folder.id, Folder.parent_folder_id).filter(
        Folder.id == item_id, Folder.vault_id == vault_id).first()
    if d is not None:
        require_scope(user, vault_id, d[0], folder_ancestry(db, vault_id, d[1]))
        return
    raise PermissionDeniedError("Scope does not permit this item")


def _scope_nav_folder_ids(db, vault_id, scope) -> set:
    """The set of folder ids on the PATH to any scoped item (each scope folder's ancestry + each
    scope file's containing-folder ancestry). These are shown as bare navigable nodes so the holder
    can descend to its subtree, but they are NOT themselves in scope (no read/write on them)."""
    nav = set()
    for fid in (scope.get('folders') or []):
        nav.update(folder_ancestry(db, vault_id, fid))
    for xid in (scope.get('files') or []):
        xf = db.query(File.folder_id).filter(File.id == xid, File.vault_id == vault_id).first()
        if xf is not None:
            nav.update(folder_ancestry(db, vault_id, xf[0]))
    return nav


def folder_is_navigable(db, user, vault_id, folder_id) -> bool:
    """Whether a scoped credential may SEE/traverse `folder_id` as a container (for stat/list/`cd`):
    it is IN scope (itself or an ancestor is a scope folder), OR it is an ANCESTOR of an in-scope
    item (on the path down to the scope). True (no restriction) for a non-scoped principal, a
    whole-vault grant, or the vault ROOT (folder_id None). This is WEAKER than require_folder_scope
    (which gates writes/deletes ON/INTO a folder) — it must NOT be used to authorize mutation.
    Honors a temp-credential OR a share-claim scope (via scope_ids)."""
    from app.core.temp_scope import scope_ids
    from app.core.id_scope import id_in_scope
    scope = scope_ids(user, vault_id)
    if scope is None or folder_id is None:
        return True
    fid = str(folder_id)
    if id_in_scope(scope, fid, folder_ancestry(db, vault_id, folder_id)):
        return True
    return fid in _scope_nav_folder_ids(db, vault_id, scope)


def filter_listing_for_scope(db, user, vault_id, folder_id, folders, files):
    """Filter a folder listing to what a path-scoped principal (temp credential OR share recipient)
    may SEE: files/folders in its scope, PLUS the ancestor folders needed to NAVIGATE down toward a
    scoped item. Returns (folders, files) unchanged for a non-scoped principal or a whole-vault
    grant. This is the anti-enumeration defense -- out-of-scope names/sizes/counts are never emitted.
    `folders` and `files` are the child rows of `folder_id` (None = vault root); each child's
    containing folder is `folder_id`, so they share its ancestry."""
    from app.core.temp_scope import scope_ids
    from app.core.id_scope import id_in_scope
    scope = scope_ids(user, vault_id)
    if scope is None:
        return folders, files
    base_anc = folder_ancestry(db, vault_id, folder_id)  # ancestry of the folder being listed
    # Every folder on the path to any scoped item is navigable (shown so the user can descend).
    nav = _scope_nav_folder_ids(db, vault_id, scope)
    vis_folders = [f for f in folders
                   if id_in_scope(scope, str(f.id), base_anc) or str(f.id) in nav]
    vis_files = [x for x in files if id_in_scope(scope, str(x.id), base_anc)]
    return vis_folders, vis_files


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
        vault_type: str = 'standard',
        size_limit: Optional[int] = None,
        vault_id: Optional[uuid.UUID] = None
    ) -> Vault:
        """
        Create a new vault.
        
        Args:
            name: Vault name
            owner: Owner user
            description: Optional description
            password: Optional vault password
            expire_files_after_days: Optional file expiration policy
            vault_id: Optionally the id to create the vault under, chosen by the caller.
                A zero-knowledge client needs the id BEFORE it locks the vault key, because
                the newer lock format stamps the key with the vault it belongs to and the
                key is sent in this same request. Absent, the server assigns one as before.
            
        Returns:
            Created Vault object
        """
        from app.core.vault_key_utils import generate_vault_key, encrypt_vault_key
        from app.core.config import settings
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
        
        # Belt and braces against the endpoint's own check: the id must not already belong to
        # a vault. Two vaults sharing an id would let a key locked for one be opened as the
        # other, which is the single property choosing your own id could otherwise cost.
        # A retired vault id is the most valuable one to refuse. The server never generates a
        # zero-knowledge vault's key -- it stores a wrap the browser supplies -- so anyone still
        # holding an old key could otherwise recreate the vault under its own id, re-supply that
        # same wrap, and read whatever survived the delete.
        if vault_id is not None and (
                self.db.query(Vault.id).filter(Vault.id == vault_id).first()
                or self._id_is_spent(vault_id)):
            raise ValueError("vault id already in use")

        vault = Vault(
            id=vault_id or uuid.uuid4(),
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
        # Per-vault size cap. When unset, the model column default (1 GB) applies.
        if size_limit is not None:
            vault.size_limit = size_limit

        self.db.add(vault)
        self.db.commit()
        self.db.refresh(vault)
        
        # Create vault directory
        vault_dir = self._get_vault_path(vault.id)
        vault_dir.mkdir(parents=True, exist_ok=True)
        
        return vault
    
    def _redeem_temp_passcode(self, user, vault, passcode, burn) -> bool:
        """Redeem a temp-credential passcode as an alternative to the real vault password on a
        password-protected STANDARD vault. Returns True when a valid passcode was redeemed; False when
        no passcode applies (caller falls through to the real-password path). Raises InvalidPasswordError
        (recording a rate-limit failure via ``burn`` on a wrong/absent-verifier passcode) when a passcode
        was supplied but is wrong, expired, or used up. The passcode is a second server-side access
        gate — it does NOT re-encrypt content; caps/scope are still enforced independently."""
        if not passcode:
            return False
        if not getattr(user, "_is_temp_session", False) or not getattr(user, "_temp_cred_id", None):
            return False  # only a temp session redeems a passcode; others use the real password

        _cred_id = getattr(user, "_temp_cred_id", None)

        def _fail(reason, message):
            # Record the failed redemption (short reason code, NEVER the attempted passcode) and raise.
            # Auditing must never itself break redemption, so it is best-effort.
            try:
                from app.services.audit_logger import AuditLogger
                AuditLogger(self.db).log_temp_passcode_failed(user, vault.id, _cred_id, reason)
            except Exception:
                pass
            raise InvalidPasswordError(message)

        # Master kill-switch: if the feature is turned OFF, outstanding passcodes stop working (defense
        # in depth — an admin can disable redemption org-wide, e.g. on a suspected passcode leak).
        from app.core import temp_passcode_policy
        from app.core.models import SystemSetting, TempCredentialVaultAccess
        _pol = self.db.query(SystemSetting).filter(SystemSetting.key == "global").first()
        if not temp_passcode_policy.passcodes_enabled((_pol.value or {}) if (_pol and _pol.value) else {}):
            _fail("disabled", "Temporary vault passcodes are disabled")
        grant = self.db.query(TempCredentialVaultAccess).filter(
            TempCredentialVaultAccess.temp_credential_id == user._temp_cred_id,
            TempCredentialVaultAccess.vault_id == vault.id,
        ).first()
        if grant is None or not grant.passcode_hash:
            burn()
            _fail("no_passcode", "Invalid vault passcode")
        # Expiry (stored naive-UTC or tz-aware).
        exp = grant.passcode_expires_at
        if exp is not None:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= exp:
                _fail("expired", "This vault passcode has expired")
        # Use cap (one-time = max_uses 1; NULL = multi-use).
        if grant.passcode_max_uses is not None and (grant.passcode_use_count or 0) >= grant.passcode_max_uses:
            _fail("used_up", "This vault passcode has already been used")
        if not verify_password(passcode, grant.passcode_hash):
            burn()
            _fail("wrong", "Invalid vault passcode")
        # Success: count the use. For a capped passcode do an ATOMIC conditional increment so two
        # concurrent redemptions can't both burn a one-time passcode (row-count guards the race).
        if grant.passcode_max_uses is not None:
            updated = self.db.query(TempCredentialVaultAccess).filter(
                TempCredentialVaultAccess.id == grant.id,
                TempCredentialVaultAccess.passcode_use_count < grant.passcode_max_uses,
            ).update(
                {TempCredentialVaultAccess.passcode_use_count: TempCredentialVaultAccess.passcode_use_count + 1},
                synchronize_session=False)
            self.db.commit()
            if not updated:
                _fail("used_up", "This vault passcode has already been used")
        else:
            # Multi-use (no cap): still count uses for audit, atomically so a concurrent redemption
            # can't lose a count.
            self.db.query(TempCredentialVaultAccess).filter(
                TempCredentialVaultAccess.id == grant.id).update(
                {TempCredentialVaultAccess.passcode_use_count: TempCredentialVaultAccess.passcode_use_count + 1},
                synchronize_session=False)
            self.db.commit()
        # Success: record the redemption (best-effort — never let auditing break a valid redemption).
        try:
            from app.services.audit_logger import AuditLogger
            AuditLogger(self.db).log_temp_passcode_used(user, vault.id, _cred_id)
        except Exception:
            pass
        return True

    def get_vault(
        self,
        vault_id: uuid.UUID,
        user: User,
        vault_password: Optional[str] = None,
        require_password: bool = False,
        allow_share: bool = False,
    ) -> Vault:
        """
        Get a vault with access verification.

        Args:
            vault_id: Vault UUID
            user: User requesting access
            vault_password: Optional vault password
            require_password: If True, validates password even for metadata access.
                            If False, password only validated when provided.
            allow_share: When True (opt-in ONLY at the recipient READ endpoints), a
                caller with no owner/member/group access may be granted read-only
                access by an active whole-vault share claim. Defaults False, so SFTP
                and every write/delete caller never opens a vault via a share claim.
                A password-protected vault is still refused for a share grant (the
                permission layer declines it, and the password gate below blocks file
                access without the real password / a temp passcode).

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
            user, vault_id, VaultPermissionEnum.READ, allow_share=allow_share
        )

        # Least-privilege gate: a scoped temp credential may only reach vaults in
        # its scope. No-op for normal users / legacy creds. Covers web AND SFTP
        # because every per-vault operation funnels through get_vault().
        from app.core.temp_scope import enforce_vault
        enforce_vault(user, vault_id)

        # Share-claim subtree scoping: when this is a recipient READ path (allow_share), stamp the
        # caller's per-vault share scope so the id-scope wrappers (listing filter + per-file gate)
        # restrict a file/folder share to its subtree. share-ONLY (never downgrades an owner/member
        # who also holds a claim); a whole-vault share stamps no id restriction. NOT reached over
        # SFTP (allow_share is False there), so a share confers no subtree access over SFTP.
        if allow_share:
            self.permission_service.stamp_share_scope(user, vault)

        # Password / passcode gate for a password-protected vault. On file access (require_password) a
        # real password OR a temp-credential passcode is required; on a metadata read a supplied
        # password is soft-verified. BOTH checks share the same inline, failure-only, fixed-window rate
        # counter so neither is an unthrottled brute-force surface (the soft-verify path used to be
        # un-throttled). Skipped entirely for a metadata read with no password supplied.
        if vault.password_hash and (require_password or vault_password):
            rate_key = f"rate_limit:vault:{vault_id}:{user.id}"
            from app.core.models import RoleEnum
            # Different limits based on role (admins get higher limit)
            limit = settings.rate_limit_vault_attempts_admin if user.role == RoleEnum.ADMIN else settings.rate_limit_vault_attempts
            attempts = redis_client.get(rate_key)
            if attempts and int(attempts) >= limit:
                raise RateLimitExceededError("Too many vault access attempts. Please try again later.")

            def _burn():
                # One failed attempt on the inline, failure-only, fixed-window counter (shared by the
                # real-password and passcode checks so neither is an unthrottled bypass of the other).
                # The bucket is keyed by (vault, account); a temp session runs AS the owning account, so
                # a temp holder's wrong-passcode guesses share the owner's bucket — an intentional
                # trade-off (a separate bucket would grant an attacker 2x total guesses).
                pipe = redis_client.pipeline()
                pipe.incr(rate_key)
                pipe.expire(rate_key, settings.rate_limit_vault_window_seconds)
                pipe.execute()

            if require_password:
                # A temp-credential passcode opens the vault in place of the real vault password. When a
                # passcode is supplied (X-Vault-Passcode, via the request contextvar) it must be valid;
                # otherwise fall through to the real-password check.
                if not self._redeem_temp_passcode(user, vault, current_vault_passcode(), _burn):
                    if not vault_password:
                        raise PasswordRequiredError("Vault password is required")
                    if not verify_password(vault_password, vault.password_hash):
                        _burn()
                        raise InvalidPasswordError("Invalid vault password")
            elif vault_password:
                # Soft-verify: a password supplied on a metadata read — verify it and rate-limit
                # failures (no passcode path here; the passcode is a file-access gate).
                if not verify_password(vault_password, vault.password_hash):
                    _burn()
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
        from app.core.models import vault_group_access, user_groups
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
        from app.core.temp_scope import is_scoped
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
            from app.core.authorization import PermissionDeniedError
            raise PermissionDeniedError("Only vault owner can update vault")
        
        if name is not None:
            vault.name = name
        
        if description is not None:
            vault.description = description
        
        # ✅ NEW: Handle password changes that require re-encrypting vault key
        if password is not None:
            from app.core.vault_key_utils import decrypt_vault_key, encrypt_vault_key
            from app.core.config import settings
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
        from app.core.models import RoleEnum
        if vault.owner_id != user.id and user.role != RoleEnum.ADMIN:
            from app.core.authorization import PermissionDeniedError
            raise PermissionDeniedError("Only the vault owner or an admin can delete this vault")
        
        vault_dir = self._get_vault_path(vault_id)
        # Commit the DB delete (cascade) BEFORE removing the physical dir: a rmtree sequenced before a
        # FAILED commit would zombify the whole vault (rows survive, files gone). After a successful
        # commit the dir is safely orphaned and best-effort removed.
        self.db.delete(vault)
        self.db.commit()
        if vault_dir.exists():
            try:
                shutil.rmtree(vault_dir)
            except Exception as _e:
                safe_event('vault.dir-removal.failed', _e)
    
    def create_folder(
        self,
        vault_id: uuid.UUID,
        name: str,
        user: User,
        parent_folder_id: Optional[uuid.UUID] = None,
        password: Optional[str] = None,
        zk_enc_name: Optional[str] = None,
        zk_name_bi: Optional[str] = None,
        zk_name_bi_candidates: Optional[list] = None,
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

        # Hash password if provided. NOTE: folder passwords are an UNIMPLEMENTED feature — the
        # create_folder HTTP endpoint never forwards a `password`, so this is always None in
        # practice, and no access path enforces a folder password even if one were set. See
        # get_folder() for the full state and what a real implementation must cover.
        password_hash = hash_password(password) if password else None

        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        is_zk = getattr(vault, 'type', 'standard') == 'zero_knowledge'

        # Reject a duplicate name in the same parent (folders are NOT auto-replaced, unlike
        # files). This mirrors rename's uniqueness check and is enforced at rest by the
        # (vault, parent, name_bi) unique index; the pre-check turns the common case into a
        # clean 409 instead of relying on the IntegrityError path below.
        clash_name = zk_name_bi if is_zk else sanitize_filename(name)
        # ZK: match every epoch's candidate so a folder created before a rotation (whose
        # index is at an old epoch) is still detected as a duplicate. Superset of the single
        # value; absent falls back to it. Standard: unchanged plaintext match.
        _cand = [c for c in dict.fromkeys(zk_name_bi_candidates or []) if isinstance(c, str)]
        if is_zk:
            clash_match = Folder.name_bi.in_(_cand) if _cand else (Folder.name_bi == zk_name_bi)
        else:
            clash_match = _name_match_filter(Folder, vault, clash_name)
        if self.db.query(Folder).filter(
            Folder.vault_id == vault_id,
            Folder.parent_folder_id == parent_folder_id,
            clash_match,
        ).first() is not None:
            raise DuplicateNameError("A folder with that name already exists in this location")

        # Folder ID: a CLIENT-supplied id (zero-knowledge v2 name binding — the browser seals
        # the name bound to this id) or a server-generated one; assigned now so the at-rest name
        # cipher key (per id) is available. The endpoint validates a client id is a fresh UUID.
        # Folder ids matter more here than they look. Deleting a folder removes rows and
        # nothing else -- the only `rmtree` on persistent storage is in `delete_vault` -- so
        # `<vault>/folders/<folder_id>/` outlives the folder, and any blob whose secure-delete
        # fell through its best-effort fallback is still inside it. Re-claim the folder id and the
        # file id and the old bytes are back at their exact path.
        if folder_id is not None and (
                self.db.query(Folder.id).filter(Folder.id == folder_id).first()
                or self._id_is_spent(folder_id)):
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
        """Get a folder with access verification.

        UNIMPLEMENTED FEATURE — folder passwords are NOT wired end-to-end yet, and this method
        is currently the ONLY reader of ``Folder.password_hash`` and has no callers. Folder
        passwords are a planned, not-yet-shipped feature: today no endpoint SETS one (the
        ``create_folder`` HTTP endpoint never forwards a password to ``create_folder`` below, and
        there is no set/clear-password endpoint), and no access path ENFORCES one — file listing,
        download, delete, rename and upload all authorize on the VAULT (and any file's own
        password), never on a containing folder's password, on both the REST and SFTP surfaces.
        The ``has_password`` flag emitted for folders in listings is therefore cosmetic today.

        When this feature is implemented it must be enforced as a nearest-protected-ANCESTOR walk
        at every file/folder access path (listing, download, delete, rename, upload) on BOTH REST
        and SFTP, plus a share-time ancestor check — not merely on a single folder via this method
        — otherwise a file inside a protected folder would stay reachable with only the vault
        password. Until then a folder cannot obtain a ``password_hash`` through the shipped API, so
        there is no live bypass; the gap is latent (a legacy DB row with a folder password set
        out-of-band would NOT be enforced).
        """
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
        from app.services.streaming_upload import StreamingUploadContext
        from app.core.security import GcmChunkStreamCodecV2, IdentityChunkCodec, calculate_file_checksum
        
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
        # Defence in depth, and honestly so: today the only caller that passes a client-chosen
        # file_id is the chunked-upload completion, which checks the same two things first and
        # answers with a clean 409 rather than this ValueError. So removing the ledger half of
        # THIS check currently fails no test -- it was mutated to confirm that. It stays because
        # this is the one place every upload path goes through, so a future caller that starts
        # accepting a client id is covered without anyone remembering to add it.
        if file_id is not None and (
                self.db.query(File.id).filter(File.id == file_id).first()
                or self._id_is_spent(file_id)):
            raise ValueError("file id already in use")
        file_id = file_id or uuid.uuid4()
        # The blob's name on disk is NOT the row id, and that is the entire fix for one of the two
        # defects here. While they were the same string, two completions carrying one client-chosen
        # id opened the same path 'wb' and interleaved; the loser hit the primary-key violation and
        # its cleanup deleted the blob at that path -- the WINNER'S committed bytes, leaving a live
        # row with nothing behind it. With a name of its own, each writer owns its own file and a
        # loser's cleanup can only reach its own.
        #
        # Nothing reconstructs this path from the id: `_get_file_storage_path` has exactly one
        # caller (here), and every later read and delete goes through the `storage_path` column
        # recorded below. So existing rows keep working untouched and there is no migration. It
        # does NOT address re-claiming a retired id -- the transcript binds the row id, not the
        # path -- which is what the check above and the ledger behind it are for.
        storage_path = self._get_file_storage_path(vault_id, uuid.uuid4(), folder_id)
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
        # New Standard writes use 0x20. Existing 0x10 and legacy Fernet blobs keep being read;
        # there is no bulk rewrite, and this does not introduce the first blob-rewriting migration
        # in this codebase.
        codec = IdentityChunkCodec() if is_zk else GcmChunkStreamCodecV2(vault_id, file_id)

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
                                     name_bi: Optional[str] = None,
                                     name_bi_candidates: Optional[list] = None) -> List[str]:
        """Mark prior same-name File rows in (vault, folder) for deletion as part of the
        CALLER's open transaction (NO commit here) and return their on-disk blob paths,
        decrementing vault stats for each.

        This is the replace-on-clash step done BEFORE the replacement row is inserted, in
        the SAME transaction — so the old and new rows never coexist under the
        (vault_id, folder_id, name_bi) unique index, while a rollback still leaves the old
        file fully intact (its blob is only removed from disk by _remove_blobs AFTER the
        commit succeeds). Zero-knowledge matches on the client blind index; Standard matches
        the per-vault blind index OR the plaintext column (un-backfilled legacy rows)."""
        candidate_vals = [c for c in dict.fromkeys(name_bi_candidates or []) if isinstance(c, str)]
        if candidate_vals:
            # Delete every prior row whose index is in the match set, not just the one at the
            # uploader's current epoch -- an existing file sealed before a rotation carries an
            # old-epoch index the single value would miss, leaving both rows under different
            # name_bi values and the "duplicate" this replace exists to prevent. A superset of the
            # single-value match (name_bi is expected among the candidates), so it never removes
            # fewer rows, only the older same-name ones.
            match = File.name_bi.in_(candidate_vals)
        elif name_bi is not None:
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
            self._adjust_vault_totals(vault, -(ex.size_bytes or 0), -1)
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
                # The blob's relative path is a storage path; the exception carries the
                # ABSOLUTE one on an OSError. Neither belongs in a log an operator pastes.
                safe_event('blob.replace-cleanup.failed', e)

    def _adjust_vault_totals(self, vault, size_delta, count_delta):
        """Move a vault's size and file counters by a delta, atomically and never below zero.

        In SQL, for the same reason the increment is: `vault.total_size_bytes -= n` in Python reads
        the value this session loaded, subtracts, and writes the whole number back, so it erases any
        change another session committed in between. On the way up that loses stored bytes and
        unbounds the size limit. On the way down it does the same in reverse -- and two of the
        subtraction sites had no floor at all, so a lost update could drive the counter negative,
        which the limit check reads as free headroom.

        GREATEST is applied in the database rather than in Python for the same reason as the
        arithmetic: a floor computed from a stale read is not a floor.
        """
        self.db.query(Vault).filter(Vault.id == vault.id).update(
            {
                Vault.total_size_bytes: func.greatest(
                    0, func.coalesce(Vault.total_size_bytes, 0) + size_delta),
                Vault.file_count: func.greatest(
                    0, func.coalesce(Vault.file_count, 0) + count_delta),
            },
            synchronize_session=False,
        )

    def finalize_streaming_upload(self, file_info: dict, total_size: int, checksum: str,
                                  zk_key_version: Optional[int] = None,
                                  zk_enc_name: Optional[str] = None,
                                  zk_enc_mime: Optional[str] = None,
                                  zk_name_bi: Optional[str] = None,
                                  zk_name_bi_candidates: Optional[list] = None,
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
                name_bi_candidates=zk_name_bi_candidates if is_zk else None,
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

        # Re-checked here, right before the insert. The check at claim time is separated from
        # this point by the entire blob assembly, and the ledger is not a database constraint --
        # only the primary key is, and it sees live rows only. Today a head-of-line block in the
        # single worker happens to serialise these, which is luck rather than design: moving
        # assembly off the event loop, or adding a worker, opens the window. One index probe.
        if getattr(file, "id", None) is not None and self._id_is_spent(file.id):
            raise ValueError("file id already in use")
        self.db.add(file)

        # Encrypt the filename/MIME at rest (Standard vaults) before persisting. No-op for ZK.
        _seal_named_object(file_info['vault'], file, is_file=True)

        # Update vault statistics.
        #
        # In SQL, not in Python. `vault.total_size_bytes += total_size` reads the value this
        # session loaded, adds to it, and writes the whole number back -- so two uploads that
        # overlap both start from the same total and the second commit erases the first. The
        # arithmetic is lost, and the size limit with it, because the limit is checked against
        # exactly this counter: measured, six concurrent uploads put 144 MB into a 64 MB vault and
        # every one of them returned success. Sequentially the same uploads are refused correctly,
        # which is why it went unnoticed.
        #
        # Letting the database do the addition makes each increment atomic regardless of what any
        # session last read. The row lock taken by the caller before the limit check is what stops
        # two uploads both passing a check they would jointly fail; this is what stops the totals
        # from being wrong even when they legitimately both pass.
        vault = file_info['vault']
        self.db.query(Vault).filter(Vault.id == vault.id).update(
            {
                Vault.total_size_bytes: func.coalesce(Vault.total_size_bytes, 0) + total_size,
                Vault.file_count: func.coalesce(Vault.file_count, 0) + 1,
            },
            synchronize_session=False,
        )

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
        # A refresh failure AFTER a successful commit is non-fatal — the row is already durable. Guard
        # it so finalize never raises past the commit: otherwise the exception would reach a caller's
        # except handler (e.g. /complete's orphan-blob cleanup) and destroy the just-committed blob,
        # leaving a live File row with no blob.
        try:
            self.db.refresh(file)
            # The counters were changed by the database rather than by this session, so its copy
            # of the vault row is stale. Refresh it too, or a later read in the same request
            # reports the value this session happened to load.
            self.db.refresh(vault)
        except Exception:
            pass
        # Commit succeeded: the prior same-name rows are gone, so it is now safe to remove
        # their on-disk blobs (deferred until here so a rollback never destroys the old file).
        self._remove_blobs(stale_blobs)

        return file
    
    def download_file(
        self,
        file_id: uuid.UUID,
        user: User,
        file_password: Optional[str] = None,
        allow_share: bool = False,
    ) -> Tuple[bytes, str, str]:
        """
        Download and decrypt a file.

        Args:
            file_id: File UUID
            user: User downloading file
            file_password: Optional file password
            allow_share: opt-in to an active whole-vault share claim on this file's
                vault (see PermissionService.get_vault_permissions). Set True ONLY by
                the web download endpoint; SFTP downloads keep the default (False) so
                a share claim grants nothing over SFTP.

        Returns:
            Tuple of (file_content, file_name, mime_type)
        """
        file, vault = self._resolve_download(file_id, user, file_password, allow_share)
        return self._open_stored_file(file, vault, file_id)

    def _resolve_download(
        self,
        file_id: uuid.UUID,
        user: User,
        file_password: Optional[str],
        allow_share: bool,
    ):
        """Authorize a download and return `(file, vault)`.

        Extracted so the whole-file and streaming entry points cannot diverge. Every check below
        is security-relevant and several are subtle; two copies of them is two places for one to be
        updated and the other forgotten.
        """
        file = self.db.query(File).filter(File.id == file_id).first()

        if not file:
            raise FileNotFoundError(f"File not found: {file_id}")

        # Check vault access
        self.permission_service.require_vault_permission(
            user, file.vault_id, VaultPermissionEnum.READ, allow_share=allow_share
        )

        # Defense-in-depth for the share path: a file/folder share grants READ on the vault but must
        # not download outside its subtree. The web download endpoint already stamps the recipient's
        # scope (via get_vault) and enforces require_file_scope before calling here; re-stamp + re-check
        # so this is self-protecting regardless of caller. No-op for a whole-vault share or a
        # non-scoped principal (require_file_scope short-circuits when scope_ids is None).
        if allow_share:
            share_vault = self.db.query(Vault).filter(Vault.id == file.vault_id).first()
            if share_vault is not None:
                self.permission_service.stamp_share_scope(user, share_vault)
            require_file_scope(self.db, user, file.vault_id, file_id)
            # View-only shares grant visibility but not download: the file may be in the visible scope
            # yet outside the downloadable scope.
            require_download_scope(self.db, user, file.vault_id, file_id)

        # Check file password if set
        if file.password_hash:
            if not file_password:
                raise PasswordRequiredError("File password is required")

            if not verify_password(file_password, file.password_hash):
                raise InvalidPasswordError("Invalid file password")

        # Get vault for decryption
        vault = self.db.query(Vault).filter(Vault.id == file.vault_id).first()
        return file, vault

    def open_download_stream(
        self,
        file_id: uuid.UUID,
        user: User,
        file_password: Optional[str] = None,
        allow_share: bool = False,
    ):
        """The same download, opened for streaming instead of returned whole.

        Every authorization step is shared with :meth:`download_file`, which is the point of the
        arrangement: a second copy of the vault permission, share scope, download scope and
        per-file password checks would be a second place for one of them to drift.

        Returns a :class:`BoundedDownload`. The caller owns it and must close it.
        """
        file, vault = self._resolve_download(file_id, user, file_password, allow_share)
        return self._open_stored_file(file, vault, file_id, whole=False)

    def open_random_reader(
        self,
        file_id: uuid.UUID,
        user: User,
        file_password: Optional[str] = None,
    ):
        """Authorize a read and return something that answers arbitrary byte ranges.

        For SFTP, whose contract is "any offset, any order, any number of times". The download
        entry points serve a stream from beginning to end; this one serves a file a client will
        seek around in, and holds the same index the stream's walk already builds rather than the
        file itself.

        Shares :meth:`_resolve_download`, so the permission, scope and per-file password checks are
        the same ones the HTTP path runs -- `allow_share` is False, because a share claim confers
        nothing over SFTP.

        Returns a :class:`RandomAccessFile`. The caller owns it and must close it.
        """
        file, vault = self._resolve_download(file_id, user, file_password, allow_share=False)
        return self._open_random(file, vault, file_id)

    def _open_random(self, file, vault, file_id):
        from app.core.security import is_gcm_chunk_stream, GcmChunkStreamReader
        from app.services.download_stream import RandomAccessFile

        storage_path = self.storage_path / file.storage_path
        if not storage_path.exists():
            raise FileNotFoundError(f"File data not found on disk: {file_id}")

        if vault is not None and getattr(vault, 'type', 'standard') == 'zero_knowledge':
            # The blob is the client's ciphertext, stored verbatim, and the server holds no key for
            # it -- there are no records to index and nothing to decrypt. SFTP never reaches this
            # (it refuses any vault that is not standard), but this is a public method and the
            # sequential opener beside it makes the same check first. Failing here is better than
            # routing an attacker-chosen blob that happens to start with the format magic into a
            # reader that will try to authenticate it under the deployment key.
            raise FileServiceError("Zero-knowledge files cannot be read by range")

        handle = open(storage_path, 'rb')
        try:
            try:
                looks_like_gcm = is_gcm_chunk_stream(storage_path)
            except Exception as e:
                raise FileServiceError(f"Failed to read file: {e}")

            if looks_like_gcm:
                try:
                    reader = GcmChunkStreamReader(handle, file.vault_id, file.id)
                except Exception as e:
                    raise FileServiceError(f"Failed to decrypt file: {e}")

                if not reader.length_is_authenticated:
                    # The retained format has no terminal, so nothing signs its length. The
                    # whole-file read this replaces caught a truncation incidentally, by hashing
                    # everything and comparing; a reader that only decrypts what is asked for
                    # cannot. Comparing the walk's total against the recorded size restores that,
                    # and costs nothing. It is unauthenticated -- whoever can rewrite the blob can
                    # usually rewrite the row -- but it is what this format already had.
                    recorded = file.size_bytes or 0
                    if recorded and reader.total_length != recorded:
                        raise FileServiceError(
                            "Failed to read file: stored length does not match the record")

                return RandomAccessFile(handle, reader.read_range, reader.total_length,
                                        file.original_name)

            # Legacy Fernet keeps the whole-file behaviour. Its plaintext lengths are not derivable
            # from the framing -- padding hides up to sixteen bytes per token -- so an index cannot
            # be built without decrypting everything anyway. No writer produces this format, so the
            # exposure shrinks as those files are replaced and cannot grow.
            content, _name, _mime = self._open_stored_file(file, vault, file_id)
            handle.close()
            return RandomAccessFile.from_bytes(content, file.original_name)
        except Exception:
            handle.close()
            raise

    def _open_stored_file(self, file, vault, file_id, whole: bool = True):
        """Open the blob, pick a reader for its at-rest format, and describe what it will produce.

        With `whole`, the pieces are joined and the historical `(bytes, name, mime)` tuple comes
        back. Without, the caller receives the pieces and decides when to stop -- which is what
        makes a bounded response possible, and what lets the stored checksum be enforced with
        bytes still owed instead of after the last one has gone.
        """
        from app.core.security import EncryptionError, ObjectChangedDuringRead
        from app.services.download_stream import BoundedDownload, ChecksumMismatch

        storage_path = self.storage_path / file.storage_path

        if not storage_path.exists():
            raise FileNotFoundError(f"File data not found on disk: {file_id}")

        is_zk = bool(vault) and getattr(vault, 'type', 'standard') == 'zero_knowledge'
        # A ZK file's real MIME is client-encrypted (enc_mime); the server must never serve a
        # plaintext mime_type -- a legacy pre-seal row still holds one, which would leak through
        # the download Content-Type. Always a neutral type for ZK.
        mime = ('application/octet-stream' if is_zk
                else (file.mime_type or 'application/octet-stream'))

        handle = open(storage_path, 'rb')
        try:
            download = self._reader_for(handle, storage_path, file, is_zk, mime)
        except Exception:
            handle.close()
            raise

        if not whole:
            return download

        with download:
            try:
                content = b''.join(download.chunks())
            except ChecksumMismatch:
                raise FileServiceError("File integrity check failed")
            except ObjectChangedDuringRead as e:
                raise FileServiceError(f"Failed to read file: {e}")
            except EncryptionError as e:
                # Mid-stream decrypt failures used to be wrapped by this function, and callers --
                # the SFTP path among them -- were written against that. Streaming moved them out
                # of the try that used to catch them.
                raise FileServiceError(f"Failed to decrypt file: {e}")
        return content, download.name, download.mime_type

    def _reader_for(self, handle, storage_path, file, is_zk: bool, mime: str):
        """Auto-detect the at-rest format and return a reader for it.

         - AES-256-GCM chunked stream (MAGIC + version 0x10 or 0x20): the current formats. Every
           record's AAD binds this file's vault_id and file_id, so a blob swapped in from another
           file or vault fails to authenticate; 0x20 adds a terminal binding the record count and
           the total plaintext length, which is what makes the length below authenticated.
         - otherwise: the legacy global-key Fernet chunk stream (length-prefixed tokens, no magic).

        NB: the old whole-file AES-GCM writer (upload_file + EncryptedFileStorage) is never called,
        and its detector compared only header[:5] to a 9-byte magic so it never matched -- there
        are no such files to read.
        """
        from app.core.security import (
            is_gcm_chunk_stream, decrypt_chunk_stream, GcmChunkStreamReader,
        )
        from app.services.download_stream import BoundedDownload

        if is_zk:
            # The server stored the client's ciphertext verbatim and holds no key for it. There are
            # no records to walk, so the pieces are fixed-size windows, and the stored checksum --
            # which is over the CIPHERTEXT here, the codec being a passthrough -- is the only
            # integrity statement the server can make. Plaintext integrity stays the client's own
            # AEAD, unchanged.
            size = storage_path.stat().st_size

            def _raw_range(offset: int, length: int) -> bytes:
                """Bytes straight out of the stored blob, decrypting nothing.

                This is why zero-knowledge can answer a range at all. `_open_random` refuses the
                type outright, and rightly: it would build an authenticated reader over a blob the
                deployment holds no key for, and an attacker-chosen file beginning with the format
                magic would be handed to it. Nothing here constructs a reader. The server copies
                bytes it never interprets, which is what it already does for the whole file.

                Offsets mean the same thing to the client as to us: the response body IS the
                ciphertext, so a byte range names the same bytes at both ends. The client derives
                record boundaries from the stored length and decrypts what it asked for.

                Safe to seek because the two paths are mutually exclusive within one request: a
                ranged response never iterates the sequential generator above, and a sequential
                one never calls this.
                """
                if length <= 0 or offset < 0 or offset >= size:
                    return b''
                handle.seek(offset)
                return handle.read(min(length, size - offset))

            return BoundedDownload(
                handle, _primed(_fixed_windows(handle)), size,
                file.original_name, mime, file.checksum_sha256,
                read_range=_raw_range)

        # The identification itself can fail, and it must be caught HERE: it used to return False
        # for an unreadable file, which silently routed a healthy object to the wrong reader and
        # called it damaged.
        try:
            looks_like_gcm = is_gcm_chunk_stream(storage_path)
        except Exception as e:
            raise FileServiceError(f"Failed to read file: {e}")

        if looks_like_gcm:
            try:
                reader = GcmChunkStreamReader(handle, file.vault_id, file.id)
            except FileServiceError:
                raise
            except Exception as e:
                # The walk settles truncation, a missing terminal, trailing bytes, a dropped record
                # and a substituted blob -- so this is where those now surface, before a response
                # body exists rather than after most of it has been sent.
                raise FileServiceError(f"Failed to decrypt file: {e}")
            return BoundedDownload(
                handle, reader.records(), reader.total_length,
                file.original_name, mime, file.checksum_sha256,
                length_is_authenticated=reader.length_is_authenticated,
                # The same open handle and the same index the walk above already built, so a
                # ranged response costs no second authorization, no second open and no second
                # walk. The other two branches leave this None and are therefore not rangeable.
                read_range=reader.read_range)

        # Legacy Fernet chunk stream. Already a generator; the only reason this path was ever
        # unbounded is that its caller joined the output. Its plaintext length is not derivable
        # without decrypting -- padding hides up to 16 bytes per token -- so the recorded size is
        # used, and it is not authenticated.
        try:
            pieces = _primed(_fernet_pieces(handle, decrypt_chunk_stream))
        except Exception as e:
            raise FileServiceError(f"Failed to decrypt chunked file: {e}")
        return BoundedDownload(
            handle, pieces, file.size_bytes or 0,
            file.original_name, mime, file.checksum_sha256)
    
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
        storage_path = self.storage_path / file.storage_path

        # Update stats, delete the row, and COMMIT before touching the blob. An irreversible
        # secure_delete sequenced BEFORE the commit would, on a commit failure, leave a live row
        # pointing at a destroyed blob (every download then 500s with FileNotFoundError). Destroying
        # the blob AFTER a successful commit leaves at most a recoverable/GC-able orphan on failure
        # (mirrors the _remove_blobs-after-commit ordering in finalize_streaming_upload).
        self._adjust_vault_totals(vault, -(file.size_bytes or 0), -1)
        self.db.delete(file)
        self.db.commit()

        if storage_path.exists():
            try:
                # Secure delete with overwrite
                self.encrypted_storage.secure_delete(storage_path)
            except Exception as e:
                # Fallback to manual overwrite if secure delete fails
                safe_event('blob.secure-delete.failed-using-fallback', e)
                try:
                    file_size = storage_path.stat().st_size
                    with open(storage_path, 'wb') as f:
                        # Overwrite in bounded 1 MB chunks (mirrors secure_delete) so a large blob
                        # can't spike memory the way a single os.urandom(file_size) allocation would.
                        remaining = file_size
                        while remaining > 0:
                            n = min(1024 * 1024, remaining)
                            f.write(os.urandom(n))
                            remaining -= n
                        f.flush()
                        os.fsync(f.fileno())
                    storage_path.unlink()
                except Exception as fallback_error:
                    safe_event('blob.fallback-delete.failed', fallback_error)
                    # Last resort: just delete (best-effort — the row is already gone)
                    try:
                        storage_path.unlink()
                    except Exception:
                        pass
    
    def rename_file(self, file_id: uuid.UUID, new_name: str, user: User,
                    vault_id: Optional[uuid.UUID] = None, *,
                    zk_enc_name: Optional[str] = None,
                    zk_name_bi: Optional[str] = None,
                    zk_name_bi_candidates: Optional[list] = None,
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
                # Match every epoch's candidate, not just the current one: a folder sealed
                # before a rotation carries an old-epoch index the single value would miss, so a
                # rename INTO its name would go undetected and create a second folder with the same
                # visible name. Superset of the single value; absent falls back to it.
                _cand = [c for c in dict.fromkeys(zk_name_bi_candidates or []) if isinstance(c, str)]
                _fmatch = Folder.name_bi.in_(_cand) if _cand else (Folder.name_bi == zk_name_bi)
                clash = self.db.query(Folder).filter(and_(
                    Folder.vault_id == folder.vault_id,
                    Folder.parent_folder_id == folder.parent_folder_id,
                    _fmatch,
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
            _candf = [c for c in dict.fromkeys(zk_name_bi_candidates or []) if isinstance(c, str)]
            _fimatch = File.name_bi.in_(_candf) if _candf else (File.name_bi == zk_name_bi)
            clash = self.db.query(File).filter(and_(
                File.vault_id == file.vault_id,
                File.folder_id == file.folder_id,
                _fimatch,
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
            file.modified_by = user.id
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
        file.modified_by = user.id

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
        
        # Delete the rows + update stats and COMMIT before destroying any blob: an irreversible
        # overwrite/unlink sequenced before the commit would, on a commit failure, leave live rows
        # pointing at gone blobs. Capture each path only after its delete is staged.
        stale_paths = []
        for file in expired_files:
            try:
                _path = self.storage_path / file.storage_path
                vault = file.vault
                if vault:
                    self._adjust_vault_totals(vault, -(file.size_bytes or 0), -1)
                self.db.delete(file)
                stale_paths.append(_path)
            except Exception as e:
                safe_event('expired-file.delete.failed', e, file=file.id)
                continue

        try:
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            safe_event('expired-file.cleanup-commit.failed', e)
            return

        # Rows are durably gone; now securely destroy the blobs (best-effort — an orphan blob is
        # recoverable/GC-able, a dangling row is not). secure_delete overwrites in bounded 1 MB
        # chunks (+ fsync) so a large blob can't spike memory, and is a no-op on an absent path.
        for storage_path in stale_paths:
            try:
                self.encrypted_storage.secure_delete(storage_path)
            except Exception as e:
                safe_event('expired-blob.remove.failed', e)
    
    # ---- Move / Copy (files + folders) --------------------------------------------------------
    # Semantics (Phase E, Standard vaults + within-vault):
    #   * A within-vault MOVE is a cheap reparent. The at-rest AAD is bound to (vault_id, id) and the
    #     folder is not part of it, so relocating within one vault needs no re-encryption (this is the
    #     one case _guard_no_cross_vault_move explicitly permits).
    #   * A COPY always creates a NEW id, so it re-encrypts (new AAD). A CROSS-vault move/copy also
    #     re-encrypts (new vault_id). Re-encryption reuses the tested download-decrypt and
    #     streaming-upload-encrypt paths — no bespoke crypto lives here.
    #   * Zero-knowledge vaults hold client ciphertext the server cannot re-encrypt, so a COPY or any
    #     CROSS-vault operation involving a ZK vault is refused. A within-ZK MOVE (reparent) is fine.
    #   * Cross-vault FOLDER move/copy is deferred (a folder tree spanning vaults would re-encrypt
    #     every descendant); the endpoints return a clean error pointing the caller at file-level ops.
    _COPY_MAX_ITEMS = 1000  # guard a recursive folder copy against an unbounded tree

    def _require_standard(self, vault, role: str) -> None:
        if getattr(vault, 'type', 'standard') != 'standard':
            raise FileServiceError(
                f"This operation is not supported for zero-knowledge vaults ({role})."
            )

    def _dest_folder_or_raise(self, dest_vault_id, dest_folder_id):
        """Resolve a destination folder id and prove it belongs to the destination vault."""
        if dest_folder_id is None:
            return None
        folder = self.db.query(Folder).filter(Folder.id == dest_folder_id).first()
        if not folder or folder.vault_id != dest_vault_id:
            raise FolderNotFoundError("Destination folder not found in the destination vault")
        return folder

    def _assert_not_into_self_or_descendant(self, folder_id, candidate_parent_id):
        """Refuse to move/copy a folder into itself or one of its own descendants (a cycle)."""
        if candidate_parent_id is None:
            return
        if str(candidate_parent_id) == str(folder_id):
            raise FileServiceError("Cannot move or copy a folder into itself.")
        seen = 0
        node = self.db.query(Folder).filter(Folder.id == candidate_parent_id).first()
        while node is not None:
            if str(node.id) == str(folder_id):
                raise FileServiceError("Cannot move or copy a folder into one of its own subfolders.")
            seen += 1
            if seen > self._COPY_MAX_ITEMS:  # defence against a pre-existing cycle in the data
                raise FileServiceError("Folder hierarchy too deep to move or copy safely.")
            node = (self.db.query(Folder).filter(Folder.id == node.parent_folder_id).first()
                    if node.parent_folder_id else None)

    def _stream_copy_file_record(self, source_file, user, dest_vault_id, dest_folder_id, *,
                                 source_file_password=None, replace_same_name=False):
        """Re-encrypt one file's content + name into dest as a NEW file; returns the new File.

        Content is read through open_download_stream (decrypts under the deployment key + the source
        AAD) and written through upload_file_streaming (re-encrypts under the deployment key + the
        NEW (dest_vault_id, new file_id) AAD). Name/MIME (decrypted in-memory on load for a Standard
        vault) are handed to the upload path, which re-seals them for the destination. The caller has
        already resolved vaults and checked ZK and the destination folder.
        """
        import hashlib
        # Quota: the destination gains a full copy of the bytes, so enforce the SAME two limits every
        # upload path does — the per-vault size_limit AND the deployment-wide stored-bytes cap. Doing
        # it here covers every re-encrypt caller (file copy, cross-vault move, recursive folder copy),
        # so none can bypass a limit the normal upload honours.
        add_bytes = source_file.size_bytes or 0
        dest_vault = self.db.query(Vault).filter(Vault.id == dest_vault_id).first()
        if (dest_vault is not None and dest_vault.size_limit
                and (dest_vault.total_size_bytes or 0) + add_bytes > dest_vault.size_limit):
            raise FileTooLargeError("The copy would exceed the destination vault's size limit")
        exceeds, _used, _cap = would_exceed_deployment_storage(self.db, add_bytes)
        if exceeds:
            raise FileTooLargeError("The destination is out of storage")
        name = source_file.original_name or source_file.name
        mime = source_file.mime_type
        # Open the decrypting reader first: this authorizes READ on the source vault and enforces any
        # per-file password, so a copier who cannot read the source never reaches the write.
        reader = self.open_download_stream(source_file.id, user,
                                           file_password=source_file_password, allow_share=False)
        try:
            file_info, ctx = self.upload_file_streaming(
                dest_vault_id, name, user, folder_id=dest_folder_id, mime_type=mime,
            )
            hasher = hashlib.sha256()
            with ctx:
                for chunk in reader.chunks():
                    hasher.update(chunk)
                    ctx.write_chunk(chunk)
            total = ctx.total_bytes
        finally:
            reader.close()
        new_file = self.finalize_streaming_upload(
            file_info, total, hasher.hexdigest(), replace_same_name=replace_same_name,
        )
        # Preserve a file-level password on the copy (same hash → same protection). The reader above
        # already proved the caller can read the source, so this grants no new access.
        if source_file.password_hash:
            new_file.password_hash = source_file.password_hash
            self.db.commit()
            self.db.refresh(new_file)
        return new_file

    def copy_file(self, file_id, user, dest_vault_id, dest_folder_id=None, *,
                  source_file_password=None, replace_same_name=False):
        """Copy a file into dest_vault_id/dest_folder_id, leaving the original in place. Standard
        vaults only (server cannot re-encrypt a ZK blob). Returns the new File."""
        src_file = self.db.query(File).filter(File.id == file_id).first()
        if not src_file:
            raise FileNotFoundError(f"File not found: {file_id}")
        src_vault = self.db.query(Vault).filter(Vault.id == src_file.vault_id).first()
        dest_vault = self.db.query(Vault).filter(Vault.id == dest_vault_id).first()
        if not dest_vault:
            raise VaultNotFoundError("Destination vault not found")
        self._require_standard(src_vault, "source")
        self._require_standard(dest_vault, "destination")
        self._dest_folder_or_raise(dest_vault_id, dest_folder_id)
        # Quota (per-vault size_limit + deployment cap) is enforced in _stream_copy_file_record so
        # every re-encrypt path shares one check.
        return self._stream_copy_file_record(
            src_file, user, dest_vault_id, dest_folder_id,
            source_file_password=source_file_password, replace_same_name=replace_same_name,
        )

    def move_file(self, file_id, user, dest_vault_id, dest_folder_id=None, *,
                  source_file_password=None, replace_same_name=False):
        """Move a file. Within the same vault this is a reparent (no re-encryption). Across vaults it
        re-encrypts into the destination (Standard↔Standard) and then deletes the source."""
        src_file = self.db.query(File).filter(File.id == file_id).first()
        if not src_file:
            raise FileNotFoundError(f"File not found: {file_id}")
        dest_vault = self.db.query(Vault).filter(Vault.id == dest_vault_id).first()
        if not dest_vault:
            raise VaultNotFoundError("Destination vault not found")
        self._dest_folder_or_raise(dest_vault_id, dest_folder_id)

        if str(dest_vault_id) == str(src_file.vault_id):
            # Within-vault reparent — AAD-safe, allowed by _guard_no_cross_vault_move. Needs WRITE.
            self.permission_service.require_vault_permission(
                user, src_file.vault_id, VaultPermissionEnum.WRITE)
            if str(src_file.folder_id or '') == str(dest_folder_id or ''):
                return src_file  # already there
            src_file.folder_id = dest_folder_id
            src_file.updated_at = datetime.now(timezone.utc)
            try:
                self.db.commit()
            except IntegrityError:
                self.db.rollback()
                raise DuplicateNameError("A file with that name already exists in the destination.")
            self.db.refresh(src_file)
            return src_file

        # Cross-vault move = re-encrypt into the destination, then delete the source. Standard only.
        src_vault = self.db.query(Vault).filter(Vault.id == src_file.vault_id).first()
        self._require_standard(src_vault, "source")
        self._require_standard(dest_vault, "destination")
        # Removing the source is a DELETE; the destination write authorizes WRITE inside the copy.
        self.permission_service.require_vault_permission(
            user, src_file.vault_id, VaultPermissionEnum.DELETE)
        # Quota is enforced in _stream_copy_file_record (per-vault size_limit + deployment cap).
        new_file = self._stream_copy_file_record(
            src_file, user, dest_vault_id, dest_folder_id,
            source_file_password=source_file_password, replace_same_name=replace_same_name,
        )
        # Copy is durable before the source is removed: a failure here leaves a copy (safe), never a
        # hole. delete_file re-checks DELETE and securely destroys the source blob.
        self.delete_file(file_id, user)
        return new_file

    def move_folder(self, folder_id, user, dest_vault_id, dest_parent_folder_id=None):
        """Move a folder within its vault (a reparent). Cross-vault folder moves are not supported."""
        folder = self.db.query(Folder).filter(Folder.id == folder_id).first()
        if not folder:
            raise FolderNotFoundError(f"Folder not found: {folder_id}")
        if str(dest_vault_id) != str(folder.vault_id):
            raise FileServiceError(
                "Moving a folder to a different vault is not supported yet; move its files instead.")
        self.permission_service.require_vault_permission(
            user, folder.vault_id, VaultPermissionEnum.WRITE)
        self._dest_folder_or_raise(dest_vault_id, dest_parent_folder_id)
        self._assert_not_into_self_or_descendant(folder_id, dest_parent_folder_id)
        if str(folder.parent_folder_id or '') == str(dest_parent_folder_id or ''):
            return folder  # already there
        folder.parent_folder_id = dest_parent_folder_id
        folder.updated_at = datetime.now(timezone.utc)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            raise DuplicateNameError("A folder with that name already exists in the destination.")
        self.db.refresh(folder)
        return folder

    def copy_folder(self, folder_id, user, dest_vault_id, dest_parent_folder_id=None):
        """Recursively copy a folder (and its files + subfolders) within one vault. Standard vaults
        only; cross-vault folder copies are not supported (copy the files instead)."""
        folder = self.db.query(Folder).filter(Folder.id == folder_id).first()
        if not folder:
            raise FolderNotFoundError(f"Folder not found: {folder_id}")
        if str(dest_vault_id) != str(folder.vault_id):
            raise FileServiceError(
                "Copying a folder to a different vault is not supported yet; copy its files instead.")
        vault = self.db.query(Vault).filter(Vault.id == folder.vault_id).first()
        self._require_standard(vault, "source")
        self._dest_folder_or_raise(dest_vault_id, dest_parent_folder_id)
        self._assert_not_into_self_or_descendant(folder_id, dest_parent_folder_id)
        counter = [0]
        return self._copy_folder_recursive(folder, user, dest_vault_id, dest_parent_folder_id, counter)

    def _copy_folder_recursive(self, folder, user, dest_vault_id, dest_parent_folder_id, counter):
        counter[0] += 1
        if counter[0] > self._COPY_MAX_ITEMS:
            raise FileServiceError("Folder is too large to copy (item limit reached).")
        new_folder = self.create_folder(
            dest_vault_id, folder.name, user, parent_folder_id=dest_parent_folder_id)
        # Copy the files directly under this folder.
        child_files = self.db.query(File).filter(
            File.vault_id == folder.vault_id, File.folder_id == folder.id).all()
        for f in child_files:
            counter[0] += 1
            if counter[0] > self._COPY_MAX_ITEMS:
                raise FileServiceError("Folder is too large to copy (item limit reached).")
            self._stream_copy_file_record(f, user, dest_vault_id, new_folder.id)
        # Recurse into subfolders.
        child_folders = self.db.query(Folder).filter(
            Folder.vault_id == folder.vault_id, Folder.parent_folder_id == folder.id).all()
        for sub in child_folders:
            self._copy_folder_recursive(sub, user, dest_vault_id, new_folder.id, counter)
        return new_folder

    def _get_vault_path(self, vault_id: uuid.UUID) -> Path:
        """Get physical path for vault directory."""
        return self.storage_path / str(vault_id)
    
    def _get_folder_path(self, vault_id: uuid.UUID, folder_id: uuid.UUID) -> Path:
        """Get physical path for folder directory."""
        return self._get_vault_path(vault_id) / "folders" / str(folder_id)
    
    def _id_is_spent(self, object_id) -> bool:
        """Has this id ever been taken out of circulation?

        The check every client-choosable id needs, and the one thing all three of them used to
        get wrong in the same way: they asked whether a row holds the id NOW. A deleted row holds
        nothing, so every id a deleted object used to own was free again -- and deleting an object
        does not reliably erase its bytes, so re-claiming one can put an old version back where a
        reader will find it and authenticate it.
        """
        from app.core.models import RetiredObjectId
        return self.db.query(RetiredObjectId.id).filter(
            RetiredObjectId.id == object_id).first() is not None

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


def _primed(pieces):
    """Pull the first piece now, so a reader that fails on contact fails before it is streamed.

    The chunk-stream reader does its structural work when it is constructed, so a malformed blob
    of that format is already rejected before a caller has a response object. The other two readers
    are plain generators: nothing in them runs until the first `next`, which under a streaming
    response is after the headers have gone out. A blob that is simply not readable would then
    produce a `200`, a full Content-Length, and an empty body -- where the reader this replaces
    produced an error status.

    Priming costs one piece held briefly and restores that behaviour.
    """
    iterator = iter(pieces)
    try:
        first = next(iterator)
    except StopIteration:
        return iter(())
    return itertools.chain((first,), iterator)


def _fixed_windows(handle, window: int = 1024 * 1024):
    """Yield a file in fixed-size pieces.

    For the zero-knowledge path, where the blob is one opaque object with no record structure to
    follow. The window doubles as the hold-back size, so it bounds what a failing checksum costs.
    """
    while True:
        piece = handle.read(window)
        if not piece:
            return
        yield piece


def _fernet_pieces(handle, decrypt_chunk_stream):
    """Yield the legacy Fernet stream's plaintext one token at a time.

    A thin wrapper so the caller receives pieces rather than a joined result; the generator it
    wraps already produced them one at a time.
    """
    for piece in decrypt_chunk_stream(handle):
        yield piece
