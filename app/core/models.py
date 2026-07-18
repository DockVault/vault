"""
Database models for the secure SFTP server.
Implements a comprehensive schema for users, credentials, vaults, files, permissions, and audit logs.
"""
from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum as PyEnum
import uuid

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, ForeignKey,
    Text, BigInteger, Enum, Table, JSON, Index, CheckConstraint, UniqueConstraint, text
)
from sqlalchemy.orm import relationship, declarative_base, backref
from sqlalchemy.dialects.postgresql import UUID

Base = declarative_base()


class RoleEnum(PyEnum):
    """User role enumeration."""
    ADMIN = "admin"
    USER = "user"
    EXTERNAL = "external"


class PermissionEnum(PyEnum):
    """Permission types enumeration."""
    # User Management
    USER_CREATE = "user.create"
    USER_READ = "user.read"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_LIST = "user.list"
    
    # Vault Management
    VAULT_CREATE = "vault.create"
    VAULT_READ = "vault.read"
    VAULT_UPDATE = "vault.update"
    VAULT_DELETE = "vault.delete"
    VAULT_LIST = "vault.list"
    
    # File Operations
    FILE_UPLOAD = "file.upload"
    FILE_DOWNLOAD = "file.download"
    FILE_DELETE = "file.delete"
    FILE_LIST = "file.list"
    
    # Folder Operations
    FOLDER_CREATE = "folder.create"
    FOLDER_DELETE = "folder.delete"
    FOLDER_LIST = "folder.list"
    
    # Temporary Credentials
    TEMP_CRED_CREATE = "temp_cred.create"
    TEMP_CRED_LIST = "temp_cred.list"
    TEMP_CRED_REVOKE = "temp_cred.revoke"
    
    # Dashboard
    DASHBOARD_VIEW = "dashboard.view"
    DASHBOARD_ADMIN = "dashboard.admin"
    
    # Audit Logs
    AUDIT_VIEW = "audit.view"


class VaultPermissionEnum(PyEnum):
    """Vault-specific permissions."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


# Association table for user permissions
user_permissions = Table(
    'user_permissions',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE')),
    Column('permission', String(50), nullable=False),
    Column('granted_at', DateTime, default=datetime.utcnow),
    Column('granted_by', UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
)


# Association table for user <-> organizational group membership.
# Carries a lightweight per-membership role + provenance. Writes are done via
# direct inserts/deletes (see the /groups endpoints) so the User.groups /
# Group.members relationships are declared viewonly.
user_groups = Table(
    'user_groups',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', UUID(as_uuid=True), ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    Column('group_role', String(20), nullable=False, default='member'),  # 'member' | 'manager'
    Column('added_at', DateTime, default=datetime.utcnow),
    Column('added_by', UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
)


# Association table for vault members
vault_members = Table(
    'vault_members',
    Base.metadata,
    Column('vault_id', UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE')),
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE')),
    Column('read_permission', Boolean, default=True),
    Column('write_permission', Boolean, default=False),
    Column('delete_permission', Boolean, default=False),
    # Delegated administration: a member with manage_permission is a vault "Manager"
    # — they can add/remove members and grant/revoke access (the owner keeps
    # destructive/ownership actions: delete vault, rotate keys, change password).
    Column('manage_permission', Boolean, default=False),
    Column('added_at', DateTime, default=datetime.utcnow),
    Column('added_by', UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    # A member has at most one row per vault: stops a concurrent double-grant from creating divergent
    # duplicate rows (the permission read would otherwise resolve an arbitrary one). Mirrors the
    # composite keys on the sibling association tables (user_groups, vault_group_access, temp-cred access).
    UniqueConstraint('vault_id', 'user_id', name='uq_vault_members_vault_user'),
)


# Association table granting an organizational group access to a vault.
# A user gains the group's permission level on a vault if they belong to any
# group listed here for that vault (in addition to direct vault_members).
vault_group_access = Table(
    'vault_group_access',
    Base.metadata,
    Column('vault_id', UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', UUID(as_uuid=True), ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    Column('permission', String(10), nullable=False, default='read'),  # 'read' | 'write'
    Column('added_at', DateTime, default=datetime.utcnow),
    Column('added_by', UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
)


# Per-user "starred" vaults — purely a personal view preference.
vault_favorites = Table(
    'vault_favorites',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('vault_id', UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), primary_key=True),
    Column('created_at', DateTime, default=datetime.utcnow),
)


class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(RoleEnum), nullable=False, default=RoleEnum.USER)
    
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)
    # When a FAILED-LOGIN auto-lock expires (naive UTC). is_locked True + locked_until in the
    # future = time-boxed lockout (auto-unlocks); is_locked True + locked_until NULL = a
    # permanent ADMIN lock. Bounds the "5 wrong passwords permanently DoS a known account" hole.
    locked_until = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    last_login = Column(DateTime, nullable=True)

    # SFTP access controls (per account). sftp_enabled gates ALL direct SFTP login
    # for this user; sftp_password_auth allows password-based SFTP (key auth via
    # user_ssh_keys is allowed whenever sftp_enabled and a key matches). Both default
    # ON to preserve today's behaviour. (Temporary credentials are a separate
    # mechanism and are not gated by these flags.)
    sftp_enabled = Column(Boolean, nullable=False, default=True, server_default='true')
    sftp_password_auth = Column(Boolean, nullable=False, default=True, server_default='true')

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    temporary_credentials = relationship('TemporaryCredential', back_populates='user', cascade='all, delete-orphan')
    active_sessions = relationship('ActiveSession', back_populates='user', cascade='all, delete-orphan')
    ssh_keys = relationship('UserSSHKey', back_populates='user', cascade='all, delete-orphan',
                            foreign_keys='UserSSHKey.user_id')
    vaults_owned = relationship('Vault', back_populates='owner', foreign_keys='Vault.owner_id')
    vaults_accessible = relationship(
        'Vault',
        secondary=vault_members,
        primaryjoin='User.id == vault_members.c.user_id',
        secondaryjoin='Vault.id == vault_members.c.vault_id',
        back_populates='members'
    )
    audit_logs = relationship('AuditLog', back_populates='user', foreign_keys='AuditLog.user_id')
    key_pair = relationship('UserKeyPair', back_populates='user', uselist=False, cascade='all, delete-orphan')
    # Organizational group memberships (read-only view; writes via /groups endpoints)
    groups = relationship(
        'Group',
        secondary=user_groups,
        primaryjoin='User.id == user_groups.c.user_id',
        secondaryjoin='Group.id == user_groups.c.group_id',
        viewonly=True,
        order_by='Group.name',
    )

    __table_args__ = (
        Index('idx_user_username', 'username'),
        Index('idx_user_email', 'email'),
    )


class UserSSHKey(Base):
    """An SSH public key authorized for a user's SFTP access.

    Keys attach to the ACCOUNT (not a vault): a key authenticates the user, who
    then sees exactly the vaults their membership/scope already grants — same
    authorization path as password auth. For least-privilege machine access, use a
    dedicated service-account user scoped to the right vaults and put the key there.

    NOTE: this is the SSH *authorized key* store, distinct from UserKeyPair (the ECC
    keypair used for the team-key / zero-knowledge feature).
    """
    __tablename__ = 'user_ssh_keys'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    name = Column(String(120), nullable=False)        # human label, e.g. "backup-bot laptop"
    key_type = Column(String(32), nullable=True)       # 'ssh-ed25519', 'ssh-rsa', ...
    public_key = Column(Text, nullable=False)          # full OpenSSH public key line
    fingerprint = Column(String(128), nullable=False)  # SHA256:... (for display + dedup)

    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    user = relationship('User', back_populates='ssh_keys', foreign_keys=[user_id])

    __table_args__ = (
        Index('idx_ssh_key_user', 'user_id'),
        # A given key may be registered once per user.
        UniqueConstraint('user_id', 'fingerprint', name='uq_user_ssh_fingerprint'),
    )


class Group(Base):
    """Organizational group / department.

    Hierarchical via a self-referential parent (e.g. Engineering -> Backend).
    Purely organizational for now: membership + nesting + filtering/overview.
    Deliberately decoupled from roles and vault access so those can be layered
    on later without reworking the data model.
    """
    __tablename__ = 'groups'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)
    color = Column(String(20), nullable=True)  # optional accent tag, e.g. 'indigo'
    parent_id = Column(UUID(as_uuid=True), ForeignKey('groups.id', ondelete='SET NULL'), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Self-referential hierarchy. Deleting a parent SET NULLs children (they
    # become roots); the API reparents to the grandparent for a cleaner tree.
    parent = relationship('Group', remote_side=[id], backref='children')
    members = relationship(
        'User',
        secondary=user_groups,
        primaryjoin='Group.id == user_groups.c.group_id',
        secondaryjoin='User.id == user_groups.c.user_id',
        viewonly=True,
    )

    __table_args__ = (
        Index('idx_group_parent', 'parent_id'),
        Index('idx_group_name', 'name'),
    )


class TemporaryCredential(Base):
    """Temporary one-time credentials for untrusted environments."""
    __tablename__ = 'temporary_credentials'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    temp_username = Column(String(255), unique=True, nullable=False, index=True)
    credential_hash = Column(String(255), nullable=False)  # Bcrypt hash for SFTP authentication
    encrypted_password = Column(Text, nullable=True)  # DEPRECATED - No longer used (security enhancement)
    password_shown = Column(Boolean, default=True)  # Tracks if user viewed password at creation
    
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    deactivate_at = Column(DateTime, nullable=False)  # 20 minutes after creation
    
    is_used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    # Optional creator note explaining why the credential was issued.
    note = Column(String(500), nullable=True)
    # Whether THIS temp credential may itself create further temp credentials.
    can_create_temp_credentials = Column(Boolean, default=False, nullable=False)

    # Least-privilege scope. NULL = legacy credential = unrestricted (inherits the
    # creating user's full access). See app/core/temp_scope.py for the document shape.
    scope = Column(JSON, nullable=True)
    # 'all' -> every vault the creator can reach; 'selected' -> only the vaults in
    # temp_credential_vault_access. Only consulted when scope is non-NULL.
    vault_access_mode = Column(String(10), nullable=False, default='selected')
    # Provenance: which temp credential minted this one (if a temp session did).
    # Powers "a temp account may invalidate only the creds it created".
    created_by_temp_credential_id = Column(
        UUID(as_uuid=True), ForeignKey('temporary_credentials.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    user = relationship('User', back_populates='temporary_credentials')
    sessions = relationship('ActiveSession', back_populates='temporary_credential')
    
    __table_args__ = (
        Index('idx_temp_cred_username', 'temp_username'),
        Index('idx_temp_cred_expires', 'expires_at'),
    )


class TempCredentialVaultAccess(Base):
    """Per-(temp credential, vault) access grant. Mirrors vault_members so the
    creation modal and the (future) in-vault Permissions tab write the same rows.
    Only meaningful when the owning credential's vault_access_mode == 'selected'."""
    __tablename__ = 'temp_credential_vault_access'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    temp_credential_id = Column(
        UUID(as_uuid=True), ForeignKey('temporary_credentials.id', ondelete='CASCADE'), nullable=False)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    # Capability strings this credential holds on THIS vault (subset of the vocab
    # in app/core/temp_scope.py, e.g. ["vault.see_files", "file.download"]).
    vault_caps = Column(JSON, nullable=False, default=list)
    # Optional per-file/folder restriction WITHIN this vault (ID-based). NULL/absent = the WHOLE
    # vault (default, backward compatible). A dict {"files": [file_id, ...], "folders": [folder_id,
    # ...]}: a folders entry means that folder AND its whole subtree, a files entry means exactly
    # that one file. A PROVIDED dict with both lists empty means "no files" (fail closed). IDs are
    # used (not names/paths) so this enforces even for zero-knowledge vaults whose names the server
    # never holds. Matching/normalization live in app/core/id_scope.py; folder ancestry via
    # app/services/vault_service.folder_ancestry.
    scope_ids = Column(JSON, nullable=True)
    # Fingerprint of the vault's password hash captured when this grant was minted (only
    # for password-protected vaults; NULL otherwise). Re-checked on every SFTP access so a
    # later password add/change/rotation voids this credential's standing SFTP proof —
    # keeping SFTP at the web's live two-factor bar rather than a proof frozen at mint.
    vault_password_fingerprint = Column(String(64), nullable=True)
    # --- Temporary passcode: a second server-side access gate on a password-protected STANDARD vault
    # (never on a zero-knowledge vault). An Argon2 verifier that opens the vault in place of the real
    # password for the holder of this credential — scoped, expiring, revocable, rate-limited. NULL =
    # no passcode (today's behavior: the holder must know the real password). Content is NOT
    # re-encrypted (it is keyed off the deployment secret, not the password); this is authorization
    # only. Redemption (a later phase) enforces expiry + max_uses and rate-limits like the password.
    passcode_hash = Column(String(255), nullable=True)
    passcode_kind = Column(String(16), nullable=True)              # 'generated' | 'custom'
    passcode_max_uses = Column(Integer, nullable=True)            # NULL = multi-use within TTL; 1 = one-time
    passcode_use_count = Column(Integer, nullable=False, default=0)
    passcode_expires_at = Column(DateTime, nullable=True)         # <= the credential's deactivate_at
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    __table_args__ = (
        UniqueConstraint('temp_credential_id', 'vault_id', name='uq_temp_cred_vault'),
        Index('idx_temp_cred_vault_cred', 'temp_credential_id'),
        Index('idx_temp_cred_vault_vault', 'vault_id'),
    )


class ActiveSession(Base):
    """Track active SFTP sessions."""
    __tablename__ = 'active_sessions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    temp_credential_id = Column(UUID(as_uuid=True), ForeignKey('temporary_credentials.id', ondelete='CASCADE'), nullable=True)
    
    ip_address = Column(String(45), nullable=False)  # IPv6 compatible
    started_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    is_active = Column(Boolean, default=True)
    # Explicit revocation (logout / lock / deactivate), DISTINCT from is_active=False which a
    # new login also sets on superseded sessions. Regular-user JWTs are rejected per request
    # when their session is `revoked` — a DURABLE (DB) revocation that survives a Redis outage,
    # unlike the best-effort Redis logout denylist. A new login does NOT set this, so concurrent
    # sessions keep working (no single-session side effect).
    revoked = Column(Boolean, nullable=False, default=False, server_default='false')
    
    # Relationships
    user = relationship('User', back_populates='active_sessions')
    temporary_credential = relationship('TemporaryCredential', back_populates='sessions')
    
    __table_args__ = (
        Index('idx_session_token', 'session_token'),
        Index('idx_session_user', 'user_id'),
    )


class Vault(Base):
    """Vault for organizing and securing files."""
    __tablename__ = 'vaults'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Password protection (hashed)
    password_hash = Column(String(255), nullable=True)
    
    # Per-vault encryption keys (for isolating vault breaches)
    encrypted_vault_key = Column(Text, nullable=True)  # Base64-encoded encrypted vault key
    key_salt = Column(String(32), nullable=True)  # Salt for PBKDF2 key derivation
    key_version = Column(Integer, default=1)  # For future key rotation
    key_encryption_metadata = Column(JSON, nullable=True)  # Algorithm, iterations, etc.
    key_created_at = Column(DateTime, default=datetime.utcnow)  # When current key was created
    
    # ECC team key management
    key_wrapping_mode = Column(String(20), default='direct')  # 'direct' or 'hierarchical'
    member_keys = Column(JSON, nullable=True)  # UNUSED placeholder; VaultMemberKey is the source of truth
    # Hierarchical mode (large ZK vaults): the vault DEK is wrapped ONCE per DEK epoch to the
    # per-vault TEAM public key (team_public_key); team_key is a JSON-text map keyed by DEK epoch:
    #   {"<dek_version>": {"wrapped_dek": <b64>, "ephemeral_public_key": <b64>, "team_key_version": <T>}}
    # The team PRIVATE key is wrapped per-member in VaultMemberKey rows tagged
    # wrapping_algorithm='ECDH-P384-AES-GCM-TEAMPRIV', keyed by team_key_version. The server holds
    # only public keys + opaque wraps. See docs/vault-zk-team-key-design.md.
    team_key = Column(Text, nullable=True)            # JSON map: DEK epoch -> {wrapped_dek, eph, team_key_version}
    team_public_key = Column(Text, nullable=True)     # the CURRENT team public key (PEM/SPKI)
    # The team-KEYPAIR epoch, SEPARATE from dek_version. Bumps ONLY on a team-keypair rotation
    # (a team-member revoke / forward-secrecy path), NEVER on a routine O(1) DEK rotation — so a
    # routine rotation that bumps dek_version does not require re-wrapping the team privkey for
    # every member. TEAMPRIV VaultMemberKey rows are keyed by this. Always 1 for direct vaults.
    team_key_version = Column(Integer, nullable=False, default=1, server_default='1')

    # Zero-knowledge DEK epoch (forward-only rotation on member revoke). Bumped by
    # POST /ecc/vaults/{id}/rekey when a ZK member is revoked: a fresh DEK is minted
    # + re-wrapped for the remaining members IN THE BROWSER, old files keep their
    # original DEK epoch (read-old/write-new), and the revoked member never receives
    # the new epoch. DISTINCT from key_version above, which is the STANDARD-vault
    # Fernet rotation counter (vault_key_utils + VaultKeyHistory + /vaults/{id}/rotate-key);
    # conflating the two would regress Standard vaults. Always 1 for never-rotated /
    # non-ZK vaults.
    dek_version = Column(Integer, nullable=False, default=1, server_default='1')
    
    # Expiration policy
    expire_files_after_days = Column(Integer, nullable=True)  # null means never expire
    expire_files_unit = Column(String(20), default='days')  # 'minutes', 'hours', or 'days'

    # How long (minutes) the client may remember this vault's password before
    # re-prompting. null = default (15), 0 = always ask. Lower for sensitive vaults.
    unlock_remember_minutes = Column(Integer, nullable=True)
    
    # Size limit
    size_limit = Column(BigInteger, default=1073741824)  # Default 1GB
    
    # Storage statistics
    total_size_bytes = Column(BigInteger, default=0)
    file_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = Column(DateTime, nullable=True)

    is_active = Column(Boolean, default=True)

    # Confidentiality tier (per-vault, effectively immutable). 'standard' =
    # server-side encryption, SFTP-capable (the only behaviour built today).
    # 'zero_knowledge' (browser-side crypto, web-only) slots in later — see
    # docs/vault-zero-trust-and-sftp-design.md §2. Defaulting every vault to
    # 'standard' keeps today's behaviour unchanged.
    type = Column(String(20), nullable=False, default='standard', server_default='standard')

    # Relationships
    owner = relationship('User', back_populates='vaults_owned', foreign_keys=[owner_id])
    members = relationship(
        'User',
        secondary=vault_members,
        primaryjoin='Vault.id == vault_members.c.vault_id',
        secondaryjoin='User.id == vault_members.c.user_id',
        back_populates='vaults_accessible'
    )
    folders = relationship('Folder', back_populates='vault', cascade='all, delete-orphan')
    files = relationship('File', back_populates='vault', cascade='all, delete-orphan')
    
    __table_args__ = (
        Index('idx_vault_owner', 'owner_id'),
        Index('idx_vault_name', 'name'),
    )


class VaultKeyHistory(Base):
    """
    Historical vault encryption keys for key rotation support.
    
    When a vault's encryption key is rotated, the old key is archived here
    to allow decryption of files encrypted with previous key versions.
    This enables secure key rotation without requiring re-encryption of all files.
    """
    __tablename__ = 'vault_key_history'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    key_version = Column(Integer, nullable=False)  # 1, 2, 3, etc.
    encrypted_key = Column(Text, nullable=False)  # Encrypted vault key (same format as Vault.encrypted_vault_key)
    key_salt = Column(String(32), nullable=True)  # Salt used for this key version
    key_encryption_metadata = Column(JSON, nullable=True)  # Algorithm, iterations, etc.
    
    # Lifecycle timestamps
    created_at = Column(DateTime, nullable=False)  # When this key version was created
    retired_at = Column(DateTime, default=datetime.utcnow, nullable=False)  # When it was rotated out
    
    # Relationships
    vault = relationship('Vault', foreign_keys=[vault_id])
    
    __table_args__ = (
        # Efficient lookup by vault and version
        Index('idx_vault_key_history_vault_version', 'vault_id', 'key_version'),
        # Ensure no duplicate key versions for same vault
        UniqueConstraint('vault_id', 'key_version', name='uq_vault_key_version'),
        # Track rotation timeline
        Index('idx_vault_key_history_retired', 'retired_at'),
    )


class Folder(Base):
    """Folder within a vault for organizing files."""
    __tablename__ = 'folders'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable: Standard-vault folders store the name encrypted at rest (enc_name) and
    # NULL this plaintext column; legacy/ZK rows keep the plaintext here.
    name = Column(String(255), nullable=True)
    # Filename encryption at rest. Standard vaults: AES-GCM blob (server key) + per-vault
    # HMAC index. Zero-knowledge vaults: the blob is encrypted IN THE BROWSER under the
    # vault DEK (marked with security.ZK_NAME_PREFIX) and name_bi is a CLIENT-computed
    # blind index — the server stores both verbatim and can read neither.
    enc_name = Column(Text, nullable=True)
    name_bi = Column(String(64), nullable=True, index=True)
    # Zero-knowledge only: the DEK epoch the browser encrypted enc_name under (folders have
    # no content epoch of their own). NULL => epoch 1. Lets a reader pick the right wrapped
    # DEK to decrypt the folder name after a forward-only rotation. Unused by Standard vaults.
    name_key_version = Column(Integer, nullable=True)

    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    parent_folder_id = Column(UUID(as_uuid=True), ForeignKey('folders.id', ondelete='CASCADE'), nullable=True)
    
    # Password protection (hashed)
    password_hash = Column(String(255), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    # Relationships
    vault = relationship('Vault', back_populates='folders')
    parent_folder = relationship('Folder', remote_side=[id], backref='subfolders')
    files = relationship('File', back_populates='folder', cascade='all, delete-orphan')
    
    __table_args__ = (
        Index('idx_folder_vault', 'vault_id'),
        Index('idx_folder_parent', 'parent_folder_id'),
        # DB-level dedup backstop: one folder name per (vault, parent). name_bi is the
        # per-vault HMAC blind index (Standard) or the client blind index (ZK). NULL
        # parent_folder_id (vault-root folders) is folded to a fixed sentinel so two
        # root folders with the same name DO collide (Postgres treats NULLs as distinct
        # in a plain unique index). Partial (WHERE name_bi IS NOT NULL) so legacy
        # plaintext rows that predate name encryption — name_bi NULL — are exempt until
        # they are backfilled. Mirrored as a raw idempotent migration for existing DBs.
        Index(
            'uq_folders_vault_parent_name_bi',
            'vault_id',
            text("COALESCE(parent_folder_id, '00000000-0000-0000-0000-000000000000'::uuid)"),
            'name_bi',
            unique=True,
            postgresql_where=text('name_bi IS NOT NULL'),
        ),
    )


class File(Base):
    """File stored in the system."""
    __tablename__ = 'files'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable: Standard-vault files store name/MIME encrypted at rest (enc_name/enc_mime)
    # and NULL these plaintext columns; legacy/ZK rows keep the plaintext.
    name = Column(String(255), nullable=True)
    original_name = Column(String(255), nullable=True)

    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    folder_id = Column(UUID(as_uuid=True), ForeignKey('folders.id', ondelete='CASCADE'), nullable=True)

    # File metadata
    size_bytes = Column(BigInteger, nullable=False)
    mime_type = Column(String(255), nullable=True)
    checksum_sha256 = Column(String(64), nullable=False)  # For integrity verification

    # Storage information
    storage_path = Column(String(512), nullable=False)  # Encrypted file path
    is_encrypted = Column(Boolean, default=True)
    encryption_metadata = Column(JSON, nullable=True)  # Store encryption details

    # Filename / MIME encryption at rest (Standard vaults). enc_* hold AES-GCM blobs;
    # name_bi is a per-vault HMAC blind index for server-side exact-match lookup.
    enc_name = Column(Text, nullable=True)
    enc_mime = Column(Text, nullable=True)
    name_bi = Column(String(64), nullable=True, index=True)
    
    # Password protection (hashed)
    password_hash = Column(String(255), nullable=True)
    
    # Expiration
    expires_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    uploaded_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    # Relationships
    vault = relationship('Vault', back_populates='files')
    folder = relationship('Folder', back_populates='files')
    
    __table_args__ = (
        Index('idx_file_vault', 'vault_id'),
        Index('idx_file_folder', 'folder_id'),
        Index('idx_file_expires', 'expires_at'),
        # DB-level dedup backstop: one file name per (vault, folder). name_bi is the
        # per-vault HMAC blind index (Standard) or the client blind index (ZK). NULL
        # folder_id (vault-root files) is folded to a fixed sentinel so two root files
        # with the same name DO collide (Postgres treats NULLs as distinct otherwise).
        # Partial (WHERE name_bi IS NOT NULL) so legacy plaintext rows (name_bi NULL,
        # pre-encryption) are exempt until backfilled. The replace-on-clash upload path
        # deletes the prior same-name row in the SAME transaction as the new insert
        # (see app/services/vault_service.py finalize_streaming_upload) so a legitimate overwrite never
        # trips this; a lost race surfaces as a clean 409. Mirrored as a raw migration.
        Index(
            'uq_files_vault_folder_name_bi',
            'vault_id',
            text("COALESCE(folder_id, '00000000-0000-0000-0000-000000000000'::uuid)"),
            'name_bi',
            unique=True,
            postgresql_where=text('name_bi IS NOT NULL'),
        ),
    )


# --- Transparent filename/MIME decryption (Standard vaults) -----------------
# Standard-vault files/folders store name/MIME encrypted at rest (enc_*) with the
# plaintext columns NULL. Decrypt on load/refresh into the plaintext attributes via
# set_committed_value (sets without marking dirty -> no write-back), so every read site
# keeps using file.original_name / file.mime_type / folder.name unchanged. Rows without
# enc_* (zero-knowledge, or not-yet-backfilled legacy) are left exactly as-is — this is
# safe and fully backward-compatible. The 'refresh' event reuses the same handler (its
# extra (context, attrs) args are absorbed by *_args).
from sqlalchemy import event as _sa_event
from sqlalchemy.orm import attributes as _sa_attributes


def _decrypt_file_names(target, *_args):
    enc_name = getattr(target, 'enc_name', None)
    enc_mime = getattr(target, 'enc_mime', None)
    if not enc_name and not enc_mime:
        return
    from app.core.security import decrypt_object_field, is_zk_sealed_name
    # Zero-knowledge names are encrypted client-side under the vault DEK; the server has
    # no key and MUST leave them opaque (plaintext columns stay NULL — the browser
    # decrypts). Detect by the ZK marker so we never spam decrypt failures or, worse,
    # surface a placeholder as if it were the name.
    if is_zk_sealed_name(enc_name) or is_zk_sealed_name(enc_mime):
        return
    if enc_name:
        try:
            plain = decrypt_object_field(target.vault_id, target.id, enc_name, 'name')
            # Sealed rows store only the original name (enc_name); the sanitized `name`
            # column is intentionally collapsed to the same value on read. Nothing relies
            # on `name` holding the distinct sanitized form (storage keys off the UUID,
            # path-traversal defense uses the UUID, matching uses the blind index).
            _sa_attributes.set_committed_value(target, 'original_name', plain)
            _sa_attributes.set_committed_value(target, 'name', plain)
        except Exception:  # noqa: BLE001 — never let a decrypt error break a load
            # enc_name present but undecryptable usually means a wrong/rotated
            # ENCRYPTION_KEY; log the id (never the plaintext) so it's diagnosable.
            print(f"⚠ file name decrypt failed for {getattr(target, 'id', None)}")
    if enc_mime:
        try:
            _sa_attributes.set_committed_value(
                target, 'mime_type',
                decrypt_object_field(target.vault_id, target.id, enc_mime, 'mime'))
        except Exception:  # noqa: BLE001
            print(f"⚠ file mime decrypt failed for {getattr(target, 'id', None)}")


def _decrypt_folder_name(target, *_args):
    enc_name = getattr(target, 'enc_name', None)
    if not enc_name:
        return
    from app.core.security import decrypt_object_field, is_zk_sealed_name
    # Zero-knowledge folder names are browser-encrypted under the vault DEK — leave opaque.
    if is_zk_sealed_name(enc_name):
        return
    try:
        _sa_attributes.set_committed_value(
            target, 'name',
            decrypt_object_field(target.vault_id, target.id, enc_name, 'name'))
    except Exception:  # noqa: BLE001
        print(f"⚠ folder name decrypt failed for {getattr(target, 'id', None)}")


_sa_event.listen(File, 'load', _decrypt_file_names)
_sa_event.listen(File, 'refresh', _decrypt_file_names)
_sa_event.listen(Folder, 'load', _decrypt_folder_name)
_sa_event.listen(Folder, 'refresh', _decrypt_folder_name)


# --- Cross-vault-move guard (at-rest AAD integrity) -------------------------
# Every at-rest blob is bound by AAD to (vault_id, id): the file CONTENT stream
# (GcmChunkStreamCodec) and the encrypted name/MIME (encrypt_object_field) both
# mix vault_id + the row id into their AAD. Re-pointing a row's vault_id to a
# different vault WITHOUT re-encrypting would therefore make every blob silently
# undecryptable. No code moves rows across vaults today (vault_id is written only
# at creation; SFTP/web rename are in-place, same vault), so this is a fail-closed
# defensive invariant against a future move that forgets to re-encrypt.
#
# A genuine re-encrypting migration can opt out by setting target._allow_vault_reencrypt
# = True before flushing. The guard fires only on a real committed-value change, so it
# is invisible to:
#   * INSERT  — SQLAlchemy fires before_insert, not before_update, on creation;
#   * the load/refresh decrypt events above — set_committed_value leaves attribute
#     history empty, so get_history reports no change;
#   * in-place rename — it never touches vault_id / folder_id / parent_folder_id.
def _guard_no_cross_vault_move(mapper, connection, target):
    # NOTE: this is an ORM before_update event — it CANNOT see bulk Session.execute(update())
    # or raw-SQL UPDATEs. A future re-encrypting migration must go through the ORM and set
    # _allow_vault_reencrypt (or be back-stopped by a DB trigger); a raw UPDATE that re-points
    # vault_id would bypass this guard entirely.
    if getattr(target, '_allow_vault_reencrypt', False):
        return
    vh = _sa_attributes.get_history(target, 'vault_id')
    # Fire when vault_id changed to a value different from a KNOWN old value, OR when the old
    # value is simply UNKNOWN (expired after a prior commit with expire_on_commit=True and not
    # re-read before the reassignment — SQLAlchemy won't fetch it mid-flush, so vh.deleted is
    # empty). Gating on has_changes() (not on vh.deleted being populated) keeps this fail-closed
    # for that case; an unchanged vault_id yields has_changes()==False so ordinary updates/renames
    # don't trip it.
    if (vh.has_changes() and vh.added and vh.added[0] is not None
            and (not vh.deleted or str(vh.deleted[0]) != str(vh.added[0]))):
        raise ValueError(
            f"Refusing to move {type(target).__name__} {getattr(target, 'id', None)} to a "
            f"different vault without re-encryption: at-rest AAD is bound to vault_id+id."
        )
    # Cross-vault REPARENT: changing the (parent) folder reference to a folder in another
    # vault is just as corrupting (the row would live under a foreign vault's tree while its
    # blobs stay bound to the old vault_id). A SAME-vault reparent is AAD-safe and allowed.
    # This only ever queries when the reference actually changes — no code reparents today,
    # so it costs nothing on the normal rename/update paths.
    ref = 'folder_id' if isinstance(target, File) else 'parent_folder_id'
    fh = _sa_attributes.get_history(target, ref)
    if fh.has_changes() and fh.added and fh.added[0] is not None:
        row = connection.execute(
            text("SELECT vault_id FROM folders WHERE id = :fid"), {"fid": str(fh.added[0])}
        ).first()
        if row is not None and str(row[0]) != str(target.vault_id):
            raise ValueError(
                f"Refusing to reparent {type(target).__name__} {getattr(target, 'id', None)} "
                f"into a folder in a different vault without re-encryption."
            )


_sa_event.listen(File, 'before_update', _guard_no_cross_vault_move)
_sa_event.listen(Folder, 'before_update', _guard_no_cross_vault_move)


class AuditLog(Base):
    """Comprehensive audit logging for security and compliance."""
    __tablename__ = 'audit_logs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Who
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username = Column(String(255), nullable=True)  # Denormalized for deleted users
    
    # What
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(255), nullable=True)
    
    # When
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Where
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    
    # How
    method = Column(String(10), nullable=True)  # HTTP method for API calls
    endpoint = Column(String(255), nullable=True)
    
    # Result
    status = Column(String(20), nullable=False)  # success, failure, error
    details = Column(JSON, nullable=True)  # Additional context
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship('User', back_populates='audit_logs', foreign_keys=[user_id])
    
    __table_args__ = (
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_user', 'user_id'),
        Index('idx_audit_action', 'action'),
    )


class SystemSetting(Base):
    """Key-value store for global application settings (admin Settings page).

    A single row keyed 'global' holds the whole settings dict as JSON. Created
    automatically by init_db()/create_all() — no manual migration needed.
    """
    __tablename__ = 'system_settings'

    key = Column(String(100), primary_key=True)
    value = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserPreference(Base):
    """Per-user UI preferences (light/dark theme, accent, background, skin) so a
    user's look-and-feel follows their ACCOUNT across browsers and devices instead
    of living only in one browser's localStorage.

    One row per user holds the whole prefs dict as JSON. A WHOLE NEW TABLE (not a
    users column) is used deliberately: init_db() only runs create_all(), which
    creates missing tables but never ALTERs existing ones — so a new table migrates
    cleanly on already-deployed vaults, whereas a new column would not. Created
    lazily on the first PUT; a user with no row simply has no stored preferences.
    """
    __tablename__ = 'user_preferences'

    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    preferences = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LogPullToken(Base):
    """A named bearer token that may PULL the container logs via GET /logs.

    Multiple tokens can coexist (zero-gap rotation = mint a new one, then disable the old).
    Only the peppered HMAC-SHA256 hash is stored — the plaintext is shown ONCE at mint time and
    never again. `token_prefix` (the first chars of the plaintext) is a public, indexed handle
    so verification scans only same-prefix rows before the constant-time hash compare. `scope` is
    a validated LIST of components the token may read (e.g. ['web','sftp']); it must be a list so
    a scope check is exact membership, never a substring match. Created by create_all() — a whole
    new table needs no lightweight migration entry.
    """
    __tablename__ = 'log_pull_tokens'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    token_prefix = Column(String(16), nullable=False, index=True)          # public lookup handle
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # HMAC-SHA256 hex
    scope = Column(JSON, nullable=False, default=list)                     # ['web','sftp',...]
    disabled = Column(Boolean, nullable=False, default=False, server_default='false')
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    __table_args__ = (
        Index('idx_logpulltoken_prefix', 'token_prefix'),
    )


class RateLimitRecord(Base):
    """Track rate limiting for login attempts."""
    __tablename__ = 'rate_limit_records'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identifier = Column(String(255), nullable=False, index=True)  # IP or username
    action = Column(String(50), nullable=False)
    attempt_count = Column(Integer, default=1)
    window_start = Column(DateTime, default=datetime.utcnow)
    last_attempt = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_rate_limit_identifier', 'identifier', 'action'),
        # One canonical row per (identifier, action) so the DB-backed login
        # throttle can do an atomic INSERT ... ON CONFLICT upsert (no duplicate
        # rows splitting the count under concurrent attempts during a Redis
        # outage). On an existing DB the constraint is added by the lightweight
        # migration in api_server._run_lightweight_migrations.
        UniqueConstraint('identifier', 'action', name='uq_rate_limit_identifier_action'),
    )


class UserEndpointPermission(Base):
    """Track which endpoint permissions each user has."""
    __tablename__ = 'user_endpoint_permissions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    endpoint_group = Column(String(100), nullable=False)  # e.g., "users.list", "vaults.create"
    granted_at = Column(DateTime, default=datetime.utcnow)
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    # Relationships
    # Cascade-delete a user's endpoint permissions when the user is deleted.
    # passive_deletes defers to the DB-level ON DELETE CASCADE on user_id and
    # stops the ORM from trying to NULL the (NOT NULL) FK first.
    user = relationship(
        "User",
        foreign_keys=[user_id],
        backref=backref("endpoint_permissions", cascade="all, delete-orphan", passive_deletes=True),
    )
    granter = relationship("User", foreign_keys=[granted_by])
    
    __table_args__ = (
        Index('idx_user_endpoint', 'user_id', 'endpoint_group'),
        # Unique constraint: user can't have same permission twice
        UniqueConstraint('user_id', 'endpoint_group', name='uq_user_endpoint'),
    )


class SecurityAlert(Base):
    """
    Security alert model for monitoring and threat detection.
    
    Records security events that require attention:
    - Multiple failed login attempts
    - Rate limit violations
    - Suspicious activity patterns
    - Bulk file operations
    - Unauthorized access attempts
    """
    __tablename__ = 'security_alerts'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False)  # Type of security event
    severity = Column(String(20), nullable=False)  # info, warning, critical
    message = Column(Text, nullable=False)  # Human-readable description
    
    # Context information
    username = Column(String(255), nullable=True)  # Username involved
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    details = Column(JSON, nullable=True)  # Additional structured details
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(255), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    __table_args__ = (
        Index('idx_security_alert_timestamp', 'timestamp'),
        Index('idx_security_alert_severity', 'severity'),
        Index('idx_security_alert_resolved', 'resolved'),
        Index('idx_security_alert_username', 'username'),
        Index('idx_security_alert_ip', 'ip_address'),
        # Composite index for dashboard queries
        Index('idx_security_alert_unresolved', 'resolved', 'severity', 'timestamp'),
    )


# ============================================================================
# ECC Zero-Trust Encryption Models
# ============================================================================

class UserKeyPair(Base):
    """
    Stores user's ECC public keys for Zero-Trust encryption.
    Private keys are NEVER stored on the server - only on client side.
    """
    __tablename__ = 'user_keypairs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True)
    
    # Public key for ECDH (PEM format, Base64 encoded)
    public_key = Column(Text, nullable=False)
    
    # Encrypted private key (for recovery via password)
    # Client encrypts with password-derived key before uploading
    encrypted_private_key = Column(Text, nullable=True)
    
    # Key metadata
    curve = Column(String(50), default='SECP384R1')  # ECC curve type
    fingerprint = Column(String(64), nullable=False)  # SHA256 hash of public key
    
    # Key rotation support
    version = Column(Integer, default=1)
    previous_public_key = Column(Text, nullable=True)  # For key rotation transition
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship('User', foreign_keys=[user_id])
    
    __table_args__ = (
        Index('idx_user_keypair_user', 'user_id'),
        Index('idx_user_keypair_fingerprint', 'fingerprint'),
    )


class ZKShareInvite(Base):
    """A pending zero-knowledge share invite (team-onboarding for keyless recipients).

    When a vault manager tries to share a zero-knowledge vault with a user who has no
    encryption key yet, the DEK can't be wrapped for them, so we record the intent here
    and prompt the recipient to set up a key ("invite-then-share"). The server holds NO
    key material — this row is only a "please set up your encryption key so a vault can be
    shared with you" nudge (the vault name stays client-sealed, so it is not stored here).
    Cleared when the recipient registers a keypair, or when the share actually lands.
    """
    __tablename__ = 'zk_share_invites'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    target_user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    invited_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('vault_id', 'target_user_id', name='uq_zk_invite_vault_target'),
        Index('idx_zk_invite_target', 'target_user_id'),
    )


class ECCRegistrationChallenge(Base):
    """A one-time proof-of-possession challenge for ECC public-key registration (app/services/ecc_pop.py).

    Holds the server's EPHEMERAL private key + nonce so the register endpoint can verify the
    client's ECDH key-confirmation MAC. NOT a user key and never a DEK — a transient,
    single-use, short-TTL server challenge (deleted on verify; expired rows swept). This is
    what stops a caller registering a public key whose private key they don't hold.
    """
    __tablename__ = 'ecc_registration_challenges'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    server_private_key = Column(Text, nullable=False)  # server ephemeral PKCS8 PEM (transient)
    nonce = Column(Text, nullable=False)               # base64
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_ecc_challenge_user', 'user_id'),
    )


class VaultMemberKey(Base):
    """
    Stores per-member wrapped vault Data Encryption Keys (DEKs).
    Each member has their own copy of the vault DEK, wrapped with their public key via ECDH.
    """
    __tablename__ = 'vault_member_keys'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Wrapped DEK (encrypted with ECDH-derived key)
    encrypted_dek = Column(Text, nullable=False)
    
    # Alias for compatibility with ecc_crypto_service
    @property
    def wrapped_dek(self):
        return self.encrypted_dek
    
    @wrapped_dek.setter
    def wrapped_dek(self, value):
        self.encrypted_dek = value
    
    # ECDH ephemeral public key (for deriving shared secret)
    ephemeral_public_key = Column(Text, nullable=False)
    
    # Key metadata
    wrapping_algorithm = Column(String(50), default='ECDH-AES-256-GCM')
    # Which DEK epoch (Vault.dek_version) this wrapped copy belongs to. On a forward-only
    # rekey the remaining members KEEP their old-epoch rows (to read old files) AND gain a
    # new row at the new epoch — so a member can hold several active rows, one per epoch they
    # still need. The unique constraint below is therefore on (vault, user, key_version).
    # NOT NULL with a server default: the version-aware get_vault_keys read-path matches on
    # key_version == requested epoch, so a NULL here would silently make a row unfetchable.
    key_version = Column(Integer, nullable=False, default=1, server_default='1')
    
    # Access control
    granted_at = Column(DateTime, default=datetime.utcnow)
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    vault = relationship('Vault', foreign_keys=[vault_id])
    user = relationship('User', foreign_keys=[user_id])
    granter = relationship('User', foreign_keys=[granted_by])
    revoker = relationship('User', foreign_keys=[revoked_by])
    
    __table_args__ = (
        # One wrapped copy per (vault, user, DEK epoch). Widened from (vault, user) so a
        # member can hold a row per epoch they still need after a forward-only rekey.
        UniqueConstraint('vault_id', 'user_id', 'key_version', name='uq_vault_member_key_version'),
        Index('idx_vault_member_key_vault', 'vault_id'),
        Index('idx_vault_member_key_user', 'user_id'),
        Index('idx_vault_member_key_active', 'vault_id', 'user_id', 'key_version', 'is_active'),
    )


class ChunkedUploadSession(Base):
    """
    Manages chunked file uploads for large files.
    Tracks upload progress and allows resumption on failure.
    """
    __tablename__ = 'chunked_upload_sessions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # File metadata. filename/mime_type are the PLAINTEXT name (Standard vaults + the
    # transient working state of a normal upload). For ZERO-KNOWLEDGE uploads they are
    # NULL — the server must never see the plaintext name; the client sends the encrypted
    # name in enc_name/enc_mime (+ the client blind index name_bi) instead.
    filename = Column(String(255), nullable=True)
    total_size = Column(BigInteger, nullable=False)
    mime_type = Column(String(255), nullable=True)

    # Zero-knowledge only: the browser-encrypted name/MIME (security.ZK_NAME_PREFIX +
    # base64) and the client-computed blind index, carried from init through to finalize
    # where they are stamped onto the File. NULL for Standard vaults / legacy clients.
    enc_name = Column(Text, nullable=True)
    enc_mime = Column(Text, nullable=True)
    name_bi = Column(String(64), nullable=True)
    
    # Upload progress
    chunks_received = Column(Integer, default=0)
    total_chunks = Column(Integer, nullable=False)
    bytes_received = Column(BigInteger, default=0)
    
    # Temporary storage
    temp_file_path = Column(Text, nullable=True)  # Path to temporary file during upload

    # Destination folder (persisted so a resumed session targets the right place)
    folder_id = Column(UUID(as_uuid=True), nullable=True)

    # Zero-knowledge upload only: the DEK epoch the client encrypted this file under
    # (declared at init). At finalize we reject (409) if it no longer matches the vault's
    # current dek_version — i.e. the vault was re-keyed mid-upload — so a stale-epoch file
    # (readable by a just-revoked member who kept the old DEK) can never be committed. NULL
    # for Standard vaults and legacy clients.
    zk_key_version = Column(Integer, nullable=True)

    # Session management
    created_at = Column(DateTime, default=datetime.utcnow)
    last_chunk_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # Auto-cleanup after 24 hours
    completed_at = Column(DateTime, nullable=True)
    
    # Status
    status = Column(String(20), default='active')  # active, completed, failed, expired
    error_message = Column(Text, nullable=True)
    
    # Final file ID after completion
    file_id = Column(UUID(as_uuid=True), ForeignKey('files.id', ondelete='SET NULL'), nullable=True)
    
    # Relationships
    vault = relationship('Vault', foreign_keys=[vault_id])
    user = relationship('User', foreign_keys=[user_id])
    file = relationship('File', foreign_keys=[file_id])
    
    __table_args__ = (
        Index('idx_chunked_upload_vault', 'vault_id'),
        Index('idx_chunked_upload_user', 'user_id'),
        Index('idx_chunked_upload_status', 'status', 'expires_at'),
    )
