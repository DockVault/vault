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
    Text, BigInteger, LargeBinary, Enum, Table, JSON, Index, CheckConstraint, UniqueConstraint, text
)
from sqlalchemy.orm import relationship, declarative_base, backref
from sqlalchemy.dialects.postgresql import UUID, JSONB

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


# When each user last OPENED each vault, so the list can be ordered by "last viewed by me".
#
# Deliberately separate from Vault.last_accessed, which is one column recording the last access by
# ANYONE. On a shared vault that is a different question with a different answer, and it cannot
# express "the one I looked at yesterday" for the person asking.
#
# A whole new TABLE rather than a column on vaults, because init_db() only runs create_all(), which
# creates missing tables but never ALTERs existing ones — so a new table migrates onto an
# already-deployed vault for free, whereas a new column would need a hand-written ALTER.
#
# Rows are personal data about one user's activity: every read is filtered to the requesting user,
# and both foreign keys cascade so deleting either the user or the vault takes the history with it.
vault_views = Table(
    'vault_views',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('vault_id', UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), primary_key=True),
    Column('viewed_at', DateTime, nullable=False, default=datetime.utcnow),
)



class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    # Optional: an account may have no email at all. Uniqueness stays case-insensitive via the
    # lower(email) index built at boot; NULLs are distinct under UNIQUE, so any number of
    # email-less accounts coexist. See app/core/email_identity.py.
    email = Column(String(255), unique=True, nullable=True, index=True)
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

    # Per-account storage budget, in bytes, spent by ALLOCATING storage to vaults (see
    # VaultStorageGrant) rather than by storing files. Tri-state: NULL inherits the deployment
    # default (the 'default_user_quota' setting), -1 exempts the account, and any other value
    # >= 0 is an exact budget. Admin-settable per account so one user can be given more (or
    # less) room than the deployment default without moving the default for everyone.
    storage_quota_bytes = Column(BigInteger, nullable=True)

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
    # only. Redemption (at the vault-access chokepoint) enforces expiry + max_uses and rate-limits like the password.
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


class ShareTag(Base):
    """Admin-owned share classification + policy — the spine of the Sharing feature.

    One row per tag (e.g. Confidential / Internal / Temporary). Carries the POLICY a share minted under
    it inherits (lifetime ceiling/default, recipient/download caps + defaults, allowed audiences,
    view-only, whether a creator may customize within caps) AND a CREATE-ALLOWLIST governing who may
    create shares with it. Soft-deactivated (is_active=False), never hard-deleted while shares reference
    it — deactivating stops NEW creates; existing shares run out their snapshot. A WHOLE NEW TABLE (not
    columns on an existing one) so init_db()'s create_all() migrates it cleanly onto already-deployed
    vaults (create_all never ALTERs). The create-allowlist is evaluated LIVE (never snapshotted); the
    limit/policy fields are snapshotted onto each Share at creation (see app/core/sharing_policy.py).
    """
    __tablename__ = 'share_tags'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(120), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    color = Column(String(20), nullable=True)  # optional accent tag, e.g. 'indigo'
    is_active = Column(Boolean, nullable=False, default=True)

    # --- Policy (snapshotted onto a Share at creation; editing a tag does NOT change existing shares) ---
    # Lifetime is admin-bounded with NO app cap (may be years); hard floor 1 minute (sharing_policy.MIN_LIFETIME_MINUTES).
    max_lifetime_minutes = Column(Integer, nullable=False, default=10080)     # ceiling (default 7 days)
    default_lifetime_minutes = Column(Integer, nullable=False, default=1440)  # default (1 day)
    # NULL cap / NULL default = unlimited on that axis (within the tag). A default may not exceed its cap.
    max_recipients_cap = Column(Integer, nullable=True)
    max_recipients_default = Column(Integer, nullable=True)
    max_downloads_cap = Column(Integer, nullable=True)
    max_downloads_default = Column(Integer, nullable=True)
    allow_view_only = Column(Boolean, nullable=False, default=True)   # may a creator CHOOSE view-only?
    default_view_only = Column(Boolean, nullable=False, default=False)  # is view-only the default (overridable)?
    # force_view_only MANDATES view-only on every share minted under this tag, regardless of the creator's
    # request or allow_custom — so an admin can require non-download while still letting creators customize
    # the other limits (lifetime/recipients/downloads). Distinct from default_view_only (a mere default).
    force_view_only = Column(Boolean, nullable=False, default=False)
    allow_custom = Column(Boolean, nullable=False, default=True)  # may a creator override defaults within caps?
    # Subset of sharing_policy.AUDIENCES the creator may pick for a share's claim-audience.
    allowed_audiences = Column(JSON, nullable=False, default=list)

    # --- Create-allowlist (evaluated LIVE, never snapshotted): who may create a share with this tag ---
    allowed_department_ids = Column(JSON, nullable=False, default=list)  # group ids (str)
    allowed_user_ids = Column(JSON, nullable=False, default=list)        # user ids (str)
    blocked_user_ids = Column(JSON, nullable=False, default=list)        # user ids (str) — the blocklist wins
    auto_enroll_new_users = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    __table_args__ = (
        Index('idx_share_tag_active', 'is_active'),
    )


class Share(Base):
    """One shared item — a file, a folder (recursively), or a whole Standard vault — granted to
    authorized, logged-in internal users and classified by a ShareTag. The tag's LIMIT policy is
    SNAPSHOTTED here at creation (editing the tag later never changes an existing share); the tag's
    create-allowlist and any revoke stay LIVE. New table (created by create_all). Standard vaults only
    (never zero-knowledge); a password-protected vault is refused at create. The link token is stored
    HASHED (a bearer secret) and the plaintext is shown once at create."""
    __tablename__ = 'shares'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    creator_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    # RESTRICT: a tag can't be hard-deleted while shares reference it (tags soft-deactivate instead).
    tag_id = Column(UUID(as_uuid=True), ForeignKey('share_tags.id', ondelete='RESTRICT'), nullable=False)

    target_type = Column(String(10), nullable=False)  # 'vault' | 'folder' | 'file'
    target_folder_id = Column(UUID(as_uuid=True), ForeignKey('folders.id', ondelete='CASCADE'), nullable=True)
    target_file_id = Column(UUID(as_uuid=True), ForeignKey('files.id', ondelete='CASCADE'), nullable=True)

    # --- Distribution ---
    link_token_hash = Column(String(64), nullable=True)  # sha256 hex of the bearer link token; NULL = direct-only
    claim_audience = Column(String(20), nullable=False)  # 'users' | 'departments' | 'anyone_internal'
    # JSONB (not JSON) so the "shared with me" scan can filter server-side with @> containment and be
    # GIN-indexed (below), instead of fetching every active named-audience share and filtering in Python.
    audience_user_ids = Column(JSONB, nullable=False, default=list)       # only for claim_audience 'users'
    audience_department_ids = Column(JSONB, nullable=False, default=list)  # only for claim_audience 'departments'

    # --- Limits (SNAPSHOT at creation) ---
    expires_at = Column(DateTime, nullable=False)
    max_recipients = Column(Integer, nullable=True)  # NULL = unlimited (within the tag cap at create)
    max_downloads = Column(Integer, nullable=True)   # NULL = unlimited (within the tag cap at create)
    view_only = Column(Boolean, nullable=False, default=False)  # capability: view-only vs read+download
    tag_policy_snapshot = Column(JSON, nullable=True)  # the tag's limit fields at creation (provenance)

    # --- State ---
    status = Column(String(10), nullable=False, default='active')  # 'active' | 'revoked' | 'expired'
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_share_creator', 'creator_id'),
        Index('idx_share_vault', 'vault_id'),
        Index('idx_share_token', 'link_token_hash'),
        # GIN indexes for the JSONB @> containment used by the direct-push "shared with me" scan.
        Index('idx_share_aud_users', 'audience_user_ids', postgresql_using='gin'),
        Index('idx_share_aud_depts', 'audience_department_ids', postgresql_using='gin'),
    )


class ShareClaim(Base):
    """One claimant of a Share (one row per distinct claiming user, created at claim time). Enforces
    max_recipients (# active rows) and carries the per-recipient download counter + the single-recipient
    kick. Unique per (share, user)."""
    __tablename__ = 'share_claims'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    share_id = Column(UUID(as_uuid=True), ForeignKey('shares.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    claimed_at = Column(DateTime, default=datetime.utcnow)
    last_access_at = Column(DateTime, nullable=True)
    download_count = Column(Integer, nullable=False, default=0)
    revoked = Column(Boolean, nullable=False, default=False)  # single-recipient kick

    __table_args__ = (
        UniqueConstraint('share_id', 'user_id', name='uq_share_claim_user'),
        Index('idx_share_claim_share', 'share_id'),
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
    # only public keys + opaque wraps and can never reconstruct the team private key.
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
    # Stamped at creation and never incremented: the rotate-key route refuses, and no content codec reads this;
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
    # 'zero_knowledge' (browser-side crypto, web-only because SFTP has no browser-held
    # decryption keys) slots in later. Defaulting every vault to
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


class VaultStorageGrant(Base):
    """One person's storage allocation to one vault — the ledger behind Vault.size_limit.

    A vault's size limit is not a number somebody typed; it is the SUM of the allocations its
    owner and managers have made out of their own account budgets. Keeping the contributions
    itemised is what makes a SHARED vault work: if two managers each add 5 GB to a 1 GB vault,
    the vault holds 11 GB and each of them can later reclaim exactly the 5 GB they put in —
    never the other's, and never more than they gave.

    INVARIANT: for every active vault, SUM(granted_bytes) == vaults.size_limit. Writes go
    through the storage-allocation helpers in the API so the two can never drift; an existing
    deployment is backfilled with a single owner-held grant for each vault it already has.
    """
    __tablename__ = 'vault_storage_grants'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    # CASCADE on the user too: deleting an account removes its rows. The vault's size_limit is
    # NOT lowered to match — the next read repairs the ledger by attributing the now-unexplained
    # difference to the owner, so a departing contributor never shrinks a vault out from under
    # files already stored in it.
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    granted_bytes = Column(BigInteger, nullable=False, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vault = relationship('Vault', foreign_keys=[vault_id])
    user = relationship('User', foreign_keys=[user_id])

    __table_args__ = (
        # One row per (vault, contributor): the allocation is absolute, so a concurrent
        # double-write updates the same row instead of creating divergent duplicates that the
        # SUM would then count twice.
        UniqueConstraint('vault_id', 'user_id', name='uq_vault_storage_grant_vault_user'),
        Index('idx_vault_storage_grant_vault', 'vault_id'),
        Index('idx_vault_storage_grant_user', 'user_id'),
        # No negative contributions: a would-be reclaim past zero must be rejected by the API,
        # and the database refuses to store the result if that check is ever bypassed.
        CheckConstraint('granted_bytes >= 0', name='ck_vault_storage_grant_non_negative'),
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
    # Which temporary credential performed this, when one did. `username` is the ACCOUNT's,
    # because a temp session is the account -- so without this column the audit trail cannot
    # answer "what did the credential I handed that contractor actually do?", and anything it
    # did wrong is recorded under the account owner's name.
    temp_credential_id = Column(UUID(as_uuid=True), nullable=True)
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


class EmailChangeCode(Base):
    """Single-use, short-lived proof that a user controls a NEW email address.

    Only a peppered HMAC-SHA256 hash of the emailed code is stored; the plaintext reaches only the
    new address, by email. The account's email is not touched until the code is confirmed. A whole
    new table — created by create_all(), so it needs no lightweight-migration entry.
    """
    __tablename__ = 'email_change_codes'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'),
                     nullable=False, index=True)
    new_email = Column(String(255), nullable=False)                        # the pending address
    code_hash = Column(String(64), unique=True, nullable=False, index=True)  # HMAC-SHA256 hex
    expires_at = Column(DateTime, nullable=False)                          # short-lived
    consumed_at = Column(DateTime, nullable=True)                          # single-use: set on redeem
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_emailchangecode_user', 'user_id'),
    )


class OtpCode(Base):
    """Durable fallback store for the generalized one-time-code (OTP) service.

    OTPs live in Redis first (fast, auto-expiring); a row is written here only when Redis is
    unavailable at issue time, and verify consults both stores. A row is bound to one (purpose,
    user_id) — a new issue for that pair invalidates any prior row — and carries the action's
    destination (e.g. a pending new email) so a code can't be redeemed for a different target. Only a
    peppered HMAC-SHA256 hash of the code is stored, never the plaintext. Single-use (consumed_at) with
    a 3-strike attempt counter. A WHOLE NEW TABLE — created by create_all(), so it needs no
    lightweight-migration entry (create_all builds it on already-deployed vaults). This supersedes
    email_change_codes (kept for now, but no longer written)."""
    __tablename__ = 'otp_codes'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    purpose = Column(String(64), nullable=False)                           # e.g. 'email_change'
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'),
                     nullable=False, index=True)
    destination = Column(String(255), nullable=True)                       # e.g. the pending new email
    code_hash = Column(String(64), nullable=False)                         # peppered HMAC-SHA256 hex
    attempts = Column(Integer, nullable=False, default=0)                  # wrong-guess counter
    max_attempts = Column(Integer, nullable=False, default=3)             # invalidate after this many
    expires_at = Column(DateTime, nullable=False)
    consumed_at = Column(DateTime, nullable=True)                          # single-use: set on redeem
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_otpcode_purpose_user', 'purpose', 'user_id'),
    )


class AccountInvitation(Base):
    """Admin-minted account invitation.

    An admin invites someone by username (email optional per org policy); the plaintext invite link
    is shown ONCE at mint and only its peppered HMAC-SHA256 hash is stored — the log-pull token
    discipline. A whole new table — created by create_all(), so it needs no lightweight-migration
    entry. Status is DERIVED from the three lifecycle timestamps (revoked / accepted / expired /
    pending), so there is no redundant status column to keep in sync. Acceptance (stamping
    accepted_at / accepted_user_id) is a later phase; the columns exist here so it needs no schema
    change.
    """
    __tablename__ = 'account_invitations'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), nullable=False)                        # pre-assigned; schema validates 3..50
    email = Column(String(255), nullable=True)                           # required only when policy demands it
    role = Column(String(20), nullable=False, default='user')            # a validated RoleEnum value

    token_prefix = Column(String(16), nullable=False, index=True)        # public lookup handle (plaintext[:12])
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # HMAC-SHA256 hex

    expires_at = Column(DateTime, nullable=False)                        # naive UTC
    accepted_at = Column(DateTime, nullable=True)                        # set at acceptance (later phase)
    accepted_user_id = Column(UUID(as_uuid=True),
                              ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    revoked_at = Column(DateTime, nullable=True)                         # soft revoke

    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True),
                        ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    __table_args__ = (
        Index('idx_account_invitation_prefix', 'token_prefix'),
        Index('idx_account_invitation_username', 'username'),
    )


class Notification(Base):
    """Per-user in-app notification (the bell + the Dashboard "What's waiting for you" lane).

    A WHOLE NEW TABLE (not columns on an existing one) so init_db()'s create_all() builds it cleanly
    on already-deployed vaults (create_all never ALTERs) — needs no lightweight-migration entry. Rows
    are personal data about ONE user; every read/write MUST be filtered to the requesting user, and
    the user_id FK cascades so deleting a user takes their notifications with it.

    `dedup_key` is an optional idempotency handle: Postgres treats NULLs as DISTINCT under a UNIQUE
    constraint, so un-keyed notifications (e.g. each temp-credential login) coexist freely while keyed
    ones (e.g. one 'share_received' per share per recipient) are deduplicated — a retry can't double
    a notification. `target` is an optional in-app deep link the bell/lane row navigates to.
    """
    __tablename__ = 'notifications'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # No standalone index=True here: the composite idx_notification_user_created below leads with
    # user_id, so a separate single-column index would be redundant write overhead.
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    type = Column(String(50), nullable=False)          # e.g. 'share_received', 'temp_login'
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=True)
    target = Column(String(500), nullable=True)         # optional in-app deep link (NULL = none)
    is_read = Column(Boolean, nullable=False, default=False)
    dedup_key = Column(String(255), nullable=True)      # optional idempotency handle (NULLs distinct)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    read_at = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint('user_id', 'dedup_key', name='uq_notification_user_dedup'),
        Index('idx_notification_user_created', 'user_id', 'created_at'),
        Index('idx_notification_user_unread', 'user_id', 'is_read'),
    )


class Note(Base):
    """A personal note (title + free text), owned by ONE account.

    A WHOLE NEW TABLE, so init_db()'s create_all() builds it on already-deployed vaults without a
    lightweight-migration entry (create_all never ALTERs). Notes are Standard/server-side (Q1 = a):
    the server can read them; "hidden" is a UI privacy mask, not encryption. Every read/write MUST be
    filtered to the requesting account (owner_id), and the FK cascades so deleting a user takes their
    notes with it.

    "Send note" is a SNAPSHOT COPY, never a live share (Q2b): sending note N to user B inserts a NEW
    row owned by B with sent_from_user_id/-_name set and adopted=False — it appears in B's "sent to
    me" list. B may edit their copy freely (it is theirs) and "add to my notes" flips adopted=True so
    it joins B's own notes. No cascade, no revoke: the sender's later edits never touch B's copy.
    """
    __tablename__ = 'notes'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    title = Column(String(255), nullable=False, default='')
    body = Column(Text, nullable=False, default='')
    is_favorite = Column(Boolean, nullable=False, default=False)
    # A received copy carries who sent it; a self-authored note leaves these NULL. sent_from_user_id
    # SET NULL on the sender's deletion keeps the recipient's copy (only the attribution is lost).
    sent_from_user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'),
                               nullable=True)
    sent_from_name = Column(String(255), nullable=True)
    # False on a freshly-received copy (shows under "sent to me"); True once the recipient adopts it
    # (or always True for a self-authored note). "My notes" = adopted rows; "sent to me" = the rest.
    adopted = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_note_owner_adopted', 'owner_id', 'adopted'),
    )


class NoteLinkTag(Base):
    """Admin-owned policy template for a PUBLIC note link ("Links" feature).

    A tag is a security FLOOR: a user creating a public link with it may only TIGHTEN each axis
    (longer token, sooner expiry, fewer uses, add a secret) — never loosen it (a tag that requires a
    password can't have it removed). Public note links are anonymous, so the tag governs how hard the
    link is to reach. A WHOLE NEW TABLE, created by create_all (additive; no migration). The
    create-allowlist mirrors ShareTag and is evaluated LIVE via sharing_policy.user_can_create_with_tag.
    """
    __tablename__ = 'note_link_tags'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(120), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    # Presentation for the "Shared (by me)" tiles.
    border_color = Column(String(20), nullable=True)   # e.g. 'indigo' / a hex
    icon = Column(String(40), nullable=True)           # an i-* icon name

    # --- Link policy (the FLOOR) ---
    # Token length: floor on the URL id. 6 is the "easy" minimum; the default tier uses 10-12.
    min_token_len = Column(Integer, nullable=False, default=10)
    # Expiry ceiling/default in hours. NULL default_ttl = no default expiry; NULL max_ttl = no ceiling.
    default_ttl_hours = Column(Integer, nullable=True)
    max_ttl_hours = Column(Integer, nullable=True)
    # Secret requirement: 'none' (user MAY add one), 'pin', or 'password' (mandated — user can't remove).
    require_secret = Column(String(16), nullable=False, default='none')
    min_pin_len = Column(Integer, nullable=False, default=4)          # 4 | 6 | 8
    password_min_len = Column(Integer, nullable=False, default=8)
    password_require_alnum = Column(Boolean, nullable=False, default=False)
    # Max redemptions cap. NULL = unlimited (within the tag).
    max_uses_cap = Column(Integer, nullable=True)

    # --- Create-allowlist (LIVE; who may create a public link with this tag) — mirrors ShareTag ---
    allowed_department_ids = Column(JSON, nullable=False, default=list)
    allowed_user_ids = Column(JSON, nullable=False, default=list)
    blocked_user_ids = Column(JSON, nullable=False, default=list)
    auto_enroll_new_users = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)


class NoteLink(Base):
    """A PUBLIC, anonymous, tokenized SNAPSHOT of one note ("Links" feature).

    The platform's first anonymous read path. Reachable by anyone holding the token (no login),
    optionally behind a PIN/password, so the title/body are FROZEN at creation (title_snapshot/
    body_snapshot) — the link never reflects later edits to the source note, and revoking/deleting
    the note leaves the snapshot intact. Notes are Standard/server-side, so the server renders the
    snapshot directly (never a ZK vault). The effective policy is resolved at creation from the
    NoteLinkTag floor + the owner's tightening (note_link_policy.resolve_link_policy) and PERSISTED
    here, so a later tag edit/delete never changes an existing link. A whole new table, created by
    create_all (additive; no migration).
    """
    __tablename__ = 'note_public_links'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    # The tag it was created under (for the "Shared (by me)" tile colour/icon). SET NULL so an admin
    # can delete a tag without destroying links — the frozen policy below still governs the link.
    tag_id = Column(UUID(as_uuid=True), ForeignKey('note_link_tags.id', ondelete='SET NULL'), nullable=True)

    # The opaque URL id. base62, length == token_len (>= the tag's min_token_len). Unique + indexed.
    token = Column(String(64), nullable=False, unique=True, index=True)
    token_len = Column(Integer, nullable=False)

    # Frozen content snapshot.
    title_snapshot = Column(String(255), nullable=False, default='')
    body_snapshot = Column(Text, nullable=False, default='')

    # Frozen effective policy (resolved from the tag floor + owner tightening at creation).
    secret_kind = Column(String(16), nullable=False, default='none')   # none | pin | password
    password_hash = Column(String(255), nullable=True)                 # Argon2 of the PIN/password
    expires_at = Column(DateTime, nullable=True)                       # NULL = no expiry
    max_uses = Column(Integer, nullable=True)                          # NULL = unlimited

    use_count = Column(Integer, nullable=False, default=0)             # counts toward max_uses
    view_count = Column(Integer, nullable=False, default=0)            # total successful views
    last_viewed_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_note_link_owner', 'owner_id'),
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


class ECCKeyUpdateChallenge(Base):
    """A one-time proof-of-possession challenge for REPLACING the stored private-key envelope.

    Deliberately a SEPARATE table from ECCRegistrationChallenge rather than one table with a
    purpose column: a discriminator makes cross-use one query-filter bug away, whereas two tables
    make a registration challenge simply unreachable from the update verifier. The key-derivation
    domain differs too, so even a misrouted row could not yield a valid MAC.

    Holds the server's EPHEMERAL private key and nonce so the update endpoint can verify the
    client's proof. Never a user key, never a DEK: transient, single-use and short-lived.
    See app/services/ecc_update_pop.py and docs/design/vault-private-key-update-pop-v1.md.
    """
    __tablename__ = 'ecc_key_update_challenges'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    server_private_key = Column(Text, nullable=False)  # server ephemeral PKCS8 PEM (transient)
    nonce = Column(Text, nullable=False)               # base64
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_ecc_update_challenge_user', 'user_id'),
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
    # Extra blind-index values to MATCH against for same-name detection, beyond the single
    # `name_bi` that is stored on the finished row. A zero-knowledge name index is keyed per
    # (DEK, epoch), so after a rotation an existing file's index sits at an OLD epoch that a
    # new upload's single current-epoch index cannot equal -- the clash goes unseen and the
    # replace/​reject guard silently stops firing. The client sends every epoch's candidate here
    # (and, once the vault has one, the rotation-independent index-key value); the server matches
    # the union. NULL/empty falls back to matching the single `name_bi`, so an old client is
    # unaffected. Write value vs match set are deliberately separate: this never changes what is
    # stored, only what a new upload is compared against.
    name_bi_candidates = Column(JSON, nullable=True)
    
    # Upload progress
    chunks_received = Column(Integer, default=0)
    total_chunks = Column(Integer, nullable=False)
    bytes_received = Column(BigInteger, default=0)
    
    # Temporary storage
    temp_file_path = Column(Text, nullable=True)  # Path to temporary file during upload

    # Destination folder (persisted so a resumed session targets the right place)
    folder_id = Column(UUID(as_uuid=True), nullable=True)

    # The object id the client says it encrypted against, declared when the upload starts.
    # Deliberately NOT the file_id column below: that one holds the finished File's id and
    # has a foreign key to it, so it cannot carry an id whose row does not exist yet.
    #
    # Declared at the start because the end is too late to judge. At completion the server
    # cannot distinguish a client that lost its id from an older one that never sent any, so
    # it can refuse neither without breaking the other. Recorded here, the two are different
    # sessions and only one of them is wrong.
    client_object_id = Column(UUID(as_uuid=True), nullable=True)

    # Zero-knowledge upload only: the DEK epoch the client encrypted this file under
    # (declared at init). At finalize we reject (409) if it no longer matches the vault's
    # current dek_version — i.e. the vault was re-keyed mid-upload — so a stale-epoch file
    # (readable by a just-revoked member who kept the old DEK) can never be committed. NULL
    # for Standard vaults and legacy clients.
    zk_key_version = Column(Integer, nullable=True)

    # Zero-knowledge upload only: 32 lowercase hex characters naming ONE ENCRYPTION ATTEMPT at
    # this object -- 16 random bytes the client mints when it starts encrypting, declared when
    # the session opens and compared on every resume.
    #
    # The object id above cannot do this job. It is deliberately STABLE across a resumed upload,
    # because the file's name is sealed against it, so two attempts at the same object can
    # legitimately carry the same one. Only a per-attempt value separates them -- and they have
    # to be separated, because two encryptions of one file are not interchangeable: splicing a
    # chunk of one onto a chunk of the other produces bytes that will never decrypt.
    #
    # Held as opaque text, never a UUID column. A UUID column round-trips as hyphenated ASCII,
    # which is the wrong width for a value that also has to sit in a fixed-width binary header.
    # The server never interprets it; it only ever compares it for equality.
    blob_id = Column(String(32), nullable=True)

    # WHICH principal opened this session. NULL means a person signed in directly.
    #
    # `user_id` above cannot answer that question: a temporary credential acts AS the account
    # that minted it and carries the same `user_id`, so a session was identified only by the
    # account it belonged to. Any credential holding `file.upload` on the vault could
    # therefore write into, read, or destroy an upload somebody else had started -- including
    # replacing chunks of it, after which the owner's own completion succeeds and stores a
    # file made partly of the credential's bytes.
    #
    # A credential must never match a NULL: an interactive session is not "any credential's",
    # it is nobody's but the person's.
    temp_credential_id = Column(UUID(as_uuid=True), nullable=True)

    # Session management
    created_at = Column(DateTime, default=datetime.utcnow)
    last_chunk_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # Auto-cleanup after 24 hours
    completed_at = Column(DateTime, nullable=True)
    
    # Status
    status = Column(String(20), default='active')  # active, completed, failed, expired
    error_message = Column(Text, nullable=True)
    
    # Intended to hold the finished File's id, and nothing has ever written it -- the completion
    # path returns the file rather than recording it here. Kept because its foreign key is the
    # reason it cannot serve as the declared-id column above: it can only hold an id that
    # already has a row.
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



class VaultMemberIndexKey(Base):
    """Per-member wrapped copy of a vault's NAME INDEX key.

    Same-name matching in a zero-knowledge vault runs on a blind index -- an HMAC of the filename
    that the server compares but cannot invert. That HMAC needs a key, and where the key comes from
    decides whether the guard survives a rekey.

    It used to be derived per rotation, from the DEK and the epoch. A rekey therefore changed the
    index for every name, so an upload of an existing name could no longer match the stored row:
    replace-on-clash silently stopped applying, and the check that stops an upload-only credential
    creating a hidden duplicate silently stopped rejecting. A rotation switched off a guard.

    So the index key lives here instead: minted once per vault, wrapped to each member exactly as
    the DEK is, and NOT rotated by a rekey. One equality on the server, computable by every member
    including one who joined after a rotation, and nothing to re-index when membership changes.

    Separate from VaultMemberKey on purpose. That table is keyed per DEK epoch because a member
    holds one wrapped DEK per epoch they still need; this key has no epoch, so sharing that table
    would store an identical copy against every epoch row and invite someone to rotate it in step
    with the DEK -- which is the behaviour being removed.

    `index_key_version` exists for the deliberate, opt-in "rotate name index" operation, which an
    owner runs when they want filenames created after a removal out of an ex-member's reach. It
    must never be driven by rekey: rekey is the revocation path, and coupling it to a re-index lets
    one unreadable filename block an urgent removal.

    What this gives up: a removed member keeps the key, so with database read they can CONFIRM a
    guessed filename. Not read one -- the name stays sealed under the DEK and the index is one-way.
    A held index key plus stored index values (which need database access) is a confirmation
    oracle over filenames, nothing more.
    """
    __tablename__ = 'vault_member_index_keys'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vault_id = Column(UUID(as_uuid=True), ForeignKey('vaults.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # The index key, wrapped to this member's public key. Opaque to the server, like the DEK wrap.
    encrypted_index_key = Column(Text, nullable=False)
    ephemeral_public_key = Column(Text, nullable=False)
    wrapping_algorithm = Column(String(50), default='ECDH-AES-256-GCM')

    # Bumped only by an explicit re-index, never by a DEK rekey. Defaults mirror VaultMemberKey's
    # key_version: NOT NULL with a server default, so a read path matching on it cannot be
    # silently defeated by a NULL.
    index_key_version = Column(Integer, nullable=False, default=1, server_default='1')

    granted_at = Column(DateTime, default=datetime.utcnow)
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    is_active = Column(Boolean, default=True)

    vault = relationship('Vault', foreign_keys=[vault_id])
    user = relationship('User', foreign_keys=[user_id])
    granter = relationship('User', foreign_keys=[granted_by])
    revoker = relationship('User', foreign_keys=[revoked_by])

    __table_args__ = (
        UniqueConstraint('vault_id', 'user_id', 'index_key_version',
                         name='uq_vault_member_index_key_version'),
        Index('idx_vault_member_index_key_lookup', 'vault_id', 'user_id'),
    )


class RetiredObjectId(Base):
    """Every object id that has been taken out of circulation, so it can never be re-claimed.

    A client may choose the UUID of the object it is creating. That exists for a real reason: in a
    zero-knowledge vault the browser seals the name, the MIME type and now the file content bound
    to that id BEFORE any row exists, so the id has to be known client-side first. The guard on it
    was a liveness check -- is a row holding this id right now -- and a deleted row leaves nothing
    behind, so every id a deleted object used to hold was free again.

    What that costs is rollback resistance. Deleting an object does not reliably erase its bytes:
    `secure_delete` ends in a best-effort fallback chain, and a deleted FOLDER never has its
    directory removed at all -- only `delete_vault` calls `rmtree`. So a blob can outlive its row,
    and re-claiming the id it was stored under puts an old version back where a reader will find
    it, authenticating correctly, because the transcript binds the id and not the generation.

    Three properties of this table are load-bearing, and each is a decision rather than a detail:

    **The primary key is the id alone.** Not `(vault_id, id)`. A vault-scoped key invites
    vault-scoped cleanup, and freeing a deleted vault's ids is exactly the hole this closes: the
    server never generates a zero-knowledge vault's key, it accepts a browser-supplied wrap, so
    somebody who kept the old key can recreate a vault under the same id, re-supply the same
    wrapped key, re-claim a file id and read the retained blob. `vault_id` is here for provenance
    and nothing reads it in a decision.

    **There is deliberately no foreign key.** An `ON DELETE CASCADE` back to `vaults` would erase
    precisely the records this exists to keep, and it would look like tidiness in review. The
    column is expected to go dangling; that is the point.

    **Rows arrive from database triggers, not application code.** Object rows disappear through
    many paths -- explicit deletes, same-name replacement, the expiry sweep, folder deletion, the
    startup duplicate collapse, SFTP -- and, more importantly, through `ON DELETE CASCADE`
    constraints that have no Python site to patch at all. One `AFTER DELETE` trigger per table
    catches every one of them, including the ones nobody has written yet. They are `ENABLE ALWAYS`
    so that a logical-replication apply worker or a `pg_restore --disable-triggers` cannot skip
    them.

    **What this does NOT cover, stated because the guarantee above reads as unconditional.** Ids
    retired BEFORE this shipped are not in the ledger and cannot be put there -- their rows are
    gone. Those are exactly the ids whose blobs may still be sitting at the old paths, so the
    oldest deletions are the least protected. The same is true of a database restored from a
    backup taken before this shipped, which is a realistic pairing: backups here are volume-level,
    so an old database can arrive beside a storage volume that still holds the blobs.
    """
    __tablename__ = 'retired_object_ids'

    # Kinds. Small integers rather than an enum: this table is written by SQL triggers, and a
    # trigger that has to know an enum's type name is one migration-ordering problem away from
    # failing silently.
    KIND_FILE = 1
    KIND_FOLDER = 2
    KIND_VAULT = 3

    id = Column(UUID(as_uuid=True), primary_key=True)
    kind = Column(Integer, nullable=False)
    # Provenance only, and intentionally not a foreign key -- see the class docstring. NULL for a
    # retired vault, whose own id is the primary key.
    vault_id = Column(UUID(as_uuid=True), nullable=True)
    # server_default, not just default: these rows are inserted by a database trigger, which
    # never runs Python. A column with only the SQLAlchemy-side default is NOT NULL with no
    # database default, so every trigger insert fails and -- because the insert happens inside the
    # DELETE -- takes the delete down with it. create_all builds this table from the model on a
    # fresh database, so the model is where the default has to be.
    spent_at = Column(DateTime, nullable=False,
                      server_default=text("(now() AT TIME ZONE 'utc')"),
                      default=datetime.utcnow)

    __table_args__ = (
        # Not on `id`: that is the primary key already. This one is for the operator question
        # "what did this vault retire", which is the only non-lookup use.
        Index('idx_retired_object_vault', 'vault_id'),
    )


class SchemaStep(Base):
    """The outcome of every boot-time DDL statement, so an incomplete schema can be reported.

    There is no migration framework here, and that is a deliberate choice: a list of idempotent DDL
    statements is replayed on every boot, each wrapped so one failure cannot stop the rest. A step
    that does not apply is usually one that already applied, and refusing to boot over it would
    strand a self-hosted vault in the middle of an unattended update.

    What was missing is any trace of a failure that was NOT benign. The step printed and the boot
    carried on, so `/health` had nothing to consult, the container healthcheck reported well, and
    the tool that waits on it agreed -- while the first real sign of trouble was a 500 from
    whichever endpoint needed the column that never arrived. This table is that trace.

    **Keyed by a hash of the statement, not by its position.** An index would shift whenever a
    statement was inserted above, silently reattributing one step's outcome to another. Hashing the
    text means an edited statement is a NEW step, which is the right reading: a statement that was
    changed after failing is not the statement that failed.

    **Rows for statements no longer in the list are deleted on each boot.** Otherwise a step that
    failed, and was then fixed by editing its SQL, would leave its old row behind reporting failure
    forever, and health would never recover. The table describes the CURRENT list and nothing else.

    `detail` holds the database's error message for an operator reading this table directly. It is
    deliberately not surfaced by `/health`, which is unauthenticated and says only that the schema
    is incomplete.
    """
    __tablename__ = 'schema_steps'

    # Applied cleanly, or already in place -- both indistinguishable and both fine.
    OUTCOME_APPLIED = 'applied'
    # Raised, and nothing else is known. This is what makes a deployment unhealthy.
    OUTCOME_FAILED = 'failed'
    # Deliberately not applied, because a precondition in the data says it cannot be. Visible in
    # health, but not a failure: the code chose this over refusing to boot.
    OUTCOME_SKIPPED = 'skipped'

    step_id = Column(String(32), primary_key=True)
    # First line of the statement, for an operator scanning the table. Truncated: some statements
    # are whole DO blocks.
    summary = Column(String(200), nullable=False)
    outcome = Column(String(16), nullable=False)
    detail = Column(Text, nullable=True)
    # The version that last ran this step, so "when did this deployment last get this right" is
    # answerable without correlating logs.
    app_version = Column(String(32), nullable=True)
    recorded_at = Column(DateTime, nullable=False,
                         server_default=text("(now() AT TIME ZONE 'utc')"),
                         default=datetime.utcnow)

    __table_args__ = (
        # The only question health asks: is anything currently failed.
        Index('idx_schema_steps_outcome', 'outcome'),
    )


# ============================================================================
# Email Studio (admin-authored SMTP profiles, HTML templates, image resources)
# ============================================================================
#
# Three WHOLE NEW tables, deliberately (mirrors UserPreference's reasoning): init_db() only runs
# create_all(), which creates missing tables but never ALTERs existing ones, so new tables migrate
# cleanly onto already-deployed vaults.
#
# NOTE: as of this change the vault's own system mail (email-change verification) still reads the
# legacy single SMTP config in SystemSetting('global'); it is NOT yet repointed at EmailProfile.
# The follow-up that adds the profiles API also seeds a default EmailProfile from that legacy
# config and switches the system-mail path over — until then there is intentionally no default
# profile row, and nothing here depends on one.

class EmailProfile(Base):
    """One SMTP sender identity: server/credentials + a From address the admin can name.

    ``smtp_password`` is write-only at the API boundary (never returned by any GET; an update that
    omits it keeps the stored value), matching the existing settings behavior. Exactly one profile
    may be ``is_default`` — the one the vault's own system mail (email-change verification) uses.
    """
    __tablename__ = 'email_profiles'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(120), nullable=False)
    description = Column(String(255), nullable=True)
    smtp_server = Column(String(255), nullable=False, default='')
    smtp_port = Column(Integer, nullable=False, default=587)
    smtp_username = Column(String(255), nullable=True)
    # Write-only at the API boundary (never emitted to a client) AND encrypted at rest with the
    # deployment Fernet key (security.encrypt_secret/decrypt_secret); a legacy plaintext value is read
    # transparently and re-encrypted on the next save.
    smtp_password = Column(Text, nullable=True)
    # Opt out of SMTP TLS certificate verification for THIS profile only (e.g. an internal relay with
    # a self-signed cert). Default False = verify. When True, SMTP_SSL/STARTTLS accept any server cert.
    smtp_allow_insecure_tls = Column(Boolean, nullable=False, default=False)
    from_email = Column(String(255), nullable=False, default='')
    from_name = Column(String(120), nullable=True)
    is_default = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False,
                        server_default=text("(now() AT TIME ZONE 'utc')"),
                        default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False,
                        server_default=text("(now() AT TIME ZONE 'utc')"),
                        default=datetime.utcnow, onupdate=datetime.utcnow)

    templates = relationship("EmailTemplate", back_populates="profile", passive_deletes=True)

    __table_args__ = (
        # At most one default profile, enforced at the schema level by a PARTIAL unique index over
        # the rows where is_default is true (the same create_all-portable pattern this file already
        # uses for the case-insensitive name/email uniqueness above). The application write path
        # still clear-then-sets within one transaction, but the DB is the backstop against a concurrent
        # or buggy writer creating two defaults — so "the default profile" is always well-defined.
        Index('idx_email_profile_default', 'is_default',
              unique=True, postgresql_where=text('is_default')),
    )


class EmailTemplate(Base):
    """An admin-authored HTML email: a subject + a sanitized body, sent through a chosen profile.

    ``body_html`` is ALWAYS the output of email_sanitize.sanitize_email_html — nothing else is ever
    persisted here. Images inside it are referenced only by ``<img data-resource-id="UUID">``.
    """
    __tablename__ = 'email_templates'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(120), nullable=False)
    description = Column(String(255), nullable=True)
    profile_id = Column(UUID(as_uuid=True),
                        ForeignKey('email_profiles.id', ondelete='SET NULL'), nullable=True)
    subject = Column(String(255), nullable=False, default='')
    body_html = Column(Text, nullable=False, default='')
    # NULL for a user-authored template; set to the action key (e.g. 'password_reset') for a built-in
    # default template seeded at boot. A seeded default is protected from deletion and badged "Default";
    # editing it customizes it, and "Load From" restores the code default. Additive column: create_all
    # builds it on a fresh DB, the boot DDL list ADDs it on an existing one. At most one row per key,
    # enforced by the partial unique index below (Postgres treats NULLs as distinct, so user templates
    # are unconstrained) — a hard backstop against a concurrent first-boot seeding two defaults for a key.
    default_key = Column(String(64), nullable=True)
    created_by = Column(UUID(as_uuid=True),
                        ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    updated_by = Column(UUID(as_uuid=True),
                        ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = Column(DateTime, nullable=False,
                        server_default=text("(now() AT TIME ZONE 'utc')"),
                        default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False,
                        server_default=text("(now() AT TIME ZONE 'utc')"),
                        default=datetime.utcnow, onupdate=datetime.utcnow)

    profile = relationship("EmailProfile", back_populates="templates")

    __table_args__ = (
        Index('idx_email_template_profile', 'profile_id'),
        # One default template per action key. Partial (NULLs excluded) so user templates — the vast
        # majority — carry no uniqueness constraint. Same create_all-portable pattern as the
        # email_profiles single-default index above.
        Index('idx_email_template_default_key', 'default_key',
              unique=True, postgresql_where=text('default_key IS NOT NULL')),
    )


class EmailResource(Base):
    """A private image/GIF an admin uploads once and embeds in templates by its UUID.

    The bytes live IN THE DATABASE (not on disk) so there is no filesystem path to leak; the UUID
    primary key IS the only reference used anywhere. Served solely through an admin-gated endpoint,
    and embedded in outgoing mail as an inline ``cid:`` part — never as a URL back to the vault.
    """
    __tablename__ = 'email_resources'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String(255), nullable=False, default='')
    content_type = Column(String(100), nullable=False)
    byte_size = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=True)
    data = Column(LargeBinary, nullable=False)
    uploaded_by = Column(UUID(as_uuid=True),
                         ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = Column(DateTime, nullable=False,
                        server_default=text("(now() AT TIME ZONE 'utc')"),
                        default=datetime.utcnow)

    __table_args__ = (
        Index('idx_email_resource_created', 'created_at'),
    )


class EmailAction(Base):
    """A cataloged case where the vault sends an email (e.g. a password reset, an account invitation,
    or an optional "notify on share" event), associated with the template used for it.

    The catalog is SEEDED (never created/deleted through the API): ``key`` is a stable identifier the
    application code references. A ``system`` action is one the vault must be able to send (its bound
    template can't be removed and it's always on); an ``optional`` action is opt-in per admin via
    ``enabled`` (the "notify by email" switch a future trigger consults). Delivery and dynamic-token
    injection stay central — a trigger only calls the shared send helper with the action key.

    This is a NEW table, so create_all() adds it cleanly on an existing deployment.
    """
    __tablename__ = 'email_actions'

    key = Column(String(64), primary_key=True)          # stable code identifier, e.g. 'password_reset'
    name = Column(String(120), nullable=False)
    description = Column(String(500), nullable=False, default='')
    category = Column(String(16), nullable=False, default='optional')   # 'system' | 'optional'
    template_id = Column(UUID(as_uuid=True),
                         ForeignKey('email_templates.id', ondelete='SET NULL'), nullable=True)
    enabled = Column(Boolean, nullable=False, default=False)             # optional actions: the notify switch
    updated_at = Column(DateTime, nullable=False,
                        server_default=text("(now() AT TIME ZONE 'utc')"),
                        default=datetime.utcnow, onupdate=datetime.utcnow)

    template = relationship("EmailTemplate")

    __table_args__ = (
        Index('idx_email_action_template', 'template_id'),
    )
