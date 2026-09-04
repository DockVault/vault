"""
Authentication service for managing users, sessions, and temporary credentials.
Implements secure authentication flows and session management.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import uuid
import json
import time

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, case
from sqlalchemy.dialects.postgresql import insert as pg_insert

from fastapi import HTTPException, status
from app.core.models import (
    User, TemporaryCredential, ActiveSession, AuditLog,
    RateLimitRecord, RoleEnum, Vault
)
from app.core.security import (
    hash_password, verify_password, generate_temporary_credentials,
    verify_temporary_credential, generate_session_token, vault_password_fingerprint
)
from app.core.email_identity import email_in_use, normalize_email, find_user_by_email
from app.core.session_hash_utils import hash_session_token
from app.core.database import redis_client, get_db_context
from app.core.config import settings
from app.core import rate_limit_settings


# Precomputed Argon2 hash used to equalize login timing: verifying the supplied password
# against this on the "no such user" path makes a non-existent username cost ~the same as a
# real one, closing the username-enumeration timing oracle. Computed once at import.
_DUMMY_PASSWORD_HASH = hash_password("dummy-account-do-not-use-x9Q2")


def user_reaches_active_zk_vault(db, user_id) -> bool:
    """True when a user OWNS or is a keyed MEMBER of any active zero-knowledge vault — i.e. an
    unrestricted / all-vaults temporary credential for them would put zero-knowledge content in
    scope. Used to enforce the ZK-in-scope deny policy on the mint paths that don't resolve to a
    per-vault selected list (unrestricted + all-vaults + the admin-for-user unrestricted mint)."""
    from app.core.models import Vault, VaultMemberKey
    if db.query(Vault.id).filter(
            Vault.owner_id == user_id, Vault.type == "zero_knowledge", Vault.is_active == True).first():  # noqa: E712
        return True
    member = (db.query(VaultMemberKey.id)
              .join(Vault, Vault.id == VaultMemberKey.vault_id)
              .filter(VaultMemberKey.user_id == user_id, Vault.type == "zero_knowledge",
                      Vault.is_active == True).first())  # noqa: E712
    return member is not None


# --- Token revocation denylist ---------------------------------------------
# On logout we blacklist the session token in Redis until it would expire anyway, so the
# JWT stops working IMMEDIATELY without having to validate session existence on every
# request (which would also enforce single-session-per-user — a separate, opt-in concern).
# The token is stored hashed so a Redis read can't recover a live token.
def denylist_token(session_token: str, ttl_seconds: int) -> None:
    """Revoke a session token for the remainder of its lifetime (best-effort)."""
    if not session_token:
        return
    try:
        redis_client.setex(
            f"denylist:session:{hash_session_token(session_token)}",
            max(1, int(ttl_seconds)),
            "1",
        )
    except Exception:
        pass  # best-effort: the JWT still expires on its own


def is_token_denylisted(session_token: str) -> bool:
    """True if this token was revoked (logged out). Fails OPEN on a Redis error so a Redis
    outage can't lock everyone out — the token still expires via its own JWT exp."""
    if not session_token:
        return False
    try:
        return bool(redis_client.exists(f"denylist:session:{hash_session_token(session_token)}"))
    except Exception:
        return False


# --- Account lockout (time-boxed auto-unlock) ------------------------------
def account_locked(user) -> bool:
    """Whether an account is CURRENTLY locked.

    A FAILED-LOGIN auto-lock sets locked_until in the future and expires automatically (so a
    handful of wrong passwords can't permanently DoS a known account). An ADMIN lock leaves
    locked_until NULL and stays permanent until an admin clears it. Tolerates a naive (UTC)
    locked_until column value."""
    if not getattr(user, 'is_locked', False):
        return False
    locked_until = getattr(user, 'locked_until', None)
    if locked_until is None:
        return True  # permanent (admin) lock, or auto-unlock TTL disabled
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < locked_until


def clear_account_lock(user) -> None:
    """Clear a lock + its failed-attempt counter (caller commits)."""
    user.is_locked = False
    user.failed_login_attempts = 0
    user.locked_until = None


class AuthenticationError(Exception):
    """Base exception for authentication errors."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked. Carries locked_until (None = a permanent/admin lock)."""
    def __init__(self, message: str = "Account is locked", locked_until=None):
        super().__init__(message)
        self.locked_until = locked_until


class RateLimitExceededError(AuthenticationError):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: Optional[int] = None, limit: Optional[int] = None, remaining: int = 0):
        super().__init__(message)
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining


class SessionLimitExceededError(AuthenticationError):
    """Raised when maximum active sessions reached."""
    pass


# The FIXED capability set a device sync credential carries on its one granted vault: full
# read+write file/folder sync, and nothing vault-administrative (no permissions, password, expiry,
# key-rotation, or vault-delete power). A device NEVER chooses its own caps — that would be a
# self-escalation surface — so the mint always issues exactly this set (expanded to pull in its
# prerequisite vault.see_info). It is the least privilege bidirectional sync (rclone bisync) needs:
# list + download + upload + rename + delete files, and create/delete folders.
DEVICE_SYNC_VAULT_CAPS = [
    "vault.see_files", "file.download", "file.upload",
    "file.rename", "file.delete", "folder.create", "folder.delete",
]


def _device_mint_refusal(reason: str, http_status: int = status.HTTP_403_FORBIDDEN) -> HTTPException:
    """A typed refusal from the device mint. The `reason` is the single upstream source of the
    honest state the desktop renders: 'grant-needs-reproof' (a rotation voided the proof — re-prove
    once, NEVER a hard deny and NEVER a limiter burn) and 'device-revoked'/'device-expired' are
    DISTINCT recoverable/terminal states; 'no-grant'/'vault-not-standard'/'account-inactive' are
    should-never-happen guards an honest desktop never reaches, so they need no distinct copy. No
    password is ever tested on any of these paths, so none touches the vault-password rate limiter
    and none is a 400/429."""
    return HTTPException(status_code=http_status,
                         detail={"reason": reason, "message": "Device sync credential was refused"})


class AuthService:
    """Service for authentication operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_user(
        self,
        username: str,
        email: Optional[str],
        password: str,
        role: RoleEnum = RoleEnum.USER,
        created_by: Optional[uuid.UUID] = None
    ) -> User:
        """
        Create a new user account.

        Args:
            username: Unique username
            email: User email address, or None for an account with no email. Stored canonically
                (trimmed and lowercased); uniqueness is checked case-insensitively, and any number
                of email-less accounts may coexist.
            password: Plain text password (will be hashed)
            role: User role
            created_by: UUID of user creating this account
            
        Returns:
            Created User object
            
        Raises:
            ValueError: If username or email already exists
        """
        # Username and email are checked SEPARATELY, and that is not a stylistic change. The single
        # or_(User.username == username, User.email == email) this replaces compiled to
        # `email IS NULL` whenever email was None — SQLAlchemy renders `col == None` that way — so
        # it matched the FIRST email-less row and made the SECOND email-less account impossible to
        # create, reporting the nonsensical "Email 'None' already exists".
        normalized_email = normalize_email(email)

        if self.db.query(User.id).filter(User.username == username).first():
            raise ValueError(f"Username '{username}' already exists")

        # A username that equals some account's email would be an impersonation vector the moment
        # the org sets login_identifier to 'either' (username tried first, then email). Reject it at
        # creation, unconditionally — the policy can be flipped on later, and a pre-existing
        # ambiguous username would silently become live. `email_in_use` folds both sides with the
        # database and treats an absent address as no-collision, so the raw username is the right
        # thing to pass. (The '@'-in-username reject at the schema edge already blocks a real email
        # shape; this also catches a legacy no-`@` address and is the guard that survives if that
        # edge check is ever removed.)
        if email_in_use(self.db, username):
            raise ValueError(f"Username '{username}' conflicts with an existing account's email")

        # Case-insensitive, so `BOB@x.com` cannot be registered alongside `bob@x.com`. An absent
        # address never collides: Postgres treats NULLs as distinct under UNIQUE, and the
        # application check has to agree or email-less accounts would exclude one another.
        if email_in_use(self.db, normalized_email):
            raise ValueError(f"Email '{normalized_email}' already exists")

        # Hash password
        password_hash = hash_password(password)

        # Create user, storing the canonical (trimmed, lowercased) address.
        user = User(
            username=username,
            email=normalized_email,
            password_hash=password_hash,
            role=role,
            created_by=created_by
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        return user
    
    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str,
        *,
        login_identifier: str = "username"
    ) -> Tuple[User, str]:
        """
        Authenticate a user with an identifier and password.

        Args:
            username: The submitted identifier. Despite the name it is a username, an email, or
                either, depending on `login_identifier` — the wire field is still called `username`.
            password: Plain text password
            ip_address: Client IP address
            login_identifier: Org policy for how to resolve the identifier — "username" (default,
                exact username), "email" (case-insensitive email), or "either" (username first,
                then email). Defaulted so the SFTP caller and existing tests are unaffected.

        Returns:
            Tuple of (User object, session_token)

        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
            RateLimitExceededError: If rate limit exceeded
            SessionLimitExceededError: If max sessions reached
        """
        # Check rate limit. Keyed on the RAW submitted identifier (login:{identifier}), NOT the
        # resolved username — the limiter must throttle a junk/never-resolving identifier too, and
        # keying on the resolved username would let an attacker spread attempts across the two
        # forms (username and email) of one account.
        self._check_rate_limit(username, ip_address)

        # Resolve the submitted identifier to AT MOST ONE account per org policy. This MUST return a
        # User or None and never raise or early-return: every no-match outcome — username miss,
        # email miss, ambiguous `lower(email)` collision, blank/normalized-away, or a cross-user
        # legacy ambiguity — has to fall through to the dummy-verify block below so response timing
        # and the generic 401 stay identical (the username-enumeration oracle stays closed). Exactly
        # one verify_password() fires per attempt in every mode.
        if login_identifier == "email":
            user = find_user_by_email(self.db, username)  # None on blank/miss/collision
        elif login_identifier == "either":
            user = self.db.query(User).filter(User.username == username).first()
            if user is None:
                user = find_user_by_email(self.db, username)
        else:  # "username" — exact, case-sensitive; unchanged behaviour
            user = self.db.query(User).filter(User.username == username).first()

        if not user:
            # Equalize timing with the real path so a non-existent username isn't
            # distinguishable by response time (username-enumeration oracle).
            verify_password(password, _DUMMY_PASSWORD_HASH)
            self._record_failed_login(username, ip_address)
            raise InvalidCredentialsError("Invalid username or password")
        
        # A failed-login auto-lock auto-expires (locked_until in the past) — clear it so the
        # password is verified afresh; an admin lock (locked_until NULL) stays in force.
        if user.is_locked and not account_locked(user):
            clear_account_lock(user)  # committed on success below, or re-counted on failure

        # Verify the password FIRST, before any account-state branch, so a caller who does
        # NOT present valid credentials cannot distinguish existing/active/locked/deactivated
        # accounts by response body or timing. Every non-success outcome returns the
        # SAME generic message to the caller; the specific reason stays in the audit log only.
        if not verify_password(password, user.password_hash):
            self._record_failed_login(username, ip_address, user)
            raise InvalidCredentialsError("Invalid username or password")

        # Credentials are valid — now enforce account state. (The distinct exception type is
        # for audit / internal handling; the endpoint surfaces a generic message.)
        if account_locked(user):
            raise AccountLockedError("Account is locked", locked_until=user.locked_until)
        if not user.is_active:
            raise InvalidCredentialsError("Account is not active")
        
        # Check for existing active sessions (only 1 allowed)
        self._terminate_existing_sessions(user.id)

        # Create new session with an absolute server-side lifetime. Regular logins used to store
        # expires_at = NULL, which cleanup_expired_sessions never sweeps, so abandoned rows
        # accumulated forever. This cap (31 days) sits a margin above the session_timeout maximum
        # (30 days), so the row always outlives any token it backs yet still ages out once nothing
        # renews it.
        session_expires_at = datetime.now(timezone.utc) + timedelta(days=31)
        session_token = self._create_session(user, None, ip_address, expires_at=session_expires_at)
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        user.last_login = datetime.now(timezone.utc)
        self.db.commit()
        
        return user, session_token
    
    def authenticate_temporary_credential(
        self,
        temp_username: str,
        credential: str,
        ip_address: str
    ) -> Tuple[User, str]:
        """
        Authenticate using temporary one-time credentials.
        
        Args:
            temp_username: Temporary username
            credential: One-time credential string
            ip_address: Client IP address
            
        Returns:
            Tuple of (User object, session_token)
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            RateLimitExceededError: If rate limit exceeded
            SessionLimitExceededError: If max sessions reached
        """
        # Check rate limit
        self._check_rate_limit(temp_username, ip_address)
        
        # Find temporary credential
        temp_cred = self.db.query(TemporaryCredential).filter(
            TemporaryCredential.temp_username == temp_username
        ).first()
        
        if not temp_cred:
            # Equalize timing with the real verify path so an absent temp_username isn't
            # distinguishable by response time (temp-credential-enumeration oracle). Mirrors
            # authenticate_user's dummy verify. verify_temporary_credential wraps verify_password.
            verify_temporary_credential(credential, _DUMMY_PASSWORD_HASH)
            self._record_failed_login(temp_username, ip_address)
            raise InvalidCredentialsError("Invalid temporary credentials")

        # Verify the credential FIRST, before any state branch, so a caller who does NOT present a
        # valid credential cannot distinguish a live credential from an inactive/used/expired/
        # deactivated one by response time (same discipline as authenticate_user). Every non-success
        # outcome returns the same generic message; the specific reason is for internal handling only.
        if not verify_temporary_credential(credential, temp_cred.credential_hash):
            self._record_failed_login(temp_username, ip_address)
            raise InvalidCredentialsError("Invalid temporary credentials")

        # Credential is valid — now enforce credential state.
        if not temp_cred.is_active:
            raise InvalidCredentialsError("Temporary credential is no longer active")

        if temp_cred.is_used:
            raise InvalidCredentialsError("Temporary credential has already been used")

        # Check if credential has expired. expires_at is read back from the DB as a naive datetime
        # (TIMESTAMP WITHOUT TIME ZONE), while `now` is tz-aware UTC — comparing them directly raises
        # TypeError, so treat the stored value as UTC.
        now = datetime.now(timezone.utc)
        expires_at = temp_cred.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            temp_cred.is_active = False
            self.db.commit()
            raise InvalidCredentialsError("Temporary credential has expired")

        # A temp credential also carries a stated validity window: deactivate_at (= mint + validity)
        # closes BEFORE the hard expiry expires_at (= mint + total_lifetime). It must stop
        # authenticating once that window ends. Stored naive (UTC).
        deactivate_at = temp_cred.deactivate_at
        if deactivate_at is not None:
            if deactivate_at.tzinfo is None:
                deactivate_at = deactivate_at.replace(tzinfo=timezone.utc)
            if now > deactivate_at:
                temp_cred.is_active = False
                self.db.commit()
                raise InvalidCredentialsError("Temporary credential has expired")

        # The owning account must itself be active and unlocked. Otherwise a disabled/locked
        # principal could still mint a temp session, emit a misleading login-success signal,
        # and BURN this one-time credential. Check BEFORE marking it used so a deactivated
        # owner does not consume it.
        user = temp_cred.user
        if user is None or not user.is_active or account_locked(user):
            self._record_failed_login(temp_username, ip_address)
            raise InvalidCredentialsError("Invalid temporary credentials")

        # Atomically claim the one-time credential. A conditional UPDATE guarded by
        # rowcount (UPDATE ... WHERE is_used = false) takes a row lock, so two
        # concurrent logins for the same credential are serialised at the DB: exactly
        # one flips is_used false->true and proceeds; the loser matches zero rows and
        # is rejected. This replaces the check-then-set (is_used read far above, set
        # here, committed later) that let a login racing the legitimate user obtain a
        # second live session from a single one-time credential — which also defeated
        # the single-active-session tripwire, since the whole flow gates on this claim.
        used_at = datetime.now(timezone.utc)
        claimed = self.db.query(TemporaryCredential).filter(
            TemporaryCredential.id == temp_cred.id,
            TemporaryCredential.is_used == False,  # noqa: E712
        ).update(
            {TemporaryCredential.is_used: True, TemporaryCredential.used_at: used_at},
            synchronize_session=False,
        )
        if not claimed:
            raise InvalidCredentialsError("Temporary credential has already been used")

        # Tag the principal with this credential's least-privilege scope so both
        # the web (get_current_user re-attaches on JWT replay) and SFTP paths
        # enforce it. NULL scope = legacy = unrestricted.
        from app.core.temp_scope import attach_scope
        attach_scope(self.db, user, temp_cred)

        # Check if there's already an active session for this temp credential
        existing_session = self.db.query(ActiveSession).filter(
            and_(
                ActiveSession.temp_credential_id == temp_cred.id,
                ActiveSession.is_active == True
            )
        ).first()
        
        if existing_session:
            raise SessionLimitExceededError(
                "This temporary credential already has an active session"
            )
        
        # Create new session with expiration
        session_token = self._create_session(
            user,
            temp_cred.id,
            ip_address,
            expires_at=temp_cred.expires_at
        )
        
        self.db.commit()
        
        return user, session_token
    
    def create_temporary_credential(
        self,
        user_id: uuid.UUID,
        validity_minutes: Optional[int] = None,
        total_lifetime_minutes: Optional[int] = None,
        note: Optional[str] = None,
        can_create_temp_credentials: bool = False,
        scope: Optional[dict] = None,
        vault_access_mode: str = 'selected',
        selected_vaults: Optional[list] = None,
        parent_scope: Optional[dict] = None,
        parent_vault_mode: Optional[str] = None,
        parent_vault_ids: Optional[list] = None,
        parent_vault_caps: Optional[dict] = None,
        parent_vault_scope: Optional[dict] = None,
        created_by_temp_credential_id: Optional[uuid.UUID] = None,
        created_by_user_id: Optional[uuid.UUID] = None,
        passcode_same_for_all: bool = False,
    ) -> dict:
        """
        Create temporary one-time credentials for a user.

        ⚠️ SECURITY NOTE: Password is returned ONLY ONCE in this response.
        It is hashed with bcrypt and stored as credential_hash.
        Password cannot be retrieved later (one-way hashing).

        Args:
            user_id: User UUID
            validity_minutes: Optional override for how long the credential
                stays valid before it is deactivated. Falls back to
                settings.temp_cred_validity_minutes when not provided.
            total_lifetime_minutes: Optional override for the hard expiry /
                total lifetime. Falls back to
                settings.temp_cred_total_lifetime_minutes, or to the validity
                window when only the validity is customized. Never shorter than
                the validity window.

        Returns:
            Dictionary with temporary credentials information
        """
        # Resolve the effective lifetimes, honoring caller overrides over the
        # configured defaults.
        if validity_minutes is not None and validity_minutes > 0:
            validity = validity_minutes
        else:
            validity = settings.temp_cred_validity_minutes

        if total_lifetime_minutes is not None and total_lifetime_minutes > 0:
            total_lifetime = total_lifetime_minutes
        elif validity_minutes is not None and validity_minutes > 0:
            # Caller customized the validity but not the hard expiry: match them
            # so the credential is not deleted before its validity window ends.
            total_lifetime = validity
        else:
            total_lifetime = settings.temp_cred_total_lifetime_minutes

        # The hard expiry must never precede the deactivation time.
        total_lifetime = max(total_lifetime, validity)

        # Generate credentials (16-char password, bcrypt hash)
        temp_username, credential_string, credential_hash = generate_temporary_credentials()

        # Calculate expiration times
        now = datetime.now(timezone.utc)
        deactivate_at = now + timedelta(minutes=validity)
        expires_at = now + timedelta(minutes=total_lifetime)
        
        # Resolve the least-privilege scope. None = legacy/unrestricted. When a
        # temp session delegates (parent_scope set), intersect so the child can
        # never exceed its parent.
        from app.core.temp_scope import intersect_scope, expand_vault_caps
        from app.core.id_scope import normalize_id_scope, intersect_id_scope
        from app.services.vault_service import id_ancestry
        is_delegated = parent_scope is not None
        if scope is None and not is_delegated:
            # The no-scope path is LEGACY UNRESTRICTED: the credential reaches everything the
            # minting account can. A caller that also sends a vault restriction list is contradicting
            # itself -- it asked to limit the credential to those vaults but, honored as-is, the list
            # is silently dropped (the per-vault resolve below only runs when effective_scope is not
            # None) and the caller gets a credential far broader than requested. The realistic harm
            # is a delegation surprise: handing that credential to someone else believing it is
            # vault-limited. The vault UI never produces this shape (it always sends a scope
            # alongside selected_vaults), so reject it rather than return an over-broad credential.
            if selected_vaults:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=("A vault restriction list was sent without a scope. Include a scope to "
                            "restrict the credential to those vaults, or omit the list for an "
                            "unrestricted credential."),
                )
            effective_scope = None
            mode = 'selected'
        else:
            requested = scope if scope is not None else parent_scope
            effective_scope = intersect_scope(parent_scope, requested)
            mode = 'all' if vault_access_mode == 'all' else 'selected'
            if is_delegated and parent_vault_mode == 'selected':
                mode = 'selected'  # a child cannot broaden vault access to 'all'

        # The same contradiction as the no-scope case, in its other form: 'all' vault access reaches
        # every vault the account can, so the per-vault resolve below (gated on mode == 'selected')
        # drops any supplied restriction list entirely and the credential ends up broader than the
        # list asks. The vault UI clears selected_vaults whenever the mode is 'all', so this shape
        # is API-only; reject it rather than silently ignore the restriction. (A delegated child is
        # forced to 'selected' above, so this only fires on a non-delegated all-mode mint.)
        if mode == 'all' and selected_vaults:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=("A vault restriction list was sent with all-vault access mode. Use "
                        "'selected' mode to restrict the credential to those vaults, or omit the "
                        "list for all-vault access."),
            )

        # Org policy: may a zero-knowledge vault be in a temp credential's scope at all? Read once here
        # and reused below (the selected-mode per-vault loop + the passcode block).
        from app.core import temp_passcode_policy as _tpp
        from app.core.models import SystemSetting as _PolSS
        _pol_row = self.db.query(_PolSS).filter(_PolSS.key == 'global').first()
        _pol_raw = _pol_row.value if _pol_row is not None else {}
        if not isinstance(_pol_raw, dict):
            _pol_raw = {}
        _tp_policy = _tpp.effective_policy(_pol_raw)

        # Per-user cap on ACTIVE temporary credentials (finding F-R015-006): a single account cannot
        # hold unbounded temp creds. Count only credentials that are BOTH is_active AND not yet expired
        # (expiry is lazy — is_active flips only on the next auth attempt or the cleanup sweep — so
        # counting is_active alone would over-count). expires_at is naive UTC, so compare with a naive
        # utcnow(). 0 = unlimited. An admin ACCOUNT is exempt (mirrors the vault-count / storage-budget
        # exemption). The exemption keys on the OWNING account (user_id), not on whether this is a
        # direct or a delegated mint: a temp session's child credential carries the same user_id, so an
        # admin's own delegation is exempt too, while every NON-admin account stays capped whether it
        # mints directly or through a delegated child — which is the delegation-abuse vector the finding
        # cares about (a non-admin cannot amplify past the cap by minting children).
        _max_temp = _tp_policy.get("max_temp_creds_per_user", 0)
        if _max_temp > 0:
            _owner = self.db.query(User).filter(User.id == user_id).first()
            _exempt = (_owner is not None
                       and getattr(_owner, "role", None) == RoleEnum.ADMIN)
            if not _exempt:
                _active_temp = self.db.query(TemporaryCredential).filter(
                    TemporaryCredential.user_id == user_id,
                    TemporaryCredential.is_active == True,  # noqa: E712
                    TemporaryCredential.expires_at > datetime.utcnow(),
                ).count()
                if _active_temp >= _max_temp:
                    # 409 (not 400): the request is well-formed; it conflicts with the current state
                    # (already at the active-credential cap). Matches the per-user vault-count cap so
                    # the two resource-count limits answer with the same status.
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(f"You already have the maximum of {_max_temp} active temporary "
                                f"credential(s). Revoke one, or ask an administrator to raise the limit."))

        # Resolve each selected grant before any database mutation. Every later
        # persistence decision consumes this canonical plan.
        selected_access_plans = []
        if effective_scope is not None and mode == 'selected':
            # A minter may only grant temporary access to a vault the OWNING account can itself
            # READ. Enforced per selected vault below, BEFORE the password-proof loop, so a
            # non-member can never turn that proof into a vault-password oracle (a correct password
            # would mint 200, a wrong one 400 — a boolean oracle for any vault's password, by id).
            # Resolve the owning account + a permission service once. Local import avoids an
            # import cycle with app.core.authorization.
            from app.core.authorization import PermissionService as _PermissionService
            from app.core.models import VaultPermissionEnum as _VaultPermissionEnum
            _mint_perm = _PermissionService(self.db)
            minting_user = self.db.query(User).filter(User.id == user_id).first()
            parent_ids = {str(v) for v in (parent_vault_ids or [])}
            if parent_vault_scope is not None and not isinstance(parent_vault_scope, dict):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="The parent credential has an invalid stored vault scope.",
                )
            parent_scope_map = parent_vault_scope or {}
            parent_caps_map = parent_vault_caps if isinstance(parent_vault_caps, dict) else {}
            for sv in (selected_vaults or []):
                if not isinstance(sv, dict) or not sv.get('vault_id'):
                    continue
                try:
                    vault_uuid = uuid.UUID(str(sv.get('vault_id')))
                except (ValueError, AttributeError, TypeError):
                    continue
                vid = str(vault_uuid)
                if is_delegated and parent_vault_mode == 'selected' and vid not in parent_ids:
                    continue
                vault = self.db.query(Vault).filter(Vault.id == vault_uuid).first()
                if vault is None:
                    continue
                # Membership pre-check: the owning account must be able to READ this vault. A vault
                # the account cannot read is SKIPPED — treated exactly like a nonexistent id above —
                # so this closes BOTH the mint-time vault-password oracle (for a non-member a wrong
                # OR right password never reaches the proof loop, so the response never depends on
                # it) AND any vault-existence differential (existing-but-forbidden and nonexistent
                # both simply drop out of the selection identically). allow_share stays False — a
                # read-only share is not a basis to mint SFTP/delegation credentials for the vault.
                if (minting_user is None
                        or not _mint_perm.can_access_vault(
                            minting_user, vault_uuid, _VaultPermissionEnum.READ)):
                    continue
                # Org policy may forbid a zero-knowledge vault in a temp credential's scope
                # entirely (a scoped ZK cred still forces the holder to enter the account master
                # passphrase). This is the SINGLE enforcement point for selected grants, so
                # self-service and delegated-child mints both honor it before anything is
                # persisted. The admin-for-user path (no scope) is guarded at its own endpoint,
                # and the unrestricted/all-vaults path is guarded just below.
                if (
                    not _tp_policy['temp_cred_allow_zk_vaults']
                    and getattr(vault, 'type', 'standard') == 'zero_knowledge'
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=("Zero-knowledge vaults can't be included in a temporary "
                                f"credential by organization policy (vault '{vault.name}')."),
                    )

                raw_scope_ids = sv.get('scope_ids')
                if raw_scope_ids is not None and not isinstance(raw_scope_ids, dict):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="scope_ids must be null or an object.",
                    )
                scope_ids = normalize_id_scope(raw_scope_ids)
                caps = expand_vault_caps(sv.get('caps') or [])
                if is_delegated:
                    if parent_vault_mode == 'all':
                        parent_caps = set((parent_scope or {}).get('vault_caps_default', []))
                        parent_scope_ids = None
                    else:
                        parent_caps = set(parent_caps_map.get(vid, []))
                        parent_scope_ids = parent_scope_map.get(vid)
                        if parent_scope_ids is not None and not isinstance(parent_scope_ids, dict):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="The parent credential has an invalid stored vault scope.",
                            )
                        parent_scope_ids = normalize_id_scope(parent_scope_ids)
                    caps = [cap for cap in caps if cap in parent_caps]
                    scope_ids = intersect_id_scope(
                        parent_scope_ids,
                        scope_ids,
                        lambda cid, v=vault_uuid: id_ancestry(self.db, v, cid),
                    )
                selected_access_plans.append({
                    'request': sv,
                    'vault': vault,
                    'vault_uuid': vault_uuid,
                    'vault_id': vid,
                    'caps': caps,
                    'scope_ids': scope_ids,
                })

            # A wrapped ZK key unlocks the whole vault, so object-level grant maps
            # are rejected even when they normalize to an empty or stale set.
            # Scan before duplicate rejection so input order cannot change the result.
            for plan in selected_access_plans:
                if (
                    getattr(plan['vault'], 'type', 'standard') == 'zero_knowledge'
                    and plan['scope_ids'] is not None
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=("Zero-knowledge vault temporary access must use whole-vault "
                                "scope; file and folder restrictions are not supported."),
                    )
            plan_ids = [plan['vault_id'] for plan in selected_access_plans]
            if len(plan_ids) != len(set(plan_ids)):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A vault may only be selected once per temporary credential.",
                )

        # A parent whose ZK object grant blocks account key release must not shed
        # that negative boundary by delegating only its otherwise-valid ZK grants.
        # Read the parent rows from the database; request-derived scope maps are not
        # authoritative for this cutoff. Standard-only delegation remains available.
        if created_by_temp_credential_id is not None:
            from app.core.zk_temp_access import credential_has_zk_object_conflict

            if credential_has_zk_object_conflict(
                self.db, created_by_temp_credential_id
            ):
                child_can_reach_zk = (
                    effective_scope is None
                    or mode == 'all'
                    or any(
                        getattr(plan['vault'], 'type', 'standard') == 'zero_knowledge'
                        for plan in selected_access_plans
                    )
                )
                if child_can_reach_zk:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=("A delegated credential cannot include zero-knowledge "
                                "vaults while its parent has object-scoped zero-knowledge access."),
                    )
        # An UNRESTRICTED (effective_scope is None) or ALL-vaults credential does NOT pass through the
        # per-vault selected loop below, yet it reaches every vault the account can access — including
        # zero-knowledge. Enforce the deny here too, fail-closed, before anything is persisted, when the
        # minting account owns or is a keyed member of any active ZK vault. (Selected-mode ZK entries
        # are rejected per-vault in the proof loop; the admin-for-user unrestricted mint is guarded at
        # its own endpoint.)
        if (effective_scope is None or mode == 'all') and not _tp_policy['temp_cred_allow_zk_vaults'] \
                and user_reaches_active_zk_vault(self.db, user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=("Zero-knowledge vaults can't be included in a temporary credential by "
                        "organization policy. Mint a credential scoped to specific standard vaults instead."))

        # A SCOPED 'selected'-mode credential scoped to the vaults page but with no vaults that
        # will actually resolve to an access grant can reach nothing — reject rather than silently
        # mint a dead credential. Keyed on the 'vaults' page (the only signal that governs
        # selected-mode reachability — vault_caps_default is unused in 'selected' mode) and on the
        # vaults that will really persist (a valid id, and for a delegated child one the parent
        # itself holds), so a dashboard/temp-creds-only credential and a request full of unusable
        # ids are both judged correctly.
        #
        # The `effective_scope is not None` term is load-bearing twice over. Mechanically it keeps
        # `.get('pages', [])` off a None. Semantically: a legacy request (no scope, no delegating
        # parent) mints an UNRESTRICTED credential and skips the per-vault resolve entirely, so any
        # selected_vaults it carried are ignored — such a credential is not dead, it is the
        # opposite, and this check would be the wrong shape for it.
        #
        # That combination is still a poor request to honour quietly: the caller sent a restriction
        # list and received a credential reaching everything the account does, zero-knowledge
        # vaults included. Note the zero-knowledge deny above does NOT cover this by default —
        # allow_zk_vaults() returns True unless an organization has explicitly stored False — so
        # under the shipped policy nothing narrows that credential. Rejecting the combination would
        # be a behaviour change on a legacy API shape and is deliberately not made here; it is
        # recorded as a known sharp edge rather than fixed in passing.
        if mode == 'selected' and effective_scope is not None and 'vaults' in effective_scope.get('pages', []):
            if not selected_access_plans:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="This credential is scoped to vaults but no reachable vaults are "
                           "selected — select at least one vault, or switch to 'All vaults'.",
                )

        # Proof-of-knowledge gate: minting a 'selected'-scope credential that includes a
        # password-protected vault REQUIRES that vault's CURRENT password (passed per-vault
        # as selected_vaults[].password). SFTP has no per-vault prompt channel, so the
        # credential itself must embody the proof — without this gate a temp credential
        # would be an SFTP bypass of the vault password. Verified BEFORE anything is
        # persisted, so a bad/absent password mints nothing. We also capture a fingerprint
        # of the proven password hash so SFTP can later detect a rotation and void the proof
        # (a delegated child re-proves too — proof must always bind to the LIVE password,
        # never inherited stale).
        pw_fingerprints = {}  # str(vault_id) -> fingerprint of the proven password hash
        if mode == 'selected' and selected_access_plans:
            for plan in selected_access_plans:
                # The resolve pass above already canonicalized the id (so these keys match the
                # persist loop), resolved a non-null vault, and applied the organization's
                # zero-knowledge policy. This loop only proves vault passwords.
                vault = plan['vault']
                if not vault.password_hash:
                    continue  # not password-protected — nothing to prove
                # Throttle wrong mint-password attempts on the SAME failure-only, fixed-window
                # (vault, account) counter get_vault uses, so the mint proof is not an unthrottled
                # brute-force surface (reachable only by a member, after the pre-check above).
                _rl_key = f"rate_limit:vault:{plan['vault_id']}:{user_id}"
                _rl_limit = rate_limit_settings.effective(
                    "rate_limit_vault_attempts_admin"
                    if (minting_user and minting_user.role == RoleEnum.ADMIN)
                    else "rate_limit_vault_attempts")
                _rl_attempts = redis_client.get(_rl_key)
                if _rl_attempts and int(_rl_attempts) >= _rl_limit:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many vault password attempts. Please try again later.",
                    )
                supplied = plan['request'].get('password')
                if not supplied or not verify_password(supplied, vault.password_hash):
                    # Burn one failed attempt on the shared (vault, account) counter.
                    _pipe = redis_client.pipeline()
                    _pipe.incr(_rl_key)
                    _pipe.expire(_rl_key, rate_limit_settings.effective("rate_limit_vault_window_seconds"))
                    _pipe.execute()
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(f"Vault '{vault.name}' is password-protected — its correct "
                                "password is required to grant access via a temporary credential."),
                    )
                pw_fingerprints[plan['vault_id']] = vault_password_fingerprint(vault.password_hash)

        # --- Temporary passcodes (standard, password-protected vaults only) -----------------------
        # A passcode is a SECOND server-side access gate that opens a vault in place of its real
        # password for the holder of this credential — it does NOT re-encrypt content. Policy-gated
        # and fail-closed: computed BEFORE anything is persisted, so a policy violation mints nothing.
        # The plaintext is returned ONCE (like the credential password) and never stored.
        passcode_plans = {}   # str(vault_id) -> {hash, kind, max_uses, expires_at}
        passcode_reveal = []  # [{vault_id, passcode, kind}] returned once to the minter
        # Gate on the SAME condition as the persist loop below (effective_scope is not None) so a
        # passcode is only computed/revealed when a grant row will actually be written to carry its
        # verifier — never reveal a passcode that isn't persisted.
        if effective_scope is not None and mode == 'selected' and selected_access_plans:
            requested = [plan for plan in selected_access_plans
                         if plan['request'].get('issue_passcode')]
            if requested:
                from app.core.password_policy import password_policy_errors
                from app.core.security import generate_passcode
                policy = _tp_policy  # resolved unconditionally above
                if not policy['temp_passcodes_enabled']:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Temporary vault passcodes are disabled by the administrator.")
                if policy['temp_passcode_single_vault_only'] and len(requested) > 1:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="A temporary passcode may only cover a single vault (organization policy).")
                # Complexity config for CUSTOM passcodes (generated ones are always high-entropy),
                # mapped onto the account password_policy validator so both share one implementation.
                complexity_cfg = {
                    "password_min_length": policy['temp_passcode_min_length'],
                    "require_uppercase": policy['temp_passcode_require_uppercase'],
                    "require_lowercase": policy['temp_passcode_require_lowercase'],
                    "require_numbers": policy['temp_passcode_require_numbers'],
                    "require_special": policy['temp_passcode_require_special'],
                }
                # "Same passcode for all": one secret (a supplied custom value, else generated),
                # stored as N independent verifiers.
                shared_plain = shared_kind = None
                if passcode_same_for_all:
                    _custom = next((plan['request'].get('passcode') for plan in requested
                                    if plan['request'].get('passcode')), None)
                    if _custom:
                        shared_plain, shared_kind = _custom, 'custom'
                    else:
                        shared_plain, shared_kind = generate_passcode(policy['temp_passcode_min_length']), 'generated'
                for plan in requested:
                    sv = plan['request']
                    vid = plan['vault_id']
                    vault = plan['vault']
                    if getattr(vault, 'type', 'standard') == 'zero_knowledge':
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=(f"Vault '{vault.name}' is zero-knowledge — temporary passcodes "
                                    "aren't available for it. Add a member or use a disposable "
                                    "standard vault."))
                    if not vault.password_hash:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=(f"Vault '{vault.name}' has no password, so a passcode gate does "
                                    "not apply."))
                    # Resolve the plaintext + kind for THIS vault.
                    if passcode_same_for_all:
                        plain, kind = shared_plain, shared_kind
                    elif sv.get('passcode'):
                        plain, kind = sv.get('passcode'), 'custom'
                    else:
                        plain, kind = generate_passcode(policy['temp_passcode_min_length']), 'generated'
                    if kind == 'custom':
                        if not policy['temp_passcode_allow_custom']:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Custom temporary passcodes are not allowed; use a generated one.")
                        if not isinstance(plain, str):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="A custom passcode must be a string.")
                        errs = password_policy_errors(plain, complexity_cfg)
                        if errs:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Passcode must " + "; ".join(errs) + ".")
                    # One-time vs multi-use: per-vault override, else the org default.
                    one_time = sv.get('one_time')
                    if one_time is None:
                        one_time = policy['temp_passcode_one_time_default']
                    max_uses = 1 if one_time else None
                    # Expiry = the credential's validity end, capped by the org max-lifetime if set.
                    p_expires = deactivate_at
                    _max_life = policy['temp_passcode_max_lifetime_minutes']
                    if _max_life and _max_life > 0:
                        p_expires = min(p_expires, now + timedelta(minutes=_max_life))
                    passcode_plans[vid] = {
                        "hash": hash_password(plain), "kind": kind,
                        "max_uses": max_uses, "expires_at": p_expires,
                    }
                    passcode_reveal.append({"vault_id": vid, "passcode": plain, "kind": kind})

        # Persist the credential and every selected grant in one database transaction.
        # Redis is written only after the relational state is complete.
        temp_cred = TemporaryCredential(
            user_id=user_id,
            temp_username=temp_username,
            credential_hash=credential_hash,
            password_shown=True,  # User receives password in this response (never stored for re-reveal)
            deactivate_at=deactivate_at,
            expires_at=expires_at,
            note=(note.strip() if note else None),
            can_create_temp_credentials=bool(can_create_temp_credentials),
            scope=effective_scope,
            vault_access_mode=mode,
            created_by_temp_credential_id=created_by_temp_credential_id,
        )
        from app.core.models import TempCredentialVaultAccess
        try:
            self.db.add(temp_cred)
            self.db.flush()
            if effective_scope is not None and mode == 'selected':
                for plan in selected_access_plans:
                    _pp = passcode_plans.get(plan['vault_id']) or {}
                    self.db.add(TempCredentialVaultAccess(
                        temp_credential_id=temp_cred.id,
                        vault_id=plan['vault_uuid'],
                        vault_caps=plan['caps'],
                        scope_ids=plan['scope_ids'],
                        # Binds the SFTP proof to the password proven above (NULL for
                        # non-password vaults); re-checked against the live hash on access.
                        vault_password_fingerprint=pw_fingerprints.get(plan['vault_id']),
                        # Optional passcode verifier (NULL = no passcode). Computed + policy-checked above.
                        passcode_hash=_pp.get('hash'),
                        passcode_kind=_pp.get('kind'),
                        passcode_max_uses=_pp.get('max_uses'),
                        passcode_expires_at=_pp.get('expires_at'),
                        created_by=created_by_user_id,
                    ))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        self.db.refresh(temp_cred)
        
        # Store in Redis for quick expiration checks
        redis_key = f"temp_cred:{temp_username}"
        redis_client.setex(
            redis_key,
            total_lifetime * 60,
            json.dumps({
                'id': str(temp_cred.id),
                'user_id': str(user_id),
                'deactivate_at': deactivate_at.isoformat(),
                'expires_at': expires_at.isoformat()
            })
        )
        
        return {
            'id': str(temp_cred.id),
            'temp_username': temp_username,
            'credential': credential_string,  # ⚠️ ONLY TIME password is returned!
            # Emit UTC timestamps with a trailing 'Z' so JavaScript's Date()
            # parses them. created_at is naive (DB default) so we append 'Z';
            # deactivate_at/expires_at are tz-aware UTC, so their isoformat()
            # already ends in '+00:00' — normalize that to 'Z' instead of
            # appending a second suffix (which produced an invalid '+00:00Z').
            'created_at': temp_cred.created_at.isoformat() + 'Z',
            'deactivate_at': deactivate_at.isoformat().replace('+00:00', 'Z'),
            'expires_at': expires_at.isoformat().replace('+00:00', 'Z'),
            'validity_minutes': validity,
            'total_lifetime_minutes': total_lifetime,
            'note': (note.strip() if note else None),
            'can_create_temp_credentials': bool(can_create_temp_credentials),
            'scope': effective_scope,
            'vault_access_mode': mode,
            # Any temporary vault passcodes minted with this credential — shown ONCE (like the
            # credential password). Empty when no passcode was requested. [{vault_id, passcode, kind}].
            'passcodes': passcode_reveal,
            'warning': '⚠️ COPY THIS PASSWORD NOW - It cannot be retrieved later!',
            'password_length': len(credential_string),
            'password_policy': 'One-time viewing only. Password is hashed and cannot be retrieved after creation.'
        }

    def mint_device_sync_credential(self, device, vault_id, validity_minutes=None) -> dict:
        """Mint a single-use SFTP sync credential for a registered device, authorized by a device
        GRANT rather than an interactive vault-password proof.

        This is deliberately a SEPARATE path from create_temporary_credential, not a branch through
        it: it NEVER enters the password-VERIFY branch and NEVER touches the per-vault rate limiter
        (a device carries no password), and its scope is fixed server-side (a device cannot choose
        its caps — no self-escalation). The transfer path is otherwise identical to today's temp
        cred, so a device sync behaves exactly like a password-proved one at the SFTP server; only
        HOW it was authorized differs.

        Allows the mint IFF all five predicates hold (else a typed refusal; no password is ever
        supplied, no limiter is ever touched):
          1. an ACTIVE device_grants row for (device, vault)              -> else 'no-grant'
          2. the vault is Standard (never zero-knowledge)                 -> else 'vault-not-standard'
          3. the owning account is active and not locked                 -> else 'account-inactive'
          4. the device is live (is_active + not expired)                -> else 'device-revoked'/'device-expired'
          5. the grant's frozen vault_password_fingerprint still equals the vault's LIVE fingerprint
             -> else the DISTINCT, non-retrying 'grant-needs-reproof' (a rotation voided the proof).

        For a password-protected vault, predicate 5's matched fingerprint is copied from the grant
        straight onto the issued credential's TempCredentialVaultAccess row, so the transfer-time
        proof (_vault_password_proven) passes WITHOUT a fresh password test. Skipping the password
        VERIFY must not skip the fingerprint RECORD, or a password vault would be silently invisible
        over SFTP.

        Returns the credential dict (shown once). The route adds the host key + host/port."""
        from app.core.models import Device, DeviceGrant, TempCredentialVaultAccess
        from app.core.temp_scope import expand_vault_caps, normalize_scope

        # Predicate 4 (device live) UNDER A ROW LOCK — taken BEFORE any predicate and held through the
        # cred INSERT + commit below, so the whole check→mint is atomic against a concurrent revoke.
        # Lock the device row FOR UPDATE and re-read its state here: a racing revoke/delete of the same
        # device either commits first (this mint then blocks on the lock, re-reads is_active=False and
        # refuses) or blocks until this mint commits (the revoke's collection then sees this cred and
        # deactivates it). Without the lock, under READ COMMITTED a mint could slip a live cred past a
        # revoke that had already collected — the revoked device's cred would then keep working to its
        # TTL. The lock releases only at commit, so the check→insert window never reopens.
        # populate_existing() is NOT optional here: get_current_device_principal already loaded this
        # device on the way in (same request Session), so without it a query matching the cached
        # instance returns the STALE pre-lock attributes — the FOR UPDATE lock would be taken but
        # is_active would keep the value the resolver read, and a mint racing a revoke would slip a
        # live cred past. populate_existing() overwrites the instance with the locked row's committed
        # state, matching the vault-allocation lock (_lock_vault_for_allocation).
        device = (self.db.query(Device).filter(Device.id == device.id)
                  .populate_existing().with_for_update().first())
        if device is None:
            raise _device_mint_refusal("device-revoked")  # deleted out from under us
        if not device.is_active:
            raise _device_mint_refusal("device-revoked")
        # Re-assert SUSPENDED under the lock too, not just is_active — a suspend (the softened
        # reuse response) leaves is_active True, so without this a suspend that commits while this
        # mint waits on the row lock would be missed and a live cred issued after the suspend
        # deactivated the device's in-flight creds (the same race, through the suspend door). The
        # under-lock terminal-state set must match the resolver's: revoked + suspended + expired.
        if getattr(device, "suspended", False):
            raise _device_mint_refusal("device-suspended")
        # device.expires_at is stored naive-UTC (like temp_cred.expires_at), so compare with a naive
        # utcnow() — an aware value here would raise on the comparison.
        if device.expires_at is not None and device.expires_at <= datetime.utcnow():
            raise _device_mint_refusal("device-expired")

        # Predicate 1 (an active grant for exactly this device+vault).
        grant = self.db.query(DeviceGrant).filter(
            DeviceGrant.device_id == device.id,
            DeviceGrant.vault_id == vault_id,
            DeviceGrant.is_active == True,  # noqa: E712
        ).first()
        if grant is None:
            raise _device_mint_refusal("no-grant")

        # Predicate 2 (a Standard, existing vault). A grant to a since-deleted vault is effectively
        # no grant; a zero-knowledge vault is never SFTP-syncable (its keys are never server-side)
        # so the device path refuses it outright — no ZK material is ever reached.
        vault = self.db.query(Vault).filter(Vault.id == vault_id).first()
        if vault is None:
            raise _device_mint_refusal("no-grant")
        if getattr(vault, 'type', 'standard') == 'zero_knowledge':
            raise _device_mint_refusal("vault-not-standard")

        # Predicate 3 (the owning account is active and not locked).
        owner = self.db.query(User).filter(User.id == device.user_id).first()
        if owner is None or not owner.is_active or account_locked(owner):
            raise _device_mint_refusal("account-inactive")

        # Predicate 5 (the grant is still proven). The grant's frozen fingerprint must still equal
        # the vault's LIVE password fingerprint; a server-side add/change/rotation of the vault
        # password changes it -> mismatch -> 'grant-needs-reproof' (a DISTINCT, non-retrying reason;
        # the desktop shows "re-prove once", never a hard deny). No password is tested; the limiter
        # is never touched. For a no-password vault both sides are None and this passes. This mirrors
        # the SFTP-side re-check (_vault_password_proven), so mint-time and transfer-time agree.
        live_fp = vault_password_fingerprint(vault.password_hash) if vault.password_hash else None
        if grant.vault_password_fingerprint != live_fp:
            raise _device_mint_refusal("grant-needs-reproof")

        # Per-device outstanding-credential cap: a SEPARATE bound from the per-user interactive cap
        # (create_temporary_credential's max_temp_creds_per_user), so a compromised device is bounded
        # on its own and neither path can starve or exhaust the other. 0 = unlimited. Counts only
        # OUTSTANDING creds — is_active AND not yet spent (is_used == False) AND not yet expired. The
        # is_used filter is load-bearing: a single-use cred is SPENT by its one SFTP auth, which flips
        # is_used True but leaves is_active True until the lazy expiry sweep — so without it every
        # already-used cred would keep counting for its full TTL, and a device that mints-and-uses in
        # the normal way would false-hit the cap (a 409 stall) within the hour despite holding no live
        # credential. (An UNSPENT cred still counts until its hard expires_at, which a shorter
        # client validity below does not move — spending it, the normal case, is what frees the slot.)
        cap = getattr(settings, "max_device_sync_creds_per_device", 0) or 0
        if cap > 0:
            active_for_device = self.db.query(TemporaryCredential).filter(
                TemporaryCredential.device_id == device.id,
                TemporaryCredential.is_active == True,  # noqa: E712
                TemporaryCredential.is_used == False,  # noqa: E712 — a spent single-use cred frees its slot
                TemporaryCredential.expires_at > datetime.utcnow(),
            ).count()
            if active_for_device >= cap:
                # 409 (well-formed request, conflicts with current state), mirroring the per-user
                # cap's status. NOT a password/limiter path.
                raise _device_mint_refusal("device-cred-cap", http_status=status.HTTP_409_CONFLICT)

        # ---- Mint. A single-use, short-TTL SFTP credential, same lifetimes as the interactive path.
        # The client MAY request a shorter validity so the credential stops authenticating sooner —
        # a tighter usable window if the transfer finishes early or the cred is intercepted. It is
        # CLAMPED to [1, server default]: it can only SHORTEN, never extend past the server's
        # configured ceiling, so a device can never mint a longer-lived credential than the
        # interactive path. None (the default) uses the server value unchanged.
        server_validity = settings.temp_cred_validity_minutes
        if validity_minutes is not None:
            validity = max(1, min(int(validity_minutes), server_validity))
        else:
            validity = server_validity
        total_lifetime = max(settings.temp_cred_total_lifetime_minutes, validity)
        temp_username, credential_string, credential_hash = generate_temporary_credentials()
        now = datetime.now(timezone.utc)
        deactivate_at = now + timedelta(minutes=validity)
        expires_at = now + timedelta(minutes=total_lifetime)

        # A non-NULL selected-mode scope so the SFTP layer treats this as a scoped credential and
        # enforces the per-vault caps + the fingerprint (a NULL scope would be legacy/unrestricted).
        scope = normalize_scope({"pages": ["vaults"]})
        caps = expand_vault_caps(DEVICE_SYNC_VAULT_CAPS)

        temp_cred = TemporaryCredential(
            user_id=device.user_id,
            temp_username=temp_username,
            credential_hash=credential_hash,
            password_shown=True,
            deactivate_at=deactivate_at,
            expires_at=expires_at,
            note=None,
            can_create_temp_credentials=False,
            scope=scope,
            vault_access_mode='selected',
            device_id=device.id,  # the revocation cascade's primary join key — every device mint stamps it.
        )
        try:
            self.db.add(temp_cred)
            self.db.flush()
            self.db.add(TempCredentialVaultAccess(
                temp_credential_id=temp_cred.id,
                vault_id=vault.id,
                vault_caps=caps,
                scope_ids=None,  # the whole vault (device sync is not file/folder-restricted)
                # The grant's fingerprint (== live_fp by predicate 5) recorded WITHOUT a password
                # test, so _vault_password_proven accepts this cred at transfer for a password vault.
                # NULL for a no-password vault.
                vault_password_fingerprint=grant.vault_password_fingerprint,
                created_by=device.user_id,
            ))
            # Record device sync activity on the successful mint — part of THIS atomic commit, on the
            # device row already locked above. Naive-UTC, matching the device's other timestamps.
            device.last_seen = datetime.utcnow()
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        self.db.refresh(temp_cred)

        redis_key = f"temp_cred:{temp_username}"
        redis_client.setex(
            redis_key,
            total_lifetime * 60,
            json.dumps({
                'id': str(temp_cred.id),
                'user_id': str(device.user_id),
                'deactivate_at': deactivate_at.isoformat(),
                'expires_at': expires_at.isoformat(),
            })
        )

        return {
            'id': str(temp_cred.id),
            'temp_username': temp_username,
            'credential': credential_string,  # ⚠️ ONLY TIME the password is returned!
            'created_at': temp_cred.created_at.isoformat() + 'Z',
            'deactivate_at': deactivate_at.isoformat().replace('+00:00', 'Z'),
            'expires_at': expires_at.isoformat().replace('+00:00', 'Z'),
            'validity_minutes': validity,
            'total_lifetime_minutes': total_lifetime,
            'vault_id': str(vault.id),
            'warning': '⚠️ COPY THIS PASSWORD NOW - It cannot be retrieved later!',
        }

    def retrieve_temp_password(self, temp_username: str) -> Optional[str]:
        """Temporary-credential passwords are bcrypt-hashed one-way and are
        never stored in any retrievable form, so they cannot be fetched after
        creation. Always returns None; the API surfaces this as a 404 "password
        not available".
        """
        return None

    def verify_session(self, session_token: str) -> Optional[Tuple[User, ActiveSession]]:
        """
        Verify a session token and return associated user.
        
        Args:
            session_token: Session token to verify
            
        Returns:
            Tuple of (User, ActiveSession) if valid, None otherwise
        """
        # Try Redis first for fast lookup
        # Hash the token before using it as a key (security: prevents token exposure in Redis)
        token_hash = hash_session_token(session_token)
        redis_key = f"session:{token_hash}"
        cached_session = redis_client.get(redis_key)
        
        if cached_session:
            session_data = json.loads(cached_session)
            session_id = session_data['session_id']
            
            # Get from database
            session = self.db.query(ActiveSession).filter(
                ActiveSession.id == uuid.UUID(session_id)
            ).first()

            # Fail closed on revocation: the cached entry proves the token was valid once, but a
            # session revoked (logout / lock / deactivate) AFTER it was cached is still in Redis
            # until its TTL. Re-check the durable DB flags here so a revoked session is not honoured
            # off a stale cache.
            if session and session.is_active and not session.revoked:
                # Check expiration
                if session.expires_at and datetime.now(timezone.utc) > session.expires_at:
                    self._terminate_session(session)
                    return None
                
                # Update last activity
                session.last_activity = datetime.now(timezone.utc)
                self.db.commit()
                
                return session.user, session
        
        # Fallback to database. The token is stored as its SHA-256 hash, so match on the hash of
        # the presented token; also require the session to be neither inactive nor revoked.
        session = self.db.query(ActiveSession).filter(
            and_(
                ActiveSession.session_token == hash_session_token(session_token),
                ActiveSession.is_active == True,
                ActiveSession.revoked == False  # noqa: E712
            )
        ).first()

        if not session:
            return None
        
        # Check expiration
        if session.expires_at and datetime.now(timezone.utc) > session.expires_at:
            self._terminate_session(session)
            return None
        
        # Update last activity
        session.last_activity = datetime.now(timezone.utc)
        self.db.commit()
        
        # Cache in Redis with hashed token
        token_hash = hash_session_token(session_token)
        redis_key = f"session:{token_hash}"
        redis_client.setex(
            redis_key,
            1800,  # 30 minutes
            json.dumps({
                'session_id': str(session.id),
                'user_id': str(session.user_id)
            })
        )
        
        return session.user, session
    
    def terminate_session(self, session_token: str):
        """
        Terminate a session.
        
        Args:
            session_token: the plaintext session token to terminate
        """
        session = self.db.query(ActiveSession).filter(
            ActiveSession.session_token == hash_session_token(session_token)
        ).first()

        if session:
            self._terminate_session(session)
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions and temporary credentials."""
        now = datetime.now(timezone.utc)
        
        # Expire sessions
        expired_sessions = self.db.query(ActiveSession).filter(
            and_(
                ActiveSession.is_active == True,
                ActiveSession.expires_at.isnot(None),
                ActiveSession.expires_at < now
            )
        ).all()
        
        for session in expired_sessions:
            self._terminate_session(session)
        
        # Deactivate temporary credentials after validity period
        expired_temp_creds = self.db.query(TemporaryCredential).filter(
            and_(
                TemporaryCredential.is_active == True,
                TemporaryCredential.deactivate_at < now
            )
        ).all()
        
        for temp_cred in expired_temp_creds:
            temp_cred.is_active = False
        
        # Delete old temporary credentials
        old_temp_creds = self.db.query(TemporaryCredential).filter(
            TemporaryCredential.expires_at < now
        ).all()
        
        for temp_cred in old_temp_creds:
            # Terminate associated sessions
            for session in temp_cred.sessions:
                if session.is_active:
                    self._terminate_session(session)
            
            # Delete the credential
            self.db.delete(temp_cred)
        
        self.db.commit()
    
    def create_sftp_key_session(self, user: User, ip_address: str) -> str:
        """Create an SFTP session for a user authenticated via SSH public key.

        No password is involved (paramiko has already verified the client holds the
        private key before this is called). Unlike password login, this does NOT
        terminate the user's other sessions, so a service account may hold concurrent
        SFTP connections. Revoked like any session (lock/deactivate publishes a
        force-close; the SFTP layer re-checks is_active/is_locked every op)."""
        return self._create_session(user, None, ip_address)

    def _create_session(
        self,
        user: User,
        temp_credential_id: Optional[uuid.UUID],
        ip_address: str,
        expires_at: Optional[datetime] = None
    ) -> str:
        """Create a new active session."""
        session_token = generate_session_token()

        # Store the token's SHA-256 hash at rest, not the token itself: a database read then yields
        # no usable session credential. The plaintext is returned to the caller (and embedded in the
        # JWT) and never persisted; verification hashes the presented token to match this row.
        session = ActiveSession(
            session_token=hash_session_token(session_token),
            user_id=user.id,
            temp_credential_id=temp_credential_id,
            ip_address=ip_address,
            expires_at=expires_at
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        # Cache in Redis with hashed token (security: prevents token exposure)
        token_hash = hash_session_token(session_token)
        redis_key = f"session:{token_hash}"
        redis_client.setex(
            redis_key,
            1800,  # 30 minutes
            json.dumps({
                'session_id': str(session.id),
                'user_id': str(user.id)
            })
        )
        
        return session_token
    
    def _terminate_session(self, session: ActiveSession):
        """Terminate a session."""
        session.is_active = False

        # The Redis key is session:<hash>, and session.session_token IS that hash at rest -- use it
        # directly. Re-hashing it here would compute session:<hash-of-hash> and never delete the
        # real key, stranding the cached session until its own TTL.
        redis_key = f"session:{session.session_token}"
        redis_client.delete(redis_key)

        self.db.commit()
    
    def _terminate_existing_sessions(self, user_id: uuid.UUID):
        """Terminate all existing sessions for a user (except temp credentials)."""
        existing_sessions = self.db.query(ActiveSession).filter(
            and_(
                ActiveSession.user_id == user_id,
                ActiveSession.is_active == True,
                ActiveSession.temp_credential_id.is_(None)
            )
        ).all()
        
        for session in existing_sessions:
            self._terminate_session(session)
    
    def _global_setting(self, key, default):
        """A positive-integer override from the admin SystemSetting('global') blob, or `default`
        (the env value) when absent / non-positive / unreadable. Lets the admin Settings UI tune the
        login limits without a redeploy. FAILS SAFE to `default` so a settings-read hiccup (e.g. a
        pre-migration DB) can never break login."""
        from app.core.models import SystemSetting
        try:
            row = self.db.query(SystemSetting).filter(SystemSetting.key == "global").first()
            n = int((row.value or {}).get(key)) if (row and row.value) else 0
            return n if n > 0 else default
        except Exception:  # noqa: BLE001 — fail safe to the env default; login must not break
            return default

    def _check_rate_limit(self, identifier: str, ip_address: str):
        """
        Check the login rate limit (per-username AND per-IP).

        Auth must FAIL CLOSED on a Redis outage: a throttle that silently
        disappears would let an attacker brute-force at will (the correct
        password is still distinguishable, so session-creation failing later
        doesn't close the oracle). We therefore call the Redis limiter with
        fail_open=False and, if Redis is unavailable, fall back to a durable
        DB-backed throttle instead of waving the request through. The DB account
        lockout (failed_login_attempts -> is_locked) remains the final backstop.

        Raises RateLimitExceededError if the limit is exceeded; returns rate
        limit info (for response headers) otherwise.
        """
        from app.core.rate_limiter import rate_limiter, RateLimiterUnavailable

        # The admin 'Max Login Attempts' / 'Login window' settings override the env defaults when
        # configured (bounded + fail-safe-to-deployment via the rate-limit registry).
        user_limit = rate_limit_settings.effective("max_login_attempts")
        ip_limit = user_limit * 2  # 2x threshold for IPs
        window = rate_limit_settings.effective("rate_limit_login_window_seconds")

        try:
            return self._redis_rate_limit(
                rate_limiter, identifier, ip_address, user_limit, ip_limit, window
            )
        except RateLimiterUnavailable:
            # Redis is down. Do NOT disable throttling — fall back to the DB.
            return self._db_fallback_rate_limit(
                identifier, ip_address, user_limit, ip_limit, window
            )

    def _redis_rate_limit(self, rate_limiter, identifier, ip_address,
                          user_limit, ip_limit, window):
        """Primary, Redis-backed sliding-window throttle (fail closed)."""
        # Per-username limit.
        allowed_user, remaining_user, reset_user = rate_limiter.check_rate_limit(
            f"login:{identifier}", user_limit, window,
            prefix="rate_limit", fail_open=False,
        )
        if not allowed_user:
            retry_after = reset_user - int(time.time())
            raise RateLimitExceededError(
                f"Too many login attempts. Please try again in {retry_after} seconds.",
                retry_after=retry_after, limit=user_limit, remaining=0,
            )

        # Per-IP limit (2x threshold).
        allowed_ip, remaining_ip, reset_ip = rate_limiter.check_rate_limit(
            f"login:{ip_address}", ip_limit, window,
            prefix="rate_limit", fail_open=False,
        )
        if not allowed_ip:
            retry_after = reset_ip - int(time.time())
            raise RateLimitExceededError(
                f"Too many login attempts from this IP. Try again in {retry_after} seconds.",
                retry_after=retry_after, limit=ip_limit, remaining=0,
            )

        # Return rate limit info for response headers (use more restrictive limit).
        return {'limit': user_limit, 'remaining': remaining_user, 'reset': reset_user}

    def _db_fallback_rate_limit(self, identifier, ip_address,
                                user_limit, ip_limit, window):
        """DB-backed throttle used only when Redis is unavailable, so a Redis
        outage cannot silently disable login throttling."""
        allowed_user, retry_user = self._db_throttle_hit(
            identifier, "login_user", user_limit, window
        )
        if not allowed_user:
            raise RateLimitExceededError(
                f"Too many login attempts. Please try again in {retry_user} seconds.",
                retry_after=retry_user, limit=user_limit, remaining=0,
            )

        allowed_ip, retry_ip = self._db_throttle_hit(
            ip_address, "login_ip", ip_limit, window
        )
        if not allowed_ip:
            raise RateLimitExceededError(
                f"Too many login attempts from this IP. Try again in {retry_ip} seconds.",
                retry_after=retry_ip, limit=ip_limit, remaining=0,
            )

        return {'limit': user_limit, 'remaining': max(0, user_limit - 1),
                'reset': int(time.time()) + window}

    @staticmethod
    def _db_throttle_hit(identifier: str, action: str, limit: int, window: int):
        """Count one login attempt against a fixed DB window (RateLimitRecord).

        Returns (allowed, retry_after_seconds). Coarser than the Redis sliding
        window but durable, so throttling survives a Redis outage. Implemented as
        a single atomic INSERT ... ON CONFLICT (identifier, action) DO UPDATE so
        concurrent attempts can't create duplicate rows that split the count (the
        fallback is precisely the path that must hold up under a brute-force
        burst). Runs in its OWN short-lived session so its commit/rollback can
        never touch the surrounding auth transaction, and the attempt is counted
        regardless of whether that auth transaction later succeeds.

        Fails CLOSED (deny with a SHORT retry) on its own error. This fallback
        runs precisely when Redis is already down, so a simultaneous DB-throttle
        failure must not silently disable login throttling (which would let one IP
        spray across usernames unbounded). The retry is short so a transient DB
        hiccup briefly denies and recovers, rather than blocking legitimate users
        for the whole window; the DB account lockout remains the final backstop.

        Timestamps are naive UTC to match the column type (TIMESTAMP WITHOUT TIME
        ZONE) and so the window comparison happens entirely inside Postgres.
        """
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window)
        try:
            tbl = RateLimitRecord.__table__
            # On conflict: if the stored window has expired, restart it (count=1,
            # window_start=now); otherwise increment within the current window.
            expired = tbl.c.window_start < cutoff
            stmt = (
                pg_insert(tbl)
                .values(
                    id=uuid.uuid4(), identifier=identifier, action=action,
                    attempt_count=1, window_start=now, last_attempt=now,
                )
                .on_conflict_do_update(
                    index_elements=[tbl.c.identifier, tbl.c.action],
                    set_={
                        "attempt_count": case((expired, 1), else_=tbl.c.attempt_count + 1),
                        "window_start": case((expired, now), else_=tbl.c.window_start),
                        "last_attempt": now,
                    },
                )
                .returning(tbl.c.attempt_count, tbl.c.window_start)
            )
            with get_db_context() as db:
                row = db.execute(stmt).first()  # get_db_context commits on exit
            # A short deny used when the fallback can't establish the count -- long
            # enough to bound a spray during the Redis+DB double-failure, short
            # enough that a transient hiccup recovers quickly.
            fail_closed_retry = max(1, min(window, 5))
            if row is None:
                return False, fail_closed_retry
            count, win_start = row[0], row[1]
            if count > limit:
                elapsed = (now - win_start).total_seconds() if win_start else 0
                return False, max(1, int(window - elapsed))
            return True, 0
        except Exception:
            # Fail CLOSED: with Redis already down, silently allowing here would
            # disable login throttling entirely. Deny briefly; the DB account
            # lockout remains the final backstop.
            return False, max(1, min(window, 5))
    
    def _record_failed_login(
        self,
        identifier: str,
        ip_address: str,
        user: Optional[User] = None
    ):
        """Record a failed login attempt."""
        # Note: Rate limiting is handled by the RateLimiter class in _check_rate_limit
        # which uses sorted sets for sliding window algorithm.
        # We don't need to manually increment Redis counters here.
        
        # Update user failed attempts if user exists
        if user:
            user.failed_login_attempts += 1

            # Lock account after too many failed attempts. TIME-BOX the lock (locked_until)
            # so it auto-unlocks — a permanent lock here is a trivial targeted DoS (5 wrong
            # passwords against a known username). account_lockout_minutes=0 keeps it
            # permanent (locked_until NULL) if a deployment ever wants the old behaviour.
            # Since now verifies the password even for an already-locked account, a
            # failed login can reach this branch for a PERMANENT admin lock (is_locked=True,
            # locked_until=NULL). Do NOT downgrade such a standing lock into an auto-expiring
            # one — only arm a fresh auto-lock when the account is not already permanently
            # locked (regression guard).
            if user.failed_login_attempts >= rate_limit_settings.effective(
                "max_login_attempts"
            ) and not (user.is_locked and user.locked_until is None):
                user.is_locked = True
                ttl = rate_limit_settings.effective("lockout_duration")
                user.locked_until = (
                    datetime.utcnow() + timedelta(minutes=ttl) if ttl > 0 else None
                )

            self.db.commit()
