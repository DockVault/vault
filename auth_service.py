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
from models import (
    User, TemporaryCredential, ActiveSession, AuditLog,
    RateLimitRecord, RoleEnum, Vault
)
from security import (
    hash_password, verify_password, generate_temporary_credentials,
    verify_temporary_credential, generate_session_token, vault_password_fingerprint
)
from session_hash_utils import hash_session_token
from database import redis_client, get_db_context
from config import settings


# Precomputed Argon2 hash used to equalize login timing: verifying the supplied password
# against this on the "no such user" path makes a non-existent username cost ~the same as a
# real one, closing the username-enumeration timing oracle. Computed once at import.
_DUMMY_PASSWORD_HASH = hash_password("dummy-account-do-not-use-x9Q2")


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


class AuthService:
    """Service for authentication operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: RoleEnum = RoleEnum.USER,
        created_by: Optional[uuid.UUID] = None
    ) -> User:
        """
        Create a new user account.
        
        Args:
            username: Unique username
            email: User email address
            password: Plain text password (will be hashed)
            role: User role
            created_by: UUID of user creating this account
            
        Returns:
            Created User object
            
        Raises:
            ValueError: If username or email already exists
        """
        # Check if username or email already exists
        existing_user = self.db.query(User).filter(
            or_(User.username == username, User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                raise ValueError(f"Username '{username}' already exists")
            else:
                raise ValueError(f"Email '{email}' already exists")
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create user
        user = User(
            username=username,
            email=email,
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
        ip_address: str
    ) -> Tuple[User, str]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username
            password: Plain text password
            ip_address: Client IP address
            
        Returns:
            Tuple of (User object, session_token)
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
            RateLimitExceededError: If rate limit exceeded
            SessionLimitExceededError: If max sessions reached
        """
        # Check rate limit
        self._check_rate_limit(username, ip_address)
        
        # Find user
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
        
        # Create new session
        session_token = self._create_session(user, None, ip_address)
        
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
        from temp_scope import attach_scope
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
        created_by_temp_credential_id: Optional[uuid.UUID] = None,
        created_by_user_id: Optional[uuid.UUID] = None,
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
        from temp_scope import intersect_scope, VAULT_CAPS, expand_vault_caps
        is_delegated = parent_scope is not None
        if scope is None and not is_delegated:
            effective_scope = None
            mode = 'selected'
        else:
            requested = scope if scope is not None else parent_scope
            effective_scope = intersect_scope(parent_scope, requested)
            mode = 'all' if vault_access_mode == 'all' else 'selected'
            if is_delegated and parent_vault_mode == 'selected':
                mode = 'selected'  # a child cannot broaden vault access to 'all'

        # A 'selected'-mode credential scoped to the vaults page but with no vaults that will
        # actually resolve to an access grant can reach nothing — reject rather than silently mint
        # a dead credential. Keyed on the 'vaults' page (the only signal that governs selected-mode
        # reachability — vault_caps_default is unused in 'selected' mode) and on the vaults that
        # will really persist (a valid id, and for a delegated child one the parent itself holds),
        # so a dashboard/temp-creds-only credential and a request full of unusable ids are both
        # judged correctly.
        if mode == 'selected' and effective_scope is not None and 'vaults' in effective_scope.get('pages', []):
            _parent_ids = set(str(v) for v in (parent_vault_ids or []))
            _resolvable = []
            for _sv in (selected_vaults or []):
                _vid = _sv.get('vault_id') if isinstance(_sv, dict) else None
                if not _vid:
                    continue
                try:
                    uuid.UUID(str(_vid))
                except (ValueError, AttributeError):
                    continue
                if is_delegated and parent_vault_mode == 'selected' and str(_vid) not in _parent_ids:
                    continue
                _resolvable.append(str(_vid))
            if not _resolvable:
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
        if mode == 'selected' and selected_vaults:
            for sv in selected_vaults:
                vid = sv.get('vault_id') if isinstance(sv, dict) else None
                if not vid:
                    continue
                try:
                    vault = self.db.query(Vault).filter(Vault.id == uuid.UUID(str(vid))).first()
                except (ValueError, AttributeError):
                    continue
                if vault is None or not vault.password_hash:
                    continue  # not password-protected — nothing to prove
                supplied = sv.get('password') if isinstance(sv, dict) else None
                if not supplied or not verify_password(supplied, vault.password_hash):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(f"Vault '{vault.name}' is password-protected — its correct "
                                "password is required to grant access via a temporary credential."),
                    )
                pw_fingerprints[str(vid)] = vault_password_fingerprint(vault.password_hash)

        # Create temporary credential record
        # Note: encrypted_password is NULL (security enhancement - one-way hashing only)
        temp_cred = TemporaryCredential(
            user_id=user_id,
            temp_username=temp_username,
            credential_hash=credential_hash,
            encrypted_password=None,  # No longer stored (security enhancement)
            password_shown=True,  # User receives password in this response
            deactivate_at=deactivate_at,
            expires_at=expires_at,
            note=(note.strip() if note else None),
            can_create_temp_credentials=bool(can_create_temp_credentials),
            scope=effective_scope,
            vault_access_mode=mode,
            created_by_temp_credential_id=created_by_temp_credential_id,
        )

        self.db.add(temp_cred)
        self.db.commit()
        self.db.refresh(temp_cred)

        # Persist per-vault access rows for 'selected' mode. For a delegated child,
        # constrain the selection + capabilities to what the parent itself held.
        if effective_scope is not None and mode == 'selected' and selected_vaults:
            from models import TempCredentialVaultAccess
            parent_ids = set(str(v) for v in (parent_vault_ids or []))
            for sv in selected_vaults:
                vid = sv.get('vault_id') if isinstance(sv, dict) else None
                if not vid:
                    continue
                if is_delegated and parent_vault_mode == 'selected' and str(vid) not in parent_ids:
                    continue  # child cannot reach a vault the parent could not
                # Add implied prerequisite caps so the granted combination is usable, then (for a
                # delegated child) clamp to what the parent held so expansion can't broaden scope.
                caps = expand_vault_caps(sv.get('caps') or [])
                if is_delegated:
                    if parent_vault_mode == 'all':
                        parent_caps = set((parent_scope or {}).get('vault_caps_default', []))
                    else:
                        parent_caps = set((parent_vault_caps or {}).get(str(vid), []))
                    caps = [c for c in caps if c in parent_caps]
                try:
                    self.db.add(TempCredentialVaultAccess(
                        temp_credential_id=temp_cred.id,
                        vault_id=uuid.UUID(str(vid)),
                        vault_caps=caps,
                        # Binds the SFTP proof to the password proven above (NULL for
                        # non-password vaults); re-checked against the live hash on access.
                        vault_password_fingerprint=pw_fingerprints.get(str(vid)),
                        created_by=created_by_user_id,
                    ))
                except (ValueError, AttributeError):
                    continue
            self.db.commit()
        
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
            'warning': '⚠️ COPY THIS PASSWORD NOW - It cannot be retrieved later!',
            'password_length': len(credential_string),
            'password_policy': 'One-time viewing only. Password is hashed and cannot be retrieved after creation.'
        }

    def retrieve_temp_password(self, temp_username: str) -> Optional[str]:
        """Temporary-credential passwords are bcrypt-hashed one-way and never
        stored in a retrievable form (encrypted_password is NULL by design), so
        they cannot be fetched after creation. Always returns None; the API
        surfaces this as a 404 "password not available".
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
            
            if session and session.is_active:
                # Check expiration
                if session.expires_at and datetime.now(timezone.utc) > session.expires_at:
                    self._terminate_session(session)
                    return None
                
                # Update last activity
                session.last_activity = datetime.now(timezone.utc)
                self.db.commit()
                
                return session.user, session
        
        # Fallback to database
        session = self.db.query(ActiveSession).filter(
            and_(
                ActiveSession.session_token == session_token,
                ActiveSession.is_active == True
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
            session_token: Session token to terminate
        """
        session = self.db.query(ActiveSession).filter(
            ActiveSession.session_token == session_token
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
        
        session = ActiveSession(
            session_token=session_token,
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
        
        # Remove from Redis (using hashed token)
        token_hash = hash_session_token(session.session_token)
        redis_key = f"session:{token_hash}"
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
        from rate_limiter import rate_limiter, RateLimiterUnavailable

        user_limit = settings.rate_limit_login_attempts
        ip_limit = settings.rate_limit_login_attempts * 2  # 2x threshold for IPs
        window = settings.rate_limit_login_window_seconds

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
            if user.failed_login_attempts >= settings.rate_limit_login_attempts and not (
                user.is_locked and user.locked_until is None
            ):
                user.is_locked = True
                ttl = getattr(settings, 'account_lockout_minutes', 0) or 0
                user.locked_until = (
                    datetime.utcnow() + timedelta(minutes=ttl) if ttl > 0 else None
                )

            self.db.commit()
