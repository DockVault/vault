"""
Audit logging system for security and compliance.
Tracks all significant actions in the system.
"""
import copy
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import logging
import uuid
import json

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.models import AuditLog, User
from app.services import audit_row_hooks

logger = logging.getLogger(__name__)

# At-rest privacy: these keys hold plaintext names that are ENCRYPTED in the files/folders/vaults
# tables (and, for a zero-knowledge vault, the residual plaintext label), so their plaintext is never
# persisted in an audit row's `details` JSON. The recording levels decide every row's details as it is
# written (app/core/audit_privacy.py, through build_row's privacy hook, which nothing else bypasses:
# tests/test_audit_route_coverage.py holds that nothing else constructs an AuditLog), and the boot
# migration app/core/audit_migrations.py purges them from legacy rows. Both read the names' kind from
# audit_privacy.DETAIL_KEYS, so this list is the same one.
from app.core.audit_privacy import DETAIL_KEYS as _DETAIL_KEYS, NAME as _NAME_KIND  # noqa: E402
REDACTED_NAME_KEYS = tuple(sorted(k for k, kind in _DETAIL_KEYS.items() if kind == _NAME_KIND and "." not in k))


def _request_address():
    """The address the middleware resolved for this request, or None outside one."""
    from app.core.net_utils import current_client_ip
    return current_client_ip()


# Both sign-in doors take a name that starts with this as a temporary credential's, whatever the sign-in
# method (/auth/login in app/api/api_server.py, check_auth_password in app/sftp/sftp_server.py).
TEMP_CREDENTIAL_PREFIX = "temp_"
LOGIN_IDENTIFIERS = ("username", "email", "either")


def account_named(db, typed, login_identifier: str = "username") -> Optional[User]:
    """The account a name typed at a failed sign-in names, or None: the account that sign-in tried, as
    AuthService.authenticate_user resolves the name under ``login_identifier`` (the web's sign-in method; SFTP
    always signs in by username). By username, the account with that username; by email, the one account with
    that address (two accounts sharing it name neither); either way, the username first, then the address. A
    name that starts with temp_ is a temporary credential's at both doors (credential_named), never an account's.
    One query whether or not one matches, so the failure's write takes no longer for a name that is an account
    than for one that is not. Never raises: a failed lookup leaves the name a typed one (_looked_up)."""
    if not isinstance(typed, str) or not typed or typed.startswith(TEMP_CREDENTIAL_PREFIX):
        return None
    if login_identifier not in LOGIN_IDENTIFIERS:
        login_identifier = "username"      # as authenticate_user takes an unknown method
    from sqlalchemy import case, func, or_
    from app.core.email_identity import normalize_email
    by_username = login_identifier != "email"
    match = [User.username == typed] if by_username else []
    address = normalize_email(typed) if login_identifier != "username" else None
    if address:
        match.append(func.lower(User.email) == func.lower(address))
    if not match:
        return None
    rows = _looked_up(db, lambda: db.query(User).filter(or_(*match))
                      .order_by(case((User.username == typed, 0), else_=1)).limit(3).all())
    if rows is None:
        return None
    if by_username:
        by_name = [u for u in rows if u.username == typed]
        if by_name:
            return by_name[0]
    return rows[0] if len(rows) == 1 else None


def credential_named(db, typed):
    """The temporary credential a name typed at a failed sign-in names, or None: (id, owner's account id, name)
    of the credential with exactly that name, as both doors look one up, live or not. One query. Never raises:
    a failed lookup leaves the name a typed one (_looked_up)."""
    if not isinstance(typed, str) or not typed.startswith(TEMP_CREDENTIAL_PREFIX):
        return None
    from app.core.models import TemporaryCredential
    return _looked_up(db, lambda: db.query(TemporaryCredential.id, TemporaryCredential.user_id,
                                           TemporaryCredential.temp_username)
                      .filter(TemporaryCredential.temp_username == typed).first())


def _looked_up(db, query):
    """What ``query()`` returns, run under a savepoint of the session's transaction; None when it fails. On
    PostgreSQL a statement that fails aborts the transaction it runs in, so without the savepoint a lookup
    that fails (waiting past the lock timeout behind a change to its table, or a transient error) would cost
    the failure's audit row, written next in the same transaction, and the caller its answer. Rolled back to
    the savepoint, the transaction goes on and the name is recorded as a typed one."""
    try:
        with db.begin_nested():
            return query()
    except Exception:  # noqa: BLE001 -- the row is still written, as a typed name
        return None


class AuditLogger:
    """Service for audit logging."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def log_action(
        self,
        action: str,
        status: str,
        user: Optional[User] = None,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        method: Optional[str] = None,
        endpoint: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        channel: Optional[str] = None,
    ) -> AuditLog:
        """
        Log an action to the audit log.
        
        Args:
            action: Action description
            status: Status (success, failure, error)
            user: User object (optional)
            user_id: User UUID (optional, used if user not provided)
            username: Username (optional, used if user not provided)
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            ip_address: Client IP address
            user_agent: Client user agent
            method: HTTP method
            endpoint: API endpoint
            details: Additional details dictionary
            error_message: Error message if applicable
            
        Returns:
            Created AuditLog object
        """
        audit_log = self.build_row(
            action=action, status=status, user=user, user_id=user_id, username=username,
            resource_type=resource_type, resource_id=resource_id, ip_address=ip_address,
            user_agent=user_agent, method=method, endpoint=endpoint, details=details,
            error_message=error_message, channel=channel,
        )
        self.db.add(audit_log)
        self.db.commit()

        return audit_log

    def build_row(
        self,
        action: str,
        status: str,
        user: Optional[User] = None,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        method: Optional[str] = None,
        endpoint: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        channel: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        names_account: bool = False,
        temp_credential=None,
    ) -> AuditLog:
        """The row log_action writes for these arguments, neither added to a session nor committed.

        For a caller whose audit row must commit in the same transaction as the change it records
        (an automatic account lock, the file-expiry sweep): it adds the row to its own session, so
        its commit writes both and its rollback drops both. log_action cannot give that, because it
        commits on its own. log_action is this method plus the add and the commit, so a row built
        here gets everything log_action applies: the recording levels, the acting user's name and
        temporary credential, and the request's channel, method, route, user agent and address
        where they are known.

        ``timestamp`` is the row's time, now by default, which is what log_action stores. ``names_account``
        says that ``username``, given without a user, is an account's username or a temporary credential's
        name rather than a name someone typed, so the level of typed names does not apply to it (a failed
        sign-in for an account or a credential). ``temp_credential``, given without a user, is the (id, name)
        of the temporary credential the row is about (a failed sign-in with its name).
        """
        temp_credential_id = None
        temp_credential_name = None
        if temp_credential is not None and not user:
            temp_credential_id, temp_credential_name = temp_credential
        if user:
            user_id = user.id
            username = user.username
            # Derived here rather than at each call site, so every surface gets it at once and
            # a new one cannot forget. A temp session is the account object with this stamped
            # on it, which is exactly why `username` alone is not attribution.
            temp_credential_id = getattr(user, '_temp_cred_id', None)
            temp_credential_name = getattr(user, '_temp_cred_username', None) if temp_credential_id else None
        elif user_id and not username:
            # A caller that passed only the id: store the name too, or the row reads "Unknown" in the
            # Activity page and cannot be found by a username filter.
            try:
                username = self.db.query(User.username).filter(User.id == user_id).scalar()
            except Exception:  # noqa: BLE001 -- a missing name never stops the row
                username = None

        # What the caller passed, for the privacy hook below, which decides what the row's details keep
        # (app/core/audit_privacy.py: names, addresses and email addresses at their recording levels,
        # secrets never, an unclassified key never). A deep copy, so a hook cannot change the caller's dict
        # or a value inside it: a caller may also use its dict for a live broadcast that keeps the name.
        # Details are JSON values (the column stores nothing else), so they always copy. The row itself is
        # built without details: only the hook gives it any.
        raw_details = copy.deepcopy(details) if isinstance(details, dict) else details
        details = None

        # Where the request came from and what it was, when the caller did not say: the request
        # context (a web request) or the process default (the SFTP server).
        from app.core.request_context import CHANNELS, current_channel, current_request_context
        ctx = current_request_context()
        if channel not in CHANNELS:
            channel = current_channel()
        if ctx is not None:
            method = method or ctx.method
            endpoint = endpoint or ctx.endpoint
            user_agent = user_agent or ctx.user_agent
        if not ip_address:
            # The address the middleware resolved for this request. A few callers never passed one,
            # so their rows had no address; outside a request (the SFTP server, a scheduled job)
            # this is None and the caller's own value, if any, is what is stored.
            from app.core.net_utils import current_client_ip
            ip_address = current_client_ip()

        audit_log = AuditLog(
            # Set here, not left to the column default, which SQLAlchemy applies only when the row is
            # flushed: the hooks below may bind something to the row's id.
            id=uuid.uuid4(),
            user_id=user_id,
            username=username,
            temp_credential_id=temp_credential_id,
            temp_credential_name=temp_credential_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=timestamp if timestamp is not None else datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
            method=method,
            endpoint=endpoint,
            channel=channel,
            status=status,
            details=details,
            error_message=error_message
        )
        if names_account:
            audit_log._names_account = True
        # Then what other modules decide about the row, in this order (app/services/audit_row_hooks.py).
        audit_row_hooks.provenance(audit_log)
        audit_row_hooks.case(audit_log)
        audit_row_hooks.privacy(audit_log, raw_details)
        audit_row_hooks.seal_nonce(audit_log)
        audit_row_hooks.kept_records(audit_log, self.db)
        return audit_log

    def log_custom_action(
        self,
        action: str,
        user: Optional[User] = None,
        details=None,
        ip_address: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: str = "success",
    ):
        """Log an ad-hoc action. ``details`` may be a string or a dict.

        Compatibility shim for callers (user-management routes) that expect a
        ``log_custom_action`` helper; delegates to :meth:`log_action`.
        """
        if isinstance(details, str):
            details = {"message": details}
        return self.log_action(
            action=action,
            status=status,
            user=user,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details=details,
        )

    def log_login_success(
        self,
        user: User,
        ip_address: str,
        is_temporary: bool = False
    ):
        """Log successful login."""
        self.log_action(
            action="login_success",
            status="success",
            user=user,
            ip_address=ip_address,
            details={
                'is_temporary': is_temporary,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        )
    
    def log_login_failure(
        self,
        username: str,
        ip_address: str,
        reason: str,
        *,
        account: Optional[User] = None,
        login_identifier: str = "username",
    ):
        """Log failed login attempt, and its security record in the same commit (the name and address in
        full, whatever the audit row keeps: app/core/security_records.py). Returns the record's id, or None
        when the record could not be written: the audit row is written all the same (_add_security_record).

        A name that is an account's (``account``, or the account the sign-in tried under ``login_identifier``,
        the sign-in method in force: account_named) is recorded as that account's username, as every account's
        is, whatever the level of typed names. A temporary credential's name (credential_named) is recorded in
        full with the credential, as its successful sign-ins are. Only a name that is neither follows that
        level."""
        from app.core import security_records
        credential = None
        if account is None:
            credential = credential_named(self.db, username)
            if credential is None:
                account = account_named(self.db, username, login_identifier)
        if account is not None:
            recorded_name = account.username
        elif credential is not None:
            recorded_name = credential.temp_username
        else:
            recorded_name = username
        row = self.build_row(
            action="login_failure",
            status="failure",
            username=recorded_name,
            ip_address=ip_address,
            details={'reason': reason},
            error_message=reason,
            names_account=account is not None or credential is not None,
            temp_credential=(credential.id, credential.temp_username) if credential is not None else None,
        )
        record_id = self._add_security_record(
            row, kind=security_records.LOGIN, name=username, address=ip_address or _request_address(),
            reason=reason, account_id=credential.user_id if credential is not None else None)
        self.db.commit()
        return record_id

    def log_second_factor_failure(self, user: User, ip_address: Optional[str] = None,
                                  details: Optional[Dict[str, Any]] = None):
        """Log a rejected second-factor code, and its security record in the same commit (the audit row is
        written even when the record cannot be: _add_security_record)."""
        from app.core import security_records
        row = self.build_row(action="second_factor_failed", status="failed", user=user, ip_address=ip_address,
                             details=details)
        method = (details or {}).get("method")
        self._add_security_record(
            row, kind=security_records.SECOND_FACTOR, name=user.username, account_id=user.id,
            address=ip_address or _request_address(),
            reason=f"second factor ({method})" if method else "second factor")
        self.db.commit()

    def _add_security_record(self, row: AuditLog, **fields):
        """Add the audit row ``row`` of a failure to the session, then the failure's security record under a
        savepoint of the same transaction, and return the record's id; None when the record cannot be
        written. The audit row is written first, outside the savepoint, so a record that fails (a fault in
        its one table) is rolled back alone and never costs the audit row, or the caller its answer. Such a
        failure raises a degraded-recording alert for the administrators instead (the error's type and the
        row's action; no value of the failure). An audit row that cannot be written still raises, and then
        no record is written either."""
        from app.core import audit_privacy, security_records
        self.db.add(row)
        self.db.flush()
        try:
            with self.db.begin_nested():
                record = security_records.record(self.db, channel=row.channel, **fields)
            return record.id
        except Exception as exc:  # noqa: BLE001 -- the audit row stays; the alert says what is missing
            audit_privacy.raise_alert(audit_privacy.RECORD_NOT_WRITTEN, type(exc).__name__, row.action)
            # The error's type only: on PostgreSQL its text can carry the whole failing row, the name as
            # typed (which can be a password) and the address with it.
            logger.warning("A %s security record could not be written (%s); its audit row was kept",
                           row.action, type(exc).__name__)
            return None
    
    def log_logout(self, user: User, ip_address: str):
        """Log logout."""
        self.log_action(
            action="logout",
            status="success",
            user=user,
            ip_address=ip_address
        )
    
    def log_user_created(
        self,
        created_user: User,
        created_by: User,
        ip_address: str
    ):
        """Log user creation."""
        self.log_action(
            action="user_created",
            status="success",
            user=created_by,
            resource_type="user",
            resource_id=str(created_user.id),
            ip_address=ip_address,
            details={
                'created_username': created_user.username,
                'created_role': created_user.role.value
            }
        )
    
    def log_user_updated(
        self,
        updated_user: User,
        updated_by: User,
        ip_address: str,
        changes: Dict[str, Any]
    ):
        """Log user update."""
        self.log_action(
            action="user_updated",
            status="success",
            user=updated_by,
            resource_type="user",
            resource_id=str(updated_user.id),
            ip_address=ip_address,
            details={
                'updated_username': updated_user.username,
                'changes': changes
            }
        )
    
    def log_user_deleted(
        self,
        deleted_username: str,
        deleted_user_id: uuid.UUID,
        deleted_by: User,
        ip_address: str
    ):
        """Log user deletion."""
        self.log_action(
            action="user_deleted",
            status="success",
            user=deleted_by,
            resource_type="user",
            resource_id=str(deleted_user_id),
            ip_address=ip_address,
            details={'deleted_username': deleted_username}
        )
    
    def log_temp_credential_created(
        self,
        user: User,
        temp_username: str,
        ip_address: str
    ):
        """Log temporary credential creation."""
        self.log_action(
            action="temp_credential_created",
            status="success",
            user=user,
            resource_type="temporary_credential",
            ip_address=ip_address,
            details={'temp_username': temp_username}
        )

    def log_temp_passcode_minted(
        self,
        user: User,
        ip_address: Optional[str],
        passcodes,
        same_for_all: bool = False,
    ):
        """A temp credential was minted carrying one or more vault passcodes. Records the vault ids,
        passcode kinds, and count — NEVER the passcode plaintext."""
        vaults = [{'vault_id': p.get('vault_id'), 'kind': p.get('kind')} for p in (passcodes or [])]
        self.log_action(
            action="temp_passcode_minted",
            status="success",
            user=user,
            resource_type="temporary_credential",
            ip_address=ip_address,
            details={'count': len(vaults), 'vaults': vaults, 'same_for_all': bool(same_for_all)},
        )

    def log_temp_passcode_used(
        self,
        user: Optional[User],
        vault_id,
        temp_credential_id,
        ip_address: Optional[str] = None,
    ):
        """A temp-credential passcode successfully opened a password-protected vault (redemption)."""
        self.log_action(
            action="temp_passcode_used",
            status="success",
            user=user,
            resource_type="vault",
            resource_id=str(vault_id) if vault_id else None,
            ip_address=ip_address,
            details={'temp_credential_id': str(temp_credential_id) if temp_credential_id else None},
        )

    def log_temp_passcode_failed(
        self,
        user: Optional[User],
        vault_id,
        temp_credential_id,
        reason: str,
        ip_address: Optional[str] = None,
    ):
        """A temp-credential passcode redemption failed (wrong / expired / used up / disabled). The
        ``reason`` is a short code — NEVER the attempted passcode."""
        self.log_action(
            action="temp_passcode_failed",
            status="failure",
            user=user,
            resource_type="vault",
            resource_id=str(vault_id) if vault_id else None,
            ip_address=ip_address,
            details={'reason': reason,
                     'temp_credential_id': str(temp_credential_id) if temp_credential_id else None},
            error_message=reason,
        )

    def log_vault_created(
        self,
        vault_id: uuid.UUID,
        vault_name: str,
        created_by: User,
        ip_address: str
    ):
        """Log vault creation."""
        self.log_action(
            action="vault_created",
            status="success",
            user=created_by,
            resource_type="vault",
            resource_id=str(vault_id),
            ip_address=ip_address,
            details={'vault_name': vault_name}
        )
    
    def log_vault_updated(
        self,
        vault_id: uuid.UUID,
        vault_name: str,
        updated_by: User,
        ip_address: str,
        changes: Dict[str, Any]
    ):
        """Log vault update."""
        self.log_action(
            action="vault_updated",
            status="success",
            user=updated_by,
            resource_type="vault",
            resource_id=str(vault_id),
            ip_address=ip_address,
            details={
                'vault_name': vault_name,
                'changes': changes
            }
        )
    
    def log_vault_deleted(
        self,
        vault_id: uuid.UUID,
        vault_name: str,
        deleted_by: User,
        ip_address: str
    ):
        """Log vault deletion."""
        self.log_action(
            action="vault_deleted",
            status="success",
            user=deleted_by,
            resource_type="vault",
            resource_id=str(vault_id),
            ip_address=ip_address,
            details={'vault_name': vault_name}
        )
    
    def log_file_uploaded(
        self,
        file_id: uuid.UUID,
        file_name: str,
        file_size: int,
        vault_id: uuid.UUID,
        uploaded_by: User,
        ip_address: str
    ):
        """Log file upload."""
        self.log_action(
            action="file_uploaded",
            status="success",
            user=uploaded_by,
            resource_type="file",
            resource_id=str(file_id),
            ip_address=ip_address,
            details={
                'file_name': file_name,
                'file_size': file_size,
                'vault_id': str(vault_id)
            }
        )
    
    def log_file_downloaded(
        self,
        file_id: uuid.UUID,
        file_name: str,
        vault_id: uuid.UUID,
        downloaded_by: User,
        ip_address: str
    ):
        """Log file download."""
        self.log_action(
            action="file_downloaded",
            status="success",
            user=downloaded_by,
            resource_type="file",
            resource_id=str(file_id),
            ip_address=ip_address,
            details={
                'file_name': file_name,
                'vault_id': str(vault_id)
            }
        )
    
    def log_file_deleted(
        self,
        file_id: uuid.UUID,
        file_name: str,
        vault_id: uuid.UUID,
        deleted_by: User,
        ip_address: str
    ):
        """Log file deletion."""
        self.log_action(
            action="file_deleted",
            status="success",
            user=deleted_by,
            resource_type="file",
            resource_id=str(file_id),
            ip_address=ip_address,
            details={
                'file_name': file_name,
                'vault_id': str(vault_id)
            }
        )
    
    def log_permission_granted(
        self,
        target_user_id: uuid.UUID,
        target_username: str,
        permission: str,
        granted_by: User,
        ip_address: str
    ):
        """Log permission grant."""
        self.log_action(
            action="permission_granted",
            status="success",
            user=granted_by,
            resource_type="permission",
            ip_address=ip_address,
            details={
                'target_user_id': str(target_user_id),
                'target_username': target_username,
                'permission': permission
            }
        )
    
    def log_permission_revoked(
        self,
        target_user_id: uuid.UUID,
        target_username: str,
        permission: str,
        revoked_by: User,
        ip_address: str
    ):
        """Log permission revocation."""
        self.log_action(
            action="permission_revoked",
            status="success",
            user=revoked_by,
            resource_type="permission",
            ip_address=ip_address,
            details={
                'target_user_id': str(target_user_id),
                'target_username': target_username,
                'permission': permission
            }
        )
    
    def log_access_denied(
        self,
        user: User,
        resource_type: str,
        resource_id: str,
        ip_address: str,
        reason: str
    ):
        """Log access denied."""
        self.log_action(
            action="access_denied",
            status="failure",
            user=user,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            error_message=reason,
            details={'reason': reason}
        )
    
    def log_error(
        self,
        action: str,
        error_message: str,
        user: Optional[User] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log an error."""
        self.log_action(
            action=action,
            status="error",
            user=user,
            ip_address=ip_address,
            error_message=error_message,
            details=details
        )
