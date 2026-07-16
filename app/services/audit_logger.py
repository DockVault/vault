"""
Audit logging system for security and compliance.
Tracks all significant actions in the system.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import uuid
import json

from sqlalchemy.orm import Session

from models import AuditLog, User


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
        error_message: Optional[str] = None
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
        if user:
            user_id = user.id
            username = user.username

        # At-rest privacy: file/folder names are encrypted in the files/folders tables,
        # so we must not persist their plaintext in the audit details JSON (that would
        # leave the very names one table over, recoverable from a DB/backup read).
        # resource_id still identifies the affected file/folder by UUID. Redact on a COPY
        # so a details dict the caller also uses for a transient SSE broadcast is untouched.
        if isinstance(details, dict):
            _name_keys = ("file_name", "folder_name")
            if any(k in details for k in _name_keys):
                details = {k: v for k, v in details.items() if k not in _name_keys}

        audit_log = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
            method=method,
            endpoint=endpoint,
            status=status,
            details=details,
            error_message=error_message
        )
        
        self.db.add(audit_log)
        self.db.commit()

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
        reason: str
    ):
        """Log failed login attempt."""
        self.log_action(
            action="login_failure",
            status="failure",
            username=username,
            ip_address=ip_address,
            details={'reason': reason},
            error_message=reason
        )
    
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
