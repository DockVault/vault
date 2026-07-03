"""
First-Run Detection System

Detects whether the vault service needs initial setup by checking:
- Database initialization status
- Admin user existence
- Setup lock file existence
- Credential mode (encrypted/plain/setup)

This module provides:
1. Setup state detection
2. Setup lock file management
3. Docker environment detection
4. Credential mode detection
"""
import os
import sys
import json
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List
from enum import Enum
from datetime import datetime, timezone

from sqlalchemy import inspect
from sqlalchemy.exc import OperationalError


class SetupState(Enum):
    """Setup completion states."""
    NOT_STARTED = "not_started"  # Fresh installation, needs setup
    IN_PROGRESS = "in_progress"  # Setup started but not completed
    COMPLETED = "completed"      # Setup completed, normal operation
    DOCKER_AUTO = "docker_auto"  # Docker with auto-configuration


class CredentialMode(Enum):
    """Credential management modes."""
    ENCRYPTED = "encrypted"  # Master password + encrypted secrets
    PLAIN = "plain"          # Plain environment variables (Docker/test/dev)
    SETUP = "setup"          # First-run, needs configuration


class FirstRunDetector:
    """
    Detect if the vault service is running for the first time and needs setup.
    
    Provides methods to check:
    - Database initialization
    - Admin user existence
    - Setup completion status
    - Credential mode
    - Docker environment
    """
    
    def __init__(self):
        """Initialize the first-run detector."""
        self.setup_lock_path = Path("setup.lock")
        self.docker_marker_path = Path("/.dockerenv")
        
    # ============================================================
    # Setup State Detection
    # ============================================================
    
    def get_setup_state(self) -> SetupState:
        """
        Determine current setup state.
        
        Returns:
            SetupState enum value
        """
        # Check for setup lock file
        if self.is_setup_completed():
            return SetupState.COMPLETED
        
        # Check if Docker with auto-configuration
        if self.is_docker_environment() and self._has_docker_config():
            return SetupState.DOCKER_AUTO
        
        # Check if setup was started
        if self._is_setup_in_progress():
            return SetupState.IN_PROGRESS
        
        # Fresh installation
        return SetupState.NOT_STARTED
    
    def is_setup_completed(self) -> bool:
        """
        Check if setup has been completed.
        
        Returns:
            True if setup.lock file exists and is valid
        """
        if not self.setup_lock_path.exists():
            return False
        
        try:
            lock_data = self._read_setup_lock()
            return lock_data.get("completed", False)
        except Exception:
            return False
    
    def needs_setup(self) -> bool:
        """
        Check if system needs initial setup.
        
        Returns:
            True if setup is required
        """
        state = self.get_setup_state()
        return state in [SetupState.NOT_STARTED, SetupState.IN_PROGRESS]
    
    # ============================================================
    # Database Checks
    # ============================================================
    
    def is_database_initialized(self) -> Tuple[bool, Optional[str]]:
        """
        Check if database is initialized with required tables.
        
        Returns:
            Tuple of (is_initialized, error_message)
        """
        try:
            from database import engine
            from models import Base
            
            # Check if database connection works
            inspector = inspect(engine)
            
            # Get list of expected tables
            expected_tables = set(Base.metadata.tables.keys())
            
            # Get list of actual tables
            actual_tables = set(inspector.get_table_names())
            
            # Check if all expected tables exist
            missing_tables = expected_tables - actual_tables
            
            if missing_tables:
                return False, f"Missing tables: {', '.join(missing_tables)}"
            
            return True, None
            
        except OperationalError as e:
            return False, f"Database connection error: {str(e)}"
        except Exception as e:
            return False, f"Database check error: {str(e)}"
    
    def has_admin_user(self) -> Tuple[bool, Optional[str]]:
        """
        Check if at least one admin user exists.
        
        Returns:
            Tuple of (has_admin, error_message)
        """
        try:
            from database import SessionLocal
            from models import User, RoleEnum
            
            db = SessionLocal()
            try:
                # Query for admin users
                admin_count = db.query(User).filter(
                    User.role == RoleEnum.ADMIN,
                    User.is_active == True
                ).count()
                
                if admin_count == 0:
                    return False, "No active admin user found"
                
                return True, None
                
            finally:
                db.close()
                
        except Exception as e:
            return False, f"Admin check error: {str(e)}"
    
    # ============================================================
    # Environment Detection
    # ============================================================
    
    def is_docker_environment(self) -> bool:
        """
        Detect if running inside Docker container.
        
        Returns:
            True if running in Docker
        """
        # Check for /.dockerenv file
        if self.docker_marker_path.exists():
            return True
        
        # Check for DOCKER_CONTAINER environment variable
        if os.getenv("DOCKER_CONTAINER") == "true":
            return True
        
        # Check for docker in cgroup
        try:
            with open("/proc/1/cgroup", "r") as f:
                return "docker" in f.read().lower()
        except:
            pass
        
        return False
    
    def get_credential_mode(self) -> CredentialMode:
        """
        Detect current credential management mode.
        
        Returns:
            CredentialMode enum value
        """
        master_password_hash = os.getenv("MASTER_PASSWORD_HASH")
        encrypted_key = os.getenv("ENCRYPTED_ENCRYPTION_KEY")
        encryption_key = os.getenv("ENCRYPTION_KEY")
        
        # Mode 1: Encrypted (production)
        if master_password_hash and encrypted_key:
            return CredentialMode.ENCRYPTED
        
        # Mode 2: Plain (Docker/test/dev)
        if encryption_key and not encrypted_key and not master_password_hash:
            return CredentialMode.PLAIN
        
        # Mode 3: Setup (unconfigured)
        return CredentialMode.SETUP
    
    def get_environment_info(self) -> Dict[str, Any]:
        """
        Get comprehensive environment information.
        
        Returns:
            Dictionary with environment details
        """
        is_docker = self.is_docker_environment()
        credential_mode = self.get_credential_mode()
        db_initialized, db_error = self.is_database_initialized()
        has_admin, admin_error = self.has_admin_user()
        
        return {
            "is_docker": is_docker,
            "credential_mode": credential_mode.value,
            "database_initialized": db_initialized,
            "database_error": db_error,
            "has_admin_user": has_admin,
            "admin_error": admin_error,
            "has_setup_lock": self.setup_lock_path.exists(),
            "python_version": sys.version,
            "working_directory": str(Path.cwd()),
        }
    
    # ============================================================
    # Setup Lock Management
    # ============================================================
    
    def create_setup_lock(
        self,
        completed_by: Optional[str] = None,
        setup_mode: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Create setup.lock file to mark setup as completed.
        
        Args:
            completed_by: Username or identifier of who completed setup
            setup_mode: How setup was completed (wizard/docker/manual)
            metadata: Additional metadata to store
        
        Returns:
            True if lock file created successfully
        """
        try:
            lock_data = {
                "completed": True,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "completed_by": completed_by or "system",
                "setup_mode": setup_mode or "unknown",
                "credential_mode": self.get_credential_mode().value,
                "is_docker": self.is_docker_environment(),
                "metadata": metadata or {}
            }
            
            with open(self.setup_lock_path, "w") as f:
                json.dump(lock_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error creating setup lock: {e}")
            return False
    
    def remove_setup_lock(self) -> bool:
        """
        Remove setup.lock file (for re-running setup).
        
        ⚠️  WARNING: This allows re-running setup which may overwrite configuration!
        
        Returns:
            True if lock file removed successfully
        """
        try:
            if self.setup_lock_path.exists():
                self.setup_lock_path.unlink()
            return True
        except Exception as e:
            print(f"Error removing setup lock: {e}")
            return False
    
    def _read_setup_lock(self) -> Dict:
        """
        Read and parse setup.lock file.
        
        Returns:
            Dictionary with lock file contents
        """
        try:
            with open(self.setup_lock_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    
    # ============================================================
    # Private Helper Methods
    # ============================================================
    
    def _has_docker_config(self) -> bool:
        """
        Check if Docker environment has all required configuration.
        
        Returns:
            True if Docker environment is fully configured
        """
        required_vars = [
            "DATABASE_URL",
            "REDIS_HOST",
            "ENCRYPTION_KEY",
            "ADMIN_USERNAME",
            "ADMIN_PASSWORD",
        ]
        
        return all(os.getenv(var) for var in required_vars)
    
    def _is_setup_in_progress(self) -> bool:
        """
        Check if setup was started but not completed.
        
        Returns:
            True if setup is in progress
        """
        # Check if database is initialized but no admin user
        db_initialized, _ = self.is_database_initialized()
        has_admin, _ = self.has_admin_user()
        
        if db_initialized and not has_admin:
            return True
        
        # Check for incomplete setup lock file
        if self.setup_lock_path.exists():
            lock_data = self._read_setup_lock()
            if not lock_data.get("completed", False):
                return True
        
        return False
    
    def get_detailed_status(self) -> Dict[str, Any]:
        """
        Get comprehensive setup status information.
        
        Returns:
            Dictionary with detailed status
        """
        setup_state = self.get_setup_state()
        env_info = self.get_environment_info()
        
        # Get setup lock info if exists
        setup_lock_info = None
        if self.setup_lock_path.exists():
            setup_lock_info = self._read_setup_lock()
        
        return {
            "setup_state": setup_state.value,
            "setup_completed": self.is_setup_completed(),
            "needs_setup": self.needs_setup(),
            "environment": env_info,
            "setup_lock": setup_lock_info,
            "recommendations": self._get_recommendations(setup_state, env_info)
        }
    
    def _get_recommendations(
        self,
        setup_state: SetupState,
        env_info: Dict
    ) -> List[str]:
        """
        Get recommendations based on current state.
        
        Args:
            setup_state: Current setup state
            env_info: Environment information
        
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if setup_state == SetupState.NOT_STARTED:
            if env_info["is_docker"]:
                recommendations.append(
                    "Docker environment detected. Ensure all environment variables are set."
                )
            else:
                recommendations.append(
                    "Run the setup wizard at /setup to configure the instance."
                )
        
        elif setup_state == SetupState.IN_PROGRESS:
            recommendations.append(
                "Setup was started but not completed. Please complete the setup wizard."
            )
        
        if not env_info["database_initialized"]:
            recommendations.append(
                "Database is not initialized. Run database migrations."
            )
        
        if not env_info["has_admin_user"]:
            recommendations.append(
                "No admin user found. Create an admin account."
            )
        
        if env_info["credential_mode"] == CredentialMode.SETUP.value:
            recommendations.append(
                "Credentials not configured. Set up encryption keys and secrets."
            )
        
        return recommendations


# ============================================================
# Global Instance
# ============================================================

# Create global detector instance
detector = FirstRunDetector()


# ============================================================
# Convenience Functions
# ============================================================

def is_setup_completed() -> bool:
    """Check if setup is completed."""
    return detector.is_setup_completed()


def needs_setup() -> bool:
    """Check if setup is needed."""
    return detector.needs_setup()


def get_setup_state() -> SetupState:
    """Get current setup state."""
    return detector.get_setup_state()


def get_detailed_status() -> Dict[str, Any]:
    """Get detailed setup status."""
    return detector.get_detailed_status()
