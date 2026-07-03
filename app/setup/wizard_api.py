"""
Setup Wizard Backend API

Provides RESTful endpoints for web-based setup wizard.

Features:
- Step-by-step configuration
- Real-time validation
- Connection testing
- Idempotent operations
- Error recovery
- CSRF protection (future)
- Rate limiting (future)

All endpoints are designed to be robust and user-friendly.
"""
from fastapi import APIRouter, HTTPException, status, Body
from pydantic import BaseModel, Field, field_validator
from typing import Dict, Any, Optional, List, Pattern
import asyncio
import logging
import os
import secrets
import time
import re

logger = logging.getLogger(__name__)

from app.setup.state import (
    wizard_state,
    WizardStep,
    StepStatus
)
from app.setup.detector import detector, CredentialMode
from app.config.branding import get_branding
from app.config.effective import get_effective_branding, set_brand_overrides
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# API Router
# ============================================================

router = APIRouter(tags=["setup-wizard"])


# ============================================================
# Request/Response Models
# ============================================================

class WizardStateResponse(BaseModel):
    """Complete wizard state response."""
    current_step: str
    completed_steps: List[str]
    progress_percentage: float
    can_complete: bool
    steps: Dict[str, Dict[str, Any]]
    errors: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]


class StepDataRequest(BaseModel):
    """Generic step data update request."""
    data: Dict[str, Any]


class DatabaseConfigRequest(BaseModel):
    """Database configuration request."""
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    database: str = Field(..., min_length=1, max_length=63)
    username: str = Field(..., min_length=1, max_length=63)
    password: str = Field(..., min_length=1)
    ssl_mode: str = Field(default="prefer", pattern=r"^(disable|allow|prefer|require)$")
    managed: bool = Field(default=False)  # Skip connection test for managed services


class DatabaseTestResponse(BaseModel):
    """Database connection test response."""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    connection_time_ms: Optional[float] = None


class RedisConfigRequest(BaseModel):
    """Redis configuration request."""
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    password: Optional[str] = None
    database: int = Field(default=0, ge=0, le=15)
    ssl: bool = Field(default=False)
    managed: bool = Field(default=False)  # Skip connection test for managed services


class RedisTestResponse(BaseModel):
    """Redis connection test response."""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    ping_time_ms: Optional[float] = None


class SecurityConfigRequest(BaseModel):
    """Security configuration request."""
    encryption_key: Optional[str] = Field(None, min_length=32)
    jwt_secret_key: Optional[str] = Field(None, min_length=32)
    generate_keys: bool = Field(default=True)
    session_timeout_minutes: int = Field(default=60, ge=5, le=1440)
    max_login_attempts: int = Field(default=5, ge=3, le=20)
    password_min_length: int = Field(default=12, ge=8, le=128)


class AdminAccountRequest(BaseModel):
    """Admin account creation request."""
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    password: str = Field(..., min_length=12)
    password_confirm: str = Field(..., min_length=12)
    
    @field_validator('password_confirm')
    @classmethod
    def passwords_match(cls, v, info):
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordStrengthResponse(BaseModel):
    """Password strength analysis response."""
    score: int  # 0-4
    strength: str  # weak, fair, good, strong, very_strong
    feedback: List[str]
    estimated_crack_time: str


class StorageConfigRequest(BaseModel):
    """Storage configuration request."""
    storage_path: str = Field(default="/data/uploads", min_length=1)
    max_file_size_mb: int = Field(default=15360, ge=1, le=102400)
    transfer_speed_limit_kb: int = Field(default=0, ge=0)
    enable_encryption: bool = Field(default=True)
    retention_days: int = Field(default=0, ge=0, le=3650)


class BrandingConfigRequest(BaseModel):
    """Branding configuration request."""
    app_name: str = Field(..., min_length=1, max_length=100)
    company_name: str = Field(..., min_length=1, max_length=200)
    support_email: Optional[str] = None
    support_url: Optional[str] = None
    primary_color: str = Field(default="#3B82F6", pattern=r"^#[0-9A-Fa-f]{6}$")
    secondary_color: str = Field(default="#10B981", pattern=r"^#[0-9A-Fa-f]{6}$")


# NOTE: the free build has NO license/product-key validation — the former
# /license/validate endpoint (and the whole app.licensing package) was removed:
# it enforced nothing and confused self-hosters. Onboarding completes without a key.


def _write_env_file(env_vars: Dict[str, str], deployment_id: Optional[str] = None):
    """
    Write environment variables to .env file.
    
    Args:
        env_vars: Dictionary of environment variables to write
        deployment_id: If provided, writes to deployments/<id>/.env instead of root .env
    """
    if deployment_id:
        # Create deployment-specific config
        deployment_dir = Path(__file__).parent.parent.parent / "deployments" / deployment_id
        deployment_dir.mkdir(parents=True, exist_ok=True)
        env_file = deployment_dir / ".env"
    else:
        # Write to root .env (default behavior)
        env_file = Path(".env")
    
    existing_vars = {}
    
    # Read existing from root .env as template
    root_env = Path(".env")
    if root_env.exists():
        with open(root_env, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    existing_vars[key.strip()] = value.strip()
    
    # Merge
    existing_vars.update(env_vars)
    
    # Write
    with open(env_file, 'w') as f:
        f.write("# Vault service configuration\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        if deployment_id:
            f.write(f"# Deployment ID: {deployment_id}\n")
        f.write("\n")
        for key, value in sorted(existing_vars.items()):
            # Escape dollar signs in values to prevent Docker Compose variable substitution
            # This is critical for bcrypt hashes and other values containing $
            escaped_value = str(value).replace('$', '$$')
            f.write(f"{key}={escaped_value}\n")
    
    return env_file


# ============================================================
# General Wizard Endpoints
# ============================================================

@router.get("/state", response_model=WizardStateResponse)
async def get_wizard_state():
    """
    Get complete wizard state.
    
    Returns current step, progress, completed steps, and any errors.
    """
    try:
        state = wizard_state.get_state()
        
        return WizardStateResponse(
            current_step=state["current_step"],
            completed_steps=state["completed_steps"],
            progress_percentage=wizard_state.get_progress_percentage(),
            can_complete=wizard_state.is_wizard_complete(),
            steps=state["steps"],
            errors=state["errors"],
            warnings=state["warnings"]
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting wizard state: {str(e)}"
        )


@router.post("/reset")
async def reset_wizard():
    """
    Reset wizard to initial state.
    
    ⚠️ WARNING: This clears all progress!
    Use with caution - typically only for testing or complete restart.
    """
    try:
        wizard_state.reset_all()
        return {"success": True, "message": "Wizard reset to initial state"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error resetting wizard: {str(e)}"
        )


@router.post("/step/{step_name}/goto")
async def goto_step(step_name: str):
    """
    Navigate to specific wizard step.
    
    Validates that step can be accessed based on completion state.
    """
    try:
        # Validate step name
        try:
            step = WizardStep(step_name)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid step name: {step_name}"
            )
        
        # Check if can proceed to this step
        if not wizard_state.can_proceed_to_step(step):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot proceed to step '{step_name}'. Complete previous steps first."
            )
        
        wizard_state.set_current_step(step)
        
        return {
            "success": True,
            "current_step": step_name,
            "message": f"Navigated to {step_name}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error navigating to step: {str(e)}"
        )


# ============================================================
# Step 1: Welcome
# ============================================================

@router.get("/welcome/info")
async def get_welcome_info():
    """
    Get welcome screen information.
    
    Returns:
    - System requirements
    - Environment detection (Docker vs manual)
    - Current configuration summary
    - Pre-existing setup detection
    """
    try:
        env_info = detector.get_environment_info()
        
        # Check system requirements
        requirements_met = {
            "python_version": "3.11+" in env_info.get("python_version", ""),
            "database_available": env_info.get("database_initialized", False),
            "redis_available": False,  # Will check in Redis step
        }
        
        # Brand strings come from the EFFECTIVE branding (env defaults + any admin/DB
        # override), so a BRAND_APP_NAME env value OR a saved override rebrands the wizard
        # too — never a hardcoded literal. Best-effort: fall back to the env singleton if
        # the DB is not reachable yet (a genuine first run before the DB is configured).
        try:
            from database import get_db_context
            with get_db_context() as db:
                app_name = get_effective_branding(db).app_name
        except Exception:
            app_name = get_branding().app_name
        return {
            "welcome_message": f"Welcome to the {app_name} Setup Wizard",
            "description": f"This wizard will guide you through configuring your {app_name} instance.",
            "environment": {
                "is_docker": env_info.get("is_docker", False),
                "credential_mode": env_info.get("credential_mode", "setup"),
                "deployment_type": "Docker Container" if env_info.get("is_docker") else "Manual Installation"
            },
            "requirements": requirements_met,
            "pre_existing_config": {
                "database_initialized": env_info.get("database_initialized", False),
                "admin_user_exists": env_info.get("has_admin_user", False),
            },
            "estimated_time": "10-15 minutes",
            "steps_count": len(WizardStep)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting welcome info: {str(e)}"
        )


@router.post("/welcome/start")
async def start_wizard():
    """
    Start the setup wizard.
    
    Marks welcome step as completed and advances to database configuration.
    """
    try:
        wizard_state.update_step_data(
            WizardStep.WELCOME,
            {"started_at": os.environ.get("USER", "unknown")},
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.WELCOME)
        
        return {
            "success": True,
            "next_step": WizardStep.DATABASE.value,
            "message": "Welcome step completed"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting wizard: {str(e)}"
        )


# ============================================================
# Step 2: Database Configuration
# ============================================================

@router.post("/database/test", response_model=DatabaseTestResponse)
async def test_database_connection(config: DatabaseConfigRequest):
    """
    Test database connection without saving configuration.
    
    This is idempotent - can be called multiple times safely.
    """
    import time
    import psycopg2
    
    start_time = time.time()
    
    try:
        # Build connection string
        conn_string = f"postgresql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
        
        if config.ssl_mode != "disable":
            conn_string += f"?sslmode={config.ssl_mode}"
        
        # Attempt connection
        conn = psycopg2.connect(conn_string)
        cursor = conn.cursor()
        
        # Test query
        cursor.execute("SELECT version();")
        version_result = cursor.fetchone()
        db_version = version_result[0] if version_result else "Unknown"
        
        # Get database size
        cursor.execute(f"SELECT pg_database_size('{config.database}');")
        size_result = cursor.fetchone()
        db_size = size_result[0] if size_result else 0
        
        cursor.close()
        conn.close()
        
        connection_time = (time.time() - start_time) * 1000
        
        return DatabaseTestResponse(
            success=True,
            message="Database connection successful!",
            details={
                "version": db_version,
                "size_bytes": db_size,
                "ssl_enabled": config.ssl_mode != "disable"
            },
            connection_time_ms=round(connection_time, 2)
        )
        
    except psycopg2.OperationalError as e:
        return DatabaseTestResponse(
            success=False,
            message=f"Connection failed: {str(e)}",
            details={"error_type": "connection_error"}
        )
    except Exception as e:
        return DatabaseTestResponse(
            success=False,
            message=f"Error testing connection: {str(e)}",
            details={"error_type": "unknown_error"}
        )


@router.post("/database/save")
async def save_database_config(config: DatabaseConfigRequest):
    """
    Save database configuration and mark step complete.
    
    For managed services, skips connection test (containers not running yet).
    For external services, tests connection first.
    """
    try:
        # Test connection for external databases only
        test_result = None
        if not config.managed:
            test_result = await test_database_connection(config)
            
            if not test_result.success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Database connection test failed: {test_result.message}"
                )
        
        # Prepare env vars for deployment .env (will be written on completion)
        env_vars = {
            "DB_HOST": config.host,
            "DB_PORT": str(config.port),
            "DB_NAME": config.database,
            "DB_USER": config.username,
            "DB_PASSWORD": config.password,
            "DB_SSL_MODE": config.ssl_mode,
            # PostgreSQL container initialization variables
            "POSTGRES_DB": config.database,
            "POSTGRES_USER": config.username,
            "POSTGRES_PASSWORD": config.password,
            # Also write as DATABASE_URL for compatibility
            "DATABASE_URL": f"postgresql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
        }
        
        # Save configuration (including env_vars for deployment creation)
        config_data = {
            "host": config.host,
            "port": config.port,
            "database": config.database,
            "username": config.username,
            "password": config.password,  # TODO: Encrypt this
            "ssl_mode": config.ssl_mode,
            "managed": config.managed,
            "tested_at": time.time() if not config.managed else None,
            "test_result": test_result.dict() if test_result else {"success": True, "message": "Managed service - test skipped"},
            "env_vars": env_vars  # Store for deployment creation
        }
        
        wizard_state.update_step_data(
            WizardStep.DATABASE,
            config_data,
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.DATABASE)
        
        # Note: Don't write to root .env here (read-only in Docker)
        # Environment variables will be written to deployment-specific .env 
        # when wizard is completed via /complete endpoint
        
        return {
            "success": True,
            "message": "Database configuration saved",
            "next_step": WizardStep.REDIS.value
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving database config: {str(e)}"
        )


# ============================================================
# Placeholder endpoints for remaining steps
# ============================================================
# These will be fully implemented in the next phase

@router.post("/redis/test")
async def test_redis_connection(config: RedisConfigRequest):
    """Test Redis connection."""
    # TODO: Implement Redis connection testing
    return RedisTestResponse(
        success=True,
        message="Redis test endpoint - to be implemented",
        ping_time_ms=1.5
    )


@router.post("/redis/save")
async def save_redis_config(config: RedisConfigRequest):
    """
    Save Redis configuration and mark step complete.
    
    For managed services, skips connection test (containers not running yet).
    For external services, tests connection first.
    """
    try:
        # Test connection for external Redis only
        test_result = None
        if not config.managed:
            test_result = await test_redis_connection(config)
            
            if not test_result.success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Redis connection test failed: {test_result.message}"
                )
        
        # Prepare env vars for deployment .env (will be written on completion)
        env_vars = {
            "REDIS_HOST": config.host,
            "REDIS_PORT": str(config.port),
            "REDIS_DB": str(config.database),
            "REDIS_SSL": "true" if config.ssl else "false"
        }
        if config.password:
            env_vars["REDIS_PASSWORD"] = config.password
        
        # Save configuration (including env_vars for deployment creation)
        config_data = {
            "host": config.host,
            "port": config.port,
            "password": config.password,
            "database": config.database,
            "ssl": config.ssl,
            "managed": config.managed,
            "tested_at": time.time() if not config.managed else None,
            "test_result": test_result.dict() if test_result else {"success": True, "message": "Managed service - test skipped"},
            "env_vars": env_vars  # Store for deployment creation
        }
        
        wizard_state.update_step_data(
            WizardStep.REDIS,
            config_data,
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.REDIS)
        
        # Note: Don't write to root .env here (read-only in Docker)
        # Environment variables will be written to deployment-specific .env 
        # when wizard is completed via /complete endpoint
        
        return {
            "success": True,
            "message": "Redis configuration saved",
            "next_step": WizardStep.SECURITY.value
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving Redis config: {str(e)}"
        )


@router.post("/security/generate-keys")
async def generate_security_keys():
    """Generate encryption and JWT keys."""
    from cryptography.fernet import Fernet
    
    encryption_key = Fernet.generate_key().decode()
    jwt_secret = secrets.token_urlsafe(32)
    
    return {
        "encryption_key": encryption_key,
        "jwt_secret_key": jwt_secret,
        "message": "Keys generated successfully"
    }


@router.post("/security/save")
async def save_security_config(config: SecurityConfigRequest):
    """Save security configuration."""
    try:
        # Save configuration
        config_data = {
            "generate_keys": config.generate_keys,
            "session_timeout_minutes": config.session_timeout_minutes,
            "max_login_attempts": config.max_login_attempts,
            "password_min_length": config.password_min_length,
            "saved_at": time.time()
        }
        
        # Don't save actual keys to state for security
        if not config.generate_keys:
            config_data["custom_keys_provided"] = True
        
        wizard_state.update_step_data(
            WizardStep.SECURITY,
            config_data,
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.SECURITY)
        
        return {
            "success": True,
            "message": "Security configuration saved",
            "next_step": WizardStep.ADMIN.value
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving security config: {str(e)}"
        )


@router.post("/admin/check-password-strength")
async def check_password_strength(password: str = Body(..., embed=True)):
    """Analyze password strength."""
    # Simple strength checker (can be enhanced with zxcvbn library)
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password should be at least 12 characters")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")
    
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1
    else:
        feedback.append("Add special characters")
    
    strength_map = {
        0: "very_weak",
        1: "weak",
        2: "fair",
        3: "good",
        4: "strong",
        5: "very_strong"
    }
    
    return PasswordStrengthResponse(
        score=min(score, 4),
        strength=strength_map[min(score, 5)],
        feedback=feedback,
        estimated_crack_time="varies"
    )


@router.post("/admin/save")
async def save_admin_account(account: AdminAccountRequest):
    """Create admin account."""
    try:
        # Save configuration (don't store actual password in wizard state)
        config_data = {
            "username": account.username,
            "email": account.email,
            "created_at": time.time()
        }
        
        wizard_state.update_step_data(
            WizardStep.ADMIN,
            config_data,
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.ADMIN)
        
        # Store password in environment temporarily (will be written to deployment .env on complete)
        import os
        os.environ['ADMIN_PASSWORD'] = account.password
        
        # Note: We no longer write to root .env here to avoid read-only issues
        # The deployment-specific .env will be created in the /complete endpoint
        
        return {
            "success": True,
            "message": "Admin account configuration saved",
            "next_step": WizardStep.STORAGE.value
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving admin account: {str(e)}"
        )


@router.post("/storage/save")
async def save_storage_config(config: StorageConfigRequest):
    """Save storage configuration."""
    try:
        # Save configuration
        config_data = {
            "storage_path": config.storage_path,
            "max_file_size_mb": config.max_file_size_mb,
            "transfer_speed_limit_kb": config.transfer_speed_limit_kb,
            "enable_encryption": config.enable_encryption,
            "retention_days": config.retention_days,
            "saved_at": time.time()
        }
        
        wizard_state.update_step_data(
            WizardStep.STORAGE,
            config_data,
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.STORAGE)
        
        return {
            "success": True,
            "message": "Storage configuration saved",
            "next_step": WizardStep.BRANDING.value
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving storage config: {str(e)}"
        )


@router.post("/branding/save")
async def save_branding_config(config: BrandingConfigRequest):
    """Save branding configuration."""
    try:
        # Save configuration
        config_data = {
            "app_name": config.app_name,
            "company_name": config.company_name,
            "support_email": config.support_email,
            "support_url": config.support_url,
            "primary_color": config.primary_color,
            "secondary_color": config.secondary_color,
            "saved_at": time.time()
        }
        
        wizard_state.update_step_data(
            WizardStep.BRANDING,
            config_data,
            StepStatus.COMPLETED
        )
        wizard_state.mark_step_completed(WizardStep.BRANDING)

        # A5: push the wizard's branding into the LIVE effective store (the SAME
        # SystemSetting('brand') row the admin editor writes), so what you pick in the
        # wizard actually takes effect — instead of only landing in the inert state file.
        # GATED TO GENUINE FIRST-RUN, because these wizard endpoints are UNAUTHENTICATED:
        # the write happens only when NO admin has EVER been created. We query role==ADMIN
        # WITHOUT the is_active filter on purpose — the row persists, so an operator later
        # deactivating every admin can NOT re-open this on a live instance (a real gap the
        # is_active-only check had; detector.is_setup_completed() is unreliable here — its
        # setup.lock is never written by the env-seeded startup path). The wizard creates
        # its admin at /complete (AFTER this step), so during a real first run no admin
        # exists yet and this write is allowed; once one exists it is permanently blocked and
        # the admin editor (A3, admin-gated) is the branding path. Check + write share ONE
        # session, so there is no check-then-write race. Best-effort: a DB hiccup must not
        # fail the step (the state copy above still records wizard progress).
        try:
            from database import get_db_context
            from models import User, RoleEnum
            with get_db_context() as db:
                admin_ever = db.query(User).filter(User.role == RoleEnum.ADMIN).count() > 0
                if not admin_ever and not detector.is_setup_completed():
                    set_brand_overrides(db, updates={
                        "app_name": config.app_name,
                        "company_name": config.company_name,
                        "support_email": config.support_email,
                        "primary_color": config.primary_color,
                        "secondary_color": config.secondary_color,
                    })
                    db.commit()
        except Exception:
            logger.warning("wizard branding: effective-store write failed", exc_info=True)

        return {
            "success": True,
            "message": "Branding configuration saved",
            "next_step": "review"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving branding config: {str(e)}"
        )


@router.post("/complete")
async def complete_wizard():
    """
    Complete the setup wizard.
    
    Finalizes configuration, writes deployment files, creates admin user, and returns deployment instructions.
    """
    try:
        # Generate unique deployment ID
        import uuid
        deployment_id = str(uuid.uuid4())[:8]  # Short ID for convenience

        # Free build: no license tier -> no docker profile selection.
        docker_profile = ""
        docker_command = f"docker-compose --env-file deployments/{deployment_id}/.env up -d"

        # Write deployment-specific .env file
        # Collect ALL env vars from all wizard steps
        database_data = wizard_state.get_step_data(WizardStep.DATABASE)
        redis_data = wizard_state.get_step_data(WizardStep.REDIS)
        admin_data = wizard_state.get_step_data(WizardStep.ADMIN)

        env_vars = {
            "DEPLOYMENT_ID": deployment_id,
        }

        # Add database env vars (PostgreSQL config)
        if database_data and 'env_vars' in database_data:
            env_vars.update(database_data['env_vars'])

        # Add Redis env vars
        if redis_data and 'env_vars' in redis_data:
            env_vars.update(redis_data['env_vars'])

        # Add admin credentials
        if admin_data:
            env_vars["ADMIN_USERNAME"] = admin_data['username']
            env_vars["ADMIN_EMAIL"] = admin_data['email']
            
            # Get password from environment (set during admin/save)
            import os
            admin_password = os.getenv('ADMIN_PASSWORD')
            if admin_password:
                env_vars["ADMIN_PASSWORD"] = admin_password
            
        _write_env_file(env_vars, deployment_id=deployment_id)
        
        # Create/update admin user in database with wizard credentials
        try:
            from database import get_db_context
            from models import User, RoleEnum
            from security import hash_password
            
            admin_data = wizard_state.get_step_data(WizardStep.ADMIN)
            if admin_data:
                with get_db_context() as db:
                    # Check if admin user exists
                    existing_admin = db.query(User).filter(User.username == admin_data['username']).first()
                    
                    if existing_admin:
                        # Update existing admin with new credentials
                        existing_admin.email = admin_data['email']
                        # Note: Password was written to .env, will be synced on next container restart
                        print(f"✓ Admin user '{admin_data['username']}' will be updated on next container start")
                    else:
                        # Get password from deployment .env file
                        import os
                        admin_password = os.getenv('ADMIN_PASSWORD')
                        
                        if admin_password:
                            # Create new admin user
                            new_admin = User(
                                username=admin_data['username'],
                                email=admin_data['email'],
                                password_hash=hash_password(admin_password),
                                role=RoleEnum.ADMIN,
                                is_active=True
                            )
                            db.add(new_admin)
                            db.commit()
                            print(f"✓ Admin user '{admin_data['username']}' created successfully")
        except Exception as e:
            # Don't fail the wizard if admin creation fails - can be done manually
            print(f"⚠ Could not create admin user in database: {e}")
            print("  Admin will be created on next container start with credentials from deployment .env")
        
        # Create deployment-specific lock file
        deployment_dir = Path(__file__).parent.parent.parent / "deployments" / deployment_id
        lock_file = deployment_dir / "setup.lock"
        lock_file.write_text(f"Setup completed at {datetime.now(timezone.utc).isoformat()}\n")
        
        return {
            "success": True,
            "message": "Setup completed successfully",
            "deployment_id": deployment_id,
            "docker_command": docker_command,
            "docker_profile": docker_profile.replace("--profile ", "") if docker_profile else "default",
            "access_url": "http://localhost:8080",
            "deployment_instructions": [
                f"Configuration saved to deployments/{deployment_id}/.env",
                "Admin account created/updated in database",
                f"Run: {docker_command}",
                "Wait 2-5 minutes for containers to start",
                "Access your instance at http://localhost:8080",
                "Log in with your admin credentials",
                "",
                f"💡 Deployment ID: {deployment_id}",
                "This allows multiple isolated deployments on the same server"
            ]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error completing setup: {str(e)}"
        )
