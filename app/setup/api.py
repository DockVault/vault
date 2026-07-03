"""
Setup API Endpoints

Provides REST API endpoints for:
- Setup status checking
- Setup wizard steps (future)
- Setup completion
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Optional, List, Any

from app.setup import detector, SetupState, CredentialMode


# ============================================================
# API Router
# ============================================================

router = APIRouter(prefix="/setup", tags=["setup"])


# ============================================================
# Response Models
# ============================================================

class SetupStatusResponse(BaseModel):
    """Setup status response model."""
    setup_state: str
    setup_completed: bool
    needs_setup: bool
    is_docker: bool
    credential_mode: str
    database_initialized: bool
    database_error: Optional[str]
    has_admin_user: bool
    admin_error: Optional[str]
    has_setup_lock: bool
    recommendations: List[str]


class SetupLockResponse(BaseModel):
    """Setup lock file response model."""
    exists: bool
    completed: bool
    completed_at: Optional[str]
    completed_by: Optional[str]
    setup_mode: Optional[str]
    credential_mode: Optional[str]
    is_docker: Optional[bool]


class DetailedStatusResponse(BaseModel):
    """Detailed setup status response model."""
    setup_state: str
    setup_completed: bool
    needs_setup: bool
    environment: Dict[str, Any]
    setup_lock: Optional[Dict[str, Any]]
    recommendations: List[str]


# ============================================================
# API Endpoints
# ============================================================

@router.get(
    "/status",
    response_model=SetupStatusResponse,
    summary="Get setup status",
    description="Check if the vault service needs initial setup and get current state"
)
async def get_setup_status():
    """
    Get current setup status.
    
    Returns information about:
    - Setup completion state
    - Database initialization
    - Admin user existence
    - Credential mode
    - Docker environment detection
    - Recommendations for next steps
    """
    try:
        setup_state = detector.get_setup_state()
        env_info = detector.get_environment_info()
        detailed = detector.get_detailed_status()
        
        return SetupStatusResponse(
            setup_state=setup_state.value,
            setup_completed=detector.is_setup_completed(),
            needs_setup=detector.needs_setup(),
            is_docker=env_info["is_docker"],
            credential_mode=env_info["credential_mode"],
            database_initialized=env_info["database_initialized"],
            database_error=env_info.get("database_error"),
            has_admin_user=env_info["has_admin_user"],
            admin_error=env_info.get("admin_error"),
            has_setup_lock=env_info["has_setup_lock"],
            recommendations=detailed["recommendations"]
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking setup status: {str(e)}"
        )


@router.get(
    "/detailed",
    response_model=DetailedStatusResponse,
    summary="Get detailed setup status",
    description="Get comprehensive setup status with full environment information"
)
async def get_detailed_setup_status():
    """
    Get detailed setup status with full environment information.
    
    Includes:
    - All status checks
    - Environment variables
    - Setup lock file contents
    - Detailed recommendations
    """
    try:
        detailed = detector.get_detailed_status()
        return DetailedStatusResponse(**detailed)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting detailed status: {str(e)}"
        )


@router.get(
    "/lock",
    response_model=SetupLockResponse,
    summary="Get setup lock file info",
    description="Get information about the setup.lock file"
)
async def get_setup_lock_info():
    """
    Get setup lock file information.
    
    Returns details about when and how setup was completed.
    """
    try:
        lock_exists = detector.setup_lock_path.exists()
        
        if not lock_exists:
            return SetupLockResponse(
                exists=False,
                completed=False,
                completed_at=None,
                completed_by=None,
                setup_mode=None,
                credential_mode=None,
                is_docker=None
            )
        
        lock_data = detector._read_setup_lock()
        
        return SetupLockResponse(
            exists=True,
            completed=lock_data.get("completed", False),
            completed_at=lock_data.get("completed_at"),
            completed_by=lock_data.get("completed_by"),
            setup_mode=lock_data.get("setup_mode"),
            credential_mode=lock_data.get("credential_mode"),
            is_docker=lock_data.get("is_docker")
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading setup lock: {str(e)}"
        )


@router.post(
    "/complete",
    response_model=Dict[str, Any],
    summary="Mark setup as complete",
    description="Create setup.lock file to mark setup as completed (admin only)"
)
async def complete_setup(
    completed_by: Optional[str] = None,
    setup_mode: Optional[str] = None
):
    """
    Mark setup as completed by creating setup.lock file.
    
    Args:
        completed_by: Username of who completed setup
        setup_mode: How setup was completed (wizard/docker/manual)
    
    ⚠️  This should only be called after all setup steps are completed!
    """
    try:
        # TODO: Add authentication check (admin only)
        
        success = detector.create_setup_lock(
            completed_by=completed_by,
            setup_mode=setup_mode
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create setup lock file"
            )
        
        return {
            "success": True,
            "message": "Setup marked as completed",
            "setup_state": detector.get_setup_state().value
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error completing setup: {str(e)}"
        )


# ============================================================
# Future Endpoints (Placeholder)
# ============================================================
# 
# These will be implemented in Tasks #4-11:
#
# @router.get("/welcome")
# - Get welcome screen with system requirements
#
# @router.post("/database/test")
# - Test database connection
#
# @router.post("/redis/test")
# - Test Redis connection
#
# @router.post("/keys/generate")
# - Generate encryption keys
#
# @router.post("/admin/create")
# - Create admin account
#
# @router.post("/storage/configure")
# - Configure file storage
#
# @router.post("/branding/configure")
# - Configure branding
#
# @router.get("/summary")
# - Get configuration summary
# 
# ============================================================
