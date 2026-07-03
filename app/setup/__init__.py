"""
Setup module for first-run detection and the configuration wizard.

This module provides:
- First-run detection (detector.py)
- Setup wizard API endpoints (future)
- Setup wizard frontend (future)
"""

from .detector import (
    FirstRunDetector,
    SetupState,
    CredentialMode,
    detector,
    is_setup_completed,
    needs_setup,
    get_setup_state,
    get_detailed_status,
)

__all__ = [
    "FirstRunDetector",
    "SetupState",
    "CredentialMode",
    "detector",
    "is_setup_completed",
    "needs_setup",
    "get_setup_state",
    "get_detailed_status",
]
