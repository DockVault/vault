"""
Configuration package for the vault service.

This package contains branding configuration.
The main application settings are still loaded from app/core/config.py.
"""

from .branding import branding, BrandingConfig

__all__ = ['branding', 'BrandingConfig']

# Note: settings is imported from the app/core/config.py module, not this package
# Use: from app.core.config import settings
# Use: from app.config.branding import branding (imports from app/config/branding.py)

