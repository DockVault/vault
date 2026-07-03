"""
Configuration package for the vault service.

This package contains branding configuration.
The main application settings are still loaded from config.py (parent module).
"""

from .branding import branding, BrandingConfig

__all__ = ['branding', 'BrandingConfig']

# Note: settings is imported from the parent config.py module, not this package
# Use: from config import settings (imports from config.py)
# Use: from config.branding import branding (imports from config/branding.py)

