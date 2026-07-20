"""
Configurable Branding System.

This module provides a centralized configuration for all branding-related settings,
allowing the application to be easily white-labeled and customized.

All branding settings can be overridden via environment variables with the BRAND_ prefix.

Defaults are the DockVault brand: a fresh / self-hosted build with no overrides shows
DockVault (name, logo, favicon, in-vault title), so the free product keeps the DockVault
identity. Any deployment can OVERRIDE the brand — at deploy time via BRAND_* env (the SaaS
injects each customer's brand at provision) or live via the admin Settings editor — so the
same code serves both a DockVault-branded free instance and a per-tenant-branded paid one.
The one thing that is NOT part of the editable brand set is the "powered by" attribution
below (a tenant cannot remove it via the editor; only a deploy-level env flag can hide it).
"""

import os
import re
from typing import Optional

try:
    # Pydantic v2+ (moved to pydantic-settings)
    from pydantic_settings import BaseSettings
except ImportError:
    # Pydantic v1 (fallback)
    from pydantic import BaseSettings

from pydantic import Field, validator


# Strict hex-colour pattern: ``#rgb`` or ``#rrggbb`` and NOTHING else. Shared as a
# module constant so the admin brand write path (api_server ``_validate_brand_overrides``,
# A3) validates identically to the model validator below — a length-only check would
# pass CSS metacharacters like ``#}body{`` that break out of a ``:root { … }`` rule once
# the UI injects the value, enabling style-injection / ``url()`` exfil.
HEX_COLOR_RE = re.compile(r'^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$')


def _read_version_file() -> str:
    """The app's own version, read from the baked VERSION file (repo root, copied to /app/VERSION
    in the image). Single source of truth: bump VERSION to cut a release. Falls back to a
    placeholder if the file is missing so branding never fails to load."""
    here = os.path.dirname(os.path.abspath(__file__))
    for path in ("/app/VERSION", os.path.join(here, "..", "..", "VERSION")):
        try:
            value = open(path, encoding="utf-8").read().strip()
            if value:
                return value
        except OSError:
            pass
    return "0.0.0"


class BrandingConfig(BaseSettings):
    """
    Application branding configuration.
    
    All settings can be overridden via environment variables with BRAND_ prefix.
    Example: BRAND_APP_NAME="My Custom App"
    
    This enables:
    - Easy rebranding without code changes
    - White-label deployments for resellers
    - Different branding for dev/staging/production
    - Per-tenant branding (for SaaS multi-tenant)
    """
    
    # ========================================
    # Product Identity
    # ========================================
    
    app_name: str = Field(
        default="DockVault",
        description="Short product name (used in titles, CLI, logs)"
    )
    
    app_full_name: str = Field(
        default="Secure File Transfer Platform",
        description="Full descriptive product name"
    )
    
    app_tagline: str = Field(
        default="Encrypted SFTP with Zero-Knowledge Architecture",
        description="Marketing tagline"
    )
    
    app_description: str = Field(
        default="Enterprise-grade secure file transfer with end-to-end encryption, "
                "vault-based organization, and SFTP access.",
        description="Detailed product description"
    )
    
    app_version: str = Field(
        default_factory=_read_version_file,
        description="Current application version (from the VERSION file; override with BRAND_APP_VERSION)"
    )
    
    # ========================================
    # Company Information
    # ========================================
    
    company_name: str = Field(
        default="DockVault",
        description="Company or organization name"
    )
    
    company_url: str = Field(
        default="https://dockvault.io",
        description="Company website URL"
    )

    support_email: str = Field(
        default="support@dockvault.io",
        description="Support email address"
    )

    contact_email: str = Field(
        default="contact@dockvault.io",
        description="General contact email"
    )

    sales_email: str = Field(
        default="sales@dockvault.io",
        description="Sales inquiries email"
    )
    
    # ========================================
    # URLs
    # ========================================
    
    website_url: str = Field(
        default="https://dockvault.io",
        description="Main product website URL"
    )

    docs_url: str = Field(
        default="https://docs.dockvault.io",
        description="Documentation website URL"
    )

    api_docs_url: str = Field(
        default="https://docs.dockvault.io/api",
        description="API documentation URL"
    )

    status_url: str = Field(
        default="https://status.dockvault.io",
        description="System status page URL"
    )

    blog_url: str = Field(
        default="https://blog.dockvault.io",
        description="Blog URL"
    )
    
    # ========================================
    # Branding Assets
    # ========================================
    
    # Defaults point at the real bundled DockVault assets (static/assets/*.png). The UI shell
    # consumes these via /branding, so a default MUST resolve to a file that exists
    # — the old /static/logo.svg / /static/favicon.ico paths had no backing file. The
    # an admin upload path (POST /settings/brand/asset/{slot}) that overrides these at
    # runtime (served from /brand-assets/); these defaults are the DockVault logo/favicon.
    logo_url: str = Field(
        default="/static/assets/logo.png",
        description="Main logo URL (light theme)"
    )

    logo_dark_url: str = Field(
        default="/static/assets/logo.png",
        description="Logo for dark theme"
    )

    logo_small_url: str = Field(
        default="/static/assets/logo-small.png",
        description="Small logo (for header/sidebar/favicon)"
    )

    favicon_url: str = Field(
        default="/static/assets/logo-small.png",
        description="Favicon URL"
    )

    og_image_url: str = Field(
        default="/static/assets/logo.png",
        description="Open Graph image for social sharing"
    )
    
    # ========================================
    # Theme Colors (CSS color values)
    # ========================================
    
    primary_color: str = Field(
        default="#2563eb",
        description="Primary brand color (hex)"
    )
    
    secondary_color: str = Field(
        default="#7c3aed",
        description="Secondary brand color (hex)"
    )
    
    accent_color: str = Field(
        default="#10b981",
        description="Accent color (hex)"
    )
    
    success_color: str = Field(
        default="#10b981",
        description="Success state color (hex)"
    )
    
    warning_color: str = Field(
        default="#f59e0b",
        description="Warning state color (hex)"
    )
    
    error_color: str = Field(
        default="#ef4444",
        description="Error state color (hex)"
    )
    
    text_color: str = Field(
        default="#1f2937",
        description="Primary text color (hex)"
    )
    
    background_color: str = Field(
        default="#ffffff",
        description="Background color (hex)"
    )
    
    # ========================================
    # Legal
    # ========================================
    
    privacy_policy_url: str = Field(
        default="https://dockvault.io/privacy",
        description="Privacy policy URL"
    )

    terms_of_service_url: str = Field(
        default="https://dockvault.io/terms",
        description="Terms of service URL"
    )

    cookie_policy_url: str = Field(
        default="https://dockvault.io/cookies",
        description="Cookie policy URL"
    )

    dpa_url: str = Field(
        default="https://dockvault.io/dpa",
        description="Data Processing Agreement URL"
    )

    sla_url: str = Field(
        default="https://dockvault.io/sla",
        description="Service Level Agreement URL"
    )
    
    # ========================================
    # Features & Capabilities
    # ========================================
    
    enable_signup: bool = Field(
        default=True,
        description="Allow new user signups"
    )
    
    enable_trial: bool = Field(
        default=True,
        description="Offer free trial period"
    )
    
    trial_days: int = Field(
        default=14,
        description="Trial period duration in days"
    )
    
    enable_sso: bool = Field(
        default=False,
        description="Enable Single Sign-On"
    )
    
    enable_2fa: bool = Field(
        default=False,
        description="Advertise Two-Factor Authentication support (no built-in TOTP yet; kept as a "
                    "forward-compatible flag / for a front-door MFA proxy). Defaults off so a stock "
                    "deployment doesn't advertise a capability it doesn't provide."
    )
    
    enable_api: bool = Field(
        default=True,
        description="Enable REST API access"
    )
    
    enable_sftp: bool = Field(
        default=True,
        description="Enable SFTP server"
    )
    
    # ========================================
    # Social Media
    # ========================================
    
    twitter_handle: Optional[str] = Field(
        default="@dockvault",
        description="Twitter handle (with @)"
    )

    github_url: Optional[str] = Field(
        default="https://github.com/DockVault/vault",
        description="GitHub repository URL"
    )
    
    linkedin_url: Optional[str] = Field(
        default=None,
        description="LinkedIn company page URL"
    )
    
    facebook_url: Optional[str] = Field(
        default=None,
        description="Facebook page URL"
    )
    
    youtube_url: Optional[str] = Field(
        default=None,
        description="YouTube channel URL"
    )
    
    # ========================================
    # Analytics & Tracking
    # ========================================
    
    google_analytics_id: Optional[str] = Field(
        default=None,
        description="Google Analytics tracking ID (GA4)"
    )
    
    mixpanel_token: Optional[str] = Field(
        default=None,
        description="Mixpanel project token"
    )
    
    sentry_dsn: Optional[str] = Field(
        default=None,
        description="Sentry DSN for error tracking"
    )
    
    # ========================================
    # Copyright
    # ========================================
    
    copyright_year: int = Field(
        default=2025,
        description="Copyright start year"
    )
    
    copyright_holder: str = Field(
        default="DockVault",
        description="Copyright holder name"
    )

    # ========================================
    # Attribution ("powered by")
    # ========================================
    # A persistent product attribution shown on the login page. Intentionally NOT part of the
    # admin-editable brand set (see api_server._BRAND_FIELDS): a tenant customizing their own
    # instance CANNOT remove it. It is configurable only via env at deploy time — e.g. a
    # premium tier that pays to hide it sets BRAND_SHOW_POWERED_BY=false. Defaults keep the
    # DockVault attribution on every free / self-hosted instance for brand reach.
    show_powered_by: bool = Field(
        default=True,
        description="Show the persistent 'powered by' attribution on the login page"
    )
    powered_by_name: str = Field(
        default="DockVault",
        description="Attribution product name (the 'powered by <name>')"
    )
    powered_by_url: str = Field(
        default="https://dockvault.io",
        description="Attribution link URL"
    )

    # ========================================
    # Validators
    # ========================================
    
    @validator('primary_color', 'secondary_color', 'accent_color',
               'success_color', 'warning_color', 'error_color',
               'text_color', 'background_color')
    def validate_color(cls, v):
        """Validate a strict hex colour (``#rgb`` or ``#rrggbb``).

        Only ``#`` + 3 or 6 hex digits are allowed — no other characters. A length-only
        check (``len in (4, 7)``) would pass CSS metacharacters like ``#}body{`` which,
        once injected into a ``:root { --primary-color: … }`` block by the UI, break
        out of the rule and enable style-injection / ``url()`` exfil. The strict pattern
        closes that at the source and, being shared, hardens the A3 admin write path too.
        """
        if not HEX_COLOR_RE.match(v):
            raise ValueError(f"Invalid hex color format: {v}")
        return v.lower()
    
    @validator('trial_days')
    def validate_trial_days(cls, v):
        """Validate trial days is positive"""
        if v < 0:
            raise ValueError("Trial days must be non-negative")
        return v
    
    @validator('support_email', 'contact_email', 'sales_email')
    def validate_email(cls, v):
        """Basic email validation"""
        if '@' not in v:
            raise ValueError(f"Invalid email format: {v}")
        return v.lower()

    @validator('app_version', always=True)
    def _fill_version(cls, v):
        """Collapse an empty version (e.g. an unset BRAND_APP_VERSION from a plain image build's
        empty --build-arg) back to the VERSION file, so the app never reports a blank version."""
        v = (v or "").strip()
        return v if v else _read_version_file()
    
    # ========================================
    # Helper Methods
    # ========================================
    
    def get_copyright_notice(self) -> str:
        """Get formatted copyright notice"""
        from datetime import datetime, timezone
        current_year = datetime.now(timezone.utc).year
        
        if current_year == self.copyright_year:
            return f"© {current_year} {self.copyright_holder}. All rights reserved."
        else:
            return f"© {self.copyright_year}-{current_year} {self.copyright_holder}. All rights reserved."
    
    def get_theme_css_vars(self) -> dict:
        """Get theme colors as CSS custom properties"""
        return {
            '--primary-color': self.primary_color,
            '--secondary-color': self.secondary_color,
            '--accent-color': self.accent_color,
            '--success-color': self.success_color,
            '--warning-color': self.warning_color,
            '--error-color': self.error_color,
            '--text-color': self.text_color,
            '--background-color': self.background_color,
        }
    
    def to_dict(self) -> dict:
        """Convert to dictionary (for API responses)"""
        return self.dict()
    
    def to_public_dict(self) -> dict:
        """Convert to dictionary with only public information (no sensitive data)"""
        return {
            'app_name': self.app_name,
            'app_full_name': self.app_full_name,
            'app_tagline': self.app_tagline,
            'app_description': self.app_description,
            'app_version': self.app_version,
            'company_name': self.company_name,
            'company_url': self.company_url,
            'support_email': self.support_email,
            'website_url': self.website_url,
            'docs_url': self.docs_url,
            'logo_url': self.logo_url,
            'primary_color': self.primary_color,
            'secondary_color': self.secondary_color,
            'copyright_notice': self.get_copyright_notice(),
        }
    
    class Config:
        env_file = ".env"
        env_prefix = "BRAND_"
        case_sensitive = False
        extra = "ignore"  # Ignore non-branding env vars from .env file


# ========================================
# Global Singleton Instance
# ========================================

# Create singleton instance that loads from environment
branding = BrandingConfig()


# ========================================
# Helper Functions
# ========================================

def get_branding() -> BrandingConfig:
    """Get the global branding configuration instance"""
    return branding


def reload_branding() -> BrandingConfig:
    """Reload branding configuration from environment (useful for testing)"""
    global branding
    branding = BrandingConfig()
    return branding


def get_app_info() -> dict:
    """Get basic application information"""
    return {
        'name': branding.app_name,
        'full_name': branding.app_full_name,
        'version': branding.app_version,
        'tagline': branding.app_tagline,
    }


def get_company_info() -> dict:
    """Get company information"""
    return {
        'name': branding.company_name,
        'website': branding.company_url,
        'support_email': branding.support_email,
        'contact_email': branding.contact_email,
    }


def get_social_links() -> dict:
    """Get social media links (only non-null values)"""
    links = {}
    if branding.twitter_handle:
        links['twitter'] = f"https://twitter.com/{branding.twitter_handle.lstrip('@')}"
    if branding.github_url:
        links['github'] = branding.github_url
    if branding.linkedin_url:
        links['linkedin'] = branding.linkedin_url
    if branding.facebook_url:
        links['facebook'] = branding.facebook_url
    if branding.youtube_url:
        links['youtube'] = branding.youtube_url
    return links


# ========================================
# Example Usage
# ========================================

if __name__ == "__main__":
    """
    Test the branding configuration.
    
    Run this file directly to see current branding settings:
        python -m app.config.branding
    """
    import json
    
    print("=" * 60)
    print(f" {branding.app_name} - Branding Configuration")
    print("=" * 60)
    print()
    
    print("📱 Product Info:")
    print(f"  Name: {branding.app_name}")
    print(f"  Full Name: {branding.app_full_name}")
    print(f"  Version: {branding.app_version}")
    print(f"  Tagline: {branding.app_tagline}")
    print()
    
    print("🏢 Company Info:")
    print(f"  Name: {branding.company_name}")
    print(f"  Website: {branding.company_url}")
    print(f"  Support: {branding.support_email}")
    print()
    
    print("🎨 Theme Colors:")
    for key, value in branding.get_theme_css_vars().items():
        print(f"  {key}: {value}")
    print()
    
    print("⚙️  Features:")
    print(f"  Signup Enabled: {branding.enable_signup}")
    print(f"  Trial Enabled: {branding.enable_trial} ({branding.trial_days} days)")
    print(f"  2FA Enabled: {branding.enable_2fa}")
    print(f"  API Enabled: {branding.enable_api}")
    print(f"  SFTP Enabled: {branding.enable_sftp}")
    print()
    
    print("🔗 Social Links:")
    for platform, url in get_social_links().items():
        print(f"  {platform.capitalize()}: {url}")
    print()
    
    print("©️  Copyright:")
    print(f"  {branding.get_copyright_notice()}")
    print()
    
    print("📋 Public API Response:")
    print(json.dumps(branding.to_public_dict(), indent=2))
