"""
Information and branding endpoints.

These endpoints provide public information about the application, including branding
configuration, features, and system information.

Branding chrome (``/branding``, ``/info``, ``/theme``, ``/legal``, ``/contact``) is
served from the EFFECTIVE branding — env defaults with DB ``SystemSetting('brand')``
overrides layered on top (see :mod:`app.config.effective`) — so an admin edit takes
effect live, with no restart. ``/version`` and ``/features`` intentionally stay on the
process-level config: they are a liveness probe and operational capability flags, not
branding, and must not depend on a DB read.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.config.branding import branding
from app.config.effective import get_effective_branding, branding_public_payload
from database import get_db

router = APIRouter(tags=["Information"])


def _social_links(cfg) -> Dict[str, str]:
    """Social-media links from an effective BrandingConfig (only non-null values)."""
    links: Dict[str, str] = {}
    if cfg.twitter_handle:
        links["twitter"] = f"https://twitter.com/{cfg.twitter_handle.lstrip('@')}"
    if cfg.github_url:
        links["github"] = cfg.github_url
    if cfg.linkedin_url:
        links["linkedin"] = cfg.linkedin_url
    if cfg.facebook_url:
        links["facebook"] = cfg.facebook_url
    if cfg.youtube_url:
        links["youtube"] = cfg.youtube_url
    return links


@router.get("/branding", response_model=Dict[str, Any])
async def get_branding_endpoint(db: Session = Depends(get_db)):
    """
    Get the EFFECTIVE public branding.

    Env defaults with DB ``SystemSetting('brand')`` overrides layered on top. This is the
    single source of truth the UI shell reads (A2) to render the app name, logo, favicon
    and theme colours. Includes:
    - identity + company + support email + key URLs + copyright (``to_public_dict``)
    - ``colors``: the 8 theme colours as CSS custom properties (``:root`` ready)
    - ``assets``: logo / favicon / og-image URLs

    **No authentication required** — branding chrome is public. Public fields only; no secrets.
    """
    return branding_public_payload(get_effective_branding(db))


@router.get("/info", response_model=Dict[str, Any])
async def get_app_info_endpoint(db: Session = Depends(get_db)):
    """
    Get public application information.

    This endpoint provides basic information about the application including:
    - Application name, version, and description
    - Company information
    - Links to documentation and support
    - Branding configuration (colors, logos)

    **No authentication required** - this is public information.

    Returns:
        Dict containing application information and branding configuration
    """
    cfg = get_effective_branding(db)
    return {
        "app": {
            "name": cfg.app_name,
            "full_name": cfg.app_full_name,
            "version": cfg.app_version,
            "tagline": cfg.app_tagline,
        },
        "company": {
            "name": cfg.company_name,
            "website": cfg.company_url,
            "support_email": cfg.support_email,
            "contact_email": cfg.contact_email,
        },
        "branding": cfg.to_public_dict(),
        "social": _social_links(cfg),
        "copyright": cfg.get_copyright_notice(),
    }


@router.get("/features", response_model=Dict[str, Any])
async def get_features():
    """
    Get enabled features and capabilities.

    This endpoint returns which features are enabled in this deployment:
    - User signup availability
    - Trial period settings
    - API access
    - SFTP server status
    - SSO support

    Operational capability flags (not branding chrome) — read from the process-level
    config, so this endpoint stays DB-independent.

    **No authentication required** - this helps users understand capabilities.

    Returns:
        Dict of feature flags and settings
    """
    return {
        "signup": {
            "enabled": branding.enable_signup,
            "trial_enabled": branding.enable_trial,
            "trial_days": branding.trial_days if branding.enable_trial else 0,
        },
        "authentication": {
            "2fa_enabled": branding.enable_2fa,
            "sso_enabled": branding.enable_sso,
        },
        "services": {
            "api_enabled": branding.enable_api,
            "sftp_enabled": branding.enable_sftp,
        },
    }


@router.get("/theme", response_model=Dict[str, Any])
async def get_theme(db: Session = Depends(get_db)):
    """
    Get theme configuration.

    Returns CSS custom properties for theming the frontend.
    Useful for dynamically applying branding colors.

    **No authentication required** - theme is public.

    Returns:
        Dict of CSS custom properties and asset URLs
    """
    cfg = get_effective_branding(db)
    return {
        "colors": cfg.get_theme_css_vars(),
        "assets": {
            "logo": cfg.logo_url,
            "logo_dark": cfg.logo_dark_url,
            "logo_small": cfg.logo_small_url,
            "favicon": cfg.favicon_url,
            "og_image": cfg.og_image_url,
        },
    }


@router.get("/version", response_model=Dict[str, str])
async def get_version():
    """
    Get application version.

    Simple endpoint returning just the version number.
    Useful for health checks and monitoring.

    Liveness / monitoring probe — intentionally DB-independent (stays up when the DB is
    down), so it reads the process-level config, not the effective (DB-merged) branding.

    **No authentication required** - version is public.

    Returns:
        Dict with version string
    """
    return {
        "version": branding.app_version,
        "name": branding.app_name,
    }


@router.get("/legal", response_model=Dict[str, Any])
async def get_legal_links(db: Session = Depends(get_db)):
    """
    Get links to legal documents.

    Returns URLs to privacy policy, terms of service, and other legal documents.

    **No authentication required** - legal links are public.

    Returns:
        Dict of legal document URLs
    """
    cfg = get_effective_branding(db)
    return {
        "privacy_policy": cfg.privacy_policy_url,
        "terms_of_service": cfg.terms_of_service_url,
        "cookie_policy": cfg.cookie_policy_url,
        "dpa": cfg.dpa_url,
        "sla": cfg.sla_url,
    }


@router.get("/contact", response_model=Dict[str, Any])
async def get_contact_info(db: Session = Depends(get_db)):
    """
    Get contact information.

    Returns various contact methods (email, social media, support).

    **No authentication required** - contact info is public.

    Returns:
        Dict of contact information
    """
    cfg = get_effective_branding(db)
    return {
        "support": cfg.support_email,
        "contact": cfg.contact_email,
        "sales": cfg.sales_email,
        "social": _social_links(cfg),
        "status_page": cfg.status_url,
    }
