"""Effective branding — DB ``SystemSetting('brand')`` overrides layered over env defaults.

The single source of truth for what the running vault should render. Two stores
historically drifted apart:

  * env  -> :class:`BrandingConfig` defaults
  * DB   -> ``SystemSetting`` overrides written by the admin Settings form

This module merges the DB brand overrides on top of the env :class:`BrandingConfig`
so the ``/branding`` endpoint, UI shell, Settings forms, and email identity all see
the same *effective* values, editable at runtime with no process restart.

Readers MUST call :func:`get_effective_branding` (which re-reads the DB each call)
rather than the module-level ``branding`` singleton, or admin edits stay stale until
the process restarts.
"""

import logging
from typing import Any, Dict

from pydantic import ValidationError

from app.config.branding import BrandingConfig, get_branding

logger = logging.getLogger(__name__)

# The SystemSetting row that holds the brand overrides. Kept DISTINCT from the general
# settings row (``_SETTINGS_KEY = "global"`` in api_server — ZK / SMTP / policy) so brand
# edits and operational settings never clobber each other.
BRAND_SETTINGS_KEY = "brand"


def _brand_field_names() -> set:
    """The set of overridable :class:`BrandingConfig` field names (pydantic v2 or v1)."""
    fields = getattr(BrandingConfig, "model_fields", None)
    if fields is None:  # pydantic v1 fallback
        fields = BrandingConfig.__fields__
    return set(fields.keys())


def _to_dict(cfg: BrandingConfig) -> Dict[str, Any]:
    """Dump a config to a plain dict (pydantic v2 ``model_dump`` / v1 ``dict``)."""
    dump = getattr(cfg, "model_dump", None)
    return dump() if dump else cfg.dict()


def load_brand_overrides(db) -> Dict[str, Any]:
    """The raw brand-override dict from ``SystemSetting('brand')``, or ``{}`` on any error.

    Best-effort: a missing row, a non-dict value, or a DB error all degrade to *no*
    overrides (env defaults win) rather than failing the caller — a public info endpoint
    must never 500 on a branding read.
    """
    try:
        from app.core.models import SystemSetting  # lazy import: keeps this module importable w/o the ORM
        row = db.query(SystemSetting).filter(SystemSetting.key == BRAND_SETTINGS_KEY).first()
        value = row.value if (row and row.value) else {}
        return dict(value) if isinstance(value, dict) else {}
    except Exception:  # noqa: BLE001 — branding reads must never bubble a DB error to the caller
        logger.warning("brand override read failed; falling back to env defaults", exc_info=True)
        return {}


def set_brand_overrides(db, updates: Dict[str, Any] = None, remove_keys=None) -> None:
    """Set/remove keys in the ``SystemSetting('brand')`` override row — the store
    :func:`get_effective_branding` merges over the env defaults.

    A non-empty value in ``updates`` sets that key; an empty/whitespace/``None`` value
    (or a key in ``remove_keys``) drops it, reverting that field to the env default.
    The **single low-level writer** for every branding path — the admin Settings editor
    and logo/favicon uploads — so both feed the same effective store. The caller commits
    (and is responsible for validating values;
    the read-time :func:`merge_branding` guard drops anything invalid as defence in depth).
    """
    from app.core.models import SystemSetting  # lazy: keep this module importable without the ORM
    row = db.query(SystemSetting).filter(SystemSetting.key == BRAND_SETTINGS_KEY).first()
    brand = dict(row.value) if (row and row.value) else {}
    for key, value in (updates or {}).items():
        cleaned = value.strip() if isinstance(value, str) else value
        if cleaned:
            brand[key] = cleaned
        else:
            brand.pop(key, None)  # empty/None -> clear the override
    for key in (remove_keys or []):
        brand.pop(key, None)
    if row is None:
        db.add(SystemSetting(key=BRAND_SETTINGS_KEY, value=brand))
    else:
        row.value = brand  # reassign so SQLAlchemy flags the JSON column dirty


def merge_branding(base: BrandingConfig, overrides: Dict[str, Any]) -> BrandingConfig:
    """Pure merge: ``overrides`` win over the env ``base``.

    * Unknown keys are dropped (only declared :class:`BrandingConfig` fields apply).
    * A value the validators reject (bad hex colour, malformed email, …) is dropped and
      falls back to the env default — so a corrupt stored override can never break a
      reader. Overrides are validated on write; this read-time guard is defence in
      depth.

    No DB access — unit-testable in isolation.
    """
    known = _brand_field_names()
    clean = {k: v for k, v in (overrides or {}).items() if k in known}
    if not clean:
        return base
    merged = {**_to_dict(base), **clean}
    # Re-validate; drop any override the validators reject and retry, so good overrides
    # still apply while a single bad value reverts to the env default (a popped key is
    # resolved from env/default by the settings constructor).
    for _ in range(len(clean) + 1):
        try:
            return BrandingConfig(**merged)
        except ValidationError as exc:
            bad = {e["loc"][0] for e in exc.errors() if e.get("loc")} & set(clean)
            if not bad:
                break  # error we can't attribute to an override — keep the safe base
            for key in bad:
                merged.pop(key, None)
                clean.pop(key, None)
            logger.warning("ignored invalid brand override(s): %s", sorted(bad))
    return base


def get_effective_branding(db) -> BrandingConfig:
    """Effective branding = DB ``SystemSetting('brand')`` overrides on the env config.

    The canonical reader. Re-reads the DB each call so admin edits take effect live.
    """
    return merge_branding(get_branding(), load_brand_overrides(db))


def branding_public_payload(cfg: BrandingConfig) -> Dict[str, Any]:
    """The public ``/branding`` response.

    Identity + company + key URLs + copyright (via the existing
    :meth:`BrandingConfig.to_public_dict`), plus the full 8-colour theme map (CSS-var
    keyed, ready for ``:root`` injection in A2) and the asset URLs (logos + favicon).
    Public fields only — no analytics tokens, no SMTP / license secrets.
    """
    payload = dict(cfg.to_public_dict())
    payload["colors"] = cfg.get_theme_css_vars()
    payload["assets"] = {
        "logo": cfg.logo_url,
        "logo_dark": cfg.logo_dark_url,
        "logo_small": cfg.logo_small_url,
        "favicon": cfg.favicon_url,
        "og_image": cfg.og_image_url,
    }
    # Persistent product attribution ("powered by <name>"). NOT part of the admin-editable
    # brand set, so a tenant customizing their instance can't remove it; only a deploy-level
    # env flag (BRAND_SHOW_POWERED_BY) hides it. The UI shell renders this on the login page.
    payload["powered_by"] = {
        "show": bool(cfg.show_powered_by),
        "name": cfg.powered_by_name,
        "url": cfg.powered_by_url,
    }
    return payload
