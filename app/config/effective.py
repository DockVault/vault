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
import os
import threading
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from app.config.branding import BrandingConfig, get_branding
from app.core.paths import PROJECT_ROOT

logger = logging.getLogger(__name__)

# The SystemSetting row that holds the brand overrides. Kept DISTINCT from the general
# settings row (``_SETTINGS_KEY = "global"`` in api_server — ZK / SMTP / policy) so brand
# edits and operational settings never clobber each other.
BRAND_SETTINGS_KEY = "brand"

# Uploaded logos and favicons are served from this path (api_server ``get_brand_asset``), out of
# the brand volume below.
BRAND_ASSET_PREFIX = "/brand-assets/"

# The asset slots of the public payload that an upload can point at, and the BrandingConfig field
# behind each one.
BRAND_ASSET_FIELDS = {
    "logo": "logo_url",
    "logo_dark": "logo_dark_url",
    "logo_small": "logo_small_url",
    "favicon": "favicon_url",
}

# The upload slots of the Branding page (api_server ``_BRAND_ASSET_SLOTS``) and the field each one is
# checked by: one logo upload drives all three logo fields.
BRAND_UPLOAD_SLOT_FIELDS = {"logo": "logo_url", "favicon": "favicon_url"}

_missing_logged = set()
_missing_lock = threading.Lock()


def brand_asset_dir() -> str:
    """The folder that holds uploaded brand assets: BRAND_ASSET_DIR, else ``brand/`` at the app root
    (the volume mounted at /app/brand in the image)."""
    return os.environ.get("BRAND_ASSET_DIR", str(PROJECT_ROOT / "brand"))


def brand_asset_missing(url: Any, asset_dir: Optional[str] = None) -> bool:
    """True when ``url`` names an uploaded asset (under /brand-assets/) whose file is not there.

    Any other address (a built-in /static asset, an outside http(s) address) is never checked. A
    name the asset route would refuse to serve counts as missing too.
    """
    if not isinstance(url, str) or not url.startswith(BRAND_ASSET_PREFIX):
        return False
    name = url[len(BRAND_ASSET_PREFIX):].split("?", 1)[0].split("#", 1)[0]
    if not name or "/" in name or "\\" in name or ".." in name:
        return True
    base = os.path.realpath(asset_dir or brand_asset_dir())
    real = os.path.realpath(os.path.join(base, name))
    if not real.startswith(base + os.sep):
        return True
    return not os.path.isfile(real)


def _field_default(name: str) -> Any:
    """The built-in default of a BrandingConfig field, not the env value (pydantic v2 or v1)."""
    fields = getattr(BrandingConfig, "model_fields", None)
    if fields is None:  # pydantic v1 fallback
        fields = BrandingConfig.__fields__
    return fields[name].default


def _note_missing_asset(slot: str) -> None:
    """Warn once per process per slot. The slot only: the stored path stays out of the log."""
    with _missing_lock:
        if slot in _missing_logged:
            return
        _missing_logged.add(slot)
    logger.warning("brand asset for the %s slot is missing; the built-in default is served instead", slot)


def brand_asset_urls(cfg: BrandingConfig, asset_dir: Optional[str] = None) -> Dict[str, Any]:
    """The asset URLs of ``cfg``, with each uploaded asset whose file is gone replaced by the built-in
    default of its slot, so a lost brand volume shows the stock logo rather than a broken image."""
    folder = asset_dir or brand_asset_dir()
    urls = {}
    for slot, field in BRAND_ASSET_FIELDS.items():
        url = getattr(cfg, field)
        if brand_asset_missing(url, folder):
            _note_missing_asset(slot)
            url = _field_default(field)
        urls[slot] = url
    return urls


def missing_brand_uploads(overrides: Dict[str, Any], asset_dir: Optional[str] = None) -> List[str]:
    """The Branding page's upload slots ("logo", "favicon") whose stored upload has no file."""
    folder = asset_dir or brand_asset_dir()
    return [slot for slot, field in BRAND_UPLOAD_SLOT_FIELDS.items()
            if brand_asset_missing((overrides or {}).get(field), folder)]


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

    A non-empty value in ``updates`` sets that key, and so does a boolean, ``False`` included;
    an empty/whitespace/``None`` value (or a key in ``remove_keys``) drops it, reverting that
    field to the env default.
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
        # A boolean is a value either way: False is a choice, not an empty field.
        if cleaned or isinstance(cleaned, bool):
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


def branding_public_payload(cfg: BrandingConfig, asset_dir: Optional[str] = None) -> Dict[str, Any]:
    """The public ``/branding`` response.

    Identity + company + key URLs + copyright (via the existing
    :meth:`BrandingConfig.to_public_dict`), plus the full 8-colour theme map (CSS-var
    keyed, ready for ``:root`` injection in A2) and the asset URLs (logos + favicon).
    Public fields only — no analytics tokens, no SMTP / license secrets.

    An uploaded asset whose file is gone from the brand volume is replaced by the built-in
    default of its slot (:func:`brand_asset_urls`). ``show_name_beside_logo`` tells the shell
    whether the name stands beside the logo or the logo shows alone.
    """
    payload = dict(cfg.to_public_dict())
    payload["show_name_beside_logo"] = bool(cfg.show_name_beside_logo)
    payload["colors"] = cfg.get_theme_css_vars()
    urls = brand_asset_urls(cfg, asset_dir)
    payload["logo_url"] = urls["logo"]
    payload["assets"] = {
        "logo": urls["logo"],
        "logo_dark": urls["logo_dark"],
        "logo_small": urls["logo_small"],
        "favicon": urls["favicon"],
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
