"""Canonical registry for the deployment-configured rate limits an admin may override at runtime.

Every rate limit has a DEPLOYMENT value (from the environment / `.env`, read through `settings`) that
is authoritative and READ-ONLY, and an optional CUSTOM override an admin stores in the global
`SystemSetting('global')` blob. The effective value used to enforce a limit is:

    a valid, in-bounds custom override  --  otherwise the deployment default.

This mirrors the model the general-API buckets already use (`resolve_api_rate_limit_policy` /
`ApiRateLimitPolicyCache`) and extends it to the dedicated login / vault-unlock / SFTP throttles, which
previously read `settings.*` directly with no override path.

Security properties (relied on by the auth throttles, so they are enforced HERE, not at the call site):
  * FAIL-SAFE: an absent / malformed / out-of-bounds custom value resolves to the DEPLOYMENT default,
    never to "unlimited" or "disabled". A bad override can only ever fall back to the shipped limit.
  * BOUNDED: a custom override is accepted only within [minimum, maximum]. A fat-finger cannot set a
    limit so high it is effectively off, nor so low it locks everyone out.
  * DEPLOYMENT IS READ-ONLY: the deployment value is never written from the API; only the custom
    override is persisted (validated by :func:`validate_override`). The API refuses writes to the
    deployment-managed keys elsewhere.
  * The stored sentinel 0 (or absent) means "use the deployment default", so clearing an override is a
    save of 0 — identical to the API-bucket and the legacy login-limit convention.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from app.core.config import settings
from app.core.rate_limiter import (
    API_RATE_LIMIT_MAX_REQUESTS,
    API_RATE_LIMIT_MAX_WINDOW_SECONDS,
)

# Bounds for the dedicated (non general-API) throttles. The attempt-counter ceiling is deliberately a
# SANE maximum (10k), not "unlimited": an admin can raise a limit but a fat-finger cannot loosen a
# brute-force protection to effectively-off. Windows share the general-API window ceiling so every
# "seconds" field reads the same maximum.
_ATTEMPTS_MAX = 10_000
_WINDOW_MAX = API_RATE_LIMIT_MAX_WINDOW_SECONDS  # 86400 (24h)


@dataclass(frozen=True)
class RateLimitSpec:
    """One overridable rate limit.

    key            -- the blob override key AND the field name the settings API accepts.
    deployment_attr-- the `settings` attribute holding the environment default.
    minimum/maximum-- inclusive bounds a custom override must satisfy (deployment default is also
                      clamped into this range as a final safety when resolving).
    unit           -- "requests" | "seconds" | "attempts" | "minutes" (UI label only).
    group          -- coarse grouping for the UI ("login" | "vault" | "sftp" | "api").
    label          -- short human label.
    description     -- plain-language "what this is".
    when            -- plain-language "when it triggers".
    """
    key: str
    deployment_attr: str
    minimum: int
    maximum: int
    unit: str
    group: str
    label: str
    description: str
    when: str
    # Floor applied when clamping the DEPLOYMENT value (not a custom override). Defaults to `minimum`;
    # set 0 only where a deployment 0 is a meaningful setting (lockout_duration 0 = permanent lock).
    deployment_min: Optional[int] = None
    # Ceiling applied to an ADMIN CUSTOM override (the UI slider), independent of the deployment clamp.
    # Defaults to `maximum`. Set it lower to bound what an admin may set from the panel without also
    # clamping a deliberate deployment .env value (R018-INFO-2: cap the login-attempts override at 1000
    # so a fat-finger can't widen the brute-force window, while the operator's env value is untouched).
    custom_max: Optional[int] = None


# NOTE: `max_login_attempts` and `lockout_duration` keep their LEGACY blob key names (the login
# throttle has read those since before this registry existed); their deployment source is the
# `rate_limit_login_attempts` / `account_lockout_minutes` env value. Every other key equals its
# `settings` attribute name, matching the general-API convention.
REGISTRY: tuple[RateLimitSpec, ...] = (
    # --- Login (password) -----------------------------------------------------------------------
    RateLimitSpec(
        "max_login_attempts", "rate_limit_login_attempts", 1, _ATTEMPTS_MAX, "attempts", "login",
        "Failed logins before lockout",
        "The number of wrong-password attempts allowed for one account within the login window.",
        "Triggers on repeated failed logins for the same account; the account is locked when the "
        "count is exceeded.",
        custom_max=1_000,  # an admin override may not widen the brute-force window past 1000 (INFO-2)
    ),
    RateLimitSpec(
        "rate_limit_login_window_seconds", "rate_limit_login_window_seconds", 10, _WINDOW_MAX,
        "seconds", "login",
        "Login window",
        "The rolling time window over which failed logins are counted.",
        "Applies to the failed-login counter above and to the SFTP key-offer throttle.",
    ),
    RateLimitSpec(
        "lockout_duration", "account_lockout_minutes", 1, 1440, "minutes", "login",
        "Lockout duration",
        "How long an account stays locked after too many failed logins before it can try again "
        "(auto-unlock).",
        "Starts when an account is locked by failed logins. (An admin-set lock is permanent and "
        "unaffected.)",
        deployment_min=0,  # a deployment account_lockout_minutes of 0 means "locks are permanent"
    ),
    # --- Vault unlock ---------------------------------------------------------------------------
    RateLimitSpec(
        "rate_limit_vault_attempts", "rate_limit_vault_attempts", 1, _ATTEMPTS_MAX, "attempts",
        "vault",
        "Vault unlock attempts (users)",
        "Wrong vault-password (or passcode) tries a non-admin may make within the vault window "
        "before being throttled.",
        "Triggers when unlocking a password-protected vault with the wrong password/passcode.",
    ),
    RateLimitSpec(
        "rate_limit_vault_attempts_admin", "rate_limit_vault_attempts_admin", 1, _ATTEMPTS_MAX,
        "attempts", "vault",
        "Vault unlock attempts (admins)",
        "The same limit as above, applied to administrator accounts (usually higher).",
        "Triggers when an admin unlocks a password-protected vault with the wrong password/passcode.",
    ),
    RateLimitSpec(
        "rate_limit_vault_window_seconds", "rate_limit_vault_window_seconds", 10, _WINDOW_MAX,
        "seconds", "vault",
        "Vault unlock window",
        "The rolling time window over which failed vault-unlock attempts are counted.",
        "Applies to the vault-unlock counters above.",
    ),
    # --- SFTP ------------------------------------------------------------------------------------
    RateLimitSpec(
        "rate_limit_sftp_key_attempts", "rate_limit_sftp_key_attempts", 1, _ATTEMPTS_MAX,
        "attempts", "sftp",
        "SFTP key-offer attempts (per IP)",
        "Failed SSH public-key offers one IP address may make within the login window before being "
        "throttled. A denial-of-service / key-enumeration bound, not a password control.",
        "Triggers on a flood of rejected SSH key offers from a single IP over the login window.",
    ),
    # --- General API buckets (enforced by the middleware policy cache; listed here so the UI shows
    #     their deployment vs custom values through the same surface) ----------------------------
    RateLimitSpec(
        "rate_limit_api_default", "rate_limit_api_default", 1, API_RATE_LIMIT_MAX_REQUESTS,
        "requests", "api",
        "API default requests",
        "Requests per window allowed on general API endpoints not covered by a more specific bucket.",
        "Triggers on ordinary API traffic that exceeds the default bucket.",
    ),
    RateLimitSpec(
        "rate_limit_api_default_window", "rate_limit_api_default_window", 1,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS, "seconds", "api",
        "API default window",
        "The window over which the default-bucket requests are counted.",
        "Applies to the default request bucket above.",
    ),
    RateLimitSpec(
        "rate_limit_api_auth", "rate_limit_api_auth", 1, API_RATE_LIMIT_MAX_REQUESTS, "requests",
        "api",
        "API auth requests",
        "Requests per window allowed on authentication endpoints (login, token, invite, reset).",
        "Triggers on bursts against /auth endpoints.",
    ),
    RateLimitSpec(
        "rate_limit_api_auth_window", "rate_limit_api_auth_window", 1,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS, "seconds", "api",
        "API auth window",
        "The window over which auth-endpoint requests are counted.",
        "Applies to the auth request bucket above.",
    ),
    RateLimitSpec(
        "rate_limit_api_upload", "rate_limit_api_upload", 1, API_RATE_LIMIT_MAX_REQUESTS, "requests",
        "api",
        "API upload operations",
        "Upload OPERATIONS (start + complete) per window — not per chunk.",
        "Triggers when many uploads are started/completed in quick succession.",
    ),
    RateLimitSpec(
        "rate_limit_api_upload_window", "rate_limit_api_upload_window", 1,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS, "seconds", "api",
        "API upload window",
        "The window over which upload operations are counted.",
        "Applies to the upload-operations bucket above.",
    ),
    RateLimitSpec(
        "rate_limit_api_upload_chunk", "rate_limit_api_upload_chunk", 1, API_RATE_LIMIT_MAX_REQUESTS,
        "requests", "api",
        "API upload chunks",
        "Per-CHUNK upload PUTs per window. One resumable upload is many chunks, so keep this high "
        "enough that a large file never trips it mid-transfer.",
        "Triggers only on an extreme chunk-PUT rate.",
    ),
    RateLimitSpec(
        "rate_limit_api_upload_chunk_window", "rate_limit_api_upload_chunk_window", 1,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS, "seconds", "api",
        "API upload-chunk window",
        "The window over which chunk PUTs are counted.",
        "Applies to the upload-chunk bucket above.",
    ),
    RateLimitSpec(
        "rate_limit_api_download", "rate_limit_api_download", 1, API_RATE_LIMIT_MAX_REQUESTS,
        "requests", "api",
        "API download requests",
        "File-content downloads per window (headroom for many files / byte-range requests).",
        "Triggers on a high download request rate.",
    ),
    RateLimitSpec(
        "rate_limit_api_download_window", "rate_limit_api_download_window", 1,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS, "seconds", "api",
        "API download window",
        "The window over which downloads are counted.",
        "Applies to the download bucket above.",
    ),
    RateLimitSpec(
        "rate_limit_api_poll", "rate_limit_api_poll", 1, API_RATE_LIMIT_MAX_REQUESTS, "requests",
        "api",
        "API poll requests",
        "Timer-polled read endpoints (security events, notifications, audit, monitor). Kept lenient "
        "so normal polling never trips the shared default bucket.",
        "Triggers only if a client polls these read endpoints far above the normal rate.",
    ),
    RateLimitSpec(
        "rate_limit_api_poll_window", "rate_limit_api_poll_window", 1,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS, "seconds", "api",
        "API poll window",
        "The window over which polled reads are counted.",
        "Applies to the poll bucket above.",
    ),
)

_BY_KEY: dict[str, RateLimitSpec] = {s.key: s for s in REGISTRY}

# The keys the settings API accepts as CUSTOM overrides. Anything else touching a rate limit (e.g.
# rate_limit_api_enabled, *_deployment_defaults) is deployment-managed and refused by the API.
OVERRIDE_KEYS: frozenset[str] = frozenset(_BY_KEY)


def deployment_default(key: str) -> int:
    """The environment-configured value for `key`, clamped into [deployment_floor, maximum] (a bad env
    value can never make the effective limit go out of range). The floor is the spec minimum unless a
    lower deployment value is meaningful (see `deployment_min`)."""
    spec = _BY_KEY[key]
    floor = spec.deployment_min if spec.deployment_min is not None else spec.minimum
    try:
        raw = int(getattr(settings, spec.deployment_attr))
    except Exception:  # noqa: BLE001 — an unreadable/absent env value falls back to the floor
        return floor
    return max(floor, min(spec.maximum, raw))


def _custom_ceiling(spec: RateLimitSpec) -> int:
    """The upper bound an admin CUSTOM override may take (custom_max, else maximum)."""
    return spec.custom_max if spec.custom_max is not None else spec.maximum


def _valid_custom(value: object, spec: RateLimitSpec) -> Optional[int]:
    """Return the custom override as an int iff it is a real, in-bounds integer; else None (meaning
    'no usable override' -> caller uses the deployment default). Booleans are rejected (bool is an int
    subclass, and a stored `true` must never coerce to 1). Bounded by the custom ceiling, which may be
    tighter than the deployment clamp maximum."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if spec.minimum <= value <= _custom_ceiling(spec):
        return value
    return None


def resolve(key: str, blob: Optional[Mapping]) -> int:
    """The effective limit for `key`: a valid, in-bounds custom override, else the deployment default.
    FAIL-SAFE — any problem with the override yields the deployment default, never an open limit."""
    spec = _BY_KEY[key]
    if isinstance(blob, Mapping):
        custom = _valid_custom(blob.get(key), spec)
        if custom is not None:
            return custom
    return deployment_default(key)


def custom_value(key: str, blob: Optional[Mapping]) -> Optional[int]:
    """The stored custom override for `key` if one is set and usable, else None (UI: no override)."""
    if isinstance(blob, Mapping):
        return _valid_custom(blob.get(key), _BY_KEY[key])
    return None


def validate_override(key: str, value: object) -> None:
    """Raise ValueError if `value` is not an acceptable custom override for `key`. The sentinel 0 (clear
    the override -> use the deployment default) is allowed; any other value must be an int in bounds."""
    spec = _BY_KEY.get(key)
    if spec is None:
        raise ValueError(f"{key} is not an overridable rate limit")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if value == 0:
        return
    ceiling = _custom_ceiling(spec)
    if not (spec.minimum <= value <= ceiling):
        raise ValueError(f"{key} must be {spec.minimum}..{ceiling} (or 0 to use the deployment default)")


def describe_all(blob: Optional[Mapping]) -> list[dict]:
    """One row per overridable limit for the settings API: deployment (read-only), custom (or None),
    effective, bounds, unit, grouping and plain-language help. The UI renders exactly this."""
    rows = []
    for spec in REGISTRY:
        rows.append({
            "key": spec.key,
            "group": spec.group,
            "label": spec.label,
            "description": spec.description,
            "when": spec.when,
            "unit": spec.unit,
            "min": spec.minimum,
            "max": _custom_ceiling(spec),
            "deployment": deployment_default(spec.key),
            "custom": custom_value(spec.key, blob),
            "effective": resolve(spec.key, blob),
        })
    return rows


# --- Effective-value cache for the enforcement call sites -------------------------------------------
# The login / vault / SFTP throttles resolve their limit through effective() rather than reading
# settings.* directly. A small process-local cache (bounded TTL) reads the override blob so the hot
# auth paths do not hit PostgreSQL on every attempt; a settings write invalidates it immediately.

class _EffectiveCache:
    def __init__(self, loader: Callable[[], Mapping], *, ttl_seconds: float = 5.0,
                 clock: Callable[[], float] = time.monotonic):
        self._loader = loader
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._blob: Mapping = {}
        self._expires_at = 0.0

    def _blob_now(self) -> Mapping:
        now = self._clock()
        with self._lock:
            if now >= self._expires_at:
                try:
                    self._blob = self._loader() or {}
                except Exception:  # noqa: BLE001 — keep the last blob; resolve() still fail-safes
                    pass
                self._expires_at = now + self._ttl
            return self._blob

    def effective(self, key: str) -> int:
        return resolve(key, self._blob_now())

    def invalidate(self) -> None:
        with self._lock:
            self._expires_at = 0.0


def _load_global_blob() -> Mapping:
    from app.core.database import SessionLocal
    from app.core.models import SystemSetting
    db = SessionLocal()
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
        return dict(row.value) if row and row.value else {}
    finally:
        db.close()


_cache = _EffectiveCache(_load_global_blob)


def effective(key: str) -> int:
    """The effective (custom-or-deployment) limit for `key`, from a bounded-TTL cache. Used by the
    login / vault / SFTP throttle call sites."""
    return _cache.effective(key)


def invalidate_cache() -> None:
    """Drop the cached override blob so the next effective() read reflects a just-saved change."""
    _cache.invalidate()
