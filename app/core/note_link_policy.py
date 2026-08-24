"""Policy helpers for PUBLIC note links ("Links" feature).

A NoteLinkTag is an admin-defined security FLOOR. This module validates admin tag input, defines the
seeded default tags, and (in later phases) enforces the "a user may only tighten, never loosen" rule
when a public link is created. Create-allowlist evaluation reuses sharing_policy.user_can_create_with_tag
(a NoteLinkTag carries the same allowlist fields as a ShareTag).

Settings (in the global settings blob, like sharing_enabled):
  * public_note_links_enabled  — bool, default False (public links are off until an admin turns them on)
  * public_note_link_user_cap  — int, a per-USER cap on active public links (anti-abuse), default 50
"""
from __future__ import annotations

SECRET_KINDS = ("none", "pin", "password")
PIN_LENGTHS = (4, 6, 8)
# The hard floor on a link token: 6 base62 chars is the smallest "easy" id we allow (~57e9 keyspace,
# only safe alongside the always-on redemption rate limit). Longer is the default for real tiers.
MIN_TOKEN_LEN_FLOOR = 6
MAX_TOKEN_LEN = 64
DEFAULT_USER_CAP = 50
MAX_USER_CAP = 10_000
MAX_TTL_HOURS = 24 * 3650  # 10 years — an admin ceiling, effectively "no expiry" when unset


def public_note_links_enabled(settings_blob: dict) -> bool:
    # Fail closed on a non-bool stored value (matches sharing_policy.sharing_enabled): only a real
    # True enables the feature, so a stray truthy string can never silently turn it on.
    return (settings_blob or {}).get("public_note_links_enabled", False) is True


def public_note_link_user_cap(settings_blob: dict) -> int:
    raw = (settings_blob or {}).get("public_note_link_user_cap", DEFAULT_USER_CAP)
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_USER_CAP
    return v if 1 <= v <= MAX_USER_CAP else DEFAULT_USER_CAP


def validate_settings(payload: dict) -> None:
    """Raise ValueError if the two public-note-link settings keys carry bad values. Called from the
    settings validator; only checks keys actually present in the payload."""
    if "public_note_links_enabled" in payload and not isinstance(
            payload["public_note_links_enabled"], bool):
        raise ValueError("public_note_links_enabled must be true or false")
    if "public_note_link_user_cap" in payload:
        v = payload["public_note_link_user_cap"]
        if isinstance(v, bool) or not isinstance(v, int) or not (1 <= v <= MAX_USER_CAP):
            raise ValueError(f"public_note_link_user_cap must be an integer 1..{MAX_USER_CAP}")


def _int_in(name, v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
        raise ValueError(f"{name} must be an integer {lo}..{hi}")


def validate_tag_fields(data: dict, *, partial: bool = False) -> None:
    """Validate an admin NoteLinkTag create/update payload. `partial` (PATCH) only checks present keys.

    Enforces the invariants the FLOOR relies on: token length >= 6, a valid secret kind, a PIN length
    in {4,6,8}, sane password length, an ordered ttl (default <= max), and positive caps.
    """
    def present(k):
        return (not partial) or (k in data)

    if present("name"):
        name = (data.get("name") or "").strip()
        if not name or len(name) > 120:
            raise ValueError("name is required (1..120 chars)")
    if present("min_token_len") or "min_token_len" in data:
        _int_in("min_token_len", data.get("min_token_len", 10), MIN_TOKEN_LEN_FLOOR, MAX_TOKEN_LEN)
    if "require_secret" in data or (not partial):
        rs = data.get("require_secret", "none")
        if rs not in SECRET_KINDS:
            raise ValueError(f"require_secret must be one of {SECRET_KINDS}")
    if "min_pin_len" in data or (not partial):
        if data.get("min_pin_len", 4) not in PIN_LENGTHS:
            raise ValueError(f"min_pin_len must be one of {PIN_LENGTHS}")
    if "password_min_len" in data or (not partial):
        _int_in("password_min_len", data.get("password_min_len", 8), 1, 256)
    if "password_require_alnum" in data and not isinstance(data["password_require_alnum"], bool):
        raise ValueError("password_require_alnum must be true or false")
    # Nullable numeric axes: None (unset) or a positive int.
    for key, lo, hi in (("default_ttl_hours", 1, MAX_TTL_HOURS),
                        ("max_ttl_hours", 1, MAX_TTL_HOURS),
                        ("max_uses_cap", 1, 1_000_000)):
        if key in data and data[key] is not None:
            _int_in(key, data[key], lo, hi)
    d_ttl, m_ttl = data.get("default_ttl_hours"), data.get("max_ttl_hours")
    if d_ttl is not None and m_ttl is not None and d_ttl > m_ttl:
        raise ValueError("default_ttl_hours cannot exceed max_ttl_hours")


# The seeded catalog: a fresh deployment gets these (inert until public links are enabled). Colours +
# icons drive the "Shared (by me)" tiles. Longer tokens for the secure tiers; the Confidential tag
# mandates a password + one-time use + a 1-day expiry.
DEFAULT_NOTE_LINK_TAGS = (
    {"name": "Open", "description": "Short, easy link — no expiry, no password, unlimited views.",
     "border_color": "green", "icon": "globe", "min_token_len": 6,
     "default_ttl_hours": None, "max_ttl_hours": None, "require_secret": "none",
     "max_uses_cap": None, "auto_enroll_new_users": True},
    {"name": "Restricted", "description": "Long link, expires after 7 days, no password.",
     "border_color": "amber", "icon": "clock", "min_token_len": 20,
     "default_ttl_hours": 168, "max_ttl_hours": 168, "require_secret": "none",
     "max_uses_cap": None, "auto_enroll_new_users": True},
    {"name": "Confidential", "description": "Long link, password-protected, one view, expires in 1 day.",
     "border_color": "red", "icon": "lock", "min_token_len": 20,
     "default_ttl_hours": 24, "max_ttl_hours": 24, "require_secret": "password",
     "password_min_len": 8, "password_require_alnum": True, "max_uses_cap": 1,
     "auto_enroll_new_users": True},
)


def should_seed_default_note_link_tags(has_existing_tags: bool, links_already_enabled: bool) -> bool:
    """Seed the starter tags ONLY on a fresh deployment (no tags AND public links not already on) —
    mirrors sharing_policy.should_seed_default_tags, so an admin who has curated tags or turned the
    feature on is never handed a fresh permissive set on upgrade."""
    return not has_existing_tags and not links_already_enabled
