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
# Strength ordering for the "a user may only TIGHTEN" rule: a link may require a stronger secret
# than its tag floor, never a weaker one. none < pin < password.
SECRET_STRENGTH = {"none": 0, "pin": 1, "password": 2}
PIN_LENGTHS = (4, 6, 8)
# The hard floor on a link token: 6 base62 chars is the smallest "easy" id we allow (~57e9 keyspace,
# only safe alongside the always-on redemption rate limit). Longer is the default for real tiers.
MIN_TOKEN_LEN_FLOOR = 6
MAX_TOKEN_LEN = 64
# Upper bound on a link password (defensive: it is verified with argon2 on an anonymous endpoint).
PASSWORD_MAX_LEN = 256
DEFAULT_USER_CAP = 50
MAX_USER_CAP = 10_000
MAX_TTL_HOURS = 24 * 3650  # 10 years — an admin ceiling, effectively "no expiry" when unset


def public_note_links_enabled(settings_blob: dict) -> bool:
    # Default ON (matches sharing_policy.sharing_enabled): available out of the box for self-hosters.
    # Only an explicit stored False disables it; a non-bool value falls back to the ON default.
    return (settings_blob or {}).get("public_note_links_enabled", True) is not False


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


# --- link creation: "tighten-only" policy resolution ----------------------------------------------
# A NoteLinkTag is the admin FLOOR. When a user creates a public link they may make it MORE
# restrictive than the tag (longer token, stronger/added secret, shorter expiry, fewer uses) but
# never LESS. resolve_link_policy is the single chokepoint that merges the tag floor with the user's
# requested overrides and REJECTS any attempt to loosen. It is pure (no DB, no hashing) so it is
# fully unit-testable; the caller hashes the returned secret and persists the frozen policy on the
# link row (so a later tag edit/delete never changes an existing link).

class PolicyViolation(ValueError):
    """A requested link override would loosen the tag floor (or is otherwise invalid)."""


def _tag_attr(tag, name, default=None):
    """Read a field from either a NoteLinkTag ORM row or a plain dict (keeps this module ORM-free
    and lets tests pass a dict)."""
    if isinstance(tag, dict):
        return tag.get(name, default)
    return getattr(tag, name, default)


def resolve_link_policy(tag, overrides: dict | None = None) -> dict:
    """Merge a NoteLinkTag floor with a user's requested overrides into the concrete link policy,
    enforcing "tighten only". Returns a dict:

        {token_len, secret_kind, secret_value (plaintext PIN/password or None — caller hashes it),
         ttl_hours (None = no expiry), max_uses (None = unlimited)}

    Raises PolicyViolation if an override tries to weaken the floor or is malformed. `overrides`
    keys (all optional): token_len:int, secret_kind:str, pin:str, password:str,
    ttl_hours:int|None (absent = tag default; explicit None = no expiry), max_uses:int|None.
    """
    o = overrides or {}
    floor_secret = (_tag_attr(tag, "require_secret", "none") or "none")
    if floor_secret not in SECRET_STRENGTH:
        floor_secret = "none"

    # --- token length: floor is the tag minimum; longer is tighter -------------------------------
    floor_token = _tag_attr(tag, "min_token_len", 10) or MIN_TOKEN_LEN_FLOOR
    floor_token = max(int(floor_token), MIN_TOKEN_LEN_FLOOR)
    token_len = floor_token
    if "token_len" in o and o["token_len"] is not None:
        v = o["token_len"]
        if isinstance(v, bool) or not isinstance(v, int):
            raise PolicyViolation("token_len must be an integer")
        if v < floor_token:
            raise PolicyViolation("token_len %d is below this tag's minimum of %d" % (v, floor_token))
        if v > MAX_TOKEN_LEN:
            raise PolicyViolation("token_len cannot exceed %d" % MAX_TOKEN_LEN)
        token_len = v

    # --- secret: may only be the SAME or STRONGER than the floor ---------------------------------
    secret_kind = floor_secret
    if "secret_kind" in o and o["secret_kind"] is not None:
        req = o["secret_kind"]
        if req not in SECRET_STRENGTH:
            raise PolicyViolation("secret_kind must be one of %s" % (SECRET_KINDS,))
        if SECRET_STRENGTH[req] < SECRET_STRENGTH[floor_secret]:
            raise PolicyViolation(
                "this tag requires at least a '%s' secret; you cannot use '%s'" % (floor_secret, req))
        secret_kind = req

    secret_value = None
    if secret_kind == "pin":
        pin = (o.get("pin") or "").strip()
        if not pin.isdigit():
            raise PolicyViolation("PIN must be digits only")
        if len(pin) not in PIN_LENGTHS:
            raise PolicyViolation("PIN length must be one of %s" % (PIN_LENGTHS,))
        min_pin = int(_tag_attr(tag, "min_pin_len", 4) or 4)
        if len(pin) < min_pin:
            raise PolicyViolation("PIN must be at least %d digits for this tag" % min_pin)
        secret_value = pin
    elif secret_kind == "password":
        pw = o.get("password") or ""
        min_len = int(_tag_attr(tag, "password_min_len", 8) or 8)
        if len(pw) < min_len:
            raise PolicyViolation("password must be at least %d characters for this tag" % min_len)
        if len(pw) > PASSWORD_MAX_LEN:
            raise PolicyViolation("password cannot exceed %d characters" % PASSWORD_MAX_LEN)
        if _tag_attr(tag, "password_require_alnum", False):
            if not (any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw)):
                raise PolicyViolation("password must contain both letters and numbers for this tag")
        secret_value = pw

    # --- ttl: max_ttl_hours is the ceiling; shorter is tighter; None = no expiry -----------------
    max_ttl = _tag_attr(tag, "max_ttl_hours", None)
    default_ttl = _tag_attr(tag, "default_ttl_hours", None)
    ttl_hours = default_ttl
    if "ttl_hours" in o:
        v = o["ttl_hours"]
        if v is None:
            # "no expiry" is the loosest option — only allowed when the tag sets no ceiling.
            if max_ttl is not None:
                raise PolicyViolation(
                    "this tag caps link lifetime at %d hours; a never-expiring link is not allowed" % max_ttl)
            ttl_hours = None
        else:
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise PolicyViolation("ttl_hours must be a positive integer or null")
            if max_ttl is not None and v > max_ttl:
                raise PolicyViolation("ttl_hours %d exceeds this tag's maximum of %d" % (v, max_ttl))
            if v > MAX_TTL_HOURS:
                raise PolicyViolation("ttl_hours cannot exceed %d" % MAX_TTL_HOURS)
            ttl_hours = v
    # A tag with a ceiling but no default: default to the ceiling rather than "no expiry".
    if ttl_hours is None and max_ttl is not None:
        ttl_hours = max_ttl

    # --- max_uses: max_uses_cap is the ceiling; fewer is tighter; None = unlimited ----------------
    cap = _tag_attr(tag, "max_uses_cap", None)
    max_uses = cap
    if "max_uses" in o:
        v = o["max_uses"]
        if v is None:
            if cap is not None:
                raise PolicyViolation(
                    "this tag caps a link at %d view(s); an unlimited-use link is not allowed" % cap)
            max_uses = None
        else:
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise PolicyViolation("max_uses must be a positive integer or null")
            if cap is not None and v > cap:
                raise PolicyViolation("max_uses %d exceeds this tag's cap of %d" % (v, cap))
            max_uses = v

    return {"token_len": token_len, "secret_kind": secret_kind, "secret_value": secret_value,
            "ttl_hours": ttl_hours, "max_uses": max_uses}
