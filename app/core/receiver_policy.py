"""Policy helpers for RECEIVERS ("Upload links" — anonymous INBOUND uploads).

A ReceiverTag is an admin-defined security FLOOR, the inbound twin of NoteLinkTag. This module
validates admin tag input, defines the seeded default tags, and enforces the "a user may only tighten,
never loosen" rule when a receiver is created. Create-allowlist evaluation reuses
sharing_policy.user_can_create_with_tag (a ReceiverTag carries the same allowlist fields as a ShareTag).

Settings (in the global settings blob, like public_note_links_enabled):
  * public_receivers_enabled   — bool, default False (anonymous inbound is OFF until an admin enables it)
  * public_receiver_user_cap   — int, a per-USER cap on active receivers (anti-abuse), default 50

The "owner pays" model (the receiver vault's size_limit is funded by a single owner grant) is the
primary anti-exhaustion control; this per-user count cap is a secondary bound.
"""
from __future__ import annotations

SECRET_KINDS = ("none", "pin", "password")
# Strength ordering for the link-secret "tighten only" rule: none < pin < password.
SECRET_STRENGTH = {"none": 0, "pin": 1, "password": 2}
PIN_LENGTHS = (4, 6, 8)
# Receiver kind: 'confidential' forces the client-side password envelope and is STRONGER than
# 'standard', so a receiver may be confidential under a standard-floor tag but never the reverse.
KINDS = ("standard", "confidential")
KIND_STRENGTH = {"standard": 0, "confidential": 1}

MIN_TOKEN_LEN_FLOOR = 6
MAX_TOKEN_LEN = 64
PASSWORD_MAX_LEN = 256
DEFAULT_USER_CAP = 50
MAX_USER_CAP = 10_000
MAX_TTL_HOURS = 24 * 3650                 # 10 years — effectively "no expiry" when unset
MAX_RETENTION_DAYS = 3650                 # 10 years
MAX_BYTES = 1 << 50                       # 1 PiB ceiling on any admin/receiver byte cap (sanity bound)


def public_receivers_enabled(settings_blob: dict) -> bool:
    # Default OFF: anonymous inbound accepts uploads from anyone with the link, so it stays disabled
    # until an admin explicitly turns it on. Only an explicit stored True enables it.
    return (settings_blob or {}).get("public_receivers_enabled", False) is True


def public_receiver_user_cap(settings_blob: dict) -> int:
    raw = (settings_blob or {}).get("public_receiver_user_cap", DEFAULT_USER_CAP)
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_USER_CAP
    return v if 1 <= v <= MAX_USER_CAP else DEFAULT_USER_CAP


def validate_settings(payload: dict) -> None:
    """Raise ValueError if the two receiver settings keys carry bad values. Called from the settings
    validator; only checks keys actually present in the payload."""
    if "public_receivers_enabled" in payload and not isinstance(
            payload["public_receivers_enabled"], bool):
        raise ValueError("public_receivers_enabled must be true or false")
    if "public_receiver_user_cap" in payload:
        v = payload["public_receiver_user_cap"]
        if isinstance(v, bool) or not isinstance(v, int) or not (1 <= v <= MAX_USER_CAP):
            raise ValueError(f"public_receiver_user_cap must be an integer 1..{MAX_USER_CAP}")


def _int_in(name, v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
        raise ValueError(f"{name} must be an integer {lo}..{hi}")


def validate_tag_fields(data: dict, *, partial: bool = False) -> None:
    """Validate an admin ReceiverTag create/update payload. `partial` (PATCH) only checks present keys.

    Enforces the invariants the FLOOR relies on: token length >= 6, a valid link-secret kind, a PIN
    length in {4,6,8}, sane password length, a valid kind_floor, an ordered ttl (default <= max) and
    retention (default <= max), and positive caps.
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
    if "kind_floor" in data or (not partial):
        if data.get("kind_floor", "standard") not in KINDS:
            raise ValueError(f"kind_floor must be one of {KINDS}")
    # Nullable numeric axes: None (unset) or a positive int within bounds.
    for key, lo, hi in (("default_ttl_hours", 1, MAX_TTL_HOURS),
                        ("max_ttl_hours", 1, MAX_TTL_HOURS),
                        ("max_uploads_cap", 1, 1_000_000),
                        ("max_file_bytes_cap", 1, MAX_BYTES),
                        ("max_total_bytes_cap", 1, MAX_BYTES),
                        ("retention_max_days", 1, MAX_RETENTION_DAYS),
                        ("retention_default_days", 1, MAX_RETENTION_DAYS)):
        if key in data and data[key] is not None:
            _int_in(key, data[key], lo, hi)
    d_ttl, m_ttl = data.get("default_ttl_hours"), data.get("max_ttl_hours")
    if d_ttl is not None and m_ttl is not None and d_ttl > m_ttl:
        raise ValueError("default_ttl_hours cannot exceed max_ttl_hours")
    d_ret, m_ret = data.get("retention_default_days"), data.get("retention_max_days")
    if d_ret is not None and m_ret is not None and d_ret > m_ret:
        raise ValueError("retention_default_days cannot exceed retention_max_days")


# The seeded catalog: a fresh deployment gets these (inert until receivers are enabled). The
# Confidential inbox forces the browser envelope via kind_floor; it is NOT auto-enrolled, so an admin
# allowlists who may open one.
DEFAULT_RECEIVER_TAGS = (
    {"name": "Drop box", "description": "Open upload link — expires in 7 days, 100 MB per file, kept 30 days.",
     "border_color": "blue", "icon": "inbox", "min_token_len": 10,
     "default_ttl_hours": 168, "max_ttl_hours": 168, "require_secret": "none",
     "kind_floor": "standard", "max_file_bytes_cap": 100 * 1024 * 1024,
     "retention_max_days": 30, "retention_default_days": 30, "auto_enroll_new_users": True},
    {"name": "Confidential inbox",
     "description": "Password-protected upload link, expires in 1 day, kept 7 days.",
     "border_color": "red", "icon": "lock", "min_token_len": 20,
     "default_ttl_hours": 24, "max_ttl_hours": 24, "require_secret": "password",
     "password_min_len": 8, "password_require_alnum": True, "kind_floor": "confidential",
     "max_file_bytes_cap": 100 * 1024 * 1024, "retention_max_days": 7, "retention_default_days": 7,
     "auto_enroll_new_users": False},
)


def should_seed_default_receiver_tags(has_existing_tags: bool, receivers_already_enabled: bool) -> bool:
    """Seed the starter tags ONLY on a fresh deployment (no tags AND receivers not already on) —
    mirrors should_seed_default_note_link_tags."""
    return not has_existing_tags and not receivers_already_enabled


# --- receiver creation: "tighten-only" policy resolution ------------------------------------------
class PolicyViolation(ValueError):
    """A requested receiver override would loosen the tag floor (or is otherwise invalid)."""


def _tag_attr(tag, name, default=None):
    """Read a field from either a ReceiverTag ORM row or a plain dict (keeps this module ORM-free)."""
    if isinstance(tag, dict):
        return tag.get(name, default)
    return getattr(tag, name, default)


def _tighten_cap(o, key, cap, label):
    """Resolve a nullable 'ceiling' axis (max_uploads / max_file_bytes / max_total_bytes) where a
    SMALLER value is tighter. cap is the tag ceiling (None = unlimited within the tag). Returns the
    resolved value (default = cap). Raises PolicyViolation on a loosen or a malformed override."""
    val = cap
    if key in o:
        v = o[key]
        if v is None:
            # 'unlimited' is the loosest — only allowed when the tag sets no ceiling.
            if cap is not None:
                raise PolicyViolation(
                    "this tag caps %s at %d; an unlimited value is not allowed" % (label, cap))
            val = None
        else:
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise PolicyViolation("%s must be a positive integer or null" % key)
            if cap is not None and v > cap:
                raise PolicyViolation("%s %d exceeds this tag's cap of %d" % (key, v, cap))
            if v > MAX_BYTES:
                raise PolicyViolation("%s is too large" % key)
            val = v
    return val


def resolve_receiver_policy(tag, overrides: dict | None = None) -> dict:
    """Merge a ReceiverTag floor with a user's requested overrides into the concrete receiver policy,
    enforcing "tighten only". Returns a dict:

        {token_len, secret_kind, secret_value (plaintext PIN/password or None — caller hashes it),
         ttl_hours (None = no expiry), kind ('standard'|'confidential'), max_uploads (None = unlimited),
         max_file_bytes (None = vault/deployment cap), max_total_bytes (None = unlimited within tag),
         retention_days (None = no receiver-imposed expiry)}

    Raises PolicyViolation if an override tries to weaken the floor or is malformed. `overrides` keys
    (all optional): token_len:int, secret_kind:str, pin:str, password:str, ttl_hours:int|None,
    kind:str, max_uploads:int|None, max_file_bytes:int|None, max_total_bytes:int|None,
    retention_days:int|None.
    """
    o = overrides or {}

    # --- link token length: floor is the tag minimum; longer is tighter -------------------------
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

    # --- link secret: may only be the SAME or STRONGER than the floor ---------------------------
    floor_secret = (_tag_attr(tag, "require_secret", "none") or "none")
    if floor_secret not in SECRET_STRENGTH:
        floor_secret = "none"
    secret_kind = floor_secret
    if "secret_kind" in o and o["secret_kind"] is not None:
        req = o["secret_kind"]
        if req not in SECRET_STRENGTH:
            raise PolicyViolation("secret_kind must be one of %s" % (SECRET_KINDS,))
        if SECRET_STRENGTH[req] < SECRET_STRENGTH[floor_secret]:
            raise PolicyViolation(
                "this tag requires at least a '%s' link secret; you cannot use '%s'" % (floor_secret, req))
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

    # --- kind: confidential is stronger; floor sets the minimum ----------------------------------
    floor_kind = (_tag_attr(tag, "kind_floor", "standard") or "standard")
    if floor_kind not in KIND_STRENGTH:
        floor_kind = "standard"
    kind = floor_kind
    if "kind" in o and o["kind"] is not None:
        req = o["kind"]
        if req not in KIND_STRENGTH:
            raise PolicyViolation("kind must be one of %s" % (KINDS,))
        if KIND_STRENGTH[req] < KIND_STRENGTH[floor_kind]:
            raise PolicyViolation(
                "this tag requires at least a '%s' receiver; you cannot use '%s'" % (floor_kind, req))
        kind = req

    # --- ttl: max_ttl_hours is the ceiling; shorter is tighter; None = no expiry -----------------
    max_ttl = _tag_attr(tag, "max_ttl_hours", None)
    default_ttl = _tag_attr(tag, "default_ttl_hours", None)
    ttl_hours = default_ttl
    if "ttl_hours" in o:
        v = o["ttl_hours"]
        if v is None:
            if max_ttl is not None:
                raise PolicyViolation(
                    "this tag caps the link lifetime at %d hours; a never-expiring link is not allowed" % max_ttl)
            ttl_hours = None
        else:
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise PolicyViolation("ttl_hours must be a positive integer or null")
            if max_ttl is not None and v > max_ttl:
                raise PolicyViolation("ttl_hours %d exceeds this tag's maximum of %d" % (v, max_ttl))
            if v > MAX_TTL_HOURS:
                raise PolicyViolation("ttl_hours cannot exceed %d" % MAX_TTL_HOURS)
            ttl_hours = v
    if ttl_hours is None and max_ttl is not None:
        ttl_hours = max_ttl

    # --- upload / size ceilings: smaller is tighter ----------------------------------------------
    max_uploads = _tighten_cap(o, "max_uploads", _tag_attr(tag, "max_uploads_cap", None), "uploads")
    max_file_bytes = _tighten_cap(o, "max_file_bytes", _tag_attr(tag, "max_file_bytes_cap", None),
                                  "the per-file size")
    max_total_bytes = _tighten_cap(o, "max_total_bytes", _tag_attr(tag, "max_total_bytes_cap", None),
                                   "the total size")

    # --- retention: retention_max_days is the ceiling; shorter is tighter ------------------------
    max_ret = _tag_attr(tag, "retention_max_days", None)
    default_ret = _tag_attr(tag, "retention_default_days", None)
    retention_days = default_ret
    if "retention_days" in o:
        v = o["retention_days"]
        if v is None:
            if max_ret is not None:
                raise PolicyViolation(
                    "this tag caps retention at %d days; keeping uploads forever is not allowed" % max_ret)
            retention_days = None
        else:
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise PolicyViolation("retention_days must be a positive integer or null")
            if max_ret is not None and v > max_ret:
                raise PolicyViolation("retention_days %d exceeds this tag's maximum of %d" % (v, max_ret))
            if v > MAX_RETENTION_DAYS:
                raise PolicyViolation("retention_days cannot exceed %d" % MAX_RETENTION_DAYS)
            retention_days = v
    if retention_days is None and max_ret is not None:
        retention_days = max_ret

    return {"token_len": token_len, "secret_kind": secret_kind, "secret_value": secret_value,
            "ttl_hours": ttl_hours, "kind": kind, "max_uploads": max_uploads,
            "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes,
            "retention_days": retention_days}
