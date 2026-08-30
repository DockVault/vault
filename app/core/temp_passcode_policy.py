"""Pure resolution of the Temporary Vault Passcode policy from the admin settings blob.

No app imports, so it unit-tests in isolation; the caller reads the SystemSetting('global') blob and
passes it in (mirrors password_policy.py / upload_policy.py). FAIL-CLOSED where it matters: the feature
master switch defaults OFF and stays OFF for any non-bool stored value; the passcode length is floored;
allowing a zero-knowledge vault in a temp credential's scope defaults ON (today's behavior — only an
explicit stored False denies). No enforcement lives here; redemption/mint read these values.
"""

MIN_FLOOR = 8        # hard floor for a passcode length (mirrors password_policy.HARD_FLOOR)
DEFAULT_LENGTH = 16  # default generated length when unset

# Boolean policy keys -> their default when unset. This is a namespace SEPARATE from the
# account-password policy so the two are independently tunable.
_BOOL_DEFAULTS = {
    "temp_passcode_allow_custom": False,
    "temp_passcode_require_uppercase": False,
    "temp_passcode_require_lowercase": False,
    "temp_passcode_require_numbers": False,
    "temp_passcode_require_special": False,
    "temp_passcode_one_time_default": True,
    "temp_passcode_single_vault_only": False,
}


def passcodes_enabled(cfg) -> bool:
    """Master switch. FAIL-CLOSED: default False, and False for any non-bool stored value (strict
    `is True`, so a stray truthy string can't turn the feature on)."""
    return (cfg or {}).get("temp_passcodes_enabled") is True


def allow_zk_vaults(cfg) -> bool:
    """May a zero-knowledge vault be included in a temp credential's scope at all. Default True
    (today's behavior); only an explicit stored False denies."""
    return (cfg or {}).get("temp_cred_allow_zk_vaults") is not False


def min_length(cfg) -> int:
    """Effective minimum length for a custom passcode AND the length of a generated one: default 16,
    floored at 8 (any stored value below the floor is raised to it)."""
    try:
        n = int((cfg or {}).get("temp_passcode_min_length"))
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        n = DEFAULT_LENGTH
    return max(MIN_FLOOR, n)


def max_lifetime_minutes(cfg) -> int:
    """Optional ceiling (minutes) on a passcode's TTL; 0 (default / non-positive / unparseable) means
    no extra cap beyond the credential's own lifetime."""
    try:
        n = int((cfg or {}).get("temp_passcode_max_lifetime_minutes"))
    except (TypeError, ValueError):
        n = 0
    return n if n > 0 else 0


DEFAULT_MAX_TEMP_CREDS = 10  # per-user cap on simultaneously-ACTIVE temp credentials (0 = unlimited)


def max_temp_creds_per_user(cfg) -> int:
    """Per-user cap on active temporary credentials. Default DEFAULT_MAX_TEMP_CREDS; 0 = unlimited. A
    bool, negative, or unparseable stored value falls back to the default (fail-safe — a cap stays in
    force), while an explicit 0 is honoured as unlimited (distinct from absent)."""
    raw = (cfg or {}).get("max_temp_creds_per_user", DEFAULT_MAX_TEMP_CREDS)
    if isinstance(raw, bool):
        return DEFAULT_MAX_TEMP_CREDS
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_TEMP_CREDS
    return n if n >= 0 else DEFAULT_MAX_TEMP_CREDS


def effective_policy(cfg) -> dict:
    """The full effective policy, keyed by the exact setting names so ONE call drives both the mint UI
    (GET /temp-passcode-policy) and the GET /settings overlay. Includes temp_cred_allow_zk_vaults so a
    caller never has to remember to bolt it on."""
    cfg = cfg or {}
    policy = {
        "temp_passcodes_enabled": passcodes_enabled(cfg),
        "temp_passcode_min_length": min_length(cfg),
        "temp_passcode_max_lifetime_minutes": max_lifetime_minutes(cfg),
        "temp_cred_allow_zk_vaults": allow_zk_vaults(cfg),
        "max_temp_creds_per_user": max_temp_creds_per_user(cfg),
    }
    for key, default in _BOOL_DEFAULTS.items():
        val = cfg.get(key)
        policy[key] = val if isinstance(val, bool) else default
    return policy
