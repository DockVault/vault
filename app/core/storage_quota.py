"""Pure storage-quota arithmetic: the deployment ceiling, per-account budgets, and the
per-vault allocation ledger.

No app imports (same contract as upload_policy), so every rule here unit-tests offline and is
shared by the web paths (app/api/api_server.py), the SFTP write path (app/sftp/sftp_server.py)
and the vault service. Callers read the raw values out of SystemSetting('global') / the User row
and pass them in; nothing here touches a database or raises HTTP.

Three DIFFERENT numbers get called "storage", and conflating them is the bug this module exists
to prevent:

* STORED   — bytes actually written into vaults. The ONLY thing the deployment-wide limit
             counts. A million empty vaults cost nothing.
* ALLOCATED — the sum of the size limits people have handed to vaults out of their own account
             quota. Spending an account budget is what makes "give 2 GB to a shared vault, take
             it back later" possible, so allocation is a reservation INSIDE one account. It
             never counts toward the deployment limit.
* CAPACITY  — what the disk physically holds. Reported for operators; not an enforcement axis
             (the volume can be grown under a running deployment).

A bound of None always means UNLIMITED / not enforced.
"""

GIB = 1024 ** 3
INT64_MAX = 2 ** 63 - 1  # vaults.size_limit is BigInteger; anything larger overflows the column

# users.storage_quota_bytes sentinel: this account is exempt from the account budget entirely.
# NULL in that column means "inherit the deployment default" instead, so the tri-state is
# NULL = inherit, UNLIMITED_QUOTA = no budget, >= 0 = exactly that many bytes.
UNLIMITED_QUOTA = -1


def parse_gb(value):
    """A GB number out of JSON/env -> float, or None when it is absent, blank, boolean or
    unparseable. Booleans are rejected explicitly: bool is an int subclass, so True would
    otherwise sail through as 1 GB."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def gb_to_bytes(gb):
    """Whole bytes for a GB number, truncated. Negative input clamps to 0."""
    return max(0, int(gb * GIB))


def quota_setting_bytes(raw):
    """A per-account / per-vault GB quota from the settings blob -> bytes, where absent, zero,
    negative or unparseable all mean UNLIMITED (None). That permissive reading is deliberate:
    a fresh deployment that never saved a quota is unbounded, and an admin opts IN by saving a
    positive number of GB."""
    gb = parse_gb(raw)
    if gb is None or gb <= 0:
        return None
    return gb_to_bytes(gb)


def env_ceiling_bytes(max_storage_gb):
    """The deployment's HARD storage ceiling from the MAX_STORAGE_GB deployment variable, in
    bytes. None / <= 0 (the shipped default is -1) means no ceiling is configured, so the admin
    panel is free to set any limit it likes."""
    gb = parse_gb(max_storage_gb)
    if gb is None or gb <= 0:
        return None
    return gb_to_bytes(gb)


def deployment_limit_bytes(max_storage_gb, stored_setting):
    """The EFFECTIVE limit on stored bytes across the deployment.

    `stored_setting` is the admin's chosen value (GB) from the settings blob; absent means the
    admin has not narrowed anything, so the deployment runs at its full configured ceiling.
    An admin value is always clamped INTO the env ceiling — the panel can lower the limit but
    never raise it above what the deployment was configured to allow.

    Note 0 is a real, honoured value here (a freeze: no further bytes accepted), unlike the
    per-account/per-vault quotas above where 0 means "unlimited". The two conventions differ
    because this one is a bounded slider from 0 to a known maximum, not an opt-in field.
    """
    ceiling = env_ceiling_bytes(max_storage_gb)
    gb = parse_gb(stored_setting)
    if gb is None:
        return ceiling
    chosen = gb_to_bytes(gb)
    return min(chosen, ceiling) if ceiling is not None else chosen


def would_exceed_deployment(stored_bytes, additional_bytes, limit_bytes):
    """Whether writing `additional_bytes` more would pass the deployment limit. No limit => never."""
    if limit_bytes is None:
        return False
    return int(stored_bytes or 0) + max(0, int(additional_bytes or 0)) > limit_bytes


def validate_deployment_limit(requested_gb, max_storage_gb, stored_bytes):
    """Reason a proposed deployment limit is unacceptable, or None when it is fine.

    Two rules, both of which an operator can act on from the message alone: it may not exceed
    the deployment's configured maximum, and it may not be set below what is ALREADY stored
    (which would strand existing files above a limit nobody can satisfy without deleting data).
    """
    gb = parse_gb(requested_gb)
    if gb is None:
        return "The storage limit must be a number of GB."
    if gb < 0:
        return "The storage limit cannot be negative."
    requested = gb_to_bytes(gb)
    ceiling = env_ceiling_bytes(max_storage_gb)
    if ceiling is not None and requested > ceiling:
        return (f"The storage limit cannot exceed this deployment's maximum of "
                f"{format_gb(ceiling)} (set by MAX_STORAGE_GB).")
    stored = int(stored_bytes or 0)
    if requested < stored:
        return (f"The storage limit cannot be lower than the {format_bytes(stored)} already "
                f"stored. Delete files first, then lower the limit.")
    return None


def account_quota_bytes(override, default_setting):
    """A user's EFFECTIVE account budget in bytes, or None when they have none.

    `override` is users.storage_quota_bytes: None inherits the deployment default, the
    UNLIMITED_QUOTA sentinel exempts the account, and any other value >= 0 is an exact byte
    budget (0 legitimately means "may not allocate any storage at all"). `default_setting` is
    the raw default_user_quota GB value from the settings blob.
    """
    if override is not None:
        override = int(override)
        return None if override < 0 else override
    return quota_setting_bytes(default_setting)


def parse_account_quota_input(value):
    """An administrator's per-account quota input -> what belongs in users.storage_quota_bytes.

    None / "inherit" / "default" / "" all mean "fall back to the deployment default" (NULL),
    "unlimited" / "none" exempt the account (UNLIMITED_QUOTA), and a number >= 0 is an exact
    budget in GB. Raises ValueError carrying a message meant for the administrator.

    "Inherit" and "unlimited" have to be separate answers: an account with no override follows
    the deployment default as it changes over time, while an exempt account keeps its exemption
    when the default moves.
    """
    if value is None:
        return None
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("", "inherit", "default"):
            return None
        if token in ("unlimited", "none", "exempt"):
            return UNLIMITED_QUOTA
        value = token  # fall through so a numeric string is parsed like a number
    if isinstance(value, bool):
        raise ValueError("The storage quota must be a number of GB, 'inherit' or 'unlimited'.")
    gb = parse_gb(value)
    if gb is None:
        raise ValueError("The storage quota must be a number of GB, 'inherit' or 'unlimited'.")
    if gb < 0:
        raise ValueError("The storage quota cannot be negative. Use 'unlimited' for no limit.")
    bytes_ = gb_to_bytes(gb)
    if bytes_ > INT64_MAX:
        raise ValueError(f"The storage quota cannot exceed {INT64_MAX // GIB} GB.")
    return bytes_


def account_headroom_bytes(quota_bytes, allocated_bytes):
    """How much of an account budget is still unspent. None (unlimited) stays None."""
    if quota_bytes is None:
        return None
    return max(0, quota_bytes - int(allocated_bytes or 0))


def max_vault_total_bytes(per_vault_ceiling, account_headroom, other_grants=0):
    """The largest TOTAL size limit a vault may carry for this contributor: their remaining
    account headroom on top of what everyone else already contributed, bounded by the admin's
    per-vault ceiling. None when neither axis is bounded."""
    bounds = []
    if per_vault_ceiling is not None:
        bounds.append(per_vault_ceiling)
    if account_headroom is not None:
        bounds.append(int(other_grants or 0) + account_headroom)
    return min(bounds) if bounds else None


def check_grant(new_grant, *, current_grant, other_grants, stored_bytes,
                per_vault_ceiling=None, account_quota=None, allocated_elsewhere=0):
    """Validate a contributor setting their own allocation on one vault to `new_grant` bytes.

    Everything is absolute rather than a delta, so a retried or concurrent request converges on
    the same state instead of stacking. `allocated_elsewhere` is what this contributor has given
    to OTHER vaults, so their own current grant here is never double-counted against them —
    that is what lets them reclaim exactly what they put in.

    Returns an operator/user-facing reason string, or None when the change is allowed.
    """
    if new_grant is None or isinstance(new_grant, bool):
        return "Your storage contribution must be a number of bytes."
    try:
        new_grant = int(new_grant)
    except (TypeError, ValueError):
        return "Your storage contribution must be a number of bytes."
    if new_grant < 0:
        return "Your storage contribution cannot be negative."

    other = int(other_grants or 0)
    new_total = other + new_grant
    if new_total > INT64_MAX:
        return f"The vault's size limit cannot exceed {INT64_MAX // GIB} GB."
    if new_total < 1:
        # A zero total would read as "no limit" to every upload guard, so the last contributor
        # cannot withdraw a vault's entire allocation — they delete the vault instead.
        return ("A vault must keep a size limit of at least 1 byte. Delete the vault instead of "
                "removing all of its storage.")

    stored = int(stored_bytes or 0)
    if new_total < stored:
        return (f"That would put the vault's limit ({format_bytes(new_total)}) below the "
                f"{format_bytes(stored)} it already stores. Free up space in the vault first.")

    if per_vault_ceiling is not None and new_total > per_vault_ceiling:
        return (f"That would put the vault's limit ({format_bytes(new_total)}) above the "
                f"{format_bytes(per_vault_ceiling)} maximum an administrator allows per vault.")

    if account_quota is not None:
        spent = int(allocated_elsewhere or 0) + new_grant
        if spent > account_quota:
            available = max(0, account_quota - int(allocated_elsewhere or 0))
            return (f"That would use {format_bytes(spent)} of your {format_bytes(account_quota)} "
                    f"storage quota. You can contribute up to {format_bytes(available)} to this vault.")

    # Reassure the caller that reclaiming is bounded by what they personally gave: any decrease
    # is fine as long as the checks above pass, and current_grant is accepted purely so callers
    # can pass their read-modify-write state through one function.
    _ = current_grant
    return None


def format_bytes(n):
    """Bytes as a short human string for user-facing messages ('2.50 GB', '512 MB', '900 B')."""
    n = int(n or 0)
    for unit, size in (("GB", GIB), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            value = n / size
            return f"{value:.2f} {unit}" if value < 10 else f"{value:.0f} {unit}"
    return f"{n} B"


def format_gb(n):
    """Bytes rendered in GB for limit messages, where GB is always the right unit."""
    value = int(n or 0) / GIB
    return f"{value:.2f} GB" if value < 10 else f"{value:.0f} GB"
