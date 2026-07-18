"""Pure account-password policy checks driven by the admin Security settings.

No app imports, so it unit-tests in isolation; the caller reads the SystemSetting('global') blob and
passes it in. The API model already enforces an absolute floor (min_length=8); this raises the
minimum and adds the optional complexity requirements the admin turns on.
"""

HARD_FLOOR = 8  # the API model's min_length; the stored policy can only tighten above this


def password_policy_errors(password, cfg):
    """Return a list of human-readable requirement phrases `password` FAILS under policy `cfg`
    (a dict from the settings blob). Empty list = the password is acceptable.

    cfg keys (all optional): password_min_length (int; clamped up to HARD_FLOOR), and the booleans
    require_uppercase / require_lowercase / require_numbers / require_special. A missing/false toggle
    is not enforced; an absent/invalid min falls back to HARD_FLOOR.
    """
    pw = password or ""
    try:
        min_len = int(cfg.get("password_min_length"))
    except (TypeError, ValueError):
        min_len = HARD_FLOOR
    min_len = max(HARD_FLOOR, min_len)

    errors = []
    if len(pw) < min_len:
        errors.append(f"be at least {min_len} characters long")
    if cfg.get("require_uppercase") and not any(c.isupper() for c in pw):
        errors.append("include an uppercase letter")
    if cfg.get("require_lowercase") and not any(c.islower() for c in pw):
        errors.append("include a lowercase letter")
    if cfg.get("require_numbers") and not any(c.isdigit() for c in pw):
        errors.append("include a number")
    if cfg.get("require_special") and not any((not c.isalnum()) and (not c.isspace()) for c in pw):
        errors.append("include a special character")
    return errors
