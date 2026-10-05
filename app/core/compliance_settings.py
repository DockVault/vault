"""The deployment's limits on compliance access: fifteen settings that only .env sets.

Compliance access lets an auditor investigate vaults, in a case a second administrator approves and the
vault's owner is told of at once, and keeps a vault's files under a legal hold. The operator sets its
boundary in .env, never the admin panel: each setting is registered here, so the panel lists it with the
value in force and SETTINGS_LOCKED_KEYS can name it (or the group ``compliance``), and a value outside its
bounds refuses to start, naming the .env line.

    COMPLIANCE_ACCESS                 enabled | disabled. Disabled suspends active cases and refuses new grants,
                                      requests, approvals, content and reveals; holds stay in force.
    COMPLIANCE_PASSWORD_VAULTS        refuse | with_password | override: how a case treats a vault with a password.
    COMPLIANCE_EXPORT                 allowed | disabled.
    COMPLIANCE_MAX_ACCESS_DAYS        the longest access period a case is given at a time.
    COMPLIANCE_MAX_TOTAL_DAYS         the longest a case's access may last, across its extensions.
    COMPLIANCE_MAX_CASE_VAULTS        vaults in one case.
    COMPLIANCE_EXPORT_TTL_HOURS       how long an export waits to be fetched, once.
    COMPLIANCE_HOLD_CONFIRM_DAYS      a hold no second administrator confirmed lapses after this.
    COMPLIANCE_HOLD_PURGE_DELAY_DAYS  from a hold's release to the deletion of what it kept.
    COMPLIANCE_HOLD_REVIEW_DAYS       an open hold asks for a review after this.
    COMPLIANCE_VIEW_RATE              views per auditor per hour.
    COMPLIANCE_REVEALS_PER_DAY        recorded names one auditor may reveal per day.
    COMPLIANCE_AUDITOR_NOT_ADMIN      true: an administrator cannot hold the auditor right.
    COMPLIANCE_AUDITOR_GRANT_DAYS     how long an auditor grant lasts.
    COMPLIANCE_RECORD_MIN_DAYS        how long case records and their audit rows are kept after the case closes.

A case never widens when .env changes after it was approved: it records the values in force at its
approval (snapshot()) and uses, for each, the stricter of that and the current value (case_value()).

The startup contract refuses a deployment whose .env contradicts itself here: case records kept at least
COMPLIANCE_RECORD_MIN_DAYS cannot be kept under a ceiling on the audit log (PLAN_LOG_MAX_DAYS) shorter than
that, and an access period cannot be longer than all of a case's access.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from app.core import settings_registry as registry

GROUP = "compliance"

ACCESS = "compliance_access"
PASSWORD_VAULTS = "compliance_password_vaults"
EXPORT = "compliance_export"
MAX_ACCESS_DAYS = "compliance_max_access_days"
MAX_TOTAL_DAYS = "compliance_max_total_days"
MAX_CASE_VAULTS = "compliance_max_case_vaults"
EXPORT_TTL_HOURS = "compliance_export_ttl_hours"
HOLD_CONFIRM_DAYS = "compliance_hold_confirm_days"
HOLD_PURGE_DELAY_DAYS = "compliance_hold_purge_delay_days"
HOLD_REVIEW_DAYS = "compliance_hold_review_days"
VIEW_RATE = "compliance_view_rate"
REVEALS_PER_DAY = "compliance_reveals_per_day"
AUDITOR_NOT_ADMIN = "compliance_auditor_not_admin"
AUDITOR_GRANT_DAYS = "compliance_auditor_grant_days"
RECORD_MIN_DAYS = "compliance_record_min_days"

ENABLED, DISABLED = "enabled", "disabled"
REFUSE, WITH_PASSWORD, OVERRIDE = "refuse", "with_password", "override"
ALLOWED = "allowed"

# Which way is stricter, for each setting: a smaller number (LOWER), a larger one (HIGHER), or, for a
# choice, its values from the strictest to the least strict.
LOWER, HIGHER = "lower", "higher"
STRICTER: dict = {
    ACCESS: (DISABLED, ENABLED),
    PASSWORD_VAULTS: (REFUSE, WITH_PASSWORD, OVERRIDE),
    EXPORT: (DISABLED, ALLOWED),
    MAX_ACCESS_DAYS: LOWER,
    MAX_TOTAL_DAYS: LOWER,
    MAX_CASE_VAULTS: LOWER,
    EXPORT_TTL_HOURS: LOWER,
    # A hold one administrator placed stands unconfirmed for less time.
    HOLD_CONFIRM_DAYS: LOWER,
    # What a released hold kept stays longer, so a release can be undone for longer.
    HOLD_PURGE_DELAY_DAYS: HIGHER,
    HOLD_REVIEW_DAYS: LOWER,
    VIEW_RATE: LOWER,
    REVEALS_PER_DAY: LOWER,
    AUDITOR_NOT_ADMIN: (True, False),
    AUDITOR_GRANT_DAYS: LOWER,
    # Case records are kept longer.
    RECORD_MIN_DAYS: HIGHER,
}


def _spec(key: str, kind: str, default: Any, label: str, help: str = "", **kw) -> registry.SettingSpec:
    return registry.register(registry.SettingSpec(
        key=key, kind=kind, default=default, env=key, editable=registry.ENV_ONLY, lockable=True, group=GROUP,
        label=label, help=help, since="0.34.0", **kw))


_spec(ACCESS, "enum", ENABLED, "Compliance access", choices=(ENABLED, DISABLED),
      help="Disabled suspends every active case and refuses new grants, requests, approvals, content and "
           "reveals. Legal holds stay in force.")
_spec(PASSWORD_VAULTS, "enum", WITH_PASSWORD, "Vaults with a password in a case",
      choices=(REFUSE, WITH_PASSWORD, OVERRIDE),
      help="Refuse them, open them only with their password, or let the approver allow them without it.")
_spec(EXPORT, "enum", ALLOWED, "Exports from a case", choices=(ALLOWED, DISABLED))
_spec(MAX_ACCESS_DAYS, "int", 30, "Longest access period of a case", minimum=1, maximum=365, unit="days")
_spec(MAX_TOTAL_DAYS, "int", 90, "Longest access of a case, with its extensions", minimum=1, maximum=730,
      unit="days")
_spec(MAX_CASE_VAULTS, "int", 25, "Vaults in one case", minimum=1, maximum=1000, unit="vaults")
_spec(EXPORT_TTL_HOURS, "int", 24, "Time to fetch an export, once", minimum=1, maximum=168, unit="hours")
_spec(HOLD_CONFIRM_DAYS, "int", 7, "An unconfirmed legal hold lapses after", minimum=1, maximum=30, unit="days")
_spec(HOLD_PURGE_DELAY_DAYS, "int", 7, "From a hold's release to deleting what it kept", minimum=1, maximum=90,
      unit="days")
_spec(HOLD_REVIEW_DAYS, "int", 180, "An open legal hold asks for a review after", minimum=30, maximum=730,
      unit="days")
_spec(VIEW_RATE, "int", 600, "Views per auditor per hour", minimum=10, maximum=36000, unit="views")
_spec(REVEALS_PER_DAY, "int", 100, "Recorded names one auditor may reveal per day", minimum=1, maximum=10000,
      unit="names")
_spec(AUDITOR_NOT_ADMIN, "bool", False, "An administrator cannot be an auditor",
      help="On, the auditor right is never held by an administrator, and an auditor is not made one.")
_spec(AUDITOR_GRANT_DAYS, "int", 365, "An auditor grant lasts", minimum=1, maximum=365, unit="days")
_spec(RECORD_MIN_DAYS, "int", 2190, "Keep case records after the case closes for at least", minimum=365,
      maximum=36500, unit="days",
      help="Case records and their audit rows are never deleted while a case is open or a hold stands, nor "
           "before this many days after the case closes.")

KEYS: tuple = tuple(STRICTER)


@registry.register_contract
def _contract(settings) -> list:
    """What in .env makes the compliance settings impossible to honour together, in plain words."""
    def number(name):
        value = getattr(settings, name, None)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    problems = []
    ceiling = number("plan_log_max_days")
    floor = number(RECORD_MIN_DAYS)
    if ceiling is not None and ceiling > 0 and floor is not None and floor > ceiling:
        problems.append(f"COMPLIANCE_RECORD_MIN_DAYS ({floor}) is longer than PLAN_LOG_MAX_DAYS ({ceiling}): case "
                        "records could be neither kept nor deleted; lower COMPLIANCE_RECORD_MIN_DAYS or raise "
                        "PLAN_LOG_MAX_DAYS")
    period, total = number(MAX_ACCESS_DAYS), number(MAX_TOTAL_DAYS)
    if period is not None and total is not None and period > total:
        problems.append(f"COMPLIANCE_MAX_ACCESS_DAYS ({period}) is longer than COMPLIANCE_MAX_TOTAL_DAYS ({total}): "
                        "one access period cannot be longer than all of a case's access")
    return problems


def current(key: str):
    """The value in force now for the compliance setting ``key``."""
    if key not in STRICTER:
        raise KeyError(key)
    return registry.resolve(key)


def snapshot() -> dict:
    """Every compliance setting's value in force now: what a case records when it is approved."""
    return {key: current(key) for key in KEYS}


def _strictest(key: str):
    """The strictest value ``key`` can take: what an unreadable recorded value counts as."""
    order = STRICTER[key]
    if isinstance(order, tuple):
        return order[0]
    spec = registry.spec_for(key)
    return spec.minimum if order == LOWER else spec.maximum


def _readable(key: str, value) -> bool:
    spec = registry.spec_for(key)
    return spec is not None and registry.check_value(spec, value) is None


def stricter(key: str, recorded, now) -> Any:
    """The stricter of ``recorded`` (the value a case recorded when it was approved) and ``now`` (the value in
    force). Nothing recorded (None) is ``now``. A recorded value that is not a valid value of the setting counts
    as the strictest one, so a damaged record never widens a case."""
    if key not in STRICTER:
        raise KeyError(key)
    if recorded is None:
        return now
    if not _readable(key, recorded):
        recorded = _strictest(key)
    order = STRICTER[key]
    if isinstance(order, tuple):
        return recorded if order.index(recorded) <= order.index(now) else now
    if order == LOWER:
        return min(recorded, now)
    return max(recorded, now)


def case_value(key: str, recorded: Optional[Mapping]) -> Any:
    """The value of ``key`` a case uses: the stricter of what it recorded (``recorded``, the snapshot kept on
    the case, or None) and what is in force now."""
    return stricter(key, (recorded or {}).get(key), current(key))
