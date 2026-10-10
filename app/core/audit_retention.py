"""How long audit rows are kept: three numbers, which the pruner's audit job applies (app/core/retention.py).

    audit_max_days        the maximum: rows older than this go. 0 keeps rows for ever. Its deployment value is
                          AUDIT_LOG_RETENTION_DAYS; PLAN_LOG_MAX_DAYS, when set, is its ceiling and forbids
                          "for ever".
    audit_min_days        the protected minimum for every row: none younger than this is deleted, by age or
                          by size. AUDIT_MIN_RETENTION_DAYS is its deployment value and its floor.
    audit_admin_min_days  the protected minimum for the administration and security rows (the categories of
                          app/core/audit_catalog.py): none younger than this is deleted by age. 365 days by
                          default; AUDIT_PROTECTED_MIN_DAYS is its deployment value and its floor, so only
                          .env can lower it. Without it, one administrator could set a short maximum and
                          have their own trail deleted a week later.
    audit_max_mb          the size cap: 0 is off. Its deployment value is AUDIT_LOG_MAX_MB, and
                          PLAN_LOG_MAX_MB, when set, is its ceiling and forbids "off".

The size cap deletes the oldest rows until what is left fits, and never an administration or security row,
nor a row younger than the protected minimum, nor one a row-keep rule keeps. What it counts is the audit
chain's: each hour's bytes as the seals that set its roots bound them, lagged over one reduction delay
(RETENTION_REDUCTION_DELAY_DAYS) of time while sealing ran (app/core/audit_chain_size.py), so an hour counts
its rows only once a delay of sealing has passed since the seal that took them in, and rows younger than the
window are never deleted by it: whoever can make the app write rows, or write them into the table, cannot make
it delete older ones before the delay. How much of an hour it may never delete comes from its rows, but never
more than the chain binds as the hour's protected bytes, so rows written into an old hour can only lower it.
When the protected rows alone exceed the cap, the administrators are told, once a day, and nothing protected
goes. The size of a row is what Postgres stores for it (pg_column_size of the row), measured by the sealer when
it seals the row's hour.

Each is a managed setting whose lowering deletes sooner, so it waits (app/core/setting_changes.py). The
startup contract refuses a deployment whose .env contradicts itself: a protected minimum longer than the
ceiling on the maximum, or a maximum shorter than the minimum for every row. The panel refuses a maximum
shorter than the minimum for every row, and the other way round.

preview() says what a choice of the numbers would delete now, by the same conditions the job uses.

The first pass after an upgrade from a release that pruned on read: an AUDIT_LOG_RETENTION_DAYS already
positive, with rows older than it, is not applied at once. The pass keeps the rows (the maximum is stored as
"for ever") and schedules the change to the .env value as a waiting change, with the notice to every
administrator, so it takes effect only after the delay, unless an administrator cancels it. Months of
dashboards nobody opened never deleted those rows, and a timer must not suddenly do so. Until that pass has
stored its marker, the audit job deletes nothing, so a failure of that pass never lets the .env value apply
at once.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import Text, and_, cast, func, literal_column, not_, or_

from app.core import settings_registry as registry

MAX_DAYS, MIN_DAYS, ADMIN_MIN_DAYS, MAX_MB = "audit_max_days", "audit_min_days", "audit_admin_min_days", "audit_max_mb"
GROUP = "audit_retention"
# The categories whose rows the size cap never deletes, and which audit_admin_min_days protects.
PROTECTED_CATEGORIES = ("administration", "security")
# Who asked for the change the first pass after an upgrade schedules.
SERVER = "the server (AUDIT_LOG_RETENTION_DAYS in .env)"
# The row in system_settings that says the first pass has looked at AUDIT_LOG_RETENTION_DAYS.
MARKER = "audit_env_retention_scheduled"
MB = 1024 * 1024

registry.register(registry.SettingSpec(
    key=MAX_DAYS, kind="int", default=0, env="audit_log_retention_days", minimum=1, maximum=36500,
    unlimited=0, ceiling="plan_log_max_days", reduction=registry.LOWER, group=GROUP, unit="days",
    label="Keep audit rows for at most",
    help="Older rows are deleted. No limit keeps them for ever."))
registry.register(registry.SettingSpec(
    key=MIN_DAYS, kind="int", default=0, env="audit_min_retention_days", minimum=0, maximum=36500,
    floor="audit_min_retention_days", reduction=registry.LOWER, group=GROUP, unit="days",
    label="Keep every audit row for at least",
    help="No row younger than this is deleted, whatever the maximum or the size cap."))
registry.register(registry.SettingSpec(
    key=ADMIN_MIN_DAYS, kind="int", default=365, env="audit_protected_min_days", minimum=0, maximum=36500,
    floor="audit_protected_min_days", reduction=registry.LOWER, group=GROUP, unit="days",
    label="Keep administration and security rows for at least",
    help="These rows record what administrators did and the security events. Only .env can lower this."))
registry.register(registry.SettingSpec(
    key=MAX_MB, kind="int", default=0, env="audit_log_max_mb", minimum=1, maximum=10_000_000, unlimited=0,
    ceiling="plan_log_max_mb", reduction=registry.LOWER, group=GROUP, unit="MB",
    label="Size cap on audit rows",
    help="Above it the oldest rows are deleted, never administration or security rows. Off keeps any size."))


def _add_cross_check() -> None:
    from app.core import setting_changes
    if cross_check not in setting_changes.CROSS_CHECKS:
        setting_changes.CROSS_CHECKS.append(cross_check)


@registry.register_contract
def _contract(settings) -> list:
    """What in .env makes the three numbers impossible to honour together."""
    problems = []
    ceiling = getattr(settings, "plan_log_max_days", -1)
    ceiling = ceiling if isinstance(ceiling, int) and not isinstance(ceiling, bool) and ceiling > 0 else None
    for name in ("audit_protected_min_days", "audit_min_retention_days"):
        value = getattr(settings, name, 0)
        if ceiling is not None and isinstance(value, int) and value > ceiling:
            problems.append(f"{name.upper()} ({value}) is longer than PLAN_LOG_MAX_DAYS ({ceiling}): those rows "
                            f"could be neither kept nor deleted; lower {name.upper()}")
    maximum = getattr(settings, "audit_log_retention_days", 0)
    minimum = getattr(settings, "audit_min_retention_days", 0)
    if isinstance(maximum, int) and isinstance(minimum, int) and 0 < maximum < minimum:
        problems.append(f"AUDIT_LOG_RETENTION_DAYS ({maximum}) is shorter than AUDIT_MIN_RETENTION_DAYS ({minimum})")
    return problems


@dataclass(frozen=True)
class Numbers:
    max_days: int
    min_days: int
    admin_min_days: int
    max_mb: int


def current() -> Numbers:
    return Numbers(registry.resolve(MAX_DAYS), registry.resolve(MIN_DAYS), registry.resolve(ADMIN_MIN_DAYS),
                   registry.resolve(MAX_MB))


def cross_check(spec, value) -> Optional[str]:
    """The panel's refusal of a maximum shorter than the minimum for every row, and the other way round."""
    from app.core import setting_changes
    if spec.key not in (MAX_DAYS, MIN_DAYS):
        return None
    new = setting_changes.resolved(spec, value)
    maximum = new if spec.key == MAX_DAYS else registry.resolve(MAX_DAYS)
    minimum = new if spec.key == MIN_DAYS else registry.resolve(MIN_DAYS)
    if maximum and minimum > maximum:
        return (f"Audit rows cannot be kept at most {maximum} days while every row is kept at least {minimum} "
                "days: raise the maximum or lower the minimum first")
    return None


_add_cross_check()


def protected_actions() -> list:
    from app.core import audit_catalog
    return audit_catalog.stored_names(PROTECTED_CATEGORIES)


# --------------------------------------------------------------------------- the conditions

def floors(model, now: datetime, numbers: Numbers) -> list:
    """Conditions for the rows the protected minimums keep from deletion by age."""
    kept = []
    if numbers.min_days > 0:
        kept.append(model.timestamp >= now - timedelta(days=numbers.min_days))
    if numbers.admin_min_days > 0:
        kept.append(and_(model.action.in_(protected_actions()),
                         model.timestamp >= now - timedelta(days=numbers.admin_min_days)))
    return kept


def by_age(model, now: datetime, numbers: Numbers) -> Optional[list]:
    """Conditions for the rows the maximum deletes, or None when rows are kept for ever. Other modules'
    row-keep rules are not in them (retention.deletable adds those)."""
    if not numbers.max_days:
        return None
    kept = floors(model, now, numbers)
    return [model.timestamp < now - timedelta(days=numbers.max_days)] + ([not_(or_(*kept))] if kept else [])


def _size_protected(model, now: datetime, numbers: Numbers):
    """The rows the size cap never deletes: administration and security rows, rows younger than the minimum
    for every row, and rows a row-keep rule keeps."""
    from app.core import retention
    kept = [model.action.in_(protected_actions())]
    if numbers.min_days > 0:
        kept.append(model.timestamp >= now - timedelta(days=numbers.min_days))
    kept.extend(retention.keep_clauses(model, now))
    return or_(*kept)


def _row_bytes(model, dialect: str):
    if dialect == "postgresql":
        return func.pg_column_size(literal_column(model.__tablename__ + ".*"))
    # Elsewhere (the offline tests' SQLite) a stand-in that grows with the row's details.
    return 100 + func.length(func.coalesce(cast(model.details, Text), ""))


def _hour(model, dialect: str):
    if dialect == "postgresql":
        return func.date_trunc("hour", model.timestamp)
    return func.strftime("%Y-%m-%d %H:00:00", model.timestamp)


def _as_time(hour) -> datetime:
    return hour if isinstance(hour, datetime) else datetime.strptime(hour, "%Y-%m-%d %H:%M:%S")


@dataclass
class SizePlan:
    counted_bytes: int = 0          # what the cap counts (the chain's total): hot hours' lagged bytes, archived parts
    protected_bytes: int = 0        # of those, rows the cap may never delete
    cutoff: Optional[datetime] = None   # delete the unprotected counted rows older than this
    met: bool = True                # whether what is left fits under the cap
    counted_before: Optional[datetime] = None   # the window's start: the cap deletes only rows older than this
    size: Optional[dict] = None     # what the prune seal records: cap, delay, from, counted, held_back


def chain_size_plan(db, model, view, record, now: datetime, numbers: Numbers, delay: timedelta, *,
                    server: bool = True) -> SizePlan:
    """How the size cap applies now, from the audit chain's verified view: each sealed hour counts its lagged
    bytes over a window of one delay of time while sealing ran, and each archived part the smaller of its bound
    length and its hours' lagged bytes (app/core/audit_chain_size.py); the total is the chain's, and the rows
    (an archived part's aggregates, app/core/audit_archive.py) decide only which part of a figure the cap may
    never delete, never more than the protected bytes the chain binds for its hours (rows only lower a share).
    It keeps the newest hours and parts, protected rows first, that fit under the cap; the
    unprotected rows of older ones go, and never a row younger than the window's start."""
    from app.core import audit_archive
    from app.core import audit_chain_format as fmt
    from app.core import audit_chain_size as chain_size
    from app.core.audit_chain_view import from_us
    plan = SizePlan()
    if not numbers.max_mb:
        return plan
    start_us = chain_size.window_start(view, record, now, delay, server=server)
    held = chain_size.held_back(view, record, start_us) if server else set()
    by_hour, parts = chain_size.counted(view, start_us, held)
    cap = numbers.max_mb * MB
    plan.counted_bytes = sum(by_hour.values()) + sum(c for _d, _p, c, _h in parts)
    plan.counted_before = from_us(start_us)
    plan.size = {"cap": cap, "delay": delay.days, "from": fmt.time_text(plan.counted_before),
                 "counted": plan.counted_bytes, "held_back": sorted(held)}
    if not plan.counted_bytes:
        return plan
    # (hour, counted, protected): an archived part's spread over its hours (app/core/audit_archive.py part_units).
    # A share comes from the rows, but never above what the chain binds as that hour's protected bytes (or the
    # whole hour, when every row of it is younger than the minimum for every row), so rows added in the database
    # can only lower it.
    bound = chain_size.protected_hours(view, start_us, held)
    young = now - timedelta(days=numbers.min_days) if numbers.min_days > 0 else None
    units = []
    if by_hour:
        dialect = db.get_bind().dialect.name
        hour = _hour(model, dialect)
        rows = (db.query(hour.label("hour"), func.sum(_row_bytes(model, dialect)))
                .filter(_size_protected(model, now, numbers)).group_by(hour).all())
        protected_rows = {_as_time(h): int(size or 0) for h, size in rows}
        for h, counted in by_hour.items():
            most = counted if young is not None and h >= young else bound.get(h, 0)
            units.append((h, counted, min(protected_rows.get(h, 0), counted, most)))
    if any(c for _d, _p, c, _h in parts):
        figures = audit_archive.part_figures(db, view)
        for d, part, c, lagged in parts:
            units += audit_archive.part_units(part, c, lagged, bound, figures.get((d, part.part)), now,
                                              numbers.min_days)
    plan.protected_bytes = sum(p for _w, _c, p in units)
    left = plan.protected_bytes
    for when, counted, protected in sorted(units, key=lambda u: u[0], reverse=True):
        if counted == protected:
            continue
        if left + counted - protected > cap:
            plan.cutoff = when + timedelta(hours=1)
            break
        left += counted - protected
    plan.met = plan.protected_bytes <= cap
    return plan


def by_size(model, now: datetime, numbers: Numbers, plan: SizePlan) -> Optional[list]:
    """Conditions for the rows the size cap deletes under ``plan``, or None when it deletes none. The cutoff
    is the end of an hour, which can be later than the start of the delay: a row younger than the delay is
    still never deleted."""
    if plan.cutoff is None:
        return None
    return [model.timestamp < plan.cutoff, model.timestamp < plan.counted_before,
            not_(_size_protected(model, now, numbers))]


# --------------------------------------------------------------------------- the job and the preview

def _delay() -> timedelta:
    """The delay the size cap's window counts: the chain's honoured one, or the registry's before the chain."""
    chain = chain_numbers()
    if chain is not None:
        return chain[1]
    from app.core import setting_changes
    return setting_changes.delay()


def chain_numbers() -> Optional[tuple]:
    """(numbers, delay, hold) as the audit chain's honoured state gives them, or None when the chain cannot
    give them yet (no chain, or sealing stopped): then the audit job deletes nothing."""
    from app.core import audit_chain_policy_seals as ps
    from app.core.audit_chain_policy import DELAY_ENTRY
    from app.core.retention import HOLD_KEY
    values = ps.numbers()
    if values is None:
        return None
    try:
        numbers = Numbers(int(values[MAX_DAYS]), int(values[MIN_DAYS]), int(values[ADMIN_MIN_DAYS]),
                          int(values[MAX_MB]))
        return numbers, timedelta(days=int(values[DELAY_ENTRY])), bool(values.get(HOLD_KEY))
    except (KeyError, TypeError, ValueError):
        return None


def prune(p, numbers: Optional[Numbers] = None):
    """The pruner's audit job: rows older than the maximum, then the oldest the size cap allows no room for.
    Both act on the audit chain's state, never on the database's values alone, and delete through ``prune``
    seals (app/core/audit_chain_prune.py), so a deletion keeps the chain valid. ``numbers`` replaces the
    chain's numbers (a test's); the chain must still be running."""
    from app.core import audit_chain_prune, retention
    from app.core.models import AuditLog
    result = retention.JobResult()
    chain = chain_numbers()
    if chain is None:
        registry._say("The pruner's audit_logs job waits for the audit chain")
        return result
    chain_values, delay, hold = chain
    if hold:
        return result
    from app.core import audit_integrity
    st = audit_integrity.state()
    why = st.holds_deletion()
    if why:
        registry._say(f"The pruner's audit_logs job deletes nothing: {why}")
        return result
    numbers = numbers or chain_values
    aged = by_age(AuditLog, p.now, numbers)
    if aged:
        # Archived rows go through their blocks (app/core/audit_archive.py), selected by the same conditions over
        # a table shaped like audit_logs; only days that start before the maximum's cutoff are read.
        done = audit_chain_prune.prune(
            p, retention.deletable(AuditLog, p.now, *aged), reason="retention",
            archived=lambda m: retention.deletable(m, p.now, *by_age(m, p.now, numbers)),
            before=p.now - timedelta(days=numbers.max_days))
        result.add(done.deleted, done.oldest, done.newest)
    # The size cap counts the chain's figures, which still hold what the maximum is about to delete: it runs
    # once the maximum's work is done (time left in the pass).
    if numbers.max_mb and p.time_left():
        def plan(w):
            sp = chain_size_plan(w.db, AuditLog, w.st.view, w.record, p.now, numbers, delay)
            sized = by_size(AuditLog, p.now, numbers, sp)
            if not sized:
                return None
            return audit_chain_prune.Selection(
                retention.deletable(AuditLog, p.now, *sized), sp.size,
                archived=lambda m: retention.deletable(m, p.now, *by_size(m, p.now, numbers, sp)),
                before=min(sp.cutoff, sp.counted_before))

        done = audit_chain_prune.prune(p, None, reason="size-cap", plan=plan)
        result.add(done.deleted, done.oldest, done.newest)
        with p.transaction() as db:
            final = chain_size_plan(db, AuditLog, st.view, st.known_record(), p.now, numbers, delay)
        if not final.met:
            warn_cap_unmet(numbers, final, p.now)
    return result


def preview(db, now: datetime, numbers: Numbers) -> dict:
    """What the audit job would delete now under ``numbers``: rows and bytes by age and by size, and the
    time of the newest row each deletes."""
    from app.core import retention
    from app.core.models import AuditLog
    dialect = db.get_bind().dialect.name
    size = _row_bytes(AuditLog, dialect)

    def measure(conditions):
        if not conditions:
            return {"rows": 0, "bytes": 0, "newest": None}
        rows, total, newest = db.query(func.count(), func.coalesce(func.sum(size), 0), func.max(AuditLog.timestamp)).filter(
            *retention.deletable(AuditLog, now, *conditions)).one()
        return {"rows": int(rows), "bytes": int(total), "newest": newest.isoformat() + "Z" if newest else None}

    from app.core import audit_archive, audit_integrity
    st = audit_integrity.state()
    aged = by_age(AuditLog, now, numbers)
    plan = chain_size_plan(db, AuditLog, st.view, st.known_record(), now, numbers, _delay())
    sized = by_size(AuditLog, now, numbers, plan)
    if sized and aged:
        sized = sized + [not_(and_(*retention.deletable(AuditLog, now, *aged)))]
    # Archived rows, estimated from their blocks' aggregates (whole hours).
    archived = audit_archive.preview(
        db, st.view, age_cut=now - timedelta(days=numbers.max_days) if numbers.max_days else None,
        admin_cut=now - timedelta(days=numbers.admin_min_days) if numbers.admin_min_days > 0 else None,
        size_cut=min(plan.cutoff, plan.counted_before) if plan.cutoff is not None else None,
        young_cut=now - timedelta(days=numbers.min_days) if numbers.min_days > 0 else None)
    return {"by_age": measure(aged), "by_size": measure(sized), "archived": archived, "cap_met": plan.met,
            "counted_bytes": plan.counted_bytes, "protected_bytes": plan.protected_bytes}


def warn_cap_unmet(numbers: Numbers, plan: SizePlan, now: datetime) -> None:
    """Tell every active administrator, once a day, that the size cap cannot be met without deleting rows
    that are protected. Never raises."""
    try:
        from app.api import api_server as api
        from app.core.database import get_db_context
        from app.core.models import RoleEnum, User
        with get_db_context() as db:
            ids = [str(a.id) for a in db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True))]
        api._notify_users(
            ids, "retention_warning", title="The audit log is over its size cap",
            body=(f"The audit rows the size cap may never delete (administration and security rows, and rows "
                  f"younger than the protected minimum) take {plan.protected_bytes // MB} MB, more than the "
                  f"cap of {numbers.max_mb} MB. They are kept. Raise the cap, or check the Settings page."),
            target="#settings", dedup_prefix=f"audit-size-cap:{now:%Y-%m-%d}")
    except Exception as exc:  # noqa: BLE001
        registry._say(f"Warning: the administrators were not told the audit log is over its cap ({type(exc).__name__})")


# --------------------------------------------------------------------------- the first pass after an upgrade

def env_retention_decided(p) -> bool:
    """Whether the first pass after an upgrade has looked at AUDIT_LOG_RETENTION_DAYS (its marker is stored)."""
    from app.core.models import SystemSetting
    with p.transaction() as db:
        return db.get(SystemSetting, MARKER) is not None


def schedule_env_retention_once(p):
    """Once per deployment: a positive AUDIT_LOG_RETENTION_DAYS with rows older than it becomes a waiting
    change, with notice, instead of deleting at the first pass (see the module's docstring)."""
    from app.core import retention, setting_changes
    from app.core.models import AuditLog, ManagedSetting, SystemSetting
    scheduled = None
    with p.transaction() as db:
        if db.get(SystemSetting, MARKER) is not None:
            return retention.JobResult()
        days = int(getattr(retention._settings(), "audit_log_retention_days", 0) or 0)
        row = db.get(ManagedSetting, MAX_DAYS)
        stored = row.value if row is not None else None
        older = days > 0 and db.query(AuditLog.id).filter(
            AuditLog.timestamp < p.now - timedelta(days=days)).first() is not None
        # A deployment that locked the maximum wants its .env value as it is; an administrator's value
        # already stored is what applies.
        if older and stored is None and not registry.is_locked(registry.spec_for(MAX_DAYS)):
            registry.store(db, MAX_DAYS, 0, by_name=SERVER, now=p.now)
            scheduled = setting_changes.schedule(db, MAX_DAYS, None, by_name=SERVER, old_value=0, now=p.now)
        db.add(SystemSetting(key=MARKER, value={"at": p.now.isoformat() + "Z", "days": days,
                                                "scheduled": scheduled is not None}))
    if scheduled is not None:
        registry.refresh(p.session_factory)
        setting_changes.announce(setting_changes.SCHEDULED, scheduled)
    return retention.JobResult()
