"""Changes to managed settings (app/core/settings_registry.py): a change that deletes data sooner waits.

A setting whose spec names a reduction direction (``reduction``) can be changed two ways:

- a change that keeps data at least as long applies at once: the value is stored, with a
  ``setting_changed`` audit row naming the values in force before and after;
- a change that deletes data sooner (a reduction) waits RETENTION_REDUCTION_DELAY_DAYS (7 by default, at
  least 1): it is recorded as a pending change in ``managed_setting_changes``, with a
  ``setting_change_requested`` row, and the pruner applies it once it is due (apply_due), writing
  ``setting_change_applied``. Any administrator may cancel it before then, the one who asked included
  (``setting_change_cancelled``).

Whether a change deletes sooner is decided against the setting in force (the administrator's value, else
the deployment's), read from the table in the request's transaction, never from a process's copy, which may
be seconds old. The setting decides, not the value it resolves to under the deployment's floor and ceiling:
lowering a setting the ceiling clamps is a reduction even where the clamp keeps today's value, because the
lower setting counts the day the deployment moves its bound. (Clamping never reverses an order, so a value
that falls always comes with a setting that falls.)

A newer change of a setting supersedes the pending one: whichever way it goes, the pending change ends as
superseded. Asking for the value already in force while a change is pending keeps that value, and cancels
the pending change.

Every change is written with its audit row in one transaction, so a change whose row cannot be written is
not made. After the commit every active administrator is told, in the app and by email: the email is a
system email, which no setting turns off. Requests, cancels and applying take a table lock on Postgres, so
two of them never decide from the same state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from app.core import settings_registry as registry

PENDING = "pending"
APPLIED = "applied"
CANCELLED = "cancelled"
SUPERSEDED = "superseded"

DELAY_KEY = "retention_reduction_delay_days"

registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=DELAY_KEY, kind="int", default=7, env="retention_reduction_delay_days", minimum=1, maximum=90,
    editable=registry.ENV_ONLY, group="retention", unit="days",
    label="Wait before a change that deletes records sooner",
    help="A change that makes records be deleted sooner takes effect only after this many days; any "
         "administrator can cancel it meanwhile, and every administrator is told."))

# The audit rows this module writes.
CHANGED = "setting_changed"
REQUESTED = "setting_change_requested"
SCHEDULED_ACTION = "setting_change_scheduled"
CANCELLED_ACTION = "setting_change_cancelled"
APPLIED_ACTION = "setting_change_applied"

# Checks across settings, added by the modules whose settings must agree with each other: each is given the
# spec and the value asked for (None: the deployment's value) and returns a refusal in plain words, or None.
CROSS_CHECKS: list = []

# The in-app notice's type, and the system email every administrator is sent.
NOTICE_TYPE = "retention_change"
EMAIL_ACTION = "retention_change"


def utcnow() -> datetime:
    """Now as the tables store it: UTC, with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def delay() -> timedelta:
    return timedelta(days=registry.resolve(DELAY_KEY))


@dataclass
class Outcome:
    """What a request did: ``applied`` (stored now), ``pending`` (waits for ``change.effective_at``),
    ``kept`` (the value in force stays, and the pending change ended), or ``unchanged`` (nothing to do)."""
    status: str
    key: str
    old: object = None
    new: object = None
    setting: object = None
    change: object = None
    superseded: list = field(default_factory=list)
    # The audit row the change wrote, and the cancel rows of the pending changes it kept (for the chain).
    audit_row: object = None
    cancel_rows: list = field(default_factory=list)


def _lock(db) -> None:
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        from sqlalchemy import text
        db.execute(text("LOCK TABLE managed_setting_changes IN SHARE ROW EXCLUSIVE MODE"))


def in_force(db, spec: registry.SettingSpec):
    """(stored, setting, value) for ``spec``, read in ``db``'s transaction: the administrator's stored value
    that applies (None when there is none, or it is invalid, or the setting is locked), the setting in force
    (that, else the deployment's value), and the value it resolves to under the deployment's bounds."""
    from app.core.models import ManagedSetting
    row = db.get(ManagedSetting, spec.key)
    stored = None
    if row is not None and not registry.is_locked(spec):
        stored = registry._stored_value(spec, {spec.key: (row.value, row.version)})
    deployment, _source = registry.deployment_value(spec)
    setting = stored if stored is not None else deployment
    floor, ceiling = registry.bounds(spec)
    return stored, setting, registry.clamp(spec, setting, floor, ceiling)


def resolved(spec: registry.SettingSpec, setting):
    """The value ``setting`` (None: the deployment's value) resolves to under the deployment's bounds."""
    deployment, _source = registry.deployment_value(spec)
    floor, ceiling = registry.bounds(spec)
    return registry.clamp(spec, deployment if setting is None else setting, floor, ceiling)


def deletes_sooner(spec: registry.SettingSpec, old_setting, new_setting) -> bool:
    """Whether moving from the old setting to the new one makes data be deleted sooner."""
    return registry.is_reduction(spec, old_setting, new_setting)


def pending_for(db, key: Optional[str] = None):
    from app.core.models import ManagedSettingChange as Change
    query = db.query(Change).filter(Change.status == PENDING)
    if key is not None:
        query = query.filter(Change.key == key)
    return query.order_by(Change.requested_at).all()


def _audit(db, action, *, user=None, details, key):
    """Add the audit row of a change to ``db``'s transaction, and return it (its id goes into the change's
    seal in the audit chain)."""
    from app.services.audit_logger import AuditLogger
    row = AuditLogger(db).build_row(action=action, status="success", user=user, resource_type="setting",
                                    resource_id=key, details=details)
    db.add(row)
    return row


def _end(change, status, *, by_id, by_name, now, reason) -> None:
    change.status, change.decided_by, change.decided_by_name = status, by_id, by_name
    change.decided_at, change.reason = now, reason


def request(db, key: str, requested, *, actor, now: Optional[datetime] = None, judge=None) -> Outcome:
    """An administrator's ``requested`` value for ``key`` (None: back to the deployment's value), in ``db``'s
    transaction, with its audit row. It does not commit. The caller checks first that the panel may set
    the value (managed_settings_router.refusal). ``judge`` (app/core/audit_chain_policy_seals.Judge), for a
    setting the audit chain records, gives the value in force and the change's direction from the chain
    instead of from the stored value."""
    from app.core.models import ManagedSettingChange as Change
    spec = registry.spec_for(key)
    if spec is None:
        raise registry.SettingRefused(f"{key} is not a setting the panel manages")
    now = now or utcnow()
    _lock(db)
    db_stored = in_force(db, spec)[0]
    stored, old_setting, old_value = judge.in_force() if judge is not None else in_force(db, spec)
    new_setting = requested if requested is not None else registry.deployment_value(spec)[0]
    new_value = resolved(spec, requested)
    waiting = pending_for(db, key)
    base = dict(key=key, old=old_value, new=new_value, setting=requested)
    # With the chain's judge, the value in force is the chain's, and the database must hold it too: a value
    # the database lost, or one written into it without the chain's key, is put right by storing the request.
    if requested == stored and (judge is None or (requested == db_stored and not judge.alters_chain(requested))):
        if not waiting:
            return Outcome("unchanged", **base)
        rows = []
        for change in waiting:
            _end(change, SUPERSEDED, by_id=actor.id, by_name=actor.username, now=now,
                 reason="the value in force was kept")
            rows.append(_audit(db, CANCELLED_ACTION, user=actor, key=key, details={
                "key": key, "change_id": str(change.id), "old": change.old_value, "new": change.new_value,
                "setting": change.setting, "kept": old_value}))
        return Outcome("kept", superseded=waiting, cancel_rows=rows, **base)
    for change in waiting:
        _end(change, SUPERSEDED, by_id=actor.id, by_name=actor.username, now=now,
             reason="a newer change of the same setting")
    superseded = [str(c.id) for c in waiting]
    sooner = judge.deletes_sooner(requested) if judge is not None else deletes_sooner(spec, old_setting, new_setting)
    if not sooner:
        registry.store(db, key, requested, by_id=actor.id, by_name=actor.username, now=now)
        row = _audit(db, CHANGED, user=actor, key=key, details={**base, "superseded": superseded})
        return Outcome("applied", superseded=waiting, audit_row=row, **base)
    change = Change(key=key, setting=requested, old_value=old_value, new_value=new_value, status=PENDING,
                    requested_by=actor.id, requested_by_name=actor.username, requested_at=now,
                    effective_at=now + delay())
    db.add(change)
    db.flush()
    row = _audit(db, REQUESTED, user=actor, key=key, details={
        **base, "change_id": str(change.id), "effective_at": change.effective_at.isoformat() + "Z",
        "superseded": superseded})
    return Outcome("pending", change=change, superseded=waiting, audit_row=row, **base)


def schedule(db, key: str, setting, *, by_name: str, old_value, now: Optional[datetime] = None,
             rows: Optional[list] = None) -> dict:
    """A waiting change the server itself asks for, with no administrator behind it (the first pass after
    an upgrade, app/core/audit_retention.py): recorded like a request, in ``db``'s transaction, with its
    audit row (added to ``rows`` when given, for the change's seal). It supersedes a waiting change of the
    setting. Returns the details its notice needs."""
    from app.core.models import ManagedSettingChange as Change
    spec = registry.spec_for(key)
    now = now or utcnow()
    _lock(db)
    for change in pending_for(db, key):
        _end(change, SUPERSEDED, by_id=None, by_name=by_name, now=now, reason="a newer change of the same setting")
    change = Change(key=key, setting=setting, old_value=old_value, new_value=resolved(spec, setting),
                    status=PENDING, requested_by=None, requested_by_name=by_name, requested_at=now,
                    effective_at=now + delay())
    db.add(change)
    db.flush()
    details = {"key": key, "old": old_value, "new": change.new_value, "setting": setting,
               "change_id": str(change.id), "effective_at": change.effective_at.isoformat() + "Z",
               "requested_by": by_name}
    row = _audit(db, SCHEDULED_ACTION, key=key, details=details)
    if rows is not None:
        rows.append(row)
    return details


def cancel(db, change_id, *, actor, now: Optional[datetime] = None):
    """Cancel a pending change, by any administrator, in ``db``'s transaction, with its audit row. Raises
    LookupError for no such change and SettingRefused for one no longer pending."""
    from app.core.models import ManagedSettingChange as Change
    now = now or utcnow()
    _lock(db)
    change = db.get(Change, change_id)
    if change is None:
        raise LookupError(change_id)
    if change.status != PENDING:
        raise registry.SettingRefused(f"This change is no longer waiting: it was {change.status}.")
    _end(change, CANCELLED, by_id=actor.id, by_name=actor.username, now=now, reason="cancelled")
    change._audit_row = _audit(db, CANCELLED_ACTION, user=actor, key=change.key, details={
        "key": change.key, "change_id": str(change.id), "old": change.old_value, "new": change.new_value,
        "setting": change.setting, "requested_by": change.requested_by_name})
    return change


def cancel_held(db, change_id, held: dict, *, actor, now: Optional[datetime] = None) -> dict:
    """Cancel a change the audit log's integrity chain holds waiting, by any administrator, in ``db``'s
    transaction, with its audit row. ``held`` is the change as the chain holds it (an entry of
    app/core/audit_chain_pending.py): the audit row and the answer say what the chain sealed, and the database's
    row, when there is one, is marked cancelled whatever it said, so an edited or deleted row neither keeps the
    change from being cancelled nor changes what is recorded. Returns the entry, ended, with the audit row under
    ``_audit_row`` (for the cancel's seal)."""
    from app.core.models import ManagedSettingChange as Change
    now = now or utcnow()
    _lock(db)
    row = db.get(Change, change_id)
    if row is not None:
        _end(row, CANCELLED, by_id=actor.id, by_name=actor.username, now=now, reason="cancelled")
    out = dict(held, status=CANCELLED, decided_by=actor.username, decided_at=now.isoformat() + "Z",
               reason="cancelled")
    out["_audit_row"] = _audit(db, CANCELLED_ACTION, user=actor, key=held["key"], details={
        "key": held["key"], "change_id": str(change_id), "old": held["old"], "new": held["new"],
        "setting": held["setting"], "requested_by": held["requested_by"]})
    return out


def apply_due(session_factory: Callable, *, now: Optional[datetime] = None, limit_statements=None) -> list:
    """Apply every pending change that is due, one per transaction, each with its audit row, and tell every
    administrator. A change the deployment has meanwhile locked or taken out of the panel's hands ends as
    cancelled, with the reason. Returns what ended, as (change id, status) pairs. Run by the pruner."""
    from app.core.models import ManagedSettingChange as Change
    now = now or utcnow()
    ended = []
    while True:
        db = session_factory()
        try:
            if limit_statements is not None:
                limit_statements(db)
            _lock(db)
            change = (db.query(Change).filter(Change.status == PENDING, Change.effective_at <= now)
                      .order_by(Change.effective_at).first())
            if change is None:
                db.rollback()
                break
            spec = registry.spec_for(change.key)
            before = in_force(db, spec)[2] if spec is not None else change.old_value
            details = {"key": change.key, "change_id": str(change.id), "old": before, "new": change.new_value,
                       "setting": change.setting, "requested_by": change.requested_by_name,
                       "requested_at": change.requested_at.isoformat() + "Z"}
            try:
                registry.store(db, change.key, change.setting, by_id=change.requested_by,
                               by_name=change.requested_by_name, now=now)
            except registry.SettingRefused as why:
                details["reason"] = str(why)
                _end(change, CANCELLED, by_id=None, by_name=None, now=now, reason=str(why)[:255])
                _audit(db, CANCELLED_ACTION, key=change.key, details=details)
            else:
                details["new"] = resolved(spec, change.setting)
                _end(change, APPLIED, by_id=None, by_name=None, now=now, reason=None)
                _audit(db, APPLIED_ACTION, key=change.key, details=details)
            done = (change.id, change.status, dict(details))
            db.commit()
            ended.append(done)
        except Exception as exc:  # noqa: BLE001 -- the next pass tries again
            db.rollback()
            registry._say(f"Warning: a waiting settings change was not applied ({type(exc).__name__}); the "
                          "next pass tries again")
            break
        finally:
            db.close()
    if ended:
        registry.refresh()
        for _id, status, details in ended:
            announce(TOOK_EFFECT if status == APPLIED else ENDED_BY_DEPLOYMENT, details)
    return [(i, s) for i, s, _d in ended]


# --------------------------------------------------------------------------- telling the administrators

CHANGED_AT_ONCE = "changed"
ASKED = "asked"
SCHEDULED = "scheduled"
CANCELLED_BY_ADMIN = "cancelled"
KEPT = "kept"
TOOK_EFFECT = "took_effect"
ENDED_BY_DEPLOYMENT = "ended"


def _words(details) -> tuple:
    spec = registry.spec_for(details.get("key", ""))
    label = (spec.label or spec.key) if spec is not None else details.get("key", "a setting")

    def show(value):
        return registry.shown(spec, value) if spec is not None else str(value)

    return label, show(details.get("old")), show(details.get("new"))


def _date(value) -> str:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.rstrip("Z"))
    return value.strftime("%d %B %Y, %H:%M UTC").lstrip("0") if value else ""


def notice_text(event: str, details: dict, by: Optional[str] = None) -> tuple:
    """(title, body) of the notice every administrator gets for ``event``."""
    label, old, new = _words(details)
    by = by or "An administrator"
    if event == CHANGED_AT_ONCE:
        return ("A setting for how long records are kept was changed",
                f"{by} changed “{label}” from {old} to {new}.")
    if event == ASKED:
        return ("A change that deletes records sooner is waiting",
                f"{by} asked to change “{label}” from {old} to {new}. Records would be deleted sooner, "
                f"so the change takes effect on {_date(details.get('effective_at'))} unless an administrator "
                "cancels it on the Settings page.")
    if event == SCHEDULED:
        spec = registry.spec_for(details.get("key", ""))
        where = f"{spec.env.upper()} in .env" if spec is not None and spec.env else "The deployment"
        return ("Old audit rows will be deleted after a wait",
                f"{where} sets “{label}” to {new}. Old records are now deleted on a timer, so this "
                f"change from {old} to {new} takes effect on {_date(details.get('effective_at'))} unless an "
                "administrator cancels it on the Settings page. Until then it deletes nothing.")
    if event == CANCELLED_BY_ADMIN:
        return ("A waiting change was cancelled",
                f"{by} cancelled the change of “{label}” from {old} to {new} that "
                f"{details.get('requested_by') or 'an administrator'} asked for. Nothing changes.")
    if event == KEPT:
        return ("A waiting change was cancelled",
                f"{by} kept “{label}” at {old}, which cancels the waiting change to {new}.")
    if event == TOOK_EFFECT:
        return ("A change that deletes records sooner took effect",
                f"The change of “{label}” from {old} to {new} that "
                f"{details.get('requested_by') or 'an administrator'} asked for on "
                f"{_date(details.get('requested_at'))} took effect.")
    return ("A waiting change did not take effect",
            f"The change of “{label}” to {new} did not take effect: {details.get('reason', '')}.")


def announce(event: str, details: dict, by: Optional[str] = None) -> None:
    """Tell every active administrator, in the app and by email, after the commit. Never raises: a notice
    never undoes the change."""
    try:
        from app.api import api_server as api
        from app.core.database import get_db_context
        from app.core.models import RoleEnum, User
        title, body = notice_text(event, details, by)
        with get_db_context() as db:
            admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
            recipients = [(a.email, a.username) for a in admins]
            api._notify_users([str(a.id) for a in admins], NOTICE_TYPE, title=title, body=body,
                              target="#settings")
            api._fire_action_email_bulk(db, EMAIL_ACTION, recipients,
                                        {"change": body, "by": by or "", "when": api._change_time_text()})
    except Exception as exc:  # noqa: BLE001
        registry._say(f"Warning: the administrators were not told of a settings change ({type(exc).__name__})")


def outcome_details(outcome: Outcome) -> dict:
    details = {"key": outcome.key, "old": outcome.old, "new": outcome.new, "setting": outcome.setting}
    if outcome.change is not None:
        details["effective_at"] = outcome.change.effective_at
    return details


def announce_outcome(outcome: Outcome, by: str) -> None:
    """The notice for what request() did (nothing for ``unchanged``)."""
    if outcome.status == "unchanged":
        return
    if outcome.status == "kept":
        for change in outcome.superseded:
            announce(KEPT, {"key": outcome.key, "old": outcome.old, "new": change.new_value}, by)
        return
    event = {"applied": CHANGED_AT_ONCE, "pending": ASKED}[outcome.status]
    announce(event, outcome_details(outcome), by)
