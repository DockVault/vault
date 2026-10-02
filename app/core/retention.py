"""The pruner: every timed deletion of records runs here, off the event loop, one runner at a time.

JOBS lists what is deleted, in order. Each job over a table that can grow large deletes in batches of
LOG_PRUNE_BATCH_ROWS rows, one batch per transaction (the records of credential changes, which are few, go in
one statement), each transaction bounded by a statement timeout, and every pass has a time budget
(PASS_SECONDS): a job that runs out of time stops where it is, and the next pass goes on. Every transaction
that deletes or clears something adds a ``retention_pruned`` audit row to itself, with the job, the table, how
many rows went and the times of the oldest and newest of them. So a pass stopped part way (a crash, a
restart) leaves a record of every batch it committed, and a batch whose record cannot be written deletes
nothing.

Where it runs. run_forever() is started by the web process only, so a split deployment's SFTP container
never runs a second pruner. Its passes run on a thread of their own (a single-thread executor), never on the
event loop: the periodic loop in the web app (cleanup_expired_sessions) is async and runs its database work
on the event loop, so nothing that can take long may be added there, and every timed deletion lives here
instead. Only one runner works at a time, in every process and on every host: a pass first takes a
session-level advisory lock on a connection of its own, and a pass that cannot take it does nothing.

What a job may not delete. Other modules register row-keep rules for a table (register_keep): each gives a
condition for rows that must stay (a category's protected minimum, rows a compliance case or a legal hold
keeps), and every job over that table leaves them.

The hold switch. ``logs_hold`` (the deployment's value is RETENTION_HOLD; with RETENTION_HOLD=true the panel
cannot turn it off) stops every job over logs and security records while it is on. The jobs over working
records (finished sessions, credential-change records, the sign-in throttle's fallback rows, waiting
settings changes) keep running. Turning the hold off deletes sooner, so it waits like any such change
(app/core/setting_changes.py).
"""
from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy import and_, not_, or_, text

from app.core import settings_registry as registry

# How long one pass may run before it stops and leaves the rest to the next.
PASS_SECONDS = 120.0
# The first pass waits this long after the web app starts, so it never delays the start.
FIRST_PASS_SECONDS = 60.0
# How long any one statement of a batch may run.
STATEMENT_TIMEOUT_MS = 30000
# The advisory lock one runner holds for its pass (distinct from the other lock classes in the app).
RUNNER_LOCK = (0x7265, 1)

HOLD_KEY = "logs_hold"
INTERVAL_KEY = "log_prune_interval_minutes"
BATCH_KEY = "log_prune_batch_rows"

registry.register(registry.SettingSpec(
    key=HOLD_KEY, kind="bool", default=False, env="retention_hold", reduction=registry.LOWER,
    floor="retention_hold",
    group="retention", label="Hold all deletion of logs",
    help="While on, nothing deletes audit rows, security records or security alerts: for an incident, or "
         "while records must be kept. Turning it off deletes sooner, so it waits before it takes effect."))
registry.register(registry.SettingSpec(
    key=INTERVAL_KEY, kind="int", default=15, env="log_prune_interval_minutes", minimum=1, maximum=1440,
    editable=registry.ENV_ONLY, group="retention", unit="minutes",
    label="Time between two passes of the pruner"))
registry.register(registry.SettingSpec(
    key=BATCH_KEY, kind="int", default=5000, env="log_prune_batch_rows", minimum=100, maximum=100000,
    editable=registry.ENV_ONLY, group="retention", unit="rows",
    label="Rows the pruner deletes in one transaction"))
# Fixed windows, listed so the panel can say what the vault keeps and for how long. Each is tied to a rule.
registry.register(registry.SettingSpec(
    key="session_records_days", kind="int", default=30, editable=registry.FIXED, group="working_records",
    unit="days", label="Finished sessions and sign-ins waiting for a second factor",
    help="Kept 30 days after they end (longer when a sign-in's token lives longer), then deleted."))
registry.register(registry.SettingSpec(
    key="credential_change_records_days", kind="int", default=14, editable=registry.FIXED,
    group="working_records", unit="days", label="Records of changes to people's sign-in details",
    help="Kept 14 days after the change, or after the request was decided, then deleted."))
registry.register(registry.SettingSpec(
    key="rate_limit_records_hours", kind="int", default=1, editable=registry.FIXED, group="working_records",
    unit="hours", label="Sign-in throttle records kept while the cache is unavailable",
    help="Deleted an hour after their window starts."))


def utcnow() -> datetime:
    """Now as the tables store it: UTC, with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hold_in_force() -> bool:
    return bool(registry.resolve(HOLD_KEY))


def _say(message: str) -> None:
    registry._say(message)


# --------------------------------------------------------------------------- what may not be deleted

KEEP_RULES: dict[str, list] = {}


def register_keep(table: str, rule: Callable) -> Callable:
    """Keep rows of ``table``: ``rule(model, now)`` returns a condition for the rows that must stay, or
    None when it keeps nothing just now. Every job over the table leaves them."""
    rules = KEEP_RULES.setdefault(table, [])
    if rule not in rules:
        rules.append(rule)
    return rule


def keep_clauses(model, now: datetime) -> list:
    """The conditions of the rows of ``model``'s table the row-keep rules keep, as of ``now``."""
    clauses = []
    for rule in KEEP_RULES.get(model.__tablename__, []):
        clause = rule(model, now)
        if clause is not None:
            clauses.append(clause)
    return clauses


def deletable(model, now: datetime, *conditions) -> list:
    """``conditions`` for the rows a job deletes, and not those a row-keep rule keeps."""
    kept = keep_clauses(model, now)
    return list(conditions) + ([not_(or_(*kept))] if kept else [])


# --------------------------------------------------------------------------- one pass

@dataclass
class JobResult:
    deleted: int = 0
    oldest: Optional[datetime] = None
    newest: Optional[datetime] = None
    # Rows a job changed rather than deleted (it cleared their personal values).
    cleared: int = 0

    def add(self, count: int, oldest=None, newest=None) -> None:
        self.deleted += count
        if oldest is not None and (self.oldest is None or oldest < self.oldest):
            self.oldest = oldest
        if newest is not None and (self.newest is None or newest > self.newest):
            self.newest = newest


@dataclass(frozen=True)
class Job:
    name: str
    label: str
    run: Callable
    # Stopped by the hold switch: the jobs over logs and security records.
    held: bool = False


class Pass:
    """What a job is given: the time the pass stands at, its batch size, its time budget, and sessions
    whose statements are bounded."""

    def __init__(self, session_factory: Callable, *, now: Optional[datetime] = None,
                 batch_rows: Optional[int] = None, budget_seconds: float = PASS_SECONDS):
        self.session_factory = session_factory
        self.now = now or utcnow()
        self.batch_rows = int(batch_rows if batch_rows is not None else registry.resolve(BATCH_KEY))
        self.deadline = time.monotonic() + budget_seconds
        # The job running now (run_pass sets it), which names the records its transactions write.
        self.job_name: Optional[str] = None

    def time_left(self) -> bool:
        return time.monotonic() < self.deadline

    @contextmanager
    def transaction(self):
        """A session whose statements are bounded, committed at the end, rolled back on an error."""
        db = self.session_factory()
        try:
            limit_statements(db)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def record(self, db, done: JobResult, table: Optional[str] = None) -> None:
        """Add to ``db``'s transaction the retention_pruned audit row for what that transaction deleted or
        cleared (``done``), so the two commit together or not at all. Nothing done, no row."""
        if not (done.deleted or done.cleared):
            return
        from app.services.audit_logger import AuditLogger
        iso = (lambda v: v.isoformat() + "Z" if v is not None else None)
        job = self.job_name or table
        details = {"job": job, "table": table, "deleted": done.deleted, "oldest": iso(done.oldest),
                   "newest": iso(done.newest)}
        if done.cleared:
            details["cleared"] = done.cleared
        db.add(AuditLogger(db).build_row(action="retention_pruned", status="success", resource_type="table",
                                         resource_id=job, details=details))

    def delete_in_batches(self, model, conditions, time_column) -> JobResult:
        """Delete the rows of ``model`` meeting ``conditions``, oldest first, one batch per transaction,
        while the pass has time, each batch's record written in that batch's transaction. Rows another
        transaction holds are skipped, not waited for."""
        result = JobResult()
        id_column = model.__mapper__.primary_key[0]
        while self.time_left():
            with self.transaction() as db:
                rows = (db.query(id_column, time_column).filter(*conditions).order_by(time_column)
                        .limit(self.batch_rows).with_for_update(skip_locked=True).all())
                batch = JobResult()
                if rows:
                    db.query(model).filter(id_column.in_([r[0] for r in rows])).delete(
                        synchronize_session=False)
                    times = [r[1] for r in rows if r[1] is not None]
                    batch.add(len(rows), min(times) if times else None, max(times) if times else None)
                    self.record(db, batch, model.__tablename__)
            result.add(batch.deleted, batch.oldest, batch.newest)
            if len(rows) < self.batch_rows:
                break
        return result


def limit_statements(db) -> None:
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


# --------------------------------------------------------------------------- the jobs

def _settings():
    from app.core.config import settings
    return settings


def apply_waiting_changes(p: Pass) -> JobResult:
    """Waiting settings changes that are due (app/core/setting_changes.py). Deletes nothing itself."""
    from app.core import setting_changes
    setting_changes.apply_due(p.session_factory, now=p.now, limit_statements=limit_statements)
    return JobResult()


def prune_sessions(p: Pass, *, session_model=None, pending_model=None) -> JobResult:
    """Finished session rows and pending sign-ins past their window (app/core/session_retention.py). The
    models are parameters so the real conditions can run against a throwaway schema."""
    from app.core import session_retention as sr
    from app.core.models import ActiveSession, PendingLogin
    session_model = session_model or ActiveSession
    pending_model = pending_model or PendingLogin
    window = sr.session_window(_settings().jwt_access_token_expire_minutes)
    result = p.delete_in_batches(
        session_model,
        deletable(session_model, p.now, *sr.finished_session_conditions(session_model, p.now, window)),
        session_model.started_at)
    pending = p.delete_in_batches(
        pending_model,
        deletable(pending_model, p.now, *sr.finished_pending_login_conditions(pending_model, p.now)),
        pending_model.created_at)
    result.add(pending.deleted, pending.oldest, pending.newest)
    return result


def prune_credential_changes(p: Pass) -> JobResult:
    """Records of credential changes applied, or requests decided, 14 days ago (credential_changes.prune_done).
    They are few, so they go in one statement, bounded like every other."""
    from app.core import credential_changes as cc
    from app.core.models import CredentialChange
    with p.transaction() as db:
        done = JobResult(deleted=cc.prune_done(db, p.now))
        p.record(db, done, CredentialChange.__tablename__)
    return done


def prune_rate_limit_records(p: Pass) -> JobResult:
    """The sign-in throttle's fallback rows (written only while Redis is down), an hour after their window."""
    from app.core.models import RateLimitRecord
    return p.delete_in_batches(
        RateLimitRecord, deletable(RateLimitRecord, p.now, RateLimitRecord.window_start < p.now - timedelta(hours=1)),
        RateLimitRecord.window_start)


def prune_resolved_alerts(p: Pass) -> JobResult:
    """Security alerts resolved more than SECURITY_ALERT_RETENTION_DAYS ago. Unresolved alerts stay."""
    from app.core import security_records
    from app.core.models import SecurityAlert
    days = int(registry.resolve(security_records.ALERT_RETENTION_KEY))
    return p.delete_in_batches(
        SecurityAlert, deletable(SecurityAlert, p.now, SecurityAlert.resolved.is_(True),
                                 SecurityAlert.timestamp < p.now - timedelta(days=days)),
        SecurityAlert.timestamp)


def prune_security_records(p: Pass) -> JobResult:
    """Failed sign-ins kept in full past the security record's window (app/core/security_records.py)."""
    from app.core import security_records
    return security_records.prune_records(p)


def clear_alert_values(p: Pass) -> JobResult:
    """The names and addresses of security alerts older than the security record's window, resolved or not."""
    from app.core import security_records
    return security_records.clear_alert_values(p)


def schedule_env_audit_retention(p: Pass) -> JobResult:
    """Once, after an upgrade: a positive AUDIT_LOG_RETENTION_DAYS waits like a change that deletes sooner
    (app/core/audit_retention.py)."""
    from app.core import audit_retention
    return audit_retention.schedule_env_retention_once(p)


def prune_audit_logs(p: Pass) -> JobResult:
    """Audit rows past the maximum, and the oldest the size cap has no room for (app/core/audit_retention.py).
    Nothing until the job before it has made its once-only decision about AUDIT_LOG_RETENTION_DAYS: had that
    job failed, this one would otherwise apply the .env maximum at once."""
    from app.core import audit_retention
    if not audit_retention.env_retention_decided(p):
        _say("The pruner's audit_logs job waits: the audit_env_retention job has not run yet")
        return JobResult()
    return audit_retention.prune(p)


JOBS: list[Job] = [
    Job("setting_changes", "Waiting settings changes that are due", apply_waiting_changes),
    Job("sessions", "Finished sessions and sign-ins", prune_sessions),
    Job("credential_changes", "Records of changes to people's sign-in details", prune_credential_changes),
    Job("rate_limit_records", "Sign-in throttle records", prune_rate_limit_records),
    Job("security_alerts", "Resolved security alerts", prune_resolved_alerts, held=True),
    Job("security_records", "Failed sign-ins kept in full", prune_security_records, held=True),
    Job("security_alert_values", "Names and addresses in old security alerts", clear_alert_values, held=True),
    Job("audit_env_retention", "A retention set in .env before timed deletion", schedule_env_audit_retention),
    Job("audit_logs", "Audit rows", prune_audit_logs, held=True),
]


@contextmanager
def _runner_turn(engine):
    """Whether this pass may run: True for the one runner that holds the lock, False for any other. On
    Postgres a session-level advisory lock held on a connection of its own for the pass, across processes
    and hosts; elsewhere this process's lock alone."""
    if not _local_turn.acquire(blocking=False):
        yield False
        return
    try:
        if engine is None or engine.dialect.name != "postgresql":
            yield True
            return
        conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
        try:
            got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:c, :k)"),
                                    {"c": RUNNER_LOCK[0], "k": RUNNER_LOCK[1]}).scalar())
            try:
                yield got
            finally:
                if got:
                    conn.execute(text("SELECT pg_advisory_unlock(:c, :k)"), {"c": RUNNER_LOCK[0], "k": RUNNER_LOCK[1]})
        finally:
            conn.invalidate()     # never back to the pool: a session lock must not outlive the pass
            conn.close()
    finally:
        _local_turn.release()


_local_turn = threading.Lock()


def run_pass(session_factory: Optional[Callable] = None, *, engine=None, now: Optional[datetime] = None,
             budget_seconds: float = PASS_SECONDS, batch_rows: Optional[int] = None):
    """Run every job once. Returns [(job name, result or None)] for the jobs that ran (None: it failed, or
    the hold switch stopped it), or None when another runner is working. Never raises."""
    try:
        if session_factory is None:
            from app.core.database import _require_engine, started_session
            session_factory, engine = started_session, _require_engine()
        p = Pass(session_factory, now=now, batch_rows=batch_rows, budget_seconds=budget_seconds)
    except Exception as exc:  # noqa: BLE001 -- the next pass asks again
        _say(f"Warning: the pruner did not run ({type(exc).__name__})")
        return None
    with _runner_turn(engine) as mine:
        if not mine:
            return None
        # The settings as they stand now, not as this process's copy had them up to seconds ago: a hold
        # turned on stops the very next pass.
        registry.refresh(session_factory)
        hold = hold_in_force()
        done = []
        for job in JOBS:
            if not p.time_left():
                break
            if job.held and hold:
                done.append((job.name, None))
                continue
            p.job_name = job.name
            try:
                result = job.run(p)
            except Exception as exc:  # noqa: BLE001 -- one job's failure never stops the others
                _say(f"Warning: the pruner's {job.name} job failed ({type(exc).__name__}); the next pass tries again")
                done.append((job.name, None))
                continue
            done.append((job.name, result))
        return done


_executor: Optional[ThreadPoolExecutor] = None


def executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="retention")
    return _executor


def interval_seconds() -> float:
    return float(registry.resolve(INTERVAL_KEY)) * 60.0


async def run_forever(*, first_delay: float = FIRST_PASS_SECONDS, interval: Optional[Callable[[], float]] = None,
                      pass_fn: Optional[Callable] = None) -> None:
    """The web process's pruner: a pass after ``first_delay`` seconds, then one every
    LOG_PRUNE_INTERVAL_MINUTES, each on the pruner's own thread. Survives any error; ends only when
    cancelled."""
    loop = asyncio.get_running_loop()
    interval = interval or interval_seconds
    pass_fn = pass_fn or run_pass
    await asyncio.sleep(first_delay)
    while True:
        try:
            await loop.run_in_executor(executor(), pass_fn)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            _say(f"Warning: the pruner's pass failed ({type(exc).__name__})")
        await asyncio.sleep(interval())
