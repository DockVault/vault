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
keeps), and every job over that table leaves them. A rule registered with register_keep_as_is keeps its rows as
they are, where they are, too: the audit archive does not move them, and an erase, a removal of earlier values or
the shortening of addresses does not change them. Those modules are listed in KEEP_MODULES and imported with
this one.

The hold switch. ``logs_hold`` (the deployment's value is RETENTION_HOLD; with RETENTION_HOLD=true the panel
cannot turn it off) stops every job over logs and security records while it is on. A pass takes the stricter of
the stored settings and the audit chain's honoured state, and reads the stored settings again before each such job
and before each batch of one, so a hold turned on during a pass stops what comes after it. The jobs over working
records (finished sessions, expired key challenges, credential-change records, the sign-in throttle's
fallback rows, ended invitations, used or expired reset links and one-time codes, old notifications, waiting
settings changes) keep running. Turning the hold off deletes sooner, so it waits like any such change
(app/core/setting_changes.py).
"""
from __future__ import annotations

import asyncio
import importlib
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
    level=registry.ADVANCED, since="0.34.0",
    key=HOLD_KEY, kind="bool", default=False, env="retention_hold", reduction=registry.LOWER,
    floor="retention_hold",
    group="retention", label="Hold all deletion of logs",
    help="While on, nothing deletes audit rows, security records or security alerts: for an incident, or "
         "while records must be kept. Turning it off deletes sooner, so it waits before it takes effect."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=INTERVAL_KEY, kind="int", default=15, env="log_prune_interval_minutes", minimum=1, maximum=1440,
    editable=registry.ENV_ONLY, group="retention", unit="minutes",
    label="Time between two passes of the pruner",
    help="At most 360 minutes take effect: the audit log's integrity chain needs a seal at least every 12 "
         "hours, or every pending reduction waits the time between two passes longer."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=BATCH_KEY, kind="int", default=5000, env="log_prune_batch_rows", minimum=100, maximum=100000,
    editable=registry.ENV_ONLY, group="retention", unit="rows",
    label="Rows the pruner deletes in one transaction"))
# Fixed windows, listed so the panel can say what the vault keeps and for how long. Each is tied to a rule.
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key="session_records_days", kind="int", default=30, editable=registry.FIXED, group="working_records",
    unit="days", label="Finished sessions and sign-ins waiting for a second factor",
    help="Kept 30 days after they end (longer when a sign-in's token lives longer), then deleted."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key="credential_change_records_days", kind="int", default=14, editable=registry.FIXED,
    group="working_records", unit="days", label="Records of changes to people's sign-in details",
    help="Kept 14 days after the change, or after the request was decided, then deleted."))
registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key="rate_limit_records_hours", kind="int", default=1, editable=registry.FIXED, group="working_records",
    unit="hours", label="Sign-in throttle records kept while the cache is unavailable",
    help="Deleted an hour after their window starts."))


def utcnow() -> datetime:
    """Now as the tables store it: UTC, with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hold_in_force() -> bool:
    """The hold switch as the stored settings give it (the database's value, or the deployment's)."""
    return bool(registry.resolve(HOLD_KEY))


def stored_hold_now(session_factory: Optional[Callable] = None) -> bool:
    """The hold switch as the stored settings give it, read again now. An administrator's change of it writes the
    stored value and the audit chain's policy seal together, so a hold turned on during a pass is seen here."""
    registry.refresh(session_factory)
    return hold_in_force()


def chain_holds(session_factory: Optional[Callable] = None) -> bool:
    """Whether the audit chain holds every job over logs back: its honoured hold switch (a hold turned on in
    the chain counts at once, whatever the database says), a restore of a whole backup not finished, or the
    grace after a restore. Read together with hold_in_force(): the pruner takes the more conservative, so
    neither the database nor the chain alone can let records go. Holds when it cannot tell: a chain in the
    database this process has not read through (ChainState.view_read: sealing stopped before it could, the
    pass found the chain busy, or a check began to accept seals the head record's link has not verified while the
    hold was read) holds too; only a chain not started yet holds nothing."""
    try:
        from app.core import audit_chain_honour as honour
        from app.core import audit_integrity
        st = audit_integrity.state()
        if st.holds_deletion():
            return True

        def honoured(view):
            if view.newest_policy() is None:
                return None
            return honour.honoured_state(view, st.known_record(), st.clock())
        try:
            state = st.trusted(honoured)
        except audit_integrity.ViewUnread:
            state = None
        if state is None:
            return _chain_in_database(session_factory)
        return bool((state.get(HOLD_KEY) or {}).get("value"))
    except Exception as exc:  # noqa: BLE001 -- keeping records is the safe side
        _say(f"Warning: the audit chain's hold could not be read ({type(exc).__name__}); the jobs over logs wait")
        return True


def _chain_in_database(session_factory: Optional[Callable] = None) -> bool:
    """Whether the database holds any seal of the audit chain."""
    from app.core import audit_integrity
    if session_factory is None:
        from app.core.database import started_session as session_factory
    db = session_factory()
    try:
        return audit_integrity.newest_seq(db) > 0
    finally:
        db.close()


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
    # A model mapped to another table holding the same rows (the archive's) names the table whose rules apply.
    for rule in KEEP_RULES.get(getattr(model, "__keep_rules_of__", model.__tablename__), []):
        clause = rule(model, now)
        if clause is not None:
            clauses.append(clause)
    return clauses


def deletable(model, now: datetime, *conditions) -> list:
    """``conditions`` for the rows a job deletes, and not those a row-keep rule keeps."""
    kept = keep_clauses(model, now)
    return list(conditions) + ([not_(or_(*kept))] if kept else [])


# Rows that must stay exactly as they are, where they are: a job that moves rows elsewhere (the audit archive) or
# changes their values (a per-person erase, a removal of earlier values, the shortening of addresses) leaves them.
AS_IS_RULES: dict[str, list] = {}


def register_keep_as_is(table: str, rule: Callable) -> Callable:
    """Keep rows of ``table`` as they are: ``rule(model, now)`` as for register_keep. The rows are kept from
    deletion (the rule is a row-keep rule too), and from every job that moves or changes them."""
    register_keep(table, rule)
    rules = AS_IS_RULES.setdefault(table, [])
    if rule not in rules:
        rules.append(rule)
    return rule


def as_is_clauses(model, now: datetime) -> list:
    """The conditions of the rows of ``model``'s table that must stay as they are, as of ``now``."""
    clauses = []
    for rule in AS_IS_RULES.get(getattr(model, "__keep_rules_of__", model.__tablename__), []):
        clause = rule(model, now)
        if clause is not None:
            clauses.append(clause)
    return clauses


def changeable(model, now: datetime, *conditions) -> list:
    """``conditions`` for the rows a job moves or changes, and not those that must stay as they are."""
    kept = as_is_clauses(model, now)
    return list(conditions) + ([not_(or_(*kept))] if kept else [])


def kept_as_is(model, now: datetime):
    """One condition for the rows of ``model``'s table that must stay as they are, or None when no rule keeps any."""
    kept = as_is_clauses(model, now)
    return or_(*kept) if kept else None


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
        # The job running now (run_pass sets it), which names the records its transactions write, and whether the
        # hold switch stops it (then each of its batches asks again first: held_now()).
        self.job_name: Optional[str] = None
        self.job_held = False

    def time_left(self) -> bool:
        return time.monotonic() < self.deadline

    def held_now(self) -> bool:
        """Whether the hold switch stops the job running now: never for a job it does not stop; for one it stops,
        the stored settings read again (the audit chain's honoured hold is decided once a pass, before the first
        job it stops, and each job over the chain asks the chain itself in its transactions)."""
        if not self.job_held:
            return False
        return stored_hold_now(self.session_factory)

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

    def delete_in_batches(self, model, conditions, time_column, *, waits: Optional[Callable] = None) -> JobResult:
        """Delete the rows of ``model`` meeting ``conditions``, oldest first, one batch per transaction,
        while the pass has time, each batch's record written in that batch's transaction. Rows another
        transaction holds are skipped, not waited for. ``waits(db, now)``, when given, is asked first in each
        batch's transaction: a reason it gives (a legal hold, an open case: person_erase.rule_waits) ends the
        job with nothing more deleted."""
        result = JobResult()
        id_column = model.__mapper__.primary_key[0]
        while self.time_left():
            if self.held_now():
                break
            with self.transaction() as db:
                why = waits(db, self.now) if waits is not None else None
                if why:
                    _say(f"The pruner's {self.job_name or model.__tablename__} job waits: {why}")
                    break
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


def seal_audit_rows(p: Pass) -> JobResult:
    """The audit log's integrity chain (app/core/audit_integrity.py): every hour that may be sealed, the late
    rows of the last 6 hours, the cheap checks, and once a day the whole check. Deletes nothing; never held."""
    from app.core import audit_chain_verify, audit_integrity
    audit_integrity.seal_pass(p.session_factory, now=p.now, time_left=p.time_left)
    if p.time_left() and audit_integrity.state().stopped is None:
        audit_chain_verify.daily_check(p.session_factory)
    return JobResult()


def apply_waiting_changes(p: Pass) -> JobResult:
    """Waiting settings changes that are due, as the audit chain's request seals say, and the database's
    values compared with the chain (app/core/audit_chain_policy_seals.py). Deletes nothing itself. Before the
    chain has started, or while sealing is stopped, nothing applies."""
    from app.core import audit_chain_policy_seals as ps
    from app.core import audit_integrity
    st = audit_integrity.state()
    if st.stopped is not None or not st.view_read or st.view.newest_policy() is None:
        _say("Waiting settings changes wait for the audit chain")
        return JobResult()
    engine = audit_integrity._engine_of(p.session_factory)
    ps.apply_due(engine, st, p.now)
    found = ps.backstop(engine, st, p.now, p.session_factory)
    failures = {k: v for k, v in found.items() if k in audit_integrity.FAILURE_KINDS}
    warnings = {k: v for k, v in found.items() if k not in audit_integrity.FAILURE_KINDS}
    if failures or warnings:
        audit_integrity.report_failures(st, p.session_factory, failures, warnings)
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


def prune_key_proof_challenges(p: Pass, *, model=None) -> JobResult:
    """Zero-knowledge key-proof challenges past their lifetime, each holding a sealed one-time key
    (app/core/session_retention.py). The model is a parameter so the real condition can run against a
    throwaway schema."""
    from app.core import session_retention as sr
    from app.core.models import ZkKeyProofChallenge
    model = model or ZkKeyProofChallenge
    return p.delete_in_batches(
        model, deletable(model, p.now, *sr.expired_key_proof_challenge_conditions(model, p.now)), model.created_at)


def prune_possession_challenges(p: Pass, *, models=None) -> JobResult:
    """Key registration and envelope-replacement challenges past their lifetime, each holding a sealed one-time
    key (app/core/session_retention.py). The models are a parameter so the real condition can run against a
    throwaway schema."""
    from app.core import session_retention as sr
    from app.core.models import ECCKeyUpdateChallenge, ECCRegistrationChallenge
    result = JobResult()
    for model in models or (ECCRegistrationChallenge, ECCKeyUpdateChallenge):
        done = p.delete_in_batches(
            model, deletable(model, p.now, *sr.expired_possession_challenge_conditions(model, p.now)),
            model.created_at)
        result.add(done.deleted, done.oldest, done.newest)
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


def settle_auditor_grants(p: Pass) -> JobResult:
    """Auditor grants whose time ran out (a proposal nobody approved lapses, a grant past its end expires), and
    what a change to a holder's account calls for when no hook wrote it: a grant whose account no longer stands
    as it requires is suspended, or ended (app/core/auditor_rights.py, settle). Deletes nothing: each grant's
    row is kept as the record of who held the right."""
    from app.core import auditor_rights
    with p.transaction() as db:
        auditor_rights.settle(db, p.now)
    return JobResult()


def run_compliance_cases(p: Pass) -> JobResult:
    """The compliance cases' clock (app/core/cases.py): a case nobody approved within 7 days expires, and a case
    whose access reached its end closes or keeps only its legal hold, its owners told in the same transaction; a case
    closed 30 days ago keeps the counts of its audit rows (files opened, exports) on itself, before those rows may
    leave the table. Then the data marker that stops an earlier release from starting while the records of compliance
    access must be kept (app/core/compliance_marker.py), in a transaction of its own. Deletes nothing: a case's rows
    are its record. Not stopped by the hold switch."""
    from app.core import cases, compliance_marker
    with p.transaction() as db:
        cases.expire_pending(db, p.now)
        cases.end_due(db, p.now)
        cases.keep_counts(db, p.now)
    with p.transaction() as db:
        compliance_marker.sync(db, now=p.now)
    return JobResult()


def run_legal_holds(p: Pass) -> JobResult:
    """The legal holds' clock (app/core/legal_holds.py): holds nobody confirmed in time lapse, those due a review
    ask for one, while anything is held an SFTP server of another version is looked for again (the administrators
    are told of one), and what released holds kept is purged once their delay is over (a batch per transaction, each
    file's held_file_purged row in it, the blobs secure-deleted after its commit). Not stopped by the hold switch:
    a hold's purge is the end of what a case kept, not a log. The SFTP check runs in a transaction of its own, and
    its failure is said and goes no further: the lapses and the review prompts commit without it, and the purge
    runs."""
    from app.core import legal_holds
    with p.transaction() as db:
        legal_holds.lapse_due(db, p.now)
        legal_holds.prompt_reviews(db, p.now)
    try:
        with p.transaction() as db:
            legal_holds.sftp_while_held(db, p.now)
    except Exception as exc:  # noqa: BLE001 -- the check asks again at the next pass
        print(f"Warning: the SFTP servers' versions were not checked while legal holds keep files "
              f"({type(exc).__name__}); the next pass asks again")
    done = JobResult()

    def record(db, count, table):
        batch = JobResult(deleted=count)
        p.record(db, batch, table)
        done.add(count)

    legal_holds.purge(p.session_factory, now=p.now, batch=p.batch_rows, time_left=p.time_left, record=record,
                      limit_statements=limit_statements)
    return done


def prune_owner_notices(p: Pass) -> JobResult:
    """The notices to vaults' owners outside a case (a recorded name revealed, someone else giving access), once
    delivered or given up, COMPLIANCE_RECORD_MIN_DAYS after they were written (app/core/owner_notices.py). A
    case's notices stay with the case. Stopped by the hold switch: they are records."""
    from app.core import owner_notices
    return owner_notices.prune(p)


def prune_rate_limit_records(p: Pass) -> JobResult:
    """The sign-in throttle's fallback rows (written only while Redis is down), an hour after their window."""
    from app.core.models import RateLimitRecord
    return p.delete_in_batches(
        RateLimitRecord, deletable(RateLimitRecord, p.now, RateLimitRecord.window_start < p.now - timedelta(hours=1)),
        RateLimitRecord.window_start)


def prune_invitations(p: Pass) -> JobResult:
    """Invitations accepted, revoked or expired 30 days ago (app/core/working_records.py)."""
    from app.core import working_records
    return working_records.prune_invitations(p)


def prune_one_time_proofs(p: Pass) -> JobResult:
    """Password reset links, one-time codes and email-change codes used or expired 30 days ago."""
    from app.core import working_records
    return working_records.prune_one_time_proofs(p)


def prune_notifications(p: Pass) -> JobResult:
    """Notifications older than notification_retention_days; none while it is 0, the default."""
    from app.core import working_records
    return working_records.prune_notifications(p)


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


def run_person_erases(p: Pass) -> JobResult:
    """Per-person erases whose delay has run (app/core/audit_chain_erase.py): a name given a placeholder in the audit
    log, its archive and the other records, under the audit chain. Held by the hold switch."""
    from app.core import audit_chain_erase
    return audit_chain_erase.run_job(p)


def shorten_audit_addresses(p: Pass) -> JobResult:
    """Addresses in audit rows older than audit_ip_full_days, shortened to their network under the audit chain
    (app/core/audit_rewrite.py). Held by the hold switch."""
    from app.core import audit_rewrite
    return audit_rewrite.shorten_job(p)


def run_value_removals(p: Pass) -> JobResult:
    """Removals of values recorded under earlier recording levels whose delay has run (app/core/audit_value_removal.py),
    under the audit chain. Held by the hold switch."""
    from app.core import audit_value_removal
    return audit_value_removal.run_job(p)


def archive_audit_rows(p: Pass) -> JobResult:
    """Audit days older than the row window, moved whole into compressed daily blocks once checked against
    their seals (app/core/audit_archive.py). Deletes nothing, so the hold does not stop it."""
    from app.core import audit_archive
    return audit_archive.archive_job(p)


JOBS: list[Job] = [
    Job("audit_seals", "Sealing of audit rows", seal_audit_rows),
    Job("setting_changes", "Waiting settings changes that are due", apply_waiting_changes),
    Job("sessions", "Finished sessions and sign-ins", prune_sessions),
    Job("key_proof_challenges", "Expired key-proof challenges", prune_key_proof_challenges),
    Job("possession_challenges", "Expired key registration and envelope challenges", prune_possession_challenges),
    Job("credential_changes", "Records of changes to people's sign-in details", prune_credential_changes),
    Job("auditor_grants", "Auditor rights whose time ran out, or whose holder's account changed",
        settle_auditor_grants),
    Job("compliance_cases", "Compliance cases: those unapproved in time expire, access that ended closes them",
        run_compliance_cases),
    Job("legal_holds", "Legal holds: lapses, review prompts, and the purge of what released holds kept",
        run_legal_holds),
    Job("owner_notices", "Notices to vaults' owners outside a case, once delivered and past the record floor",
        prune_owner_notices, held=True),
    Job("rate_limit_records", "Sign-in throttle records", prune_rate_limit_records),
    Job("invitations", "Invitations that ended 30 days ago", prune_invitations),
    Job("one_time_proofs", "Reset links and one-time codes that ended 30 days ago", prune_one_time_proofs),
    Job("notifications", "Notifications older than their window", prune_notifications),
    Job("security_alerts", "Resolved security alerts", prune_resolved_alerts, held=True),
    Job("security_records", "Failed sign-ins kept in full", prune_security_records, held=True),
    Job("security_alert_values", "Names and addresses in old security alerts", clear_alert_values, held=True),
    Job("audit_env_retention", "A retention set in .env before timed deletion", schedule_env_audit_retention),
    Job("person_erase", "Per-person erases that are due", run_person_erases, held=True),
    Job("audit_value_removal", "Removals of values recorded under earlier levels", run_value_removals, held=True),
    Job("audit_ip_shortening", "Full addresses in audit rows past their days", shorten_audit_addresses, held=True),
    Job("audit_logs", "Audit rows", prune_audit_logs, held=True),
    Job("audit_archive", "Audit days moved into compressed daily blocks", archive_audit_rows),
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
        # The hold is decided at the first job over logs, once the sealing job (the first) has read the chain:
        # a process's first pass knows the chain's hold and the grace after a restore only once it has read them.
        # The stored settings are read again before each such job, and before each batch of one (Pass.held_now),
        # so a hold turned on during the pass stops what comes after it.
        chain_hold = None
        done = []
        for job in JOBS:
            if not p.time_left():
                break
            if job.held and chain_hold is None:
                chain_hold = chain_holds(session_factory)
            if job.held and (chain_hold or stored_hold_now(session_factory)):
                done.append((job.name, None))
                continue
            p.job_name, p.job_held = job.name, job.held
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


# While the audit chain's first-start backlog is being sealed, passes follow each other this closely.
BACKLOG_PAUSE_SECONDS = 5.0


# The longest time between two passes: the audit chain counts a stop of more than 12 hours between two seals
# as a gap, which no delay counts (app/core/audit_chain_policy.py); passes further apart would make every
# reduction, and every erase, wait for ever.
MAX_INTERVAL_MINUTES = 360


def interval_seconds() -> float:
    try:
        from app.core import audit_integrity
        if audit_integrity.state().backlog:
            return BACKLOG_PAUSE_SECONDS
    except Exception:  # noqa: BLE001 -- the normal interval
        pass
    return float(min(int(registry.resolve(INTERVAL_KEY)), MAX_INTERVAL_MINUTES)) * 60.0


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


# The modules that register row-keep rules, imported with this one so that every pass reads their rules
# (compliance access keeps a case's audit rows and the compliance rows: app/core/compliance_retention.py).
KEEP_MODULES: tuple = ("app.core.compliance_retention",)
for _name in KEEP_MODULES:
    importlib.import_module(_name)
