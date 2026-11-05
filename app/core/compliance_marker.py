"""Keep an older release from starting while the records of compliance access must be kept.

A release before 0.34.0 knows no compliance cases, and keeps no audit row longer than AUDIT_LOG_RETENTION_DAYS:
with a positive value it deletes every older row, whatever it records, the first time an administrator opens the
dashboard's activity feed. This release keeps a case's audit rows while the case is open and until its records may
go, and every row of the audit log's compliance category (an auditor right given or taken, a case's steps, a name
revealed, a refused request) for COMPLIANCE_RECORD_MIN_DAYS after it was written (app/core/compliance_retention.py).
It turns a positive AUDIT_LOG_RETENTION_DAYS into a waiting change (app/core/audit_retention.py), so the line stays
in .env, and an earlier release would apply it at once.

So while a case is open, a case's records must stay, or a step of compliance access recorded in the compliance
category is younger than COMPLIANCE_RECORD_MIN_DAYS (kept_now), this module keeps a row in ``data_requirements``, as
the legal holds do (app/core/legal_hold_marker.py): every release from the one that reads that table refuses to
start when a row names a version above its own (the operator's undo, or the escape variable, lets it start), and
``dockvault.py update`` refuses the rollback unless forced, naming the row (app/core/host_operator.py,
downgrade-blockers).

Not every row of the category is such a step (counts): a refused one is not, since any signed-in account can cause
one (a read of a case that does not exist, a hold it may not place), and neither are a vault owner's own steps on
Access to my vaults (OWN_STEPS). Were they counted, one request from anyone would stop every rollback for
COMPLIANCE_RECORD_MIN_DAYS on a deployment that never used compliance access. This release keeps those rows all the
same; an earlier release started anyway may delete them. A refusal under a case stays with the case's records,
which keep the marker while they must stay.

The row is written in the transaction of the change that makes it needed: every audit row that counts is built with
it (ensure(), from app/services/audit_row_hooks.py), and a case opens with such a row. ``audit unarchive`` puts
archived rows back without building them, so it writes the marker itself, in the transaction of each day it restores
(restored(), from app/core/audit_archive.py, restore_day): a row that counts may be archived, since only a case's
rows stay rows, and while it is archived only the archive's own marker stands, which the last unarchived day
removes. Only sync() removes the marker, once nothing needs it, at each start and by every pass of the pruner's
compliance_cases job, and only while it holds a lock that every write of it takes shared for the rest of its
transaction: a row that counts not yet committed keeps the marker. When the lock is taken, sync() leaves the marker
as it is until a later pass.

A release older than the reader of that table (before 0.33.1) is not protected by the row. CONDITION is the upgrade
matrix's condition for the edge back to an earlier release, written into the matrix in the release commit.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

KEY = "compliance-records"
TABLE = "data_requirements"
# The first release with compliance access: the oldest that can be rolled back to while its records must be kept.
INTRODUCED = "0.34.0"
REASON = ("Compliance cases are open, or the records of compliance access must still be kept (a case's audit rows, "
          "and those of every step of compliance access taken, for COMPLIANCE_RECORD_MIN_DAYS). A release before "
          "{introduced} knows no cases, and while AUDIT_LOG_RETENTION_DAYS is positive it deletes every audit row "
          "older than that, whatever it records.")
# How to undo it, as an older release prints it after "To go back to this version, first undo it with the newer
# version:", so it names the release that removes the marker ({version}: the one the marker asks for). True whether
# or not a case was ever opened: the steps of an auditor right, or a name revealed, write it without one.
UNDO = ("Wait until no compliance case is open and the records of compliance access are older than "
        "COMPLIANCE_RECORD_MIN_DAYS (a case's from its close): a case is closed, or its legal hold released, on the "
        "Compliance page, and dockvault.py cases can only turn down one not yet approved. Then start DockVault "
        "{version} or later once so it removes this marker.")

# The rows of the compliance category that do not keep the marker though they are kept as long (see the module's
# docstring): a step not taken (any status but TAKEN), and a vault owner's own steps on Access to my vaults, showing
# their own vault's names there and reading their notices (a case or a reveal wrote those notices, with rows of
# their own that count).
TAKEN = "success"
OWN_STEPS = frozenset({"owner_access_unlocked", "owner_notice_seen"})

# The lock sync() takes alone to remove the marker, and every write of it (ensure(), restored()) shared (distinct
# from the other lock classes).
LOCK = (0x6372, 1)
# Postgres' code for a serialization failure (restored()).
SERIALIZATION_FAILURE = "40001"

# The matrix's condition on the edge from 0.34.0 back to earlier releases (written in the release commit). Its query
# reads the marker itself: what it stands for depends on COMPLIANCE_RECORD_MIN_DAYS, which only .env sets.
CONDITION = {
    "id": "compliance-records-block-rollback",
    "summary": ("From 0.34.0, while a compliance case is open, a case's records must still be kept, or the record of "
                "a step of compliance access taken (an auditor right given or taken, a case's steps, a name "
                "revealed) is younger than COMPLIANCE_RECORD_MIN_DAYS (2190 by default, at least 365), an earlier "
                "release would not keep them: it knows no cases, and with a positive AUDIT_LOG_RETENTION_DAYS, which "
                "0.34.0 leaves in .env as a waiting change, it deletes every older audit row the first time an "
                "administrator opens the dashboard's activity feed. So 0.33.1 and later refuse to start on this "
                "database, and python dockvault.py update refuses to go back unless --force-downgrade is given. A "
                "refused request, which any account can make, and a vault owner's own steps on Access to my vaults "
                "do not count. Wait until no case is open and those records are older than "
                "COMPLIANCE_RECORD_MIN_DAYS, then start 0.34.0 once so it removes the record that stops the earlier "
                "release. An earlier release started sooner with ALLOW_START_ON_NEWER_DATA=true keeps the audit rows "
                "only while .env sets no AUDIT_LOG_RETENTION_DAYS. The check finds that record."),
    "detect": f"SELECT key, requires_at_least, since FROM {TABLE} WHERE key = '{KEY}'",
    "blocks_rollback": True,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _postgres(db) -> bool:
    bind = db.get_bind()
    return bind is not None and bind.dialect.name == "postgresql"


_actions = None


def counts(action: Optional[str], status: Optional[str]) -> bool:
    """Whether an audit row of ``action`` with ``status`` keeps the marker while it is younger than
    COMPLIANCE_RECORD_MIN_DAYS: a step of the compliance category (app/core/audit_catalog.py) that was taken
    (TAKEN), other than a vault owner's own (OWN_STEPS)."""
    global _actions
    if _actions is None:
        from app.core import audit_catalog
        _actions = frozenset(audit_catalog.stored_names(["compliance"]))
    return action in _actions and status == TAKEN and action not in OWN_STEPS


def counted_rows(model, now: datetime):
    """The rows of ``model`` (audit_logs) that keep the marker now: those counts() takes, younger than
    COMPLIANCE_RECORD_MIN_DAYS (compliance_retention.compliance_rows_kept, which keeps every row of the category)."""
    from sqlalchemy import and_
    from app.core import compliance_retention as cr
    return and_(cr.compliance_rows_kept(model, now), model.status == TAKEN, model.action.notin_(sorted(OWN_STEPS)))


def kept_now(db, now: Optional[datetime] = None) -> bool:
    """Whether the records of compliance access must be kept now: a case is open, a case's audit rows are kept
    (compliance_retention.case_rows_released_since says when they stop being kept), or a row that counts is younger
    than COMPLIANCE_RECORD_MIN_DAYS (counted_rows)."""
    from app.core import compliance_retention as cr
    from app.core.models import AuditLog, ComplianceCase
    now = now or _utcnow()
    if db.query(ComplianceCase.id).filter(ComplianceCase.closed_at.is_(None)).first() is not None:
        return True
    for case in db.query(ComplianceCase).filter(ComplianceCase.closed_at.isnot(None)).all():
        if cr.case_rows_released_since(db, case, now) is None:
            return True
    return db.query(AuditLog.id).filter(counted_rows(AuditLog, now)).first() is not None


def required_version() -> str:
    """The version the marker asks for: the release that introduced compliance access, or this build's own version
    when it is an earlier one (a build made before the release must still start on its own data)."""
    from app.core import recording_marker
    running = recording_marker.running_version()
    have = recording_marker._parse(running)
    return running if have is not None and have < recording_marker._parse(INTRODUCED) else INTRODUCED


def _params(when: datetime) -> dict:
    version = required_version()
    return {"key": KEY, "version": version, "reason": REASON.format(introduced=INTRODUCED),
            "undo": UNDO.format(version=version), "since": when}


_INSERT = (f"INSERT INTO {TABLE} (key, requires_at_least, reason, undo, since) "
           "VALUES (:key, :version, :reason, :undo, :since) ON CONFLICT (key) DO ")


def ensure(db, *, now: Optional[datetime] = None) -> None:
    """In the caller's transaction, which writes a row that counts: the marker, unless it is there,
    under the lock taken shared until the transaction ends, so sync() cannot remove it meanwhile. Never raises: on
    Postgres it runs in a savepoint of the connection, so a failure leaves the caller's transaction as it was; it is
    said, and the next sync() writes the marker. The session's savepoint is not used: it would flush what the caller
    has not written yet, and a failure of that flush belongs to the caller."""
    postgres = _postgres(db)
    point = None
    try:
        if postgres:
            connection = db.connection()
            point = connection.begin_nested()
            connection.execute(text("SELECT pg_advisory_xact_lock_shared(:c, :k)"), {"c": LOCK[0], "k": LOCK[1]})
            connection.execute(text(_INSERT + "NOTHING"), _params(now or _utcnow()))
        else:
            db.execute(text(_INSERT + "NOTHING"), _params(now or _utcnow()))
        if point is not None:
            point.commit()
    except Exception as exc:  # noqa: BLE001 -- the change the row records goes on; the next sync writes it
        if point is not None:
            try:
                point.rollback()
            except Exception:  # noqa: BLE001
                pass
        print(f"Warning: the compliance records' rollback marker was not written ({type(exc).__name__}); "
              "the pruner's next pass writes it")


def restored(db, newest: Optional[datetime], *, now: Optional[datetime] = None) -> bool:
    """In the transaction of a day ``audit unarchive`` restores (app/core/audit_archive.py, restore_day), given the
    time of the newest restored row that counts (``newest``, None when none did): the marker, unless it is there,
    when that row is younger than COMPLIANCE_RECORD_MIN_DAYS, under the lock taken shared as ensure() takes it.
    Raises when it cannot be written, so the day stays archived, behind the archive's own marker, rather than come
    back as rows an earlier release would start on. Returns whether the rows needed it."""
    from datetime import timedelta
    from sqlalchemy.exc import DBAPIError
    from app.core import compliance_retention as cr
    from app.core import recording_marker
    when = now or _utcnow()
    if newest is None or newest < when - timedelta(days=cr.floor_days()):
        return False
    recording_marker._ensure_table(db)
    params = _params(when)
    if not _postgres(db):
        db.execute(text(_INSERT + "NOTHING"), params)
        return True
    connection = db.connection()
    connection.execute(text("SELECT pg_advisory_xact_lock_shared(:c, :k)"), {"c": LOCK[0], "k": LOCK[1]})
    point = connection.begin_nested()
    try:
        connection.execute(text(_INSERT + "NOTHING"), params)
    except DBAPIError as exc:
        point.rollback()
        # The unarchive reads in one snapshot (repeatable read), and Postgres will not skip an insert over a marker
        # another transaction committed after that snapshot: it raises a serialization failure instead. That marker
        # is there, and the lock now held keeps sync() from removing it before this transaction ends.
        if getattr(getattr(exc, "orig", None), "pgcode", None) != SERIALIZATION_FAILURE:
            raise
        return True
    point.commit()
    return True


def _take_alone(db) -> bool:
    """The lock, alone, for the rest of ``db``'s transaction, without waiting: False while a transaction that wrote
    a row of the compliance category holds it shared. Always True outside Postgres."""
    if not _postgres(db):
        return True
    return bool(db.execute(text("SELECT pg_try_advisory_xact_lock(:c, :k)"), {"c": LOCK[0], "k": LOCK[1]}).scalar())


def sync(db, *, now: Optional[datetime] = None) -> Optional[bool]:
    """Bring the marker in line with the records, in the caller's transaction (the caller commits): written while
    they must be kept, removed otherwise, but only while this transaction has the lock alone. Returns whether the
    marker is there, or None when it was left as it was (the lock is taken)."""
    from app.core import recording_marker
    db.flush()      # the caller's own rows, not yet written (the sessions do not autoflush)
    when = now or _utcnow()
    alone = _take_alone(db)
    there = kept_now(db, when)
    recording_marker._ensure_table(db)
    if there:
        if alone:
            db.execute(text(_INSERT + "UPDATE SET requires_at_least = EXCLUDED.requires_at_least, "
                                      "reason = EXCLUDED.reason, undo = EXCLUDED.undo"), _params(when))
        else:
            db.execute(text(_INSERT + "NOTHING"), _params(when))
        return True
    if not alone:
        return None
    db.execute(text(f"DELETE FROM {TABLE} WHERE key = :key"), {"key": KEY})
    return False


def check_at_start() -> Optional[bool]:
    """sync() in a transaction of its own, at the start. Never raises: a failure is said, and the pruner's next pass
    syncs again. Returns whether the marker is there, or None when it could not be checked or was left as it was."""
    from app.core.database import get_db_context
    try:
        with get_db_context() as db:
            there = sync(db)
            db.commit()
            return there
    except Exception as exc:  # noqa: BLE001
        print(f"Warning: the compliance records' rollback marker was not checked ({type(exc).__name__})")
        return None
