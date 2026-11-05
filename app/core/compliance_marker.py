"""Keep an older release from starting while the records of compliance access must be kept.

A release before 0.34.0 knows no compliance cases, and keeps no audit row longer than AUDIT_LOG_RETENTION_DAYS:
with a positive value it deletes every older row, whatever it records, the first time an administrator opens the
dashboard's activity feed. This release keeps a case's audit rows while the case is open and until its records may
go, and every row of the audit log's compliance category (an auditor right given or taken, a case's steps, a name
revealed, a refused request) for COMPLIANCE_RECORD_MIN_DAYS after it was written (app/core/compliance_retention.py).
It turns a positive AUDIT_LOG_RETENTION_DAYS into a waiting change (app/core/audit_retention.py), so the line stays
in .env, and an earlier release would apply it at once.

So while a case is open, a case's records must stay, or a row of the compliance category is younger than
COMPLIANCE_RECORD_MIN_DAYS (kept_now), this module keeps a row in ``data_requirements``, as the legal holds do
(app/core/legal_hold_marker.py): every release from the one that reads that table refuses to start when a row names
a version above its own (the operator's undo, or the escape variable, lets it start), and ``dockvault.py update``
refuses the rollback unless forced, naming the row (app/core/host_operator.py, downgrade-blockers).

The row is written in the transaction of the change that makes it needed: every audit row of the compliance
category is built with it (ensure(), from app/services/audit_row_hooks.py), and a case opens with such a row. Only
sync() removes it, once nothing needs it, at each start and by every pass of the pruner's compliance_cases job, and
only while it holds a lock that every ensure() takes shared for the rest of its transaction: a row of the category
not yet committed keeps the marker. When the lock is taken, sync() leaves the marker as it is until a later pass.

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
          "and the audit log's compliance rows for COMPLIANCE_RECORD_MIN_DAYS). A release before {introduced} knows "
          "no cases, and deletes every audit row older than AUDIT_LOG_RETENTION_DAYS, whatever it records.")
# How to undo it, as an older release prints it after "To go back to this version, first undo it with the newer
# version:", so it names the release that removes the marker ({version}: the one the marker asks for).
UNDO = ("Close every compliance case (on the Compliance page, or with dockvault.py cases) and wait until their "
        "records and the audit log's compliance rows are older than COMPLIANCE_RECORD_MIN_DAYS, then start "
        "DockVault {version} or later once so it removes this marker.")

# The lock sync() takes alone to remove the marker, and every ensure() shared (distinct from the other lock classes).
LOCK = (0x6372, 1)

# The matrix's condition on the edge from 0.34.0 back to earlier releases (written in the release commit). Its query
# reads the marker itself: what it stands for depends on COMPLIANCE_RECORD_MIN_DAYS, which only .env sets.
CONDITION = {
    "id": "compliance-records-block-rollback",
    "summary": ("From 0.34.0, while a compliance case is open, a case's records must still be kept, or a row of the "
                "audit log's compliance category (an auditor right given or taken, a case's steps, a name revealed, "
                "a refused request) is younger than COMPLIANCE_RECORD_MIN_DAYS (2190 by default, at least 365), an "
                "earlier release would not keep them: it knows no cases, and with a positive "
                "AUDIT_LOG_RETENTION_DAYS, which 0.34.0 leaves in .env as a waiting change, it deletes every older "
                "audit row the first time an administrator opens the dashboard's activity feed. So 0.33.1 and later "
                "refuse to start on this database, and python dockvault.py update refuses to go back unless "
                "--force-downgrade is given. Close the cases and wait until their records and the compliance rows are "
                "older than COMPLIANCE_RECORD_MIN_DAYS, then start 0.34.0 once so it removes the record that stops "
                "the earlier release. An earlier release started sooner with ALLOW_START_ON_NEWER_DATA=true keeps "
                "the audit rows only while .env sets no AUDIT_LOG_RETENTION_DAYS. The check finds that record."),
    "detect": f"SELECT key, requires_at_least, since FROM {TABLE} WHERE key = '{KEY}'",
    "blocks_rollback": True,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _postgres(db) -> bool:
    bind = db.get_bind()
    return bind is not None and bind.dialect.name == "postgresql"


def kept_now(db, now: Optional[datetime] = None) -> bool:
    """Whether the records of compliance access must be kept now: a case is open, a case's audit rows are kept
    (compliance_retention.case_rows_released_since says when they stop being kept), or a row of the compliance
    category is younger than COMPLIANCE_RECORD_MIN_DAYS (compliance_retention.compliance_rows_kept)."""
    from app.core import compliance_retention as cr
    from app.core.models import AuditLog, ComplianceCase
    now = now or _utcnow()
    if db.query(ComplianceCase.id).filter(ComplianceCase.closed_at.is_(None)).first() is not None:
        return True
    for case in db.query(ComplianceCase).filter(ComplianceCase.closed_at.isnot(None)).all():
        if cr.case_rows_released_since(db, case, now) is None:
            return True
    return db.query(AuditLog.id).filter(cr.compliance_rows_kept(AuditLog, now)).first() is not None


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
    """In the caller's transaction, which writes a row of the compliance category: the marker, unless it is there,
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
