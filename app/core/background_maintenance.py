"""Database maintenance the application does not need in order to be correct, done in the background
once the app is serving: building an index, dropping one, changing a table's storage settings.

Done at start, in the list of schema statements, such a change on a large table holds a lock that stops
every write to it until it ends: on the audit log that meant the web app did not answer, audit writes
waited and failed after five seconds (an SFTP sign-in, which writes one, was refused), and a failure left
/health calling the schema incomplete. Done here, it runs on a thread of its own after startup, writes
carry on meanwhile, and until it is done whatever it speeds up works without it, slower.

Every start runs each step in STEPS, in order, and these rules make that safe to repeat:

- Each step has a connection of its own, in autocommit (CREATE and DROP INDEX CONCURRENTLY refuse to run
  inside a transaction), discarded afterwards rather than handed back to the pool.
- Nothing waits without a lock timeout. The connection sets lock_timeout (LOCK_TIMEOUT_MS) before its
  first statement, so a step that cannot get its lock, or that waits too long for older transactions to
  finish, fails instead of waiting for ever. The next attempt picks it up.
- Each step looks first and is idempotent: a valid index is left alone, a drop of an absent index does
  nothing, a statement whose effect is already in place is not run again.
- An interrupted build (a stopped container, a full disk, a lock timeout) leaves an INVALID index behind,
  which Postgres keeps updating on every write and never reads. It is dropped, concurrently, and built
  again.
- One process runs a step at a time, by a session advisory lock per step. An invalid index may be another
  process's build in progress, and dropping that would be wrong; the process holding the lock is the only
  one working on the step, so an invalid index it finds is a leftover. A process that cannot take the lock
  leaves the step to the one that has it.
- A step that fails is tried again RETRIES times, RETRY_SECONDS apart, and then at the next start. A
  failure is logged by its type alone (a driver's message can carry values). Nothing here is a schema
  step: the schema is complete without it, and /health never calls it incomplete over a step.

Steps are made with create_index(), drop_index() and statement() and added to STEPS.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import text

# Stable and arbitrary, distinct from the other advisory lock classes (auth_service uses 0x7443).
_LOCK_CLASS = 0x6978

# How long any statement here waits for a lock, including a concurrent build's wait for older
# transactions, before it gives up; the step is tried again later.
LOCK_TIMEOUT_MS = 30000
# A failed step is tried this many more times in the same process, this far apart.
RETRIES = 2
RETRY_SECONDS = 300.0

CREATE_INDEX = "create_index"
DROP_INDEX = "drop_index"
STATEMENT = "statement"


@dataclass(frozen=True)
class Step:
    name: str
    kind: str
    sql: str = ""
    done_sql: str = ""


def create_index(name: str, create_sql: str) -> Step:
    """A step that builds the index ``name`` with ``create_sql``, which must be
    ``CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS <name> ...``."""
    if not (create_sql.startswith(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ")
            or create_sql.startswith(f"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {name} ")):
        raise ValueError(f"{name}: the statement must be CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS {name}")
    return Step(name, CREATE_INDEX, create_sql)


def drop_index(name: str) -> Step:
    """A step that drops the index ``name``, concurrently, when it exists."""
    return Step(name, DROP_INDEX, f"DROP INDEX CONCURRENTLY IF EXISTS {name}")


def statement(name: str, sql: str, done_sql: str) -> Step:
    """A step that runs ``sql`` unless ``done_sql``, a query answering one boolean, says its effect is
    already in place; and that is a failure unless ``done_sql`` says so afterwards."""
    if not done_sql:
        raise ValueError(f"{name}: a statement step needs the query that says it is done")
    return Step(name, STATEMENT, sql, done_sql)


# The steps every start runs, in order.
STEPS: list[Step] = [
    # The audit log's timestamp was indexed twice (idx_audit_timestamp and ix_audit_logs_timestamp, identical):
    # every audit write paid for both.
    drop_index("ix_audit_logs_timestamp"),
    # Vacuum and analyze the audit log after 2 % of its rows changed rather than 20 %: the pruner deletes
    # from it in batches, and on a large log the default would leave the dead rows and the planner's
    # statistics behind for a long time. ALTER TABLE ... SET takes a lock that audit writes pass through.
    statement("audit_logs_autovacuum",
              "ALTER TABLE audit_logs SET (autovacuum_vacuum_scale_factor = 0.02, "
              "autovacuum_analyze_scale_factor = 0.02)",
              "SELECT coalesce(c.reloptions @> ARRAY['autovacuum_vacuum_scale_factor=0.02', "
              "'autovacuum_analyze_scale_factor=0.02']::text[], false) FROM pg_class c "
              "JOIN pg_namespace n ON n.oid = c.relnamespace "
              "WHERE c.relname = 'audit_logs' AND n.nspname = current_schema()"),
    # The audit archive's blocks are compressed already: stored without Postgres's own compression, each is kept
    # as it is, and its length is read from its pointer without reading it (the daily check of the blocks'
    # lengths reads no payload). On an empty table, as when it is first created, this is instant.
    statement("audit_archive_blocks_storage",
              "ALTER TABLE audit_archive_blocks ALTER COLUMN payload SET STORAGE EXTERNAL",
              "SELECT coalesce(bool_and(a.attstorage = 'e'), false) FROM pg_attribute a "
              "JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
              "WHERE c.relname = 'audit_archive_blocks' AND n.nspname = current_schema() AND a.attname = 'payload'"),
    # The recording levels keep a shortened address, and the fingerprint of a name typed at a failed sign-in,
    # in audit_logs.recorded (app/core/audit_privacy.py); the Events filters and the most active addresses
    # look them up by value. Only rows recorded in another form than the value have the column set.
    create_index("ix_audit_logs_recorded_ip",
                 "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_logs_recorded_ip ON audit_logs "
                 "((recorded->>'ip')) WHERE recorded IS NOT NULL"),
    create_index("ix_audit_logs_recorded_signin_name",
                 "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_logs_recorded_signin_name ON audit_logs "
                 "((recorded->>'signin_name')) WHERE recorded IS NOT NULL"),
    # The rows a compliance case wrote (audit_logs.case_id): a case's own log, and what the pruner keeps for
    # it. Only those rows have the column set, so the index is partial and small.
    create_index("ix_audit_logs_case_id",
                 "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_logs_case_id ON audit_logs (case_id) "
                 "WHERE case_id IS NOT NULL"),
]

_STATE_SQL = text(
    "SELECT i.indisvalid FROM pg_class c "
    "JOIN pg_index i ON i.indexrelid = c.oid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relname = :name AND n.nspname = current_schema()"
)
_LOCK_SQL = text("SELECT pg_try_advisory_lock(:cls, hashtext(:name))")
_UNLOCK_SQL = text("SELECT pg_advisory_unlock(:cls, hashtext(:name))")


def index_state(conn, name: str) -> str:
    """``absent`` | ``valid`` | ``invalid`` (a build in progress, or one that was interrupted)."""
    row = conn.execute(_STATE_SQL, {"name": name}).first()
    if row is None:
        return "absent"
    return "valid" if row[0] else "invalid"


def run_step(conn, step: Step, announce=None) -> str:
    """Run one step on an AUTOCOMMIT connection. Returns ``present`` (nothing to do), ``built``,
    ``rebuilt`` (an invalid leftover was dropped first), ``dropped``, ``absent`` (nothing to drop),
    ``applied``, ``busy`` (another process holds the step's lock) or ``failed`` (it ran and did not take
    effect). Raises what the database raises; the caller logs it. ``announce(step)`` is called just before
    the step changes anything."""
    params = {"cls": _LOCK_CLASS, "name": step.name}
    # Before anything that could wait: the advisory lock itself never waits (pg_try_advisory_lock).
    conn.execute(text(f"SET lock_timeout = {int(LOCK_TIMEOUT_MS)}"))
    if not conn.execute(_LOCK_SQL, params).scalar():
        return "busy"
    try:
        if step.kind == CREATE_INDEX:
            state = index_state(conn, step.name)
            if state == "valid":
                return "present"
            if announce is not None:
                announce(step)
            if state == "invalid":
                conn.execute(text(f"DROP INDEX CONCURRENTLY IF EXISTS {step.name}"))
            conn.execute(text(step.sql))
            if index_state(conn, step.name) != "valid":
                return "failed"
            return "rebuilt" if state == "invalid" else "built"
        if step.kind == DROP_INDEX:
            if index_state(conn, step.name) == "absent":
                return "absent"
            if announce is not None:
                announce(step)
            conn.execute(text(step.sql))
            return "dropped" if index_state(conn, step.name) == "absent" else "failed"
        if step.kind == STATEMENT:
            if conn.execute(text(step.done_sql)).scalar():
                return "present"
            if announce is not None:
                announce(step)
            conn.execute(text(step.sql))
            return "applied" if conn.execute(text(step.done_sql)).scalar() else "failed"
        raise ValueError(f"{step.name}: unknown kind {step.kind!r}")
    finally:
        try:
            conn.execute(_UNLOCK_SQL, params)
        except Exception:  # noqa: BLE001 - the connection is discarded, which releases it anyway
            pass


def _say(message: str) -> None:
    try:
        print(message, flush=True)
    except Exception:  # noqa: BLE001 - a console that cannot take the line loses it
        pass


def _announce(step: Step) -> None:
    _say(f"Background maintenance: {step.name} ({step.kind}) is running; the app serves meanwhile")


def run_steps(engine, steps: Optional[list] = None) -> dict:
    """Run each step, one connection each. Never raises; returns name -> outcome (``skipped`` on a database
    other than Postgres, which none of this is for)."""
    steps = list(STEPS if steps is None else steps)
    if getattr(getattr(engine, "dialect", None), "name", "") != "postgresql":
        return {step.name: "skipped" for step in steps}
    outcomes = {}
    for step in steps:
        conn = None
        why = "it did not take effect"
        try:
            conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            outcomes[step.name] = run_step(conn, step, announce=_announce)
        except Exception as exc:  # noqa: BLE001 - maintenance never takes anything down
            outcomes[step.name] = "failed"
            why = type(exc).__name__
        finally:
            if conn is not None:
                # Discarded rather than returned to the pool: it is in autocommit with this lock timeout,
                # and may still hold the step's lock if the unlock did not get through.
                try:
                    conn.invalidate()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        if outcomes[step.name] in ("built", "rebuilt", "dropped", "applied"):
            _say(f"[OK] Background maintenance: {step.name} {outcomes[step.name]}")
        elif outcomes[step.name] == "failed":
            _say(f"Warning: background maintenance step {step.name} did not complete ({why}); it is tried "
                 "again later")
    return outcomes


def start_background(get_engine, steps: Optional[list] = None, *, retries: Optional[int] = None,
                     retry_seconds: Optional[float] = None, stop: Optional[threading.Event] = None
                     ) -> threading.Thread:
    """Run the steps on a daemon thread and return at once, so startup never waits for them. A step that
    failed is tried again, up to ``retries`` more times, ``retry_seconds`` apart; a stop during a step ends
    the thread with the process, and the next start picks up what is left."""
    todo = list(STEPS if steps is None else steps)
    retries = RETRIES if retries is None else retries
    retry_seconds = RETRY_SECONDS if retry_seconds is None else retry_seconds
    stop = stop or threading.Event()

    def _run():
        try:
            engine = get_engine()
        except Exception as exc:  # noqa: BLE001 - nothing to run the steps on
            _say(f"Warning: background maintenance did not run ({type(exc).__name__}); the next start "
                 "tries again")
            return
        pending = todo
        for attempt in range(retries + 1):
            if not pending:
                return
            if attempt and stop.wait(retry_seconds):
                return
            outcomes = run_steps(engine, pending)
            pending = [step for step in pending if outcomes.get(step.name) == "failed"]

    thread = threading.Thread(target=_run, name="background-maintenance", daemon=True)
    thread.start()
    return thread
