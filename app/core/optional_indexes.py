"""Indexes that only make something faster, built in the background once the app is serving.

A plain CREATE INDEX holds a lock that stops every write to its table until the build ends. At the
first start of a release that adds one to the audit log, that meant the web app did not answer
until the build finished, audit writes waited and failed after five seconds (an SFTP sign-in,
which writes one, was refused), and a build that failed (a full disk) left /health reporting the
schema incomplete and the container unhealthy. For an index the application does not need to be
correct, that is the wrong trade.

So these are built with CREATE INDEX CONCURRENTLY, on a thread of their own, after startup. Writes
carry on during the build, and until it ends the feature it speeds up works without it, slower.
Four rules make that safe to repeat at every start:

- CONCURRENTLY cannot run inside a transaction, so the connection is in autocommit.
- IF NOT EXISTS, and a valid index is left alone: every start after the one that built it does
  nothing but look.
- An interrupted build (the container stopped mid-build, a full disk, a cancelled statement)
  leaves an INVALID index behind. Postgres keeps updating it on every write and never reads from
  it, and IF NOT EXISTS would then skip it for good. It is dropped, also concurrently, and built
  again.
- One builder at a time, by a session advisory lock. An invalid index can also be another
  process's build in progress, and dropping that would be wrong; the process holding the lock is
  the only one building, so an invalid index it finds is a leftover. A process that cannot take
  the lock leaves the index to the one that has it.

A failure is logged by its type alone (a driver's message can carry values) and retried at the
next start. It is never recorded as a schema step: the schema is complete without these, and
/health must not call it incomplete over an index nothing depends on for correctness.
"""

import threading

from sqlalchemy import text

# Stable and arbitrary, distinct from the other advisory lock classes (auth_service uses 0x7443).
_LOCK_CLASS = 0x6978

USERNAME_PREFIX_INDEX = "idx_audit_username_prefix"

# Name -> its CREATE statement. Each one CONCURRENTLY and IF NOT EXISTS, for the reasons above.
OPTIONAL_INDEXES = {
    # The Activity page's username typeahead: a prefix search over every name the audit log has
    # seen, in byte order ("C") so a prefix is one contiguous range of the index. Without it the
    # search walks the table once per suggestion: correct, and slower on a large log.
    USERNAME_PREFIX_INDEX: (
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_username_prefix "
        'ON audit_logs ((lower(username) COLLATE "C"))'
    ),
}

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


def ensure_index(conn, name: str, create_sql: str, announce=None) -> str:
    """Build one index if it is missing or was left invalid, on an AUTOCOMMIT connection.

    Returns ``present`` (valid already, nothing done), ``built``, ``rebuilt`` (an invalid leftover
    was dropped first), ``busy`` (another process holds the builder lock) or ``failed`` (the build
    ran and the index is still not valid). Raises what the database raises; the caller logs it.
    `announce(name)` is called just before a build starts.
    """
    params = {"cls": _LOCK_CLASS, "name": name}
    if not conn.execute(_LOCK_SQL, params).scalar():
        return "busy"
    try:
        state = index_state(conn, name)
        if state == "valid":
            return "present"
        # No lock timeout for the build: nothing waits on it, and a timeout part-way through would
        # only leave another invalid index for the next start to drop. The connection is
        # discarded afterwards, so this setting never reaches the pool.
        conn.execute(text("SET lock_timeout = 0"))
        if announce is not None:
            announce(name)
        if state == "invalid":
            conn.execute(text(f"DROP INDEX CONCURRENTLY IF EXISTS {name}"))
        conn.execute(text(create_sql))
        if index_state(conn, name) != "valid":
            return "failed"
        return "rebuilt" if state == "invalid" else "built"
    finally:
        try:
            conn.execute(_UNLOCK_SQL, params)
        except Exception:  # noqa: BLE001 - the connection is discarded, which releases it anyway
            pass


def _announce(name: str) -> None:
    print(f"Building optional index {name} in the background; the app serves meanwhile")


def build_optional_indexes(engine) -> dict:
    """Ensure every optional index, one connection each. Never raises; returns name -> outcome
    (``skipped`` on a database other than Postgres, where these expression indexes do not apply)."""
    if getattr(getattr(engine, "dialect", None), "name", "") != "postgresql":
        return {name: "skipped" for name in OPTIONAL_INDEXES}
    outcomes = {}
    for name, create_sql in OPTIONAL_INDEXES.items():
        conn = None
        try:
            conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            outcomes[name] = ensure_index(conn, name, create_sql, announce=_announce)
            why = "it is not valid after its build"
        except Exception as exc:  # noqa: BLE001 - an optional index never takes anything down
            outcomes[name] = "failed"
            why = type(exc).__name__
        finally:
            if conn is not None:
                # Discarded rather than returned to the pool: it is in autocommit with no lock
                # timeout, and may still hold the builder lock if the unlock did not get through.
                try:
                    conn.invalidate()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        if outcomes[name] in ("built", "rebuilt"):
            print(f"[OK] Optional index {name} {outcomes[name]} in the background")
        elif outcomes[name] == "failed":
            print(f"⚠ Optional index {name} was not built ({why}). The next start tries again; "
                  "until then the search it speeds up is slower.")
    return outcomes


def start_background_build(get_engine) -> threading.Thread:
    """Start the build on a daemon thread and return at once, so startup never waits for it.

    A stop during the build ends the thread with the process; the half-built index it leaves is
    invalid, and the next start drops it and builds it again."""
    def _run():
        try:
            build_optional_indexes(get_engine())
        except Exception as exc:  # noqa: BLE001 - get_engine itself failed; nothing to build on
            print(f"⚠ Optional indexes were not built ({type(exc).__name__}); the next start tries again")

    thread = threading.Thread(target=_run, name="optional-indexes", daemon=True)
    thread.start()
    return thread
