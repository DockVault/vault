"""The username-typeahead index is built after startup, concurrently, and never holds startup up.

It used to be a plain CREATE INDEX in the boot DDL list. That takes a lock that stops every write to
the audit log until the build ends, and the boot waited for it with no lock timeout: on a large log
the first start of the release did not answer, audit writes (an SFTP sign-in among them) failed after
five seconds, and a failed build left /health reporting the schema incomplete and the container
unhealthy. It is now built by app/core/optional_indexes.py on a thread of its own, with CREATE INDEX
CONCURRENTLY outside a transaction, IF NOT EXISTS, under an advisory lock, dropping an invalid leftover
of an interrupted build first, and without recording a schema step.

These drive the module against a scripted connection (the unit lane has no Postgres) and pin the
wiring in the application source.
"""
import re
import threading
from pathlib import Path

import pytest

from app.core import optional_indexes as OI

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_NAME = OI.USERNAME_PREFIX_INDEX


class _Result:
    def __init__(self, scalar=None, row=None):
        self._scalar, self._row = scalar, row

    def scalar(self):
        return self._scalar

    def first(self):
        return self._row


class _Conn:
    """Records every statement; answers the lock and the index-state queries from a script."""

    def __init__(self, states, lock=True, fail_on=None, events=None):
        self.states = list(states)       # what each index-state query finds, in order
        self.lock = lock
        self.fail_on = fail_on
        self.events = events if events is not None else []
        self.invalidated = self.closed = False

    def execution_options(self, **options):
        self.events.append(("options", options))
        return self

    def execute(self, statement, params=None):
        sql = " ".join(str(statement).split())
        self.events.append(("sql", sql, params))
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("DETAIL: Key (username)=(someone-secret) ...")
        if "pg_try_advisory_lock" in sql:
            return _Result(scalar=self.lock)
        if "indisvalid" in sql:
            state = self.states.pop(0)
            return _Result(row=None if state == "absent" else (state == "valid",))
        return _Result()

    def invalidate(self):
        self.invalidated = True

    def close(self):
        self.closed = True

    def sql(self):
        return [e[1] for e in self.events if e[0] == "sql"]


class _Dialect:
    def __init__(self, name):
        self.name = name


class _Engine:
    def __init__(self, conn, dialect="postgresql"):
        self.conn, self.dialect, self.connects = conn, _Dialect(dialect), 0

    def connect(self):
        self.connects += 1
        return self.conn


def _kinds(sql_list):
    """Each statement reduced to what it is, in order."""
    out = []
    for s in sql_list:
        if "pg_try_advisory_lock" in s:
            out.append("lock")
        elif "pg_advisory_unlock" in s:
            out.append("unlock")
        elif "indisvalid" in s:
            out.append("state")
        elif s == "SET lock_timeout = 0":
            out.append("no-lock-timeout")
        elif s.startswith("DROP INDEX CONCURRENTLY IF EXISTS "):
            out.append("drop")
        elif s.startswith("CREATE INDEX CONCURRENTLY IF NOT EXISTS "):
            out.append("create")
        else:
            out.append(s)
    return out


def test_a_missing_index_is_built_concurrently_on_an_autocommit_connection(capsys):
    conn = _Conn(states=["absent", "valid"])
    engine = _Engine(conn)

    assert OI.build_optional_indexes(engine) == {_NAME: "built"}

    # Autocommit is set before anything runs: CONCURRENTLY refuses to run inside a transaction.
    assert conn.events[0] == ("options", {"isolation_level": "AUTOCOMMIT"})
    assert _kinds(conn.sql()) == ["lock", "state", "no-lock-timeout", "create", "state", "unlock"]
    create = [s for s in conn.sql() if s.startswith("CREATE INDEX")][0]
    assert create == ('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_username_prefix '
                      'ON audit_logs ((lower(username) COLLATE "C"))')
    # The connection is discarded, never handed back to the pool in autocommit with no lock timeout.
    assert conn.invalidated and conn.closed
    out = capsys.readouterr().out
    assert f"Optional index {_NAME} built in the background" in out


def test_a_valid_index_is_left_alone():
    conn = _Conn(states=["valid"])

    assert OI.build_optional_indexes(_Engine(conn)) == {_NAME: "present"}
    assert _kinds(conn.sql()) == ["lock", "state", "unlock"]


def test_an_invalid_leftover_of_an_interrupted_build_is_dropped_and_built_again():
    """IF NOT EXISTS alone would skip an invalid index for good: Postgres keeps writing to it and
    never reads from it, so the typeahead would stay slow for ever while the index cost every write."""
    conn = _Conn(states=["invalid", "valid"])

    assert OI.build_optional_indexes(_Engine(conn)) == {_NAME: "rebuilt"}
    assert _kinds(conn.sql()) == ["lock", "state", "no-lock-timeout", "drop", "create", "state",
                                  "unlock"]
    assert f"DROP INDEX CONCURRENTLY IF EXISTS {_NAME}" in conn.sql()


def test_a_second_builder_leaves_the_index_to_the_one_holding_the_lock():
    """An invalid index may be another process's build in progress; only the lock holder may drop."""
    conn = _Conn(states=["invalid"], lock=False)

    assert OI.build_optional_indexes(_Engine(conn)) == {_NAME: "busy"}
    assert _kinds(conn.sql()) == ["lock"]
    lock = conn.events[1]
    assert lock[2] == {"cls": OI._LOCK_CLASS, "name": _NAME}


def test_a_failed_build_is_logged_by_its_type_released_and_never_raised(capsys):
    conn = _Conn(states=["absent"], fail_on="CREATE INDEX")

    assert OI.build_optional_indexes(_Engine(conn)) == {_NAME: "failed"}
    # The builder lock is still released, and the connection discarded.
    assert _kinds(conn.sql())[-1] == "unlock"
    assert conn.invalidated and conn.closed
    out = capsys.readouterr().out
    assert f"Optional index {_NAME} was not built (RuntimeError)" in out
    assert "next start tries again" in out
    assert "someone-secret" not in out and "DETAIL" not in out


def test_a_build_that_leaves_the_index_invalid_is_a_failure_not_a_success(capsys):
    conn = _Conn(states=["absent", "invalid"])

    assert OI.build_optional_indexes(_Engine(conn)) == {_NAME: "failed"}
    assert "not valid after its build" in capsys.readouterr().out


def test_another_database_is_skipped_without_connecting():
    conn = _Conn(states=[])
    engine = _Engine(conn, dialect="sqlite")

    assert OI.build_optional_indexes(engine) == {_NAME: "skipped"}
    assert engine.connects == 0


def test_startup_does_not_wait_for_the_build():
    """The lifespan calls start_background_build and moves on; the build runs on its own thread."""
    release, entered = threading.Event(), threading.Event()
    conn = _Conn(states=["absent", "valid"])

    def get_engine():
        entered.set()
        assert release.wait(10), "the test never released the build"
        return _Engine(conn)

    thread = OI.start_background_build(get_engine)
    try:
        assert entered.wait(10)
        assert thread.daemon and thread.is_alive()    # returned while the build is still pending
        assert conn.sql() == []
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    assert _kinds(conn.sql())[-3:] == ["create", "state", "unlock"]


def test_the_index_matches_the_expression_the_typeahead_searches():
    from app.services import activity_events as AE

    create = OI.OPTIONAL_INDEXES[_NAME]
    expression = 'lower(username) COLLATE "C"'
    assert f"(({expression}))" in create
    assert AE._LOG_NAMES_SQL.count(f"{expression} >=") == 1


def test_the_boot_no_longer_builds_it_and_no_schema_step_records_it():
    source = (_ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    # No plain build anywhere in the application: that is the statement that held startup up.
    assert not re.search(r"CREATE (UNIQUE )?INDEX (IF NOT EXISTS )?idx_audit_username_prefix", source)
    assert source.count("\ndef _run_lightweight_migrations(") == 1
    migrations = source.split("\ndef _run_lightweight_migrations(", 1)[1].split("\ndef ", 1)[0]
    assert "recorder.record(stmt" in migrations           # the slice is the recorded DDL replay
    assert "idx_audit_username_prefix" not in migrations
    # The builder never writes a schema step, so /health cannot call the schema incomplete over it.
    module = (_ROOT / "app" / "core" / "optional_indexes.py").read_text(encoding="utf-8")
    assert "SchemaStep" not in module and "_SchemaStepRecorder" not in module


def test_the_lifespan_starts_the_build_after_startup_without_waiting_for_it():
    source = (_ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert source.count("async def lifespan(app: FastAPI):") == 1
    lifespan = source.split("async def lifespan(app: FastAPI):", 1)[1].split("\n    yield\n", 1)[0]
    call = "optional_indexes.start_background_build(_require_engine)"
    # Started once, from here only, under any name: a build running during the DDL replay would make
    # the replay's audit_logs changes (no lock timeout) wait for it, which is the stall this removes.
    assert source.count("start_background_build(") == 1 and lifespan.count(call) == 1
    # After every startup step that must finish first, and the last thing before serving.
    for earlier in ("_run_lightweight_migrations()", "_seed_default_email_profile()",
                    "_install_access_log_redaction()"):
        assert lifespan.index(earlier) < lifespan.index(call), earlier
    assert lifespan.rstrip().endswith(call)
