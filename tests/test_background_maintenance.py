"""Database maintenance done in the background after startup (app/core/background_maintenance.py), offline.

Building or dropping an index, or changing a table's storage settings, at start blocks every write to a
large table while it runs. These steps run instead on a thread of their own once the app serves: each on
an autocommit connection whose first statement sets a lock timeout (nothing waits without one), under a
per-step advisory lock, looking first so that a repeat does nothing, dropping the invalid leftover of an
interrupted build, retrying a failure, and never recording a schema step. These drive the module
against a scripted connection (the unit lane has no Postgres) and pin its wiring in the application;
test_background_maintenance_live.py runs it against a running stack's database.
"""
import re
import threading
from pathlib import Path

import pytest

from app.core import background_maintenance as BM

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
IDX = "idx_probe_status"
CREATE = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {IDX} ON audit_logs (status)"
TIMEOUT = f"SET lock_timeout = {BM.LOCK_TIMEOUT_MS}"


class _Result:
    def __init__(self, scalar=None, row=None):
        self._scalar, self._row = scalar, row

    def scalar(self):
        return self._scalar

    def first(self):
        return self._row


class _Conn:
    """Records every statement; answers the lock, index-state and done queries from a script."""

    def __init__(self, states=(), lock=True, fail_on=None, done=(), events=None):
        self.states = list(states)       # what each index-state query finds, in order
        self.done = list(done)           # what each done query answers, in order
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
        if sql.startswith("SELECT done"):
            return _Result(scalar=self.done.pop(0))
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
    def __init__(self, *conns, dialect="postgresql"):
        self.conns, self.dialect, self.connects = list(conns), _Dialect(dialect), 0

    def connect(self):
        self.connects += 1
        return self.conns.pop(0)


def _kinds(sql_list):
    out = []
    for s in sql_list:
        if s.startswith("SET lock_timeout = "):
            out.append("timeout" if s == TIMEOUT else s)
        elif "pg_try_advisory_lock" in s:
            out.append("lock")
        elif "pg_advisory_unlock" in s:
            out.append("unlock")
        elif "indisvalid" in s:
            out.append("state")
        elif s.startswith("DROP INDEX CONCURRENTLY IF EXISTS "):
            out.append("drop")
        elif s.startswith("CREATE INDEX CONCURRENTLY IF NOT EXISTS "):
            out.append("create")
        elif s.startswith("SELECT done"):
            out.append("done?")
        else:
            out.append(s)
    return out


STEP = BM.create_index(IDX, CREATE)


# --------------------------------------------------------------------------- building an index

def test_a_missing_index_is_built_concurrently_on_an_autocommit_connection(capsys):
    conn = _Conn(states=["absent", "valid"])
    assert BM.run_steps(_Engine(conn), [STEP]) == {IDX: "built"}
    # Autocommit before anything runs: CONCURRENTLY refuses to run inside a transaction. The lock timeout
    # is the first statement, before anything that could wait.
    assert conn.events[0] == ("options", {"isolation_level": "AUTOCOMMIT"})
    assert _kinds(conn.sql()) == ["timeout", "lock", "state", "create", "state", "unlock"]
    assert CREATE in conn.sql()
    # The connection is discarded, never handed back to the pool in autocommit.
    assert conn.invalidated and conn.closed
    out = capsys.readouterr().out
    assert f"{IDX} (create_index) is running" in out and f"[OK] Background maintenance: {IDX} built" in out


def test_a_valid_index_is_left_alone():
    conn = _Conn(states=["valid"])
    assert BM.run_steps(_Engine(conn), [STEP]) == {IDX: "present"}
    assert _kinds(conn.sql()) == ["timeout", "lock", "state", "unlock"]


def test_an_invalid_leftover_of_an_interrupted_build_is_dropped_and_built_again():
    conn = _Conn(states=["invalid", "valid"])
    assert BM.run_steps(_Engine(conn), [STEP]) == {IDX: "rebuilt"}
    assert _kinds(conn.sql()) == ["timeout", "lock", "state", "drop", "create", "state", "unlock"]
    assert f"DROP INDEX CONCURRENTLY IF EXISTS {IDX}" in conn.sql()


def test_a_second_process_leaves_the_step_to_the_one_holding_its_lock():
    conn = _Conn(states=["invalid"], lock=False)
    assert BM.run_steps(_Engine(conn), [STEP]) == {IDX: "busy"}
    assert _kinds(conn.sql()) == ["timeout", "lock"]
    lock = [e for e in conn.events if e[0] == "sql"][1]
    assert lock[2] == {"cls": BM._LOCK_CLASS, "name": IDX}


def test_a_failed_step_is_logged_by_its_type_its_lock_released_and_never_raised(capsys):
    conn = _Conn(states=["absent"], fail_on="CREATE INDEX")
    assert BM.run_steps(_Engine(conn), [STEP]) == {IDX: "failed"}
    assert _kinds(conn.sql())[-1] == "unlock"
    assert conn.invalidated and conn.closed
    out = capsys.readouterr().out
    assert f"step {IDX} did not complete (RuntimeError); it is tried again later" in out
    assert "someone-secret" not in out and "DETAIL" not in out


def test_a_build_that_leaves_the_index_invalid_is_a_failure():
    conn = _Conn(states=["absent", "invalid"])
    assert BM.run_steps(_Engine(conn), [STEP]) == {IDX: "failed"}


def test_each_step_has_a_connection_of_its_own():
    first, second = _Conn(states=["valid"]), _Conn(states=["absent", "valid"])
    other = BM.create_index("idx_probe_other", "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_probe_other ON x (y)")
    engine = _Engine(first, second)
    assert BM.run_steps(engine, [STEP, other]) == {IDX: "present", "idx_probe_other": "built"}
    assert engine.connects == 2 and first.closed and second.closed


def test_one_failing_step_does_not_stop_the_next():
    bad, good = _Conn(states=["absent"], fail_on="CREATE INDEX"), _Conn(states=["absent", "valid"])
    other = BM.create_index("idx_probe_other", "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_probe_other ON x (y)")
    assert BM.run_steps(_Engine(bad, good), [STEP, other]) == {IDX: "failed", "idx_probe_other": "built"}


# --------------------------------------------------------------------------- dropping one, and statements

def test_an_existing_index_is_dropped_concurrently_and_an_absent_one_left_alone():
    drop = BM.drop_index("ix_probe_old")
    conn = _Conn(states=["valid", "absent"])
    assert BM.run_steps(_Engine(conn), [drop]) == {"ix_probe_old": "dropped"}
    assert _kinds(conn.sql()) == ["timeout", "lock", "state", "drop", "state", "unlock"]
    conn = _Conn(states=["absent"])
    assert BM.run_steps(_Engine(conn), [drop]) == {"ix_probe_old": "absent"}
    assert "drop" not in _kinds(conn.sql())
    conn = _Conn(states=["valid", "valid"])
    assert BM.run_steps(_Engine(conn), [drop]) == {"ix_probe_old": "failed"}


def test_a_statement_runs_only_when_its_effect_is_not_in_place():
    step = BM.statement("probe_vacuum", "ALTER TABLE probe SET (fillfactor = 90)", "SELECT done FROM probe_check")
    conn = _Conn(done=[False, True])
    assert BM.run_steps(_Engine(conn), [step]) == {"probe_vacuum": "applied"}
    assert _kinds(conn.sql()) == ["timeout", "lock", "done?", "ALTER TABLE probe SET (fillfactor = 90)", "done?",
                                  "unlock"]
    conn = _Conn(done=[True])
    assert BM.run_steps(_Engine(conn), [step]) == {"probe_vacuum": "present"}
    assert "ALTER TABLE probe SET (fillfactor = 90)" not in conn.sql()
    conn = _Conn(done=[False, False])
    assert BM.run_steps(_Engine(conn), [step]) == {"probe_vacuum": "failed"}


@pytest.mark.parametrize("sql", [
    "CREATE INDEX IF NOT EXISTS idx_probe_status ON audit_logs (status)",          # not concurrently
    "CREATE INDEX CONCURRENTLY idx_probe_status ON audit_logs (status)",          # not idempotent
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_probe_other ON audit_logs (x)",   # another name
])
def test_an_index_step_must_build_concurrently_idempotently_and_by_its_own_name(sql):
    with pytest.raises(ValueError):
        BM.create_index(IDX, sql)


def test_a_statement_step_needs_the_query_that_says_it_is_done():
    with pytest.raises(ValueError):
        BM.statement("probe", "ALTER TABLE probe SET (fillfactor = 90)", "")


def test_another_database_is_skipped_without_connecting():
    engine = _Engine(dialect="sqlite")
    assert BM.run_steps(engine, [STEP]) == {IDX: "skipped"}
    assert engine.connects == 0


# --------------------------------------------------------------------------- nothing waits without a timeout

def test_nothing_here_ever_waits_without_a_lock_timeout():
    assert isinstance(BM.LOCK_TIMEOUT_MS, int) and 0 < BM.LOCK_TIMEOUT_MS <= 60000
    source = (_ROOT / "app" / "core" / "background_maintenance.py").read_text(encoding="utf-8")
    assert not re.search(r"lock_timeout\s*=\s*0\b", source)
    assert source.count("SET lock_timeout") == 1


@pytest.mark.parametrize("step,conn", [
    (STEP, lambda: _Conn(states=["invalid", "valid"])),
    (BM.drop_index("ix_probe_old"), lambda: _Conn(states=["valid", "absent"])),
    (BM.statement("probe", "ALTER TABLE probe SET (fillfactor = 90)", "SELECT done FROM c"), lambda: _Conn(done=[0, 1])),
])
def test_the_lock_timeout_comes_before_every_other_statement_of_every_kind(step, conn):
    c = conn()
    BM.run_steps(_Engine(c), [step])
    assert c.sql()[0] == TIMEOUT and TIMEOUT not in c.sql()[1:]


# --------------------------------------------------------------------------- off the startup path, and retried

def test_startup_does_not_wait_for_the_steps():
    release, entered = threading.Event(), threading.Event()
    conn = _Conn(states=["absent", "valid"])

    def get_engine():
        entered.set()
        assert release.wait(10), "the test never released the steps"
        return _Engine(conn)

    thread = BM.start_background(get_engine, [STEP])
    try:
        assert entered.wait(10)
        assert thread.daemon and thread.is_alive()
        assert conn.sql() == []
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    assert _kinds(conn.sql())[-3:] == ["create", "state", "unlock"]


def test_a_failed_step_is_tried_again_and_a_busy_one_is_left(capsys):
    busy = BM.create_index("idx_probe_busy", "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_probe_busy ON x (y)")
    engine = _Engine(_Conn(states=["absent"], fail_on="CREATE INDEX"), _Conn(lock=False),
                     _Conn(states=["invalid", "valid"]))
    thread = BM.start_background(lambda: engine, [STEP, busy], retries=2, retry_seconds=0.01)
    thread.join(10)
    assert not thread.is_alive()
    # The failure, the busy step, then the failure again: dropped (the leftover) and built. Nothing more.
    assert engine.connects == 3 and engine.conns == []
    assert f"[OK] Background maintenance: {IDX} rebuilt" in capsys.readouterr().out


def test_a_step_that_keeps_failing_is_tried_a_bounded_number_of_times():
    engine = _Engine(*[_Conn(states=["absent"], fail_on="CREATE INDEX") for _ in range(5)])
    thread = BM.start_background(lambda: engine, [STEP], retries=2, retry_seconds=0.01)
    thread.join(10)
    assert engine.connects == 3


def test_a_stop_ends_the_waiting_between_attempts():
    engine = _Engine(*[_Conn(states=["absent"], fail_on="CREATE INDEX") for _ in range(5)])
    stop = threading.Event()
    thread = BM.start_background(lambda: engine, [STEP], retries=3, retry_seconds=30, stop=stop)
    stop.set()
    thread.join(10)
    assert not thread.is_alive() and engine.connects == 1


def test_an_engine_that_cannot_be_had_is_reported_and_never_raised(capsys):
    def get_engine():
        raise RuntimeError("no database")

    thread = BM.start_background(get_engine, [STEP])
    thread.join(10)
    assert "background maintenance did not run (RuntimeError)" in capsys.readouterr().out


# --------------------------------------------------------------------------- wiring

def test_no_step_is_a_schema_step_and_nothing_is_in_the_start_up_statements():
    module = (_ROOT / "app" / "core" / "background_maintenance.py").read_text(encoding="utf-8")
    assert "SchemaStep" not in module and "_SchemaStepRecorder" not in module
    source = (_ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    migrations = source.split("\ndef _run_lightweight_migrations(", 1)[1].split("\ndef ", 1)[0]
    assert "CONCURRENTLY" not in migrations and "background_maintenance" not in migrations


def test_the_lifespan_starts_the_steps_last_without_waiting_for_them():
    source = (_ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert source.count("async def lifespan(app: FastAPI):") == 1
    lifespan = source.split("async def lifespan(app: FastAPI):", 1)[1].split("\n    yield\n", 1)[0]
    call = "background_maintenance.start_background(_require_engine)"
    assert source.count("start_background(") == 1 and lifespan.count(call) == 1
    for earlier in ("_run_lightweight_migrations()", "_seed_default_email_profile()",
                    "_install_access_log_redaction()", "settings_registry.start()"):
        assert lifespan.index(earlier) < lifespan.index(call), earlier
    assert lifespan.rstrip().endswith(call)


def test_every_shipped_step_is_well_formed():
    names = [step.name for step in BM.STEPS]
    assert len(names) == len(set(names))
    for step in BM.STEPS:
        assert step.kind in (BM.CREATE_INDEX, BM.DROP_INDEX, BM.STATEMENT)
        if step.kind == BM.STATEMENT:
            assert step.done_sql
