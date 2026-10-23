"""Background maintenance against a running stack's database (app/core/background_maintenance.py).

The unit file drives the module against a scripted connection. This one runs the real module inside the
web container against the real Postgres, because the parts that matter most are the database's: CREATE
INDEX CONCURRENTLY waiting for an open writer while other writes carry on, what a build that gives up
leaves in pg_index, a session advisory lock, and the lock timeout. It works on a throwaway index over the
audit log and a throwaway table, and removes both.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid

import pytest
import requests

from conftest import BASE_URL, skip_if_container_absent

pytestmark = pytest.mark.integration

IDX = "idx_maint_probe"
CREATE = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {IDX} ON audit_logs (status, action)"
_LOCK_CLASS = 0x6978

_RUN = """
import json, sys
from app.core import background_maintenance as M
from app.core.database import _require_engine
M.LOCK_TIMEOUT_MS = int(sys.argv[1])
steps = [M.create_index(sys.argv[2], sys.argv[3])] if sys.argv[4] == "create" else (
    [M.drop_index(sys.argv[2])] if sys.argv[4] == "drop" else [M.statement(sys.argv[2], sys.argv[3], sys.argv[5])])
print("OUTCOME=" + json.dumps(M.run_steps(_require_engine(), steps)))
"""


def _api():
    return os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _db():
    return os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    out = subprocess.run(
        ["docker", "exec", _db(), "sh", "-c", 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$0"', sql],
        capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, _db())
    assert out.returncode == 0, f"query failed: {(out.stderr or '').strip()[:300]}\n  sql: {sql}"
    return out.stdout.strip()


def _state() -> str:
    got = _psql("SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid "
                f"WHERE c.relname = '{IDX}'")
    return {"": "absent", "t": "valid", "f": "invalid"}[got]


def _run_args(timeout_ms, name, sql, kind, done=""):
    return ["docker", "exec", _api(), "python", "-c", _RUN, str(timeout_ms), name, sql, kind, done]


def _run(timeout_ms, name, sql, kind, done="") -> str:
    out = subprocess.run(_run_args(timeout_ms, name, sql, kind, done), capture_output=True, text=True, timeout=300)
    skip_if_container_absent(out, _api())
    assert out.returncode == 0, (out.stderr or "")[-800:]
    lines = [l for l in out.stdout.splitlines() if l.startswith("OUTCOME=")]
    assert len(lines) == 1, out.stdout[-800:]
    return json.loads(lines[0].split("=", 1)[1])[name]


def _holder(sql: str) -> subprocess.Popen:
    """A psql session in the database container running ``sql`` (a transaction that sleeps)."""
    return subprocess.Popen(["docker", "exec", _db(), "sh", "-c",
                             'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -tAc "$0"', sql],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _end_holders(proc: subprocess.Popen) -> None:
    # Ending the docker client does not end psql inside the container: end its session.
    _psql("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
          "WHERE application_name = 'psql' AND query LIKE '%maint-probe-holder%' AND pid <> pg_backend_pid()")
    proc.terminate()
    try:
        proc.wait(30)
    except subprocess.TimeoutExpired:
        proc.kill()


def _wait(pred, seconds, what):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.2)
    raise AssertionError(f"waited {seconds}s for {what}")


_WRITER = ("BEGIN; INSERT INTO audit_logs (id, action, status, timestamp) VALUES (gen_random_uuid(), "
           "'maint-probe-holder', 'success', now() AT TIME ZONE 'utc'); SELECT pg_sleep({s}); COMMIT; "
           "-- maint-probe-holder")


@pytest.fixture(autouse=True)
def _clean():
    _psql(f"DROP INDEX IF EXISTS {IDX}")
    yield
    _psql(f"DROP INDEX IF EXISTS {IDX}")
    _psql("DROP TABLE IF EXISTS maint_probe")
    _psql("DELETE FROM audit_logs WHERE action = 'maint-probe-holder'")


def _failed_sign_in_takes(seconds_limit: float) -> float:
    name = f"maint-{uuid.uuid4().hex[:8]}"
    t0 = time.monotonic()
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": name, "password": "not-the-password"}, timeout=30)
    took = time.monotonic() - t0
    assert r.status_code in (401, 429), r.status_code
    assert _psql(f"SELECT count(*) FROM audit_logs WHERE username = '{name}'") == "1"
    assert took < seconds_limit, f"a sign-in's audit write took {took:.1f}s during the build"
    return took


def test_an_index_is_built_concurrently_while_audit_writes_carry_on():
    # The writer stays open until the test ends it, however slowly the host runs the steps before (a writer that
    # ended on its own after a few seconds could end before the check that the build waits for it).
    holder = _holder(_WRITER.format(s=300))
    build = None
    try:
        # An open writer on the audit log: the concurrent build creates its index and then waits for it.
        _wait(lambda: _psql("SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%maint-probe-holder%' "
                            "AND state = 'active' AND pid <> pg_backend_pid()") == "1", 20, "the open writer")
        build = subprocess.Popen(_run_args(120000, IDX, CREATE, "create"), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        _wait(lambda: _state() == "invalid", 60, "the build to start")
        # While it waits, the app's audit writes go through, promptly. A plain CREATE INDEX would hold them
        # behind the open writer until it ended.
        for _ in range(3):
            _failed_sign_in_takes(5)
        assert _state() == "invalid" and build.poll() is None, "the build did not wait for the open writer"
        # The writer ends (its transaction rolled back, so it leaves no row): the build goes on and completes.
        _end_holders(holder)
        holder = None
        out, err = build.communicate(timeout=120)
        assert build.returncode == 0, err[-800:]
        assert 'OUTCOME={"idx_maint_probe": "built"}' in out, out[-800:]
        assert _state() == "valid"
    finally:
        if build is not None and build.poll() is None:
            build.kill()
        if holder is not None:
            _end_holders(holder)


def test_a_build_that_times_out_leaves_an_invalid_index_that_the_next_start_rebuilds():
    holder = _holder(_WRITER.format(s=40))
    try:
        _wait(lambda: _psql("SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%maint-probe-holder%' "
                            "AND state = 'active' AND pid <> pg_backend_pid()") == "1", 20, "the open writer")
        t0 = time.monotonic()
        # Nothing waits without a lock timeout: with 2 seconds, the build gives up long before the writer ends.
        assert _run(2000, IDX, CREATE, "create") == "failed"
        assert time.monotonic() - t0 < 30
        assert _state() == "invalid"
    finally:
        _end_holders(holder)
    # The next start: the leftover is dropped and the index built again.
    assert _run(30000, IDX, CREATE, "create") == "rebuilt"
    assert _state() == "valid"
    assert _run(30000, IDX, CREATE, "create") == "present"


def test_a_second_process_leaves_the_step_to_the_one_holding_its_lock():
    holder = _holder(f"SELECT pg_advisory_lock({_LOCK_CLASS}, hashtext('{IDX}')), pg_sleep(60); "
                     "-- maint-probe-holder")
    try:
        _wait(lambda: _psql("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                            f"AND classid = {_LOCK_CLASS} AND granted") == "1", 20, "the stand-in's lock")
        assert _run(30000, IDX, CREATE, "create") == "busy"
        assert _state() == "absent"
    finally:
        _end_holders(holder)


def test_an_index_is_dropped_concurrently_and_a_statement_applied_once():
    assert _run(30000, IDX, CREATE, "create") == "built"
    assert _run(30000, IDX, "", "drop") == "dropped"
    assert _state() == "absent"
    assert _run(30000, IDX, "", "drop") == "absent"
    _psql("CREATE TABLE IF NOT EXISTS maint_probe (x int)")
    done = ("SELECT coalesce('autovacuum_vacuum_scale_factor=0.02' = ANY(reloptions), false) "
            "FROM pg_class WHERE relname = 'maint_probe'")
    alter = "ALTER TABLE maint_probe SET (autovacuum_vacuum_scale_factor = 0.02)"
    assert _run(30000, "maint_probe_vacuum", alter, "statement", done) == "applied"
    assert _run(30000, "maint_probe_vacuum", alter, "statement", done) == "present"


def test_an_index_of_the_same_name_in_another_schema_is_not_this_ones():
    # The state of an index is read in the app's own schema: one of the same name elsewhere neither stands
    # in for it nor is dropped in its place.
    other = "maint_probe_other"
    ours = ("SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = '{0}' AND n.nspname = {1}")
    try:
        _psql(f"CREATE SCHEMA IF NOT EXISTS {other}")
        _psql(f"CREATE TABLE IF NOT EXISTS {other}.t (x int)")
        _psql(f"CREATE INDEX IF NOT EXISTS {IDX} ON {other}.t (x)")
        assert _run(30000, IDX, CREATE, "create") == "built"
        assert _psql(ours.format(IDX, "current_schema()")) == "t"
        assert _run(30000, IDX, "", "drop") == "dropped"
        assert _run(30000, IDX, "", "drop") == "absent"
        assert _psql(ours.format(IDX, "current_schema()")) == ""
        assert _psql(ours.format(IDX, f"'{other}'")) == "t"
    finally:
        _psql(f"DROP SCHEMA IF EXISTS {other} CASCADE")


def test_no_step_is_a_schema_step_and_the_schema_is_complete():
    assert _run(30000, IDX, CREATE, "create") == "built"
    assert _psql(f"SELECT count(*) FROM schema_steps WHERE summary LIKE '%{IDX}%'") == "0"
    assert requests.get(f"{BASE_URL}/health", timeout=10).json()["schema"] == "complete"
