"""The username-typeahead index on a running deployment: built after startup, rebuilt when a build
was interrupted, left to the builder that holds the lock, and never a schema step.

The unit file (test_optional_indexes.py) drives the builder against a scripted connection. This one
runs the real module inside the API container against the real Postgres, because the parts that
matter most are the database's: CREATE INDEX CONCURRENTLY refusing a transaction, what an
interrupted build leaves in pg_index, and a session advisory lock.

An interrupted build is simulated by marking the finished index invalid (pg_index.indisvalid), which
is exactly the state Postgres leaves when a concurrent build is cancelled or its process dies.
"""
from __future__ import annotations

import os
import subprocess
import time

import pytest
import requests

from conftest import skip_for_older_deployment, skip_if_container_absent

pytestmark = pytest.mark.integration

NAME = "idx_audit_username_prefix"
_BUILD = ("from app.core import optional_indexes as O; from app.core.database import _require_engine; "
          "print('OUTCOME=' + O.build_optional_indexes(_require_engine())['" + NAME + "'])")


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
                f"WHERE c.relname = '{NAME}'")
    return {"": "absent", "t": "valid", "f": "invalid"}[got]


def _build_in_the_container() -> str:
    out = subprocess.run(["docker", "exec", _api(), "python", "-c", _BUILD],
                         capture_output=True, text=True, timeout=600)
    skip_if_container_absent(out, _api())
    err = out.stderr or ""
    if out.returncode != 0 and "optional_indexes" in err and (
            "ImportError" in err or "ModuleNotFoundError" in err):
        skip_for_older_deployment("this image predates the background index build")
    assert out.returncode == 0, (out.stderr or "")[-800:]
    lines = [l for l in out.stdout.splitlines() if l.startswith("OUTCOME=")]
    assert len(lines) == 1, out.stdout[-800:]
    return lines[0].split("=", 1)[1]


_LOCK_CLASS = 0x6978                      # app/core/optional_indexes.py's builder lock
_LOCK_HOLDERS = ("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                 f"AND classid = {_LOCK_CLASS} AND granted")


def _wait_lock_free(seconds: float) -> None:
    """A build that is still running (the deployment's own, at startup) holds the builder lock."""
    deadline = time.monotonic() + seconds
    while _psql(_LOCK_HOLDERS) != "0" and time.monotonic() < deadline:
        time.sleep(0.5)
    assert _psql(_LOCK_HOLDERS) == "0", "the builder lock is still held"


def _wait_valid(seconds: float) -> str:
    deadline = time.monotonic() + seconds
    state = _state()
    while state != "valid" and time.monotonic() < deadline:
        time.sleep(1)
        state = _state()
    return state


def test_the_index_is_built_after_startup_and_no_schema_step_names_it(base_url):
    # The deployment built it on its own after startup (a fresh stack: in well under a minute).
    state = _wait_valid(120)
    if state == "absent":
        # Present in every image that has the background build. Absent with the module missing
        # means an older image, which the helper below reports as such.
        _build_in_the_container()
    assert state == "valid", f"{NAME} is {state} two minutes after startup"
    # Never a schema step, so /health cannot turn incomplete over it.
    assert _psql(f"SELECT count(*) FROM schema_steps WHERE summary LIKE '%{NAME}%'") == "0"
    assert requests.get(f"{base_url}/health", timeout=10).json()["schema"] == "complete"


def test_an_interrupted_build_is_dropped_and_built_again():
    assert _wait_valid(120) == "valid"
    _wait_lock_free(60)
    _psql(f"UPDATE pg_index SET indisvalid = false WHERE indexrelid = '{NAME}'::regclass")
    try:
        assert _state() == "invalid"
        assert _build_in_the_container() == "rebuilt"
        assert _state() == "valid"
        # And a start after that does nothing but look.
        assert _build_in_the_container() == "present"
    finally:
        # Never leave a deployment with a half-state index, whatever failed above.
        if _state() != "valid":
            _psql(f"DROP INDEX IF EXISTS {NAME}")
            _psql(f'CREATE INDEX IF NOT EXISTS {NAME} ON audit_logs ((lower(username) COLLATE "C"))')


def test_a_second_builder_leaves_the_index_to_the_one_holding_the_lock():
    assert _wait_valid(120) == "valid"
    _wait_lock_free(60)
    holder = subprocess.Popen(
        ["docker", "exec", _db(), "sh", "-c",
         'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$0"',
         f"SELECT pg_advisory_lock({_LOCK_CLASS}, hashtext('{NAME}')), pg_sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and _psql(_LOCK_HOLDERS) == "0":
            time.sleep(0.5)
        assert _psql(_LOCK_HOLDERS) == "1", "the stand-in builder never took the lock"
        assert _build_in_the_container() == "busy"
    finally:
        # Ending the docker client does not end psql inside the container: end its session, which
        # releases the lock, so nothing after this test finds the builder lock taken.
        _psql("SELECT count(pg_terminate_backend(a.pid)) FROM pg_locks l "
              "JOIN pg_stat_activity a ON a.pid = l.pid "
              f"WHERE l.locktype = 'advisory' AND l.classid = {_LOCK_CLASS} "
              "AND a.application_name = 'psql'")
        holder.terminate()
        try:
            holder.wait(30)
        except subprocess.TimeoutExpired:
            holder.kill()
        _wait_lock_free(30)
