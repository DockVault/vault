"""A start waits, within a bound, for a database it cannot reach yet; the check itself still runs.

After a host restarts, the database and the vault start together. The start-up check connected once:
a database that did not answer in time (``timeout expired``) stopped the process, the one-container
launcher stopped the container, and Docker started it again. Now a database that cannot be reached
yet is waited for, one plain line per wait, up to DATABASE_WAIT_SECONDS, and then checked like any
other: a newer-data refusal still refuses, and a database that answers with a refusal of its own (a
wrong password, say) is not waited for.

The engine here fails on demand and then hands out connections to a real SQLite database, through the
same calls the start makes; the clock is the test's, so no test waits.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import OperationalError, ProgrammingError

from app.core import data_requirements as dr

pytestmark = pytest.mark.unit

TIMEOUT = 'connection to server at "vault-db" (10.200.7.2), port 5432 failed: timeout expired\n'
REFUSED = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: Connection refused\n'
           '\tIs the server running on that host and accepting TCP/IP connections?\n')
NO_NAME = 'could not translate host name "vault-db" to address: Name or service not known\n'
STARTING = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  the database '
            'system is starting up\n')
NOT_ACCEPTING = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  the database '
                 'system is not yet accepting connections\nDETAIL:  Consistent recovery state has not been '
                 'yet reached.\n')
IN_RECOVERY = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  the database '
               'system is in recovery mode\n')
SHUTTING_DOWN = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  the database '
                 'system is shutting down\n')
BAD_PASSWORD = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  password '
                'authentication failed for user "sftp_user"\n')


def _unreachable(message):
    return OperationalError(None, None, Exception(message))


class _Clock:
    """The start's clock. Its sleep refuses a negative length, as time.sleep does: a wait that
    lets its bound pass would otherwise move this clock back and never end."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        self.slept.append(seconds)
        self.now += seconds


class _Engine:
    """Fails `failures` connects (each taking `connect_seconds` on the clock), then connects.

    A wait that never ends fails the test at MAX_ATTEMPTS, instead of running for ever."""

    MAX_ATTEMPTS = 1000

    def __init__(self, real, clock, failures, error, connect_seconds=0.0):
        self.real, self.clock = real, clock
        self.failures, self.error = failures, error
        self.connect_seconds = connect_seconds
        self.attempts = 0

    def connect(self):
        self.attempts += 1
        if self.attempts > self.MAX_ATTEMPTS:
            raise AssertionError(f"the start tried to connect {self.MAX_ATTEMPTS} times")
        if self.failures is None or self.attempts <= self.failures:
            self.clock.now += self.connect_seconds
            raise self.error
        return self.real.connect()


@pytest.fixture
def database():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'marks.db'}")
        with engine.begin() as conn:
            conn.execute(sa.text(
                "CREATE TABLE data_requirements (key VARCHAR(64) PRIMARY KEY, "
                "requires_at_least VARCHAR(32) NOT NULL, reason TEXT NOT NULL, undo TEXT, "
                "since DATETIME NOT NULL)"))
        yield engine
        engine.dispose()


@pytest.fixture
def start(monkeypatch, database):
    """check_at_startup with the engine and the clock under the test's control."""
    from app.core import config
    import app.core.database as db_module
    clock = _Clock()
    monkeypatch.setattr(dr, "_clock", clock, raising=False)
    monkeypatch.setattr(dr, "_sleep", clock.sleep, raising=False)
    monkeypatch.setattr(dr, "running_version", lambda: "0.33.5")
    monkeypatch.setattr(config.settings, "allow_start_on_newer_data", False)
    monkeypatch.delenv("VAULT_LOG_SINK_OWNER", raising=False)

    def run(failures, error, process="sftp", connect_seconds=0.0):
        engine = _Engine(database, clock, failures, error, connect_seconds)
        monkeypatch.setattr(db_module, "_require_engine", lambda: engine)
        dr.check_at_startup(process)
        return engine

    run.clock = clock
    run.database = database
    return run


def _mark_newer(engine):
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO data_requirements (key, requires_at_least, reason, undo, since) "
            "VALUES ('legal-holds', '0.34.0', 'keeps records under a legal hold', 'release the holds', "
            "CURRENT_TIMESTAMP)"))


@pytest.mark.parametrize("message, reason", [
    (TIMEOUT, "timeout expired"),
    (REFUSED, "Connection refused"),
    (NO_NAME, 'could not translate host name "vault-db" to address: Name or service not known'),
    (STARTING, "FATAL:  the database system is starting up"),
    (NOT_ACCEPTING, "FATAL:  the database system is not yet accepting connections"),
    (IN_RECOVERY, "FATAL:  the database system is in recovery mode"),
    (SHUTTING_DOWN, "FATAL:  the database system is shutting down"),
], ids=["timeout", "refused", "no-name-yet", "starting-up", "not-yet-accepting", "in-recovery",
        "shutting-down"])
def test_a_database_that_comes_up_during_the_wait_is_checked_and_the_start_goes_on(
        start, capsys, message, reason):
    engine = start(3, _unreachable(message), connect_seconds=5.0)
    assert engine.attempts == 4
    assert start.clock.slept == [1.0, 2.0, 4.0]
    lines = capsys.readouterr().err.splitlines()
    assert lines == [
        f"[sftp] The database cannot be reached yet ({reason}); trying again in 1 s.",
        f"[sftp] The database cannot be reached yet ({reason}); trying again in 2 s.",
        f"[sftp] The database cannot be reached yet ({reason}); trying again in 4 s.",
        "[sftp] The database answered after 22 s.",
    ]


def test_the_check_runs_on_the_database_the_wait_ends_with(start, capsys):
    """A database that comes up mid-wait carrying a newer release's mark is still refused."""
    _mark_newer(start.database)
    with pytest.raises(dr.NewerDataRefusal):
        start(2, _unreachable(TIMEOUT))
    err = capsys.readouterr().err
    assert err.count("cannot be reached yet") == 2
    assert "[sftp] DockVault 0.33.5 will not start" in err


def test_a_database_that_never_comes_up_stops_the_start_after_the_bound(start, capsys):
    with pytest.raises(OperationalError):
        start(None, _unreachable(TIMEOUT), connect_seconds=5.0)
    slept = start.clock.slept
    assert slept[:4] == [1.0, 2.0, 4.0, 5.0] and set(slept[3:-1]) == {5.0}
    assert start.clock.now - 1000.0 <= dr.DATABASE_WAIT_SECONDS + 5.0, "the wait ran past its bound"
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == len(slept) + 1
    assert lines[-1] == ("[sftp] The database could not be reached within 120 s (timeout expired); "
                         "stopping.")


def test_the_test_clock_refuses_a_negative_sleep_as_time_sleep_does():
    with pytest.raises(ValueError):
        time.sleep(-1)
    with pytest.raises(ValueError):
        _Clock().sleep(-1)


def test_the_wait_is_two_minutes():
    assert dr.DATABASE_WAIT_SECONDS == 120.0


def test_a_newer_data_refusal_is_not_retried(start, capsys):
    _mark_newer(start.database)
    with pytest.raises(dr.NewerDataRefusal):
        start(0, _unreachable(TIMEOUT))
    assert start.clock.slept == []
    assert "cannot be reached yet" not in capsys.readouterr().err


def test_a_database_that_refuses_this_process_is_not_waited_for(start, capsys):
    """It was reached: waiting changes nothing, and the operator should see the error at once."""
    with pytest.raises(OperationalError):
        start(None, _unreachable(BAD_PASSWORD))
    assert start.clock.slept == []
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("error", [ProgrammingError(None, None, Exception("no such table")),
                                   RuntimeError("something else")],
                         ids=["database-error", "other-error"])
def test_any_other_failure_is_not_retried(start, error):
    with pytest.raises(type(error)):
        start(None, error)
    assert start.clock.slept == []


def test_under_the_one_container_launcher_the_wait_lines_are_not_named_twice(start, monkeypatch,
                                                                             capsys):
    monkeypatch.setenv("VAULT_LOG_SINK_OWNER", "run_combined")
    start(1, _unreachable(TIMEOUT), process="web")
    assert capsys.readouterr().err.splitlines() == [
        "The database cannot be reached yet (timeout expired); trying again in 1 s.",
        "The database answered after 1 s.",
    ]


def test_a_start_that_connects_at_once_says_nothing(start, capsys):
    engine = start(0, _unreachable(TIMEOUT), process="web")
    assert engine.attempts == 1 and capsys.readouterr().err == ""
