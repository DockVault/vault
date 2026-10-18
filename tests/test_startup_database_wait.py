"""A start waits, within a bound, for a database it cannot reach yet; the check itself still runs.

After a host restarts, the database and the vault start together. The start-up check connected once:
a database that did not answer in time (``timeout expired``) stopped the process, the one-container
launcher stopped the container, and Docker started it again. Now a database that cannot be reached
yet is waited for, one plain line per wait, up to DATABASE_WAIT_SECONDS, and then checked like any
other: a newer-data refusal still refuses. Only words known to mean that the database cannot be reached
yet are waited for: a refusal from the server (a wrong password, say) or from the client library
itself (no password given), and words not known at all, stop the start at once.

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

# The client library's words, as the image's (libpq 17 on musl) says them, unless named otherwise.
TIMEOUT = 'connection to server at "vault-db" (10.200.7.2), port 5432 failed: timeout expired\n'
REFUSED = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: Connection refused\n'
           '\tIs the server running on that host and accepting TCP/IP connections?\n')
NO_NAME = 'could not translate host name "vault-db" to address: Name or service not known\n'
NO_NAME_YET = 'could not translate host name "vault-db" to address: Try again\n'
HOST_UNREACHABLE = ('connection to server at "10.200.7.2", port 5432 failed: Host is unreachable\n'
                    '\tIs the server running on that host and accepting TCP/IP connections?\n')
NETWORK_UNREACHABLE = ('connection to server at "2001:db8::7", port 5432 failed: Network unreachable\n'
                       '\tIs the server running on that host and accepting TCP/IP connections?\n')
NO_SOCKET = ('connection to server on socket "/run/postgresql/.s.PGSQL.5432" failed: No such file or '
             'directory\n\tIs the server running locally and accepting connections on that socket?\n')
CLOSED = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: server closed the '
          'connection unexpectedly\n\tThis probably means the server terminated abnormally\n\tbefore or '
          'while processing the request.\n')
# The other C library's words (glibc), and an older client library's (libpq 13).
NAME_RESOLUTION = ('could not translate host name "vault-db" to address: Temporary failure in name '
                   'resolution\n')
KERNEL_TIMEOUT = ('connection to server at "10.200.7.2", port 5432 failed: Connection timed out\n'
                  '\tIs the server running on that host and accepting TCP/IP connections?\n')
OLD_REFUSED = ('could not connect to server: Connection refused\n\tIs the server running on host '
               '"vault-db" (10.200.7.2) and accepting\n\tTCP/IP connections on port 5432?\n')
# Each of the client library's words on its own, without the question it asks after them, so that each
# is shown to be waited for by itself.
ALONE = {
    "could-not-connect": 'could not connect to server: Connection timed out\n',
    "refused": 'connection to server at "vault-db" (10.200.7.2), port 5432 failed: Connection refused\n',
    "no-route": 'connection to server at "10.200.7.2", port 5432 failed: No route to host\n',
    "host-unreachable": 'connection to server at "10.200.7.2", port 5432 failed: Host is unreachable\n',
    "network-is-unreachable": ('connection to server at "2001:db8::7", port 5432 failed: Network is '
                               'unreachable\n'),
    "network-unreachable": ('connection to server at "2001:db8::7", port 5432 failed: Network '
                            'unreachable\n'),
}
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
NO_DATABASE = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  database '
               '"sftp_db" does not exist\n')
UNKNOWN_SETTING = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  '
                   'unrecognized configuration parameter "no_such_setting"\n')
# Refusals the client library makes itself, with no server severity.
NO_PASSWORD = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: fe_sendauth: no '
               'password supplied\n')
SSL_REQUIRED = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: server does not '
                'support SSL, but SSL was required\n')
BAD_SSLMODE = 'invalid sslmode value: "bogus"\n'
# A server that answers in another language: its words are not known here, so none is waited for.
TRANSLATED_REFUSAL = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: ВАЖНО:  '
                      'пользователь "sftp_user" не прошёл проверку подлинности (по паролю)\n')
TRANSLATED_STARTING = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: ВАЖНО:  '
                       'система баз данных запускается\n')
# A server's refusal is judged by the server's words alone, even when a name in it reads like the
# client library's.
REFUSAL_NAMING_THE_WORDS = ('connection to server at "vault-db" (10.200.7.2), port 5432 failed: FATAL:  '
                            'database "no route to host" does not exist\n')


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
        run.engine = engine
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
    (NO_NAME_YET, 'could not translate host name "vault-db" to address: Try again'),
    (HOST_UNREACHABLE, "Host is unreachable"),
    (NETWORK_UNREACHABLE, "Network unreachable"),
    (NO_SOCKET, "No such file or directory"),
    (CLOSED, "server closed the connection unexpectedly"),
    (NAME_RESOLUTION,
     'could not translate host name "vault-db" to address: Temporary failure in name resolution'),
    (KERNEL_TIMEOUT, "Connection timed out"),
    (OLD_REFUSED, "could not connect to server: Connection refused"),
    (ALONE["could-not-connect"], "could not connect to server: Connection timed out"),
    (ALONE["refused"], "Connection refused"),
    (ALONE["no-route"], "No route to host"),
    (ALONE["host-unreachable"], "Host is unreachable"),
    (ALONE["network-is-unreachable"], "Network is unreachable"),
    (ALONE["network-unreachable"], "Network unreachable"),
    (STARTING, "FATAL:  the database system is starting up"),
    (NOT_ACCEPTING, "FATAL:  the database system is not yet accepting connections"),
    (IN_RECOVERY, "FATAL:  the database system is in recovery mode"),
    (SHUTTING_DOWN, "FATAL:  the database system is shutting down"),
], ids=["timeout", "refused", "no-name", "no-name-yet", "host-unreachable", "network-unreachable",
        "no-socket-yet", "closed-before-answering", "name-resolution", "kernel-timeout",
        "older-client-refused"] + [f"alone-{key}" for key in ALONE] + [
        "starting-up", "not-yet-accepting", "in-recovery", "shutting-down"])
@pytest.mark.parametrize("process", ["sftp", "web"])
def test_a_database_that_comes_up_during_the_wait_is_checked_and_the_start_goes_on(
        start, capsys, message, reason, process):
    engine = start(3, _unreachable(message), process=process, connect_seconds=5.0)
    assert engine.attempts == 4
    assert start.clock.slept == [1.0, 2.0, 4.0]
    lines = capsys.readouterr().err.splitlines()
    assert lines == [
        f"[{process}] The database cannot be reached yet ({reason}); trying again in 1 s.",
        f"[{process}] The database cannot be reached yet ({reason}); trying again in 2 s.",
        f"[{process}] The database cannot be reached yet ({reason}); trying again in 4 s.",
        f"[{process}] The database answered after 22 s.",
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


@pytest.mark.parametrize("message", [
    BAD_PASSWORD, NO_DATABASE, UNKNOWN_SETTING, NO_PASSWORD, SSL_REQUIRED, BAD_SSLMODE,
    TRANSLATED_REFUSAL, TRANSLATED_STARTING, REFUSAL_NAMING_THE_WORDS, "some other failure\n",
], ids=["wrong-password", "no-database", "unknown-setting", "no-password-given", "ssl-required",
        "bad-ssl-setting", "refusal-in-another-language", "starting-in-another-language",
        "refusal-naming-the-words", "words-not-known"])
@pytest.mark.parametrize("process", ["sftp", "web"])
def test_a_refusal_is_not_waited_for(start, capsys, message, process):
    """The server, or the client library itself, refused this connection, or said something not
    known to mean the server cannot be reached yet: waiting changes nothing, and the operator should
    see the error at once."""
    with pytest.raises(OperationalError):
        start(None, _unreachable(message), process=process)
    assert start.engine.attempts == 1
    assert start.clock.slept == []
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("error", [ProgrammingError(None, None, Exception("no such table")),
                                   RuntimeError("something else")],
                         ids=["database-error", "other-error"])
def test_any_other_failure_is_not_retried(start, error):
    with pytest.raises(type(error)):
        start(None, error)
    assert start.clock.slept == []


def test_an_error_that_is_not_an_operational_error_is_not_waited_for_whatever_it_says(start):
    """Only the database driver's own connection errors are judged by their words: any other error
    stops the start at once, even one whose text reads like a database still on its way."""
    with pytest.raises(RuntimeError):
        start(None, RuntimeError("timeout expired"))
    assert start.engine.attempts == 1
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
