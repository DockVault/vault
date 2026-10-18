"""In the one-container shape, SFTP starts only once the API's start has finished, however long the
API's start waited for its database.

The launcher starts the API, waits for its /health to answer, and only then starts SFTP, because the
API's start runs the schema step SFTP relies on. That start first waits up to DATABASE_WAIT_SECONDS
for a database it cannot reach yet. The launcher used to wait a fixed minute and then start SFTP
anyway, so a database that answered between one and two minutes after the start let SFTP start
before the schema step had run. Now the launcher's wait covers the API's database wait plus the rest
of the start; an API process that exits still ends the wait at once, and the container still stops.

These run the launcher's wait, and its main(), on a clock of the test's own with stand-in children:
nothing is started and no test waits.
"""
import os
import signal
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_combined  # noqa: E402
from app.core.data_requirements import DATABASE_WAIT_SECONDS  # noqa: E402

_MARKERS = ("VAULT_LOG_SINK_OWNER", "VAULT_LOG_SINK_ACTIVE", "VAULT_LOG_SINK_COMPONENTS",
            "VAULT_SFTP_IN_CONTAINER")


class _Clock:
    """The launcher's clock. Its sleep refuses a negative length, as time.sleep does, and a wait that
    never ends fails the test instead of running for ever."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        self.sleeps += 1
        if self.sleeps > 10_000:
            raise AssertionError("the wait never ended")
        self.now += seconds


class _Child:
    """A child process: running until `exits_at` on the clock, or until `exits_when()` holds."""

    def __init__(self, clock, target, exits_at=None, exits_when=None, code=3):
        self.clock, self.target = clock, target
        self.exits_at, self.exits_when, self.code = exits_at, exits_when, code
        self.returncode = None
        self.terminated = False
        self.stdout = iter(())

    def poll(self):
        if self.returncode is None and (
                (self.exits_at is not None and self.clock.now >= self.exits_at)
                or (self.exits_when is not None and self.exits_when())):
            self.returncode = self.code
        return self.returncode

    def terminate(self):
        self.terminated = True
        if self.returncode is None:
            self.returncode = -signal.SIGTERM

    kill = terminate


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Health:
    """The API's /health: refused until the API is ready at `ready_at` on the clock (never if None)."""

    def __init__(self, clock, ready_at):
        self.clock, self.ready_at = clock, ready_at
        self.asked = []

    def __call__(self, url, timeout=None, context=None):
        self.asked.append(self.clock.now)
        if self.ready_at is None or self.clock.now < self.ready_at:
            raise urllib.error.URLError("[Errno 111] Connection refused")
        return _Response()


@pytest.fixture
def launcher(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(run_combined, "_clock", clock)
    monkeypatch.setattr(run_combined, "_sleep", clock.sleep)
    monkeypatch.setattr(run_combined, "_PROCS", [])

    def health(ready_at):
        probe = _Health(clock, ready_at)
        monkeypatch.setattr(run_combined.urllib.request, "urlopen", probe)
        return probe

    def api(**kw):
        child = _Child(clock, "app.api.api_server", **kw)
        run_combined._PROCS.append(("app.api.api_server", child))
        return child

    return SimpleNamespace(clock=clock, health=health, api=api)


def test_the_wait_covers_the_api_database_wait_and_the_rest_of_its_start():
    assert run_combined.API_READY_SECONDS == DATABASE_WAIT_SECONDS + 60.0
    assert run_combined._wait_api_ready.__defaults__ == (run_combined.API_READY_SECONDS,)


@pytest.mark.parametrize("ready_at", [5.0, 61.0, 100.0, DATABASE_WAIT_SECONDS + 30.0],
                         ids=["at-once", "after-a-minute", "late-in-the-database-wait",
                              "after-the-whole-database-wait"])
def test_sftp_waits_for_an_api_that_is_still_starting(launcher, ready_at):
    launcher.api()
    launcher.health(ready_at)
    assert run_combined._wait_api_ready() is True
    assert ready_at <= launcher.clock.now < ready_at + 1.0


def test_an_api_that_never_answers_ends_the_wait_after_the_bound(launcher):
    launcher.api()
    launcher.health(None)
    assert run_combined._wait_api_ready() is False
    bound = DATABASE_WAIT_SECONDS + 60.0
    assert bound <= launcher.clock.now <= bound + 1.0


def test_an_api_that_exits_ends_the_wait_at_once(launcher):
    launcher.api(exits_at=30.0)
    probe = launcher.health(None)
    assert run_combined._wait_api_ready() is False
    assert launcher.clock.now == 30.0 and max(probe.asked) < 30.0


@pytest.fixture
def main(launcher, monkeypatch):
    """run_combined.main() with RUN_SFTP on, its children stand-ins made by `make(target)`."""
    monkeypatch.setenv("RUN_SFTP", "true")
    for name in _MARKERS:              # setenv first, so the values main() writes are undone
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.setattr(run_combined, "_init_sink", lambda: None)
    monkeypatch.setattr(run_combined, "_sink_logger", None)
    monkeypatch.setattr(run_combined, "_sink_writer_loop", lambda: None)
    spawned = []

    def run(make):
        def popen(argv, **kw):
            child = make(argv[-1])
            spawned.append((argv[-1], launcher.clock.now, child))
            return child

        monkeypatch.setattr(run_combined.subprocess, "Popen", popen)
        handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            with pytest.raises(SystemExit) as stopped:
                run_combined.main()
        finally:
            for s, handler in handlers.items():
                signal.signal(s, handler)
        return stopped.value.code

    run.spawned = spawned
    return run


def test_sftp_starts_only_once_the_api_has_finished_its_start(launcher, main, capsys):
    """A database that answered late in the API's wait: SFTP starts when /health answers, not at a
    minute. (The API stand-in exits once SFTP is started, which ends the launcher.)"""
    launcher.health(100.0)
    code = main(lambda target: _Child(launcher.clock, target,
                                      exits_when=lambda: len(main.spawned) == 2, code=1))
    assert [(target, at) for target, at, _ in main.spawned] == [
        ("app.api.api_server", 0.0), ("app.sftp.sftp_server", 100.0)]
    assert "starting SFTP anyway" not in capsys.readouterr().out
    assert code == 1


def test_an_api_that_never_answers_still_has_sftp_started_after_the_bound(launcher, main, capsys):
    launcher.health(None)
    main(lambda target: _Child(launcher.clock, target, exits_when=lambda: len(main.spawned) == 2))
    (_, _, _), (target, at, _) = main.spawned
    bound = DATABASE_WAIT_SECONDS + 60.0
    assert target == "app.sftp.sftp_server" and bound <= at <= bound + 1.0
    assert "[run_combined] API not ready within timeout; starting SFTP anyway" in capsys.readouterr().out


def test_an_api_that_exits_while_sftp_waits_still_stops_the_container(launcher, main, capsys):
    launcher.health(None)
    code = main(lambda target: _Child(launcher.clock, target, exits_at=30.0)
                if target == "app.api.api_server" else _Child(launcher.clock, target))
    assert code == 3, "the container must stop with the API's own exit code"
    assert launcher.clock.now == 30.0, "the launcher kept waiting for an API that had exited"
    assert ("[run_combined] app.api.api_server exited with code 3; stopping the container"
            in capsys.readouterr().out)
    assert all(child.poll() is not None for _, _, child in main.spawned), "a child was left running"
