"""The Redis circuit breaker closes only when a BACKGROUND probe proves Redis healthy, never on a
timer, and no foreground caller ever touches the socket while it is open.

The bug this pins: while Redis is down the breaker used to lapse after a cooldown, so the first
foreground caller to touch Redis afterwards -- typically RateLimitMiddleware's synchronous check, ON
the event loop, on every route -- paid the socket timeout again to rediscover the outage, freezing
the whole server for ~one timeout every cooldown. Now, once open, the breaker stays open; a single
daemon thread waits a cooldown, pings Redis on a short-timeout connection, and only its SUCCESS
closes the breaker. The server heals while idle, and a plain sleep is enough to wait it out.

Timing is pinned by threads and events, never by a sleep in an assertion path: the probe's inter-
attempt wait and its ping are seams a test replaces, and the recovery case joins the probe thread.
"""
import threading
import time

import pytest

# rate_limiter imports app.core.database (a lazy client proxy); the bare env keeps this module
# importable and runnable alone with no .env.
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_breaker():
    """Every test starts and ends with a closed breaker and no tracked probe thread. A probe thread
    a test started is joined by that test; a closed breaker makes any stray one exit at its next
    wait."""
    def _clear():
        R._cb_record_success()
        with R._cb_lock:
            R._cb_probe_thread = None
    _clear()
    yield
    _clear()


def _raise_down():
    raise RuntimeError("redis down")


class _RecordingRedis:
    """A backend that RECORDS each script call and returns a healthy result. Recording (not raising)
    is the reliable signal: a raise from eval is swallowed by the fail-open handler, so it could not
    tell a skipped socket from a touched-then-swallowed one. The test asserts it was never touched."""

    def __init__(self):
        self.evals = 0

    def eval(self, *a, **k):
        self.evals += 1
        return [1, 4, str(int(time.time()) + 10)]  # allowed, remaining, reset_at


def test_no_foreground_caller_touches_the_socket_while_the_breaker_is_open():
    # Open the breaker directly (no probe thread needed for this check).
    with R._cb_lock:
        R._cb_open = True
    try:
        fake = _RecordingRedis()
        rl = R.RateLimiter(fake)
        # Fail-open traffic is allowed without touching the socket ...
        allowed, remaining, reset = rl._sliding_window_check("k", 5, 10, fail_open=True)
        assert allowed is True
        # ... and fail-closed (auth) traffic drops to its fallback (a raise), also no socket.
        with pytest.raises(R.RateLimiterUnavailable):
            rl._sliding_window_check("k", 5, 10, fail_open=False)
        assert fake.evals == 0, "the foreground path hit Redis while the breaker was open"
    finally:
        R._cb_record_success()


def test_a_probe_attempt_failure_keeps_the_breaker_open(monkeypatch):
    with R._cb_lock:
        R._cb_open = True
    monkeypatch.setattr(R, "_cb_ping", _raise_down)
    assert R._cb_probe_attempt() is False
    assert R._cb_open is True                       # a failed probe never closes the breaker


def test_a_probe_attempt_success_closes_the_breaker(monkeypatch):
    with R._cb_lock:
        R._cb_open = True
    monkeypatch.setattr(R, "_cb_ping", lambda: None)
    assert R._cb_probe_attempt() is True
    assert R._cb_open is False


def test_opening_starts_one_background_probe_that_closes_on_recovery(monkeypatch):
    # Drive the loop without real time (no-op inter-attempt wait), and hold the ping on an Event so
    # the probe is observably in flight. A second open must not start a second probe; when Redis
    # recovers the ping returns, the probe closes the breaker and the thread exits.
    started = threading.Event()
    release = threading.Event()
    pings = []

    def _blocking_ping():
        pings.append(threading.current_thread().name)
        started.set()
        assert release.wait(5), "probe ping was never released"
        # returning (no raise) means Redis is healthy

    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", _blocking_ping)

    R._cb_record_failure(time.time())               # opens the breaker and starts the probe
    assert R._cb_is_open(time.time()) is True
    assert started.wait(5), "the background probe never ran"
    first = R._cb_probe_thread
    assert first is not None and first.is_alive() and first.name == "redis-cb-probe"

    R._cb_record_failure(time.time())               # a second open must not start a second probe
    assert R._cb_probe_thread is first

    release.set()
    first.join(timeout=5)
    assert not first.is_alive()
    assert R._cb_open is False                       # the probe's success closed it
    assert len(pings) == 1                           # exactly one probe ran


def test_a_closed_breaker_reports_not_open():
    R._cb_record_success()
    assert R._cb_is_open(time.time()) is False
    assert R.redis_circuit_open() is False
