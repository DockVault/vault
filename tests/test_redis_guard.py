"""The shared read-through guard and the slow-op instrument for on-loop Redis touches.

The guard skips a best-effort Redis op while Redis looks down (the limiter's breaker is open, or the
guard's own private memory is inside its cooldown), reads the breaker but NEVER writes it, and shares
one private memory with the auth-path cache guard. The instrument warns (function + elapsed, never
the key) when an on-loop op runs long, so a paused-Redis measurement can be pinned to its path.
"""
import logging
import time

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import redis_guard as G
from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset():
    R._cb_record_success()
    G.guard_record_success()
    with R._cb_lock:
        R._cb_probe_thread = None
        R._cb_last_attempt_at = R._cb_monotonic()
    yield
    R._cb_record_success()
    G.guard_record_success()


def test_timed_redis_warns_on_a_slow_op_naming_the_function_not_the_key(caplog, monkeypatch):
    # Force the elapsed measurement over the threshold without real time.
    ticks = iter([100.0, 100.0 + G.SLOW_REDIS_OP_SECONDS + 0.2])
    monkeypatch.setattr(G.time, "monotonic", lambda: next(ticks))
    with caplog.at_level(logging.WARNING, logger="app.core.redis_guard"):
        out = G.timed_redis("MyThing.touch", lambda: "value-for-key:secret-token")
    assert out == "value-for-key:secret-token"
    msgs = " ".join(r.getMessage() for r in caplog.records)
    assert "MyThing.touch" in msgs and "secret-token" not in msgs   # function named, key never logged


def test_timed_redis_does_not_warn_on_a_fast_op(caplog):
    with caplog.at_level(logging.WARNING, logger="app.core.redis_guard"):
        assert G.timed_redis("MyThing.touch", lambda: 7) == 7
    assert not caplog.records


def test_best_effort_skips_the_socket_while_the_guard_is_open():
    R._cb_record_failure(time.time())          # breaker open -> guard open
    touched = []
    result = G.best_effort("X.op", lambda: touched.append(1) or "ran", default="skipped")
    assert result == "skipped" and touched == []   # op never called


def test_required_skips_the_socket_while_the_guard_is_open_and_says_so():
    R._cb_record_failure(time.time())          # breaker open -> guard open
    touched = []
    with pytest.raises(G.Skipped):
        G.required("X.op", lambda: touched.append(1))
    assert touched == []


def test_required_takes_only_redis_being_away_for_an_outage():
    """The stores behind this call are reached by anyone (a sign-in code, a login state). A failure that is not
    Redis being away, such as a value the client cannot write as bytes, raised before Redis is asked at all, or an
    answer Redis gave, is raised and opens nothing: one such request must not close every store for a while.
    Redis being away (its connection, its timeout, by the built-in errors or the client library's) opens it."""
    from redis import exceptions as redis_errors
    not_an_outage = [UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"), ValueError("no"),
                     TypeError("no"), redis_errors.ResponseError("WRONGTYPE"), redis_errors.DataError("no")]
    for error in not_an_outage:
        def fails(error=error):
            raise error
        with pytest.raises(type(error)):
            G.required("X.op", fails)
        assert not G.guard_private_open(time.time()), type(error).__name__
        assert G.required("X.op", lambda: "ran") == "ran"
    an_outage = [ConnectionError("down"), ConnectionRefusedError("down"), TimeoutError("slow"), OSError("down"),
                 redis_errors.ConnectionError("down"), redis_errors.TimeoutError("slow"),
                 redis_errors.BusyLoadingError("loading")]
    for error in an_outage:
        def away(error=error):
            raise error
        with pytest.raises(type(error)):
            G.required("X.op", away)
        assert G.guard_private_open(time.time()), type(error).__name__
        with pytest.raises(G.Skipped):
            G.required("X.op", lambda: "ran")
        G.guard_record_success()


def test_required_raises_the_ops_own_failure_and_remembers_it_then_forgets_on_a_success():
    def down():
        raise ConnectionError("down")
    with pytest.raises(ConnectionError):
        G.required("X.op", down)
    assert G.guard_private_open(time.time())
    assert not R._cb_is_open(time.time())      # the limiter's breaker is read, never written
    G.guard_record_success()
    assert G.required("X.op", lambda: "ran") == "ran"
    assert not G.guard_private_open(time.time())


def test_best_effort_runs_and_returns_the_result_when_closed():
    assert G.best_effort("X.op", lambda: "ran", default=None) == "ran"


def test_best_effort_swallows_a_failure_opens_private_memory_and_returns_default():
    def _boom():
        raise RuntimeError("redis down")
    assert G.best_effort("X.op", _boom, default="fallback") == "fallback"
    assert G.guard_private_open(time.time()) is True      # its own memory opened
    # A second op now skips (guard open) without touching the socket.
    touched = []
    assert G.best_effort("X.op", lambda: touched.append(1), default="skipped") == "skipped"
    assert touched == []


def test_the_guard_reads_the_breaker_but_never_writes_it():
    # Breaker open -> guard open (reads it).
    R._cb_record_failure(time.time())
    assert G.guard_is_open(time.time()) is True
    R._cb_record_success()
    # A best-effort failure opens the guard's private memory but must NOT open the breaker.
    def _boom():
        raise RuntimeError("redis down")
    G.best_effort("X.op", _boom, default=None)
    assert G.guard_private_open(time.time()) is True
    assert R._cb_is_open(time.time()) is False            # the shared breaker stayed closed
