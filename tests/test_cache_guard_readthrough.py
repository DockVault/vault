"""A failed best-effort Redis op on the auth path must NOT open the shared rate-limiter breaker.

The auth path's best-effort Redis touches — the session-cache writes, the per-request denylist read,
the logout denylist write, and the activity/telemetry publish — skip the socket while the rate
limiter's breaker is open, so during an outage they pay one stall per cooldown instead of one per
call. The subtlety this pins: they read the limiter's breaker but must NEVER write it. Its fail
threshold is 1 and the general-API limiter is fail-open, so if a single transient error on one of
these could open that breaker it would disable rate limiting for every fail-open caller for the whole
cooldown — a brute-force window opened by one unrelated hiccup.

So for EACH consumer: one op fails with the limiter breaker closed; the breaker must stay CLOSED and
the guard's OWN private failure memory must open. The test is parametrized over all three read-through
consumers so a design that writes the shared breaker in any one of them goes red.
"""
import os
import time

import pytest

# Dummy connection strings so importing the API module for _guarded_publish is side-effect-free.
for _k, _v in {
    "DATABASE_URL": "postgresql://x:x@localhost:5432/x",
    "REDIS_URL": "redis://localhost:6379/0",
    "SECRET_KEY": "t" * 32,
    "JWT_SECRET_KEY": "t" * 32,
}.items():
    os.environ.setdefault(_k, _v)

from app.services import auth_service as A
from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


class _RaisingRedis:
    """A Redis stand-in whose every op raises, to fault the consumer's socket call."""

    def exists(self, *a, **k):
        raise RuntimeError("simulated Redis failure")

    def publish(self, *a, **k):
        raise RuntimeError("simulated Redis failure")

    def setex(self, *a, **k):
        raise RuntimeError("simulated Redis failure")


def _fail_best_effort_cache(monkeypatch):
    A._best_effort_cache("test.cache", lambda: (_ for _ in ()).throw(RuntimeError("boom")))


def _fail_denylist_read(monkeypatch):
    monkeypatch.setattr(A, "redis_client", _RaisingRedis())
    A.is_token_denylisted("some-session-token")


def _fail_denylist_write(monkeypatch):
    monkeypatch.setattr(A, "redis_client", _RaisingRedis())
    A.denylist_token("some-session-token", 60)


def _fail_guarded_publish(monkeypatch):
    import app.core.database as dbmod
    monkeypatch.setattr(dbmod, "redis_client", _RaisingRedis())
    import app.api.api_server as S
    try:
        S._guarded_publish("activity_events", "{}")  # re-raises after recording; swallow it here
    except Exception:
        pass


_CONSUMERS = [
    ("best_effort_cache", _fail_best_effort_cache),
    ("denylist_read", _fail_denylist_read),
    ("denylist_write", _fail_denylist_write),
    ("guarded_publish", _fail_guarded_publish),
]


@pytest.mark.parametrize("name,trigger", _CONSUMERS)
def test_a_failed_auth_path_redis_op_never_writes_the_shared_breaker(name, trigger, monkeypatch):
    R._cb_record_success()
    A._cache_guard_record_success()
    assert not R._cb_is_open(time.time())

    trigger(monkeypatch)

    assert not R._cb_is_open(time.time()), (
        f"{name} opened the SHARED rate-limiter breaker on a Redis failure — the general-API limiter "
        f"would fail open for the cooldown on one unrelated hiccup")
    assert A._cache_guard_is_open(time.time()), (
        f"{name} did not open the private cache guard after its Redis op failed — repeated ops would "
        f"each stall")

    A._cache_guard_record_success()


class _ExplodingRedis:
    """Every op raises AssertionError — proves the caller did NOT touch the socket."""

    def exists(self, *a, **k):
        raise AssertionError("touched Redis while the guard was open")

    def setex(self, *a, **k):
        raise AssertionError("touched Redis while the guard was open")


def _skip_denylist_read(monkeypatch):
    monkeypatch.setattr(A, "redis_client", _ExplodingRedis())
    assert A.is_token_denylisted("some-session-token") is False  # fails open, no socket


def _skip_denylist_write(monkeypatch):
    monkeypatch.setattr(A, "redis_client", _ExplodingRedis())
    A.denylist_token("some-session-token", 60)  # returns without a socket


@pytest.mark.parametrize("name,op", [
    ("denylist_read", _skip_denylist_read),
    ("denylist_write", _skip_denylist_write),
])
def test_an_open_guard_skips_the_socket(name, op, monkeypatch):
    # With the guard open, these best-effort ops must skip Redis entirely — not stall a timeout per
    # call during an outage. The exploding stub turns any socket touch into a failure. Removing the
    # `if _cache_guard_*` skip in the consumer makes it touch the stub and go red.
    R._cb_record_success()
    A._cache_guard_record_success()
    A._cache_guard_record_failure(time.time())  # guard OPEN (private memory)
    op(monkeypatch)  # must not raise
    A._cache_guard_record_success()


def test_the_guard_reads_the_limiter_breaker_but_a_success_does_not_close_it():
    # A success clears only the guard's private memory; it must never reach in and close a breaker the
    # LIMITER opened (which would cost the limiter a fresh stall on its next call).
    R._cb_record_success()
    A._cache_guard_record_success()

    R._cb_record_failure(time.time())  # limiter opens its own breaker (an outage it saw)
    assert R._cb_is_open(time.time())
    assert A._cache_guard_is_open(time.time())  # the guard reads as open too, so cache ops skip

    A._cache_guard_record_success()  # a cache success clears private memory only
    assert R._cb_is_open(time.time()), (
        "a cache success closed the limiter's breaker — the guard must only read it, never write it")

    R._cb_record_success()
    A._cache_guard_record_success()
