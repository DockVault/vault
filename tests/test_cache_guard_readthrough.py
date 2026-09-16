"""A failed best-effort session-cache op must NOT open the shared rate-limiter breaker.

The auth path's best-effort cache writes and the per-request denylist read skip Redis while the rate
limiter's breaker is open, so during an outage they pay one stall per cooldown instead of one per
call. The subtlety this pins: they read the limiter's breaker but must NEVER write it. The limiter's
breaker has a fail threshold of 1 and the general-API limiter is fail-open, so if a single transient
cache-write error on an otherwise-healthy Redis could open that breaker, it would disable rate
limiting for every fail-open caller for the whole cooldown — a brute-force window opened by one
unrelated cache hiccup.

So: one cache op fails; the limiter's breaker must stay CLOSED (unrelated login/general-API throttles
keep working), while the guard's OWN private failure memory opens so the next cache op skips the
socket. On the earlier design, where the cache op wrote the shared breaker, the first assertion goes
red — the breaker opens.
"""
import time

import pytest

from app.services import auth_service as A
from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


def _raises(exc=RuntimeError("simulated cache write failure")):
    def op():
        raise exc
    return op


def test_a_failed_cache_op_leaves_the_shared_limiter_breaker_closed():
    # Start from a clean slate: shared breaker closed, private guard memory clear.
    R._cb_record_success()
    A._cache_guard_record_success()
    assert not R._cb_is_open(time.time())
    assert not A._cache_guard_is_open(time.time())

    # One best-effort cache op fails while Redis is otherwise healthy (the breaker was closed, so the
    # op actually ran and raised — this is the "fault one setex" case, not an outage).
    A._best_effort_cache("test.session.cache.skipped", _raises())

    # The SHARED limiter breaker must NOT have opened — the general-API / login throttles that read
    # it must keep working. This is the assertion that goes red on a design that writes the shared
    # breaker from the cache path.
    assert not R._cb_is_open(time.time()), (
        "a best-effort cache failure opened the SHARED rate-limiter breaker — the general-API "
        "limiter would fail open for the cooldown on one unrelated cache hiccup")

    # But the guard's OWN memory tripped, so the next cache op in the cooldown skips the socket.
    assert A._cache_guard_is_open(time.time()), (
        "the private cache guard did not open after a failure — repeated cache ops would each stall")

    # Clean up so the private memory does not leak into other unit tests.
    A._cache_guard_record_success()


def test_the_guard_reads_the_limiter_breaker_but_a_success_does_not_close_it():
    # A cache SUCCESS clears only the guard's private memory; it must never reach in and close a
    # breaker the LIMITER opened (which would cost the limiter a fresh stall on its next call).
    R._cb_record_success()
    A._cache_guard_record_success()

    # Limiter opens its breaker (an outage it saw on its own Redis call).
    R._cb_record_failure(time.time())
    assert R._cb_is_open(time.time())
    # While the limiter's breaker is open the guard reads as open too, so cache ops skip.
    assert A._cache_guard_is_open(time.time())

    # A cache success clears the guard's private memory but leaves the limiter's breaker alone.
    A._cache_guard_record_success()
    assert R._cb_is_open(time.time()), (
        "a cache success closed the limiter's breaker — the guard must only read it, never write it")

    # Tidy up.
    R._cb_record_success()
    A._cache_guard_record_success()
