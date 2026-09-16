"""The security monitor's threshold alert publish goes through the read-through cache guard.

The monitor's windowed counter already skips the socket when the rate limiter's breaker is open, so
it does not stall the loop during an outage. The one Redis op that was NOT breaker-aware is the
threshold alert broadcast (_broadcast_alert publishes to a pub/sub channel). During an outage that
publish must skip the socket when the shared guard is open, and on a failure with the guard closed it
must open the guard's PRIVATE memory so the next publish in the cooldown skips too — WITHOUT writing
the rate limiter's breaker (a monitor alert must not fail the general-API limiter open).

Pure unit test with a fake Redis. On the earlier code the publish was a bare try/except that recorded
nothing, so the private memory never opened after a failure — the second assertion goes red.
"""
import time

import pytest

from app.services import auth_service as A
from app.core import rate_limiter as R
from app.services.security_monitor import SecurityMonitor


pytestmark = pytest.mark.unit


class _FakeRedis:
    def __init__(self, fail):
        self.fail = fail
        self.publish_calls = 0
        self.incrby_calls = 0

    def publish(self, *a, **k):
        self.publish_calls += 1
        if self.fail:
            raise RuntimeError("simulated monitor publish failure")
        return 1

    def incrby(self, *a, **k):
        self.incrby_calls += 1
        if self.fail:
            raise RuntimeError("simulated monitor counter failure")
        return 1

    def expire(self, *a, **k):
        return True


class _FakeAlert:
    id = "alert-1"
    event_type = "x"
    severity = "warning"
    message = "m"
    username = "u"
    ip_address = "203.0.113.9"
    details = {}

    class _TS:
        @staticmethod
        def isoformat():
            return "2026-09-16T00:00:00+00:00"

    timestamp = _TS()


def _monitor(fail):
    mon = SecurityMonitor.__new__(SecurityMonitor)  # bypass __init__: exercise only _broadcast_alert
    mon.redis = _FakeRedis(fail)
    return mon


def test_a_failed_alert_publish_leaves_the_limiter_breaker_closed_and_opens_the_guard():
    R._cb_record_success()
    A._cache_guard_record_success()
    assert not R._cb_is_open(time.time())

    mon = _monitor(fail=True)
    mon._broadcast_alert(_FakeAlert())  # swallows its own error after recording

    assert not R._cb_is_open(time.time()), (
        "a security-monitor alert publish failure opened the shared rate-limiter breaker")
    assert A._cache_guard_is_open(time.time()), (
        "the monitor did not open the private cache guard after its alert publish failed")

    A._cache_guard_record_success()


def test_an_alert_publish_skips_the_socket_while_the_guard_is_open():
    R._cb_record_success()
    A._cache_guard_record_success()
    A._cache_guard_record_failure(time.time())  # guard open from a prior outage

    mon = _monitor(fail=False)
    mon._broadcast_alert(_FakeAlert())

    assert mon.redis.publish_calls == 0, (
        "the monitor published while the guard was open — it should have skipped the socket")

    A._cache_guard_record_success()


def _counter_monitor(fail):
    from collections import deque
    mon = SecurityMonitor.__new__(SecurityMonitor)  # bypass __init__: exercise only _windowed_count
    mon.redis = _FakeRedis(fail)
    mon._signal_detection_degraded = lambda: None
    mon._count_recent_events = lambda dq, w: 99  # sentinel fallback value
    mon._fallback = deque()
    return mon


def test_the_counter_skips_the_socket_while_the_guard_is_open():
    from collections import deque
    R._cb_record_success()
    A._cache_guard_record_success()
    A._cache_guard_record_failure(time.time())  # guard OPEN from a prior outage
    mon = _counter_monitor(fail=False)
    result = mon._windowed_count("security:failed_login:probe", 600, deque())
    assert mon.redis.incrby_calls == 0, "the counter hit Redis while the guard was open"
    assert result == 99, "the counter did not use its in-memory fallback while the guard was open"
    A._cache_guard_record_success()


def test_a_failed_counter_op_leaves_the_limiter_breaker_closed_and_opens_the_guard():
    from collections import deque
    R._cb_record_success()
    A._cache_guard_record_success()
    assert not R._cb_is_open(time.time())
    mon = _counter_monitor(fail=True)
    result = mon._windowed_count("security:failed_login:probe", 600, deque())
    assert not R._cb_is_open(time.time()), (
        "a security-monitor counter failure opened the SHARED rate-limiter breaker")
    assert A._cache_guard_is_open(time.time()), (
        "the counter did not open the private cache guard after its Redis op failed — the boundary "
        "request would stall again")
    assert result == 99
    A._cache_guard_record_success()
