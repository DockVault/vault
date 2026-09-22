"""The Live Monitor activity feed and progress tracker skip the socket while Redis looks down.

Every Redis touch in activity_monitor is on the event loop (the broadcaster runs on the request path;
the progress tracker on transfer paths and the WebSocket poller). They are best-effort, so during an
outage they go through the read-through guard: while the breaker (or the shared private memory) is
open they skip the socket entirely and return safe defaults, instead of each paying a socket timeout
on the loop.
"""
import time

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.services.activity_monitor import ActivityBroadcaster, ProgressTracker
from app.core import rate_limiter as R
from app.core import redis_guard as G

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


class _RecordingRedis:
    def __init__(self):
        self.calls = []

    def publish(self, *a, **k):
        self.calls.append("publish")
        return 1

    def setex(self, *a, **k):
        self.calls.append("setex")
        return True

    def get(self, *a, **k):
        self.calls.append("get")
        return None

    def eval(self, *a, **k):
        self.calls.append("eval")
        return None


def _open_breaker():
    R._cb_record_failure(time.time())


def test_broadcast_skips_the_socket_while_the_breaker_is_open():
    fake = _RecordingRedis()
    _open_breaker()
    ActivityBroadcaster(fake).broadcast_sync({"type": "x"})
    assert fake.calls == []                     # no publish on the loop during the outage


def test_broadcast_publishes_when_redis_is_healthy():
    fake = _RecordingRedis()
    ActivityBroadcaster(fake).broadcast_sync({"type": "x"})
    assert fake.calls == ["publish"]


def test_tracker_ops_skip_and_return_safe_defaults_while_open():
    fake = _RecordingRedis()
    tracker = ProgressTracker(fake)
    _open_breaker()
    assert tracker.is_cancelled("op1") is False          # not cancelled (safe default), no get
    assert tracker.complete_operation("op1") is None      # no eval
    assert tracker.cancel_operation("op1", is_admin=True) is False
    tracker.start_operation("op1", 1, "u", "upload", "f", 10)  # no setex, no broadcast
    assert fake.calls == []                               # nothing touched the socket while open


def test_tracker_touches_redis_when_healthy():
    fake = _RecordingRedis()
    tracker = ProgressTracker(fake)
    tracker.is_cancelled("op1")
    assert "get" in fake.calls
