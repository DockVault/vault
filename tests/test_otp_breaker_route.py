"""The OTP store routes straight to its durable DB path while the breaker is open.

otp_service already fails closed with a DB fallback, but the issue path touched Redis up to three
times (delete, put, rollback delete) and verify once, so a step-up prompt during a Redis outage was a
multi-second on-loop stall. Consulting the breaker at the single choke point _resolve_redis -- return
None when open -- makes issue/verify/invalidate skip their Redis branches (each guards on `redis is
not None`) and use the DB, with no socket touched.
"""
import time

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import otp_service
from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset():
    R._cb_record_success()
    with R._cb_lock:
        R._cb_probe_thread = None
        R._cb_last_attempt_at = R._cb_monotonic()
    yield
    R._cb_record_success()


def test_resolve_redis_returns_none_while_the_breaker_is_open():
    R._cb_record_failure(time.time())
    # Even an explicitly passed client is dropped to None -> the caller uses its DB path, no socket.
    assert otp_service._resolve_redis(object()) is None


def test_resolve_redis_returns_the_client_when_healthy():
    sentinel = object()
    assert otp_service._resolve_redis(sentinel) is sentinel


class _RecordingRedis:
    # Records touches (a raise would be swallowed by _redis_load's except and hide a real touch).
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def _rec(*a, **k):
            self.calls.append(name)
            return None
        return _rec


class _FakeQuery:
    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def first(self):
        return None


class _FakeDB:
    def query(self, *a, **k):
        return _FakeQuery()

    def execute(self, *a, **k):
        return None

    def commit(self):
        pass


def test_verify_uses_the_db_and_never_touches_the_socket_while_open():
    R._cb_record_failure(time.time())
    tripwire = _RecordingRedis()
    result = otp_service.verify(_FakeDB(), purpose="login", user_id=1, code="000000", redis=tripwire)
    assert result.ok is False           # no DB row + Redis skipped -> not found
    assert tripwire.calls == []          # the socket was never touched while open
