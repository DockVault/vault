"""The vault-password attempt counter: fail-closed, failure-only, Redis with a DB fallback.

The (vault, account) wrong-attempt counter runs synchronously on the loop at three sites (the vault
gate, the device-grant proof, the temp-credential mint proof). During a Redis outage it must NOT skip
-- skipping would leave vault-password guessing unthrottled -- so while the breaker is open it uses
the durable DB fallback WITHOUT touching the socket (no stall), and if the DB is unreachable too it
fails closed (reports over-limit). Only a wrong attempt burns (failure-only), and a Redis error opens
the guard's private memory, never the limiter's breaker.
"""
import time

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import vault_attempt_throttle as V
from app.core import rate_limiter as R
from app.core import redis_guard as G

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset():
    R._cb_record_success()
    G.guard_record_success()
    with R._cb_lock:
        R._cb_probe_thread = None
        R._cb_last_attempt_at = time.time()
    yield
    R._cb_record_success()
    G.guard_record_success()


class _FakeRedis:
    def __init__(self, count=None, fail=False):
        self.count = count
        self.fail = fail
        self.calls = []

    def get(self, key):
        self.calls.append("get")
        if self.fail:
            raise RuntimeError("redis down")
        return str(self.count) if self.count is not None else None

    def pipeline(self):
        return _FakePipe(self)


class _FakePipe:
    def __init__(self, redis):
        self.redis = redis

    def incr(self, key):
        self.redis.calls.append("incr")
        return self

    def expire(self, key, window):
        self.redis.calls.append("expire")
        return self

    def execute(self):
        if self.redis.fail:
            raise RuntimeError("redis down")
        self.redis.calls.append("execute")


def test_over_limit_reads_redis_when_healthy(monkeypatch):
    fake = _FakeRedis(count=3)
    monkeypatch.setattr(V, "redis_client", fake)
    assert V.over_limit("k", 5, 60) is False       # 3 < 5
    assert V.over_limit("k", 3, 60) is True         # 3 >= 3
    assert "get" in fake.calls


def test_burn_increments_redis_when_healthy(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(V, "redis_client", fake)
    V.burn("k", 60)
    assert fake.calls == ["incr", "expire", "execute"]


def test_over_limit_uses_the_db_without_touching_the_socket_while_the_breaker_is_open(monkeypatch):
    # The reviewer's pin: breaker open + at the limit -> refuse, with NO Redis stall.
    fake = _FakeRedis(count=999)               # would say over-limit if consulted
    monkeypatch.setattr(V, "redis_client", fake)
    monkeypatch.setattr(V, "_db_count", lambda rate_key, window: 5)
    R._cb_record_failure(time.time())          # breaker open -> guard open
    assert V.over_limit("k", 5, 60) is True    # decided by the DB (5 >= 5)
    assert fake.calls == []                    # never touched the socket -> no stall


def test_burn_uses_the_db_without_touching_the_socket_while_the_breaker_is_open(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(V, "redis_client", fake)
    burned = {"n": 0}
    monkeypatch.setattr(V, "_db_burn", lambda rate_key, window: burned.__setitem__("n", burned["n"] + 1))
    R._cb_record_failure(time.time())
    V.burn("k", 60)
    assert fake.calls == [] and burned["n"] == 1


def test_over_limit_fails_closed_when_redis_and_the_db_are_both_unavailable(monkeypatch):
    fake = _FakeRedis(fail=True)
    monkeypatch.setattr(V, "redis_client", fake)

    def _db_down(rate_key, window):
        raise RuntimeError("db down")

    monkeypatch.setattr(V, "_db_count", _db_down)
    assert V.over_limit("k", 5, 60) is True    # both down -> refuse rather than unthrottle


def test_a_redis_error_opens_the_private_memory_not_the_breaker(monkeypatch):
    fake = _FakeRedis(fail=True)
    monkeypatch.setattr(V, "redis_client", fake)
    monkeypatch.setattr(V, "_db_count", lambda rate_key, window: 0)
    V.over_limit("k", 5, 60)
    assert G.guard_private_open(time.time()) is True   # its own memory opened
    assert R._cb_is_open(time.time()) is False          # the shared breaker stayed closed
