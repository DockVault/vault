"""A session force-close publish honours ONLY the private cache-failure memory, never the limiter.

A revocation's live teardown signal must still fire when the rate limiter's breaker is open — a
limiter-only blip must not suppress the SFTP/WebSocket force-close of a revoked session — yet during a
REAL cache outage N revocations must pay ONE stall, not one per session. So the force-close publish
reads the guard's PRIVATE failure memory (a cache op that actually failed inside the cooldown) and
never the limiter's breaker.

Two invariants: with the limiter's breaker open and Redis healthy the publish still fires (a revert to
the read-through shape, which also checks the limiter's breaker, would skip it — red); with Redis
failing, the first revocation attempts and the rest skip (a revert to a raw publish attempts every
one — red).
"""
import os
import time

import pytest

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


class _CountingRedis:
    def __init__(self, fail):
        self.fail = fail
        self.publish_calls = 0

    def publish(self, *a, **k):
        self.publish_calls += 1
        if self.fail:
            raise RuntimeError("simulated Redis outage")
        return 1


def _force_publish():
    import app.api.api_server as S
    return S._guarded_publish_force


def test_force_close_still_fires_when_only_the_limiter_breaker_is_open(monkeypatch):
    R._cb_record_success()
    A._cache_guard_record_success()
    R._cb_record_failure(time.time())  # limiter breaker OPEN; the private memory stays clear
    assert R._cb_is_open(time.time())

    fake = _CountingRedis(fail=False)
    import app.core.database as dbmod
    monkeypatch.setattr(dbmod, "redis_client", fake)

    sent = _force_publish()("session_terminations", "{}")
    assert sent is True and fake.publish_calls == 1, (
        "the force-close publish was suppressed by the limiter's breaker — a limiter-only blip must "
        "not stop a revoked session's live teardown")

    R._cb_record_success()
    A._cache_guard_record_success()


def test_a_real_outage_makes_n_revocations_pay_one_stall_not_n(monkeypatch):
    R._cb_record_success()
    A._cache_guard_record_success()

    fake = _CountingRedis(fail=True)  # Redis is down
    import app.core.database as dbmod
    monkeypatch.setattr(dbmod, "redis_client", fake)

    force = _force_publish()
    # The first revocation attempts the socket (and fails), opening the private memory.
    with pytest.raises(Exception):
        force("session_terminations", "{}")
    assert fake.publish_calls == 1

    # Every further revocation in the cooldown skips the socket — no repeated stall.
    for _ in range(5):
        assert force("session_terminations", "{}") is False
    assert fake.publish_calls == 1, (
        f"a real outage stalled on every revocation ({fake.publish_calls} attempts) — they must pay "
        f"one stall, not one per session")

    A._cache_guard_record_success()
