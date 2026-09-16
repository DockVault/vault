"""The anonymous-surface lockouts fail CLOSED before the socket while the breaker is open.

Note-link, public-link (and its single-use download grant) and receiver redeems are anonymous read
paths, so the failed-secret lockout is the ONLY throttle a secret-guesser meets. If a lockout check
returned "not locked" during a Redis outage, an attacker could guess unthrottled -- a HIGH on the
enumeration lens. So each check raises (caller -> 503) or returns the LOCKED / absent value while the
breaker is open, and BEFORE touching the socket (no on-loop stall). This pins the fail-closed value
per site, and that the guard short-circuits before any Redis access.
"""
import time

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S
from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


class _NeverTouchedRedis:
    """Its methods must never be called while the breaker is open (that would be an on-loop stall)."""
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def _rec(*a, **k):
            self.calls.append(name)
            raise AssertionError(f"touched Redis ({name}) while the breaker was open")
        return _rec


@pytest.fixture(autouse=True)
def _open_breaker_with_a_tripwire_redis(monkeypatch):
    R._cb_record_success()
    with R._cb_lock:
        R._cb_probe_thread = None
        R._cb_last_attempt_at = time.time()
    # Point the lockout helpers' client at a tripwire, then open the breaker: a correct guard never
    # reaches the client.
    fake = _NeverTouchedRedis()
    monkeypatch.setattr(R.rate_limiter, "redis", fake, raising=False)
    R._cb_record_failure(time.time())
    yield fake
    R._cb_record_success()


def test_notelink_lockout_stays_locked_and_off_the_socket_while_open(_open_breaker_with_a_tripwire_redis):
    with pytest.raises(RuntimeError):
        S._notelink_locked("tok")                       # 503, never "not locked"
    assert S._notelink_record_fail("tok") == S._NOTELINK_FAIL_MAX   # counts as locked
    S._notelink_clear_fails("tok")                      # skip (no raise, no socket)
    assert _open_breaker_with_a_tripwire_redis.calls == []


def test_publiclink_lockout_and_grant_fail_closed_off_the_socket_while_open(_open_breaker_with_a_tripwire_redis):
    with pytest.raises(RuntimeError):
        S._publiclink_locked("h")
    assert S._publiclink_record_fail("h") == S._PUBLINK_FAIL_MAX
    S._publiclink_clear_fails("h")
    with pytest.raises(RuntimeError):
        S._publiclink_issue_grant("lid", "192.0.2.10")     # a grant that can't be stored is never issued
    assert S._publiclink_consume_grant("g", "lid", "192.0.2.10") is False   # uniform 404
    assert _open_breaker_with_a_tripwire_redis.calls == []


def test_receiver_lockout_fails_closed_off_the_socket_while_open(_open_breaker_with_a_tripwire_redis):
    with pytest.raises(RuntimeError):
        S._receiver_locked("h")
    assert S._receiver_record_fail("h") == S._RECV_FAIL_MAX
    S._receiver_clear_fails("h")
    assert _open_breaker_with_a_tripwire_redis.calls == []
