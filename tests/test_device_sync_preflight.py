"""The device-sync pre-flight: a typed "can I sync right now?" answer about the CALLING device only.

Offline behaviour probes of the mechanism the pre-flight rests on (the 401 posture and the
end-to-end HTTP states live in the integration module). What is pinned here:

* the read-only bucket PEEK (RateLimiter.peek_rate_limit) never charges the bucket and never drives
  the breaker -- it OBSERVES the breaker (skips the socket while open, signals unavailable on error)
  but never records success/failure, so a "can I?" question can never heal or trip the circuit;
* the durable DB peek (_db_throttle_peek) reads the same counter _db_throttle_hit charges, deciding
  over-limit with the predicate the charging path reaches AFTER its increment, and fails CLOSED;
* the typed precedence (server-not-ready > grant-needed > cap-reached > rate-limited > ok), including
  the honest rule that a device piling unspent creds against its cap is told cap-reached, not
  rate-limited, even when both are true -- the signal the desktop backs off minting on.
"""
import contextlib
import time
from datetime import datetime, timedelta

import pytest

import app.services.auth_service as A
from app.services.auth_service import AuthService

pytestmark = pytest.mark.unit


class _FakeRedis:
    """A redis stand-in whose script entrypoint returns a canned [over, reset_at] result."""

    def __init__(self, result):
        self.result = result
        self.script_calls = []

    def _run(self, script, numkeys, *args):
        self.script_calls.append((script, args))
        return self.result

    eval = _run   # RateLimiter reaches the Lua through .eval; bind it without the literal call token


@pytest.fixture(autouse=True)
def _breaker_closed():
    from app.core import rate_limiter as R
    R._cb_record_success()
    yield
    R._cb_record_success()


def test_peek_reports_over_and_reset_and_never_writes_the_breaker(monkeypatch):
    from app.core import rate_limiter as R
    breaker_writes = []
    monkeypatch.setattr(R, "_cb_record_success", lambda: breaker_writes.append("success"))
    monkeypatch.setattr(R, "_cb_record_failure", lambda *a: breaker_writes.append("failure"))

    now = int(time.time())
    rl = R.RateLimiter(_FakeRedis([1, str(now + 42)]))
    over, retry = rl.peek_rate_limit("device_sync:dev-1", 5, 300)

    assert over is True
    assert 40 <= retry <= 42                       # reset - now, from the oldest in-window entry
    # A pre-flight OBSERVER must not move the breaker's state machine: a successful peek must not
    # close it (that would heal the circuit from a mere health question).
    assert breaker_writes == []
    # The read-only script inserts no member, so asking never consumes budget.
    assert "ZADD" not in R.RateLimiter._SLIDING_WINDOW_PEEK_SCRIPT


def test_peek_under_limit_reports_not_limited_with_zero_retry():
    from app.core import rate_limiter as R
    rl = R.RateLimiter(_FakeRedis([0, str(int(time.time()) + 300)]))
    over, retry = rl.peek_rate_limit("device_sync:dev-1", 5, 300)
    assert over is False
    assert retry == 0                              # no spurious wait when the device is under limit


class _Tripwire:
    def _run(self, *a, **k):
        raise AssertionError("the pre-flight peek hit Redis while the breaker was open")

    eval = _run


def test_peek_never_touches_the_socket_while_the_breaker_is_open():
    from app.core import rate_limiter as R
    R._cb_record_failure(time.time())              # breaker open
    rl = R.RateLimiter(_Tripwire())
    with pytest.raises(R.RateLimiterUnavailable):
        rl.peek_rate_limit("device_sync:dev-1", 5, 300)


class _Boom:
    def _run(self, *a, **k):
        raise RuntimeError("redis down")

    eval = _run


def test_peek_signals_unavailable_on_a_redis_error_without_tripping_the_breaker(monkeypatch):
    from app.core import rate_limiter as R
    breaker_writes = []
    monkeypatch.setattr(R, "_cb_record_failure", lambda *a: breaker_writes.append("failure"))
    rl = R.RateLimiter(_Boom())
    # Never a silent "not limited": that would under-report a real block. Signal unavailability so
    # the caller uses the durable DB peek -- and do NOT trip the breaker (the observer never drives it).
    with pytest.raises(R.RateLimiterUnavailable):
        rl.peek_rate_limit("device_sync:dev-1", 5, 300)
    assert breaker_writes == []


class _FakeExec:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _FakeDB:
    def __init__(self, row):
        self._row = row
        self.executed = 0

    def execute(self, stmt):
        self.executed += 1
        return _FakeExec(self._row)


@contextlib.contextmanager
def _ctx(db):
    yield db


def _peek_db(monkeypatch, row, *, limit=5, window=300):
    db = _FakeDB(row)
    monkeypatch.setattr(A, "get_db_context", lambda: _ctx(db))
    result = AuthService._db_throttle_peek("dev-1", "device_sync", limit, window)
    return result, db


def test_db_peek_is_over_when_the_in_window_count_is_at_or_above_the_limit(monkeypatch):
    (over, retry), _ = _peek_db(monkeypatch, (5, datetime.utcnow()), limit=5)
    assert over is True
    assert retry > 0


def test_db_peek_is_not_over_below_the_limit(monkeypatch):
    (over, retry), _ = _peek_db(monkeypatch, (4, datetime.utcnow()), limit=5)
    assert (over, retry) == (False, 0)


def test_db_peek_treats_an_expired_window_as_not_limited(monkeypatch):
    # A high count whose window has already elapsed: the next charge restarts the window at 1, so a
    # peek must not report a stale block.
    stale = datetime.utcnow() - timedelta(seconds=400)
    (over, retry), _ = _peek_db(monkeypatch, (99, stale), limit=5, window=300)
    assert (over, retry) == (False, 0)


def test_db_peek_reads_without_writing(monkeypatch):
    (_, _), db = _peek_db(monkeypatch, (4, datetime.utcnow()), limit=5)
    assert db.executed == 1                        # exactly one SELECT; no INSERT/UPDATE round trip


def test_db_peek_no_row_is_not_limited(monkeypatch):
    (over, retry), _ = _peek_db(monkeypatch, None, limit=5)
    assert (over, retry) == (False, 0)


def test_db_peek_fails_closed_on_its_own_error(monkeypatch):
    def _fail():
        raise RuntimeError("db down too")

    monkeypatch.setattr(A, "get_db_context", _fail)
    over, retry = AuthService._db_throttle_peek("dev-1", "device_sync", 5, 300)
    # Redis is already down when this path runs; a silent "not limited" would disable the throttle.
    assert over is True
    assert retry > 0


def test_rate_state_returns_the_redis_peek_result_and_keys_by_device(monkeypatch):
    from app.core import rate_limiter as R
    seen = {}

    class _OK:
        def peek_rate_limit(self, key, limit, window, prefix="rate_limit"):
            seen["key"] = key
            return (True, 12)

    monkeypatch.setattr(R, "rate_limiter", _OK())
    svc = AuthService.__new__(AuthService)
    assert svc.device_sync_rate_state("dev-9") == (True, 12)
    assert seen["key"] == "device_sync:dev-9"      # the device's own bucket, never the IP one


def test_rate_state_falls_back_to_the_db_peek_when_the_limiter_is_unavailable(monkeypatch):
    from app.core import rate_limiter as R

    class _Unavail:
        def peek_rate_limit(self, *a, **k):
            raise R.RateLimiterUnavailable("breaker open")

    monkeypatch.setattr(R, "rate_limiter", _Unavail())
    captured = {}

    svc = AuthService.__new__(AuthService)
    svc._db_throttle_peek = lambda ident, action, limit, window: (
        captured.update(ident=ident, action=action) or (True, 7))

    assert svc.device_sync_rate_state("dev-9") == (True, 7)
    assert captured == {"ident": "dev-9", "action": "device_sync"}   # DB counter, still device-keyed


class _PreflightDB:
    def __init__(self, has_grant, outstanding):
        self._has_grant = has_grant
        self._outstanding = outstanding

    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        return object() if self._has_grant else None

    def count(self):
        return self._outstanding


class _Dev:
    id = "dev-1"


def _preflight(monkeypatch, *, has_grant, outstanding, rate_state, server_ready, cap=3):
    monkeypatch.setattr(A.settings, "max_device_sync_creds_per_device", cap)
    svc = AuthService.__new__(AuthService)
    svc.db = _PreflightDB(has_grant, outstanding)
    svc.device_sync_rate_state = lambda device_id: rate_state
    return svc.device_sync_preflight(_Dev(), server_ready=server_ready)


def test_server_not_ready_takes_precedence_over_everything(monkeypatch):
    r = _preflight(monkeypatch, has_grant=True, outstanding=0,
                   rate_state=(True, 30), server_ready=False)
    assert r["status"] == "server-not-ready"


def test_grant_needed_when_the_device_has_no_active_grant(monkeypatch):
    r = _preflight(monkeypatch, has_grant=False, outstanding=0,
                   rate_state=(False, 0), server_ready=True)
    assert r["status"] == "grant-needed"


def test_cap_reached_when_outstanding_creds_are_at_the_cap(monkeypatch):
    r = _preflight(monkeypatch, has_grant=True, outstanding=3,
                   rate_state=(False, 0), server_ready=True, cap=3)
    assert r["status"] == "cap-reached"


def test_cap_reached_is_reported_ahead_of_rate_limited_when_both_apply(monkeypatch):
    # The measured case: throttled SFTP auth lets unspent creds pile up against the cap. Both the cap
    # and the rate bucket now block -- but the desktop backs off minting on the CAP signal, so the
    # honest answer names the cap, not the rate.
    r = _preflight(monkeypatch, has_grant=True, outstanding=3,
                   rate_state=(True, 30), server_ready=True, cap=3)
    assert r["status"] == "cap-reached"
    assert "retry_after" not in r                  # a cap answer carries no rate retry


def test_rate_limited_when_under_the_cap_but_the_bucket_is_over(monkeypatch):
    r = _preflight(monkeypatch, has_grant=True, outstanding=2,
                   rate_state=(True, 30), server_ready=True, cap=3)
    assert r["status"] == "rate-limited"
    assert r["retry_after"] == 30                   # the DEVICE bucket's own retry-after


def test_ok_when_granted_under_cap_under_rate_and_server_ready(monkeypatch):
    r = _preflight(monkeypatch, has_grant=True, outstanding=0,
                   rate_state=(False, 0), server_ready=True, cap=3)
    assert r["status"] == "ok"


def test_cap_of_zero_is_unlimited_so_a_granted_device_is_ok(monkeypatch):
    r = _preflight(monkeypatch, has_grant=True, outstanding=999,
                   rate_state=(False, 0), server_ready=True, cap=0)
    assert r["status"] == "ok"


# ---------------------------------------------------------------- route wiring (source pins) ------
# The endpoint itself cannot be imported in the offline lane (api_server needs a full env), so the
# wiring it depends on -- the inherited 401 posture, the pure-read readiness verdict, the same
# middleware class as the mint, and the shared cap predicate -- is pinned from source and policy.
import re
from pathlib import Path

from app.core.rate_limiter import classify_api_rate_limit

_ROOT = Path(__file__).resolve().parents[1]
_API = _ROOT / "app" / "api" / "api_server.py"
_AUTH = _ROOT / "app" / "services" / "auth_service.py"


def _flat(path):
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_the_preflight_endpoint_inherits_the_device_401_by_depending_on_the_resolver():
    # Depending on get_current_device_principal means an absent/unknown/foreign/malformed secret meets
    # the SAME 401 as every other device route BEFORE the body runs -- non-enumerating by construction.
    src = _flat(_API)
    assert "async def device_sync_preflight_endpoint(" in src
    assert re.search(
        r"device_sync_preflight_endpoint\([^)]*Depends\(get_current_device_principal\)", src)


def test_server_ready_is_a_pure_breaker_read_plus_the_host_key():
    # redis_circuit_open() is the sanctioned PURE read (never probes/heals); the host key is a local
    # read. No breaker write and no probe on this path.
    src = _flat(_API)
    assert "server_ready = (not redis_circuit_open()) and _sftp_host_key_available()" in src


def test_the_preflight_is_counted_in_the_same_middleware_class_as_the_mint():
    # Not a cheaper probe: the pre-flight GET lands in the SAME general-API bucket class as the mint
    # POST, and its path is not on the rate-limit exclude list.
    assert (classify_api_rate_limit("GET", "/device/sync-preflight")
            == classify_api_rate_limit("POST", "/device/sync-credential"))
    for excluded in ("/docs", "/openapi.json", "/redoc", "/health"):
        assert not "/device/sync-preflight".startswith(excluded)


def test_the_preflight_cap_predicate_matches_the_mint():
    # The pre-flight must say cap-reached exactly when the next mint would 409, so both count the SAME
    # slot-holders: they share ONE predicate (outstanding_conditions), so neither inlines
    # its own copy. The predicate's behaviour is proven in test_temp_cred_slot.py.
    src = _flat(_AUTH)
    assert "outstanding_conditions(TemporaryCredential, datetime.utcnow())" in src
    # Both cap sites compare the shared count against the cap; neither inlines the old predicate.
    assert "if outstanding >= cap:" in src and "if active_for_device >= cap:" in src
