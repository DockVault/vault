"""The two remaining outage stalls are instrumented and the health tick no longer freezes the loop.

(a) The general-API middleware's sliding-window eval -- the per-request Redis touch that pays the
discovery stall during an outage -- now runs through the slow-op instrument, so a slow one is logged
by function (never the key). (b) /health is on a 30 s cadence and is excluded from the rate-limit
middleware, so nothing consulted the breaker there; a bare ping on the main client froze the loop for
its 2 s timeout once per tick. It now reports 'disconnected' with no socket while the breaker is open,
and otherwise probes off the loop on the short-timeout client.
"""
import asyncio
import logging
import threading
import time

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

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


class _SlowEvalRedis:
    def eval(self, *a, **k):
        return [1, 4, str(int(time.time()) + 10)]  # allowed, remaining, reset_at


def test_a_slow_limiter_eval_logs_the_warning_naming_the_function_not_the_key(caplog, monkeypatch):
    # Force the elapsed measurement over the threshold without real time (timed_redis reads
    # redis_guard.time.monotonic twice, around the eval).
    ticks = iter([100.0, 100.0 + G.SLOW_REDIS_OP_SECONDS + 0.2])
    monkeypatch.setattr(G.time, "monotonic", lambda: next(ticks))
    rl = R.RateLimiter(_SlowEvalRedis())
    with caplog.at_level(logging.WARNING, logger="app.core.redis_guard"):
        rl._sliding_window_check("secret-key:user:42", 5, 10, fail_open=True)
    msgs = " ".join(r.getMessage() for r in caplog.records)
    assert "RateLimiter._sliding_window_check" in msgs      # the path is named
    assert "secret-key" not in msgs and "user:42" not in msgs  # the key is never logged


def _run_coro_on_own_thread(coro_factory):
    """Run an async callable on a FRESH event loop in ITS OWN THREAD and return its result.

    Never asyncio.run()/get_event_loop().run_until_complete() in the test body: the full suite runs
    under Playwright's already-running loop, where asyncio.run() raises "cannot be called from a
    running event loop" (the offline lane, with no such loop, does not show it). This mirrors
    _drive_login in test_login_handler_helpers.py."""
    out = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            out["result"] = loop.run_until_complete(coro_factory())
        except BaseException as exc:  # noqa: BLE001 — re-raised on the test thread below
            out["error"] = exc
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join(30)
    assert not t.is_alive(), "the health coroutine did not finish"
    if "error" in out:
        raise out["error"]
    return out["result"]


def test_health_reports_redis_disconnected_without_a_socket_while_the_breaker_is_open(monkeypatch):
    import app.api.api_server as S
    import app.core.health as H

    probe_calls = []

    def _tripwire(*a, **k):
        probe_calls.append("probe")
        raise AssertionError("health pinged Redis while the breaker was open")

    monkeypatch.setattr(S, "redis_probe_ping", _tripwire)
    monkeypatch.setattr(S, "check_db_connection", lambda: True)
    monkeypatch.setattr(H, "check_sftp_status", lambda: "disabled")
    monkeypatch.setattr(H, "check_storage_status", lambda: "writable")
    monkeypatch.setattr(H, "check_schema_state", lambda: "complete")

    R._cb_record_failure(time.time())          # breaker open
    body = _run_coro_on_own_thread(S.health_check)

    assert body["redis"] == "disconnected"      # honest report, no richer
    assert probe_calls == []                     # the socket was never touched on the loop
