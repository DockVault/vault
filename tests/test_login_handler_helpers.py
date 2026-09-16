"""Unit pins for the login handler's helpers: the 429 body/header shaping, the awaited-offloaded
failed-login record, and the metrics-free login broadcast. These are the handler-level guarantees the
general rate-limit middleware would mask on the wire (it re-stamps X-RateLimit-*), so they are pinned
here.
"""
import asyncio
import contextlib
import json
import threading

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


def _drive_login(S, body_dict, events, drain=False, done_event=None):
    """Drive POST /auth/login through the ASGI app in-process on a fresh loop in its own thread — the
    suite has no httpx/TestClient, so this speaks raw ASGI. Appends ("response", status) to the shared
    `events` list (the test's patched monitor appends its own ("record", thread) entry), so their
    ORDER is observable. Returns the loop thread's name. With drain=True and a `done_event`, waits
    deterministically for that event (set by the patched fire-and-forget broadcast) before the loop
    closes — no fixed sleep."""
    holder = {}

    async def _drive():
        holder["loop_thread"] = threading.current_thread().name
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": "/auth/login",
                 "raw_path": b"/auth/login", "query_string": b"",
                 "headers": [(b"content-type", b"application/json")],
                 "client": ("127.0.0.1", 1234), "server": ("testserver", 80), "scheme": "http"}
        payload = json.dumps(body_dict).encode()

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                events.append(("response", msg["status"]))

        await S.app(scope, receive, send)
        if drain and done_event is not None:
            # Deterministic wait (no fixed sleep): block a helper thread on the event the patched
            # broadcast sets, so the fire-and-forget broadcast is guaranteed to have run before the
            # loop closes. Bounded at 5 s so a genuine failure surfaces rather than hangs.
            await asyncio.get_running_loop().run_in_executor(None, done_event.wait, 5)

    err = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_drive())
        except BaseException as exc:  # noqa: BLE001
            err["e"] = exc
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join(30)
    assert not t.is_alive(), "the ASGI drive did not finish"
    if "e" in err:
        raise err["e"]
    return holder.get("loop_thread")


def _api():
    """Import the API module LAZILY (inside a test), never at module scope. Importing it runs the
    API bootstrap, which fails closed with SystemExit in a bare environment — that would abort strict
    COLLECTION (pytest imports every test module to collect it) before any test runs. Deferring the
    import to call time keeps collection free of the bootstrap, matching the sibling unit tests. The
    shared helper sets the minimal env the bootstrap requires so this module passes when run alone."""
    set_bare_api_env()
    import app.api.api_server as S
    return S


class _Exc(Exception):
    def __init__(self, message, limit=None, remaining=None, retry_after=None):
        super().__init__(message)
        self._message = message
        self.limit = limit
        self.remaining = remaining
        self.retry_after = retry_after

    def __str__(self):
        return self._message


@pytest.mark.parametrize("raiser_name,expected_status", [
    ("InvalidCredentialsError", 401),   # wrong password
    ("AuthRateLimitExceededError", 429),  # throttled
])
def test_a_failed_login_records_off_loop_and_before_the_response(raiser_name, expected_status,
                                                                 monkeypatch):
    """In-process handler test (raw ASGI; the suite has no httpx/TestClient). For BOTH except branches:
    the failed-login record runs on a NON-loop thread (the offload pool) AND completes BEFORE the
    response is sent. Reverting to an inline call runs it on the loop thread (thread assertion reds);
    _fire_offloop-ing it lets the response go first (order assertion reds). The broadcast queue is
    filled to the cap first, proving the awaited record bypasses the shed entirely."""
    S = _api()
    from unittest.mock import MagicMock
    from app.core.database import get_db
    from app.services.auth_service import AuthService, InvalidCredentialsError
    from app.services.auth_service import RateLimitExceededError as AuthRateLimitExceededError
    from app.core import rate_limiter as R
    import time as _t

    raiser = {"InvalidCredentialsError": InvalidCredentialsError("bad"),
              "AuthRateLimitExceededError": AuthRateLimitExceededError("too many", retry_after=1,
                                                                       limit=5, remaining=0)}[raiser_name]

    events = []

    class _Monitor:
        def record_failed_login(self, username, ip_address, reason):
            events.append(("record", threading.current_thread().name))

    def _fake_db():
        yield MagicMock()

    monkeypatch.setitem(S.app.dependency_overrides, get_db, _fake_db)
    monkeypatch.setattr(AuthService, "authenticate_user",
                        lambda *a, **k: (_ for _ in ()).throw(raiser))
    monkeypatch.setattr("app.services.security_monitor.get_security_monitor", lambda db: _Monitor())
    monkeypatch.setattr("app.core.database.get_db_context",
                        lambda: contextlib.nullcontext(object()))
    # Open the breaker so the general middleware / guarded reads skip the socket (no real Redis).
    R._cb_record_failure(_t.time())
    # Saturate the droppable broadcast queue; the awaited record must still land.
    S._BG_TASKS.clear()
    for i in range(S._OFFLOOP_MAX_PENDING):
        S._BG_TASKS.add(("dummy", i))
    try:
        loop_thread = _drive_login(S, {"username": "alice", "password": "wrong"}, events)
    finally:
        S._BG_TASKS.clear()
        R._cb_record_success()

    kinds = [e[0] for e in events]
    assert ("record" in kinds and "response" in kinds), f"missing record or response: {events}"
    assert kinds.index("record") < kinds.index("response"), (
        f"the failed-login record did not complete before the response: {events}")
    record_thread = next(e[1] for e in events if e[0] == "record")
    assert record_thread.startswith("auth-offload"), (
        f"the failed-login record ran on {record_thread!r}, not the offload pool — it was not "
        f"offloaded off the loop {loop_thread!r}")
    response_status = next(e[1] for e in events if e[0] == "response")
    assert response_status == expected_status, (response_status, events)


def test_a_successful_login_broadcasts_with_include_metrics_false(monkeypatch):
    """In-process handler test (raw ASGI) for the SUCCESS path: a successful login's activity broadcast
    is fired with include_metrics=False, so it does not run the six COUNT queries (a full file count
    among them) per login. Patches broadcast_event at the module attribute to record its kwarg. Flip
    the kwarg in the handler (include_metrics=True) and this reds. The broadcast fires before the
    response is built, so the response's own status is irrelevant here."""
    import types
    import uuid
    from unittest.mock import MagicMock
    from app.core.database import get_db
    from app.services.auth_service import AuthService
    from app.core import rate_limiter as R
    import time as _t

    S = _api()
    user = types.SimpleNamespace(id=uuid.uuid4(), username="alice", email="alice@example.com")
    recorded = []
    fired = threading.Event()

    def _fake_db():
        yield MagicMock()

    def _record(event, include_metrics=True):
        recorded.append(include_metrics)
        fired.set()

    monkeypatch.setitem(S.app.dependency_overrides, get_db, _fake_db)
    monkeypatch.setattr(AuthService, "authenticate_user", lambda *a, **k: (user, "session-tok"))
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, u: False)  # no 2FA pending
    monkeypatch.setattr(S, "_setting_int", lambda db, key, default: default)
    monkeypatch.setattr(S, "broadcast_event", _record)
    R._cb_record_failure(_t.time())  # skip real Redis on the middleware / guarded reads
    S._BG_TASKS.clear()
    try:
        _drive_login(S, {"username": "alice", "password": "right"}, [], drain=True, done_event=fired)
    finally:
        S._BG_TASKS.clear()
        R._cb_record_success()

    assert fired.is_set(), "the login broadcast never fired"
    assert recorded == [False], (
        f"the login broadcast was not fired with include_metrics=False: recorded={recorded}")


def test_a_temp_429_drops_the_ratelimit_headers_and_uses_a_generic_body():
    # A device bucket's exception would carry limit=30 and the IP leg would say "from this IP" — both
    # kind oracles. For a temp_ username neither must survive. Deleting the `if not is_temp` branch in
    # the helper (so the headers are always added) turns the header assertions red.
    S = _api()
    exc = _Exc("Too many login attempts from this IP. Try again in 42 seconds.",
               limit=30, remaining=0, retry_after=42)
    detail, headers = S._login_429_detail_and_headers("temp_devicename", exc)
    assert "X-RateLimit-Limit" not in headers, headers
    assert "X-RateLimit-Remaining" not in headers, headers
    assert headers.get("Retry-After") == "42"
    assert "from this IP" not in detail
    assert detail == "Too many login attempts. Please try again in 42 seconds."


@pytest.mark.parametrize("remaining", [0, 3])
def test_a_human_429_keeps_its_headers_and_exact_body(remaining):
    S = _api()
    exc = _Exc("Too many login attempts. Please try again in 42 seconds.",
               limit=5, remaining=remaining, retry_after=42)
    detail, headers = S._login_429_detail_and_headers("alice", exc)
    assert headers.get("X-RateLimit-Limit") == "5"
    # The human keeps ALL its rate-limit headers, whatever the remaining count — including 0, where a
    # `hasattr`/`if exc.remaining` guard would wrongly drop the header.
    assert headers.get("X-RateLimit-Remaining") == str(remaining)
    assert headers.get("Retry-After") == "42"
    assert detail == "Too many login attempts. Please try again in 42 seconds."


def test_the_failed_login_record_is_wired_awaited_offloaded_not_queued():
    """WIRING PIN (source). Complements the behavioural in-process test below: the failed-login record
    must be AWAITED through run_offloaded — awaited so the counter lands before the response and is
    never shed, offloaded so its one boundary re-probe runs off the loop — in BOTH login except
    branches, and never through _fire_offloop (whose queue is droppable). Both branches count."""
    import pathlib
    src = pathlib.Path("app/api/api_server.py").read_text(encoding="utf-8")
    assert "_fire_offloop(_record_failed_login_bg" not in src, (
        "the failed-login record is queued through _fire_offloop — it can be shed under a broadcast "
        "spray; it must be awaited via run_offloaded")
    assert src.count("run_offloaded(_record_failed_login_bg, login_request.username") == 2, (
        "expected the failed-login record awaited via run_offloaded in BOTH login except branches")


def test_a_temp_429_with_no_retry_after_uses_the_generic_no_countdown_body():
    # The retry-less branch: when the exception carries no retry_after, the temp_ body is the generic
    # no-countdown message and no Retry-After header is emitted. Pins that branch too.
    S = _api()
    exc = _Exc("Too many login attempts from this IP.", limit=30, remaining=0, retry_after=None)
    detail, headers = S._login_429_detail_and_headers("temp_name", exc)
    assert detail == "Too many login attempts. Please try again later."
    assert "Retry-After" not in headers
    assert "X-RateLimit-Limit" not in headers


def test_record_failed_login_bg_records_through_the_monitor(monkeypatch):
    # The inline failed-login helper must open its own session and record via the monitor. If it
    # silently dropped the event this stays empty — red.
    seen = []

    class _Monitor:
        def record_failed_login(self, username, ip_address, reason):
            seen.append((username, ip_address, reason))

    S = _api()
    monkeypatch.setattr("app.core.database.get_db_context",
                        lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr("app.services.security_monitor.get_security_monitor",
                        lambda db: _Monitor())

    S._record_failed_login_bg("temp_x", "203.0.113.9", "bad password")
    assert seen == [("temp_x", "203.0.113.9", "bad password")]


def test_login_broadcast_skips_metrics_when_include_metrics_false(monkeypatch):
    # The login broadcast passes include_metrics=False so it does not run the six COUNT queries
    # (a full file count among them) per login. Pin the metrics-free contract: get_current_metrics
    # must not be called.
    S = _api()
    called = {"metrics": False}

    def _boom():
        called["metrics"] = True
        return {}

    monkeypatch.setattr(S, "get_current_metrics", _boom)
    monkeypatch.setattr(S, "_guarded_publish", lambda *a, **k: True)  # never touch Redis
    S.broadcast_event({"event": {"type": "login"}}, include_metrics=False)
    assert called["metrics"] is False, "the login broadcast ran the metrics counts"
