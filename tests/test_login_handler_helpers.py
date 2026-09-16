"""Unit pins for the login handler's helpers: the 429 body/header shaping, the off-loop failed-login
record, and the metrics-free login broadcast. These are the handler-level guarantees the general
rate-limit middleware would mask on the wire (it re-stamps X-RateLimit-*), so they are pinned here.
"""
import contextlib
import os

import pytest

pytestmark = pytest.mark.unit


def _api():
    """Import the API module LAZILY (inside a test), never at module scope. Importing it runs the
    API bootstrap, which fails closed with SystemExit in a bare environment — that would abort strict
    COLLECTION (pytest imports every test module to collect it) before any test runs. Deferring the
    import to call time keeps collection free of the bootstrap, matching the sibling unit tests. Dummy
    connection strings so the import that does happen at run time is side-effect-free."""
    for _k, _v in {
        "DATABASE_URL": "postgresql://x:x@localhost:5432/x",
        "REDIS_URL": "redis://localhost:6379/0",
        "SECRET_KEY": "t" * 32,
        "JWT_SECRET_KEY": "t" * 32,
    }.items():
        os.environ.setdefault(_k, _v)
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


def test_a_human_429_keeps_its_headers_and_exact_body():
    S = _api()
    exc = _Exc("Too many login attempts. Please try again in 42 seconds.",
               limit=5, remaining=0, retry_after=42)  # a 429 leaves 0 remaining
    detail, headers = S._login_429_detail_and_headers("alice", exc)
    assert headers.get("X-RateLimit-Limit") == "5"
    assert headers.get("X-RateLimit-Remaining") == "0"  # the human keeps ALL its rate-limit headers
    assert headers.get("Retry-After") == "42"
    assert detail == "Too many login attempts. Please try again in 42 seconds."


def test_the_failed_login_record_runs_inline_not_through_the_droppable_queue():
    # T4: the brute-force failed-login counter must advance on EVERY failed login, so it runs inline
    # in both except branches, never through _fire_offloop (whose queue sheds under saturation). This
    # is the regression guard the reviewer asked for: if the record is ever put back on the queue it
    # can be dropped by a broadcast spray. Reads the handler source (a workflow-contract pin like
    # test_infra_hardening's), since the async handler cannot be driven without a live DB here.
    import pathlib
    src = pathlib.Path("app/api/api_server.py").read_text(encoding="utf-8")
    assert "_fire_offloop(_record_failed_login_bg" not in src, (
        "the failed-login record is queued through _fire_offloop — it can be shed under a broadcast "
        "spray; it must run inline")
    assert "_record_failed_login_bg(login_request.username" in src, (
        "the failed-login record is not called inline in the login handler")


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
    # The off-loop failed-login helper must open its own session and record via the monitor. If it
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
