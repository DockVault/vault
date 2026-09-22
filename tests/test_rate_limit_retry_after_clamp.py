"""A rate limiter's retry-after must never exceed the window it belongs to.

The Lua computes reset_at = math.ceil(oldest + window) while Python derives the wait as
reset_at - int(now): the ceil on one side and the int-truncation on the other can disagree by a
whole second, so when the oldest entry carries a fractional second the raw wait comes out at
window + 1. Both the peek (pre-flight) and the 429 (check_and_raise) paths clamp the derived value
to [0, window]. Driven here with a FAKE CLOCK so the off-by-one is deterministic -- it is a
sub-second effect that a live test hit only by luck until it didn't.
"""
import math

import pytest

pytestmark = pytest.mark.unit

_T = 1000          # an integer second boundary, so the fractions below are the whole story
_WINDOW = 300


def _limiter():
    from app.core.rate_limiter import RateLimiter
    return RateLimiter(redis_client=object())   # redis is faked per test; the real client is unused


def _fake_peek(monkeypatch, limiter, now, reset_at):
    """Wire peek_rate_limit to a fixed clock and a Redis that returns (over=1, reset_at)."""
    from app.core import rate_limiter as rl
    from app.core import redis_guard
    monkeypatch.setattr(rl.time, "time", lambda: now)
    monkeypatch.setattr(rl, "_cb_is_open", lambda _now: False)
    monkeypatch.setattr(redis_guard, "timed_redis", lambda _label, fn: fn())
    limiter.redis = type("_FakeRedis", (), {"eval": lambda self, *a, **k: [1, reset_at]})()


def test_peek_retry_after_is_clamped_to_the_window(monkeypatch):
    # oldest and now share a second; oldest has a positive fraction, so ceil(oldest+window) and
    # int(now) disagree and the raw wait is window + 1. The clamp caps it at the window.
    oldest, now = _T + 0.2, _T + 0.9
    reset_at = math.ceil(oldest + _WINDOW)               # 1301, the Lua's value
    assert reset_at - int(now) == _WINDOW + 1            # the raw, unclamped wait is 301 -- the bug

    limiter = _limiter()
    _fake_peek(monkeypatch, limiter, now, reset_at)
    over, retry_after = limiter.peek_rate_limit("id", limit=1, window=_WINDOW)
    assert over is True
    assert retry_after == _WINDOW, f"peek retry_after not clamped: {retry_after}"
    # mutation: drop the min(window, ...) clamp in peek_rate_limit -> 301 -> red.


def test_peek_retry_after_clamp_is_a_no_op_for_a_normal_wait(monkeypatch):
    # Several seconds into the window the raw wait is already well under the window, so the clamp is
    # inert: it must not shorten a legitimate wait, only cap the off-by-one overshoot.
    oldest, now = _T + 0.2, _T + 5.9
    reset_at = math.ceil(oldest + _WINDOW)               # 1301
    raw = reset_at - int(now)                            # 296
    assert 0 < raw < _WINDOW

    limiter = _limiter()
    _fake_peek(monkeypatch, limiter, now, reset_at)
    over, retry_after = limiter.peek_rate_limit("id", limit=1, window=_WINDOW)
    assert retry_after == raw, f"the clamp altered a normal in-window wait: {retry_after} != {raw}"


def test_an_over_limit_peek_never_answers_zero(monkeypatch):
    # The peek returns (over, retry_after) and its contract says retry_after is 0 when NOT over the
    # limit. Its over-limit arm used to floor at 0, so an over-limit peek whose reset had already
    # passed answered 0 too -- indistinguishable from "not limited", which is the one thing that
    # value exists to say. With the floor at 1, a 0 means exactly "not limited".
    # (mutation: the peek arm back to `max(0, ...)` -> 0 -> red.)
    limiter = _limiter()
    _fake_peek(monkeypatch, limiter, now=_T + 0.9, reset_at=_T - 3)     # over, and the reset is past
    over, retry_after = limiter.peek_rate_limit("id", limit=1, window=_WINDOW)
    assert over is True and retry_after == 1, (over, retry_after)


def test_the_429_path_retry_after_is_clamped_to_the_window(monkeypatch):
    # The same ceil-vs-int overshoot reaches the 429 (check_and_raise) path through reset_time; it
    # clamps identically, so a Retry-After header never promises longer than the window.
    from app.core import rate_limiter as rl
    from app.core.rate_limiter import RateLimitExceeded

    reset_time, now = _T + _WINDOW + 1, _T + 0.9         # 1301, int(now) 1000 -> raw 301
    limiter = _limiter()
    monkeypatch.setattr(rl.time, "time", lambda: now)
    # Over the limit: (allowed=False, remaining, reset_time); retry_after is derived + clamped.
    monkeypatch.setattr(limiter, "check_rate_limit", lambda *a, **k: (False, 0, reset_time))

    with pytest.raises(RateLimitExceeded) as caught:
        limiter.check_and_raise("id", limit=1, window=_WINDOW)
    assert caught.value.retry_after == _WINDOW, f"429 retry_after not clamped: {caught.value.retry_after}"
    # mutation: drop the min(window, ...) clamp on the 429 path -> 301 -> red.


# ---- one helper, every emission ----------------------------------------------------------------------------
#
# Four emissions lived in this module and each had its own arithmetic: floor 0 capped (the 429 path),
# floor 1 uncapped (the middleware), no clamp at all (the endpoint decorator), and the peek's tuple
# arm. Twenty more inline sites across the API had a fifth. One helper now does it everywhere, and
# what it promises is pinned here from both ends: its own arithmetic, and that no site still rolls
# its own.

def test_retry_after_seconds_is_at_least_one_and_at_most_the_window():
    from app.core.rate_limiter import retry_after_seconds as ras
    assert ras(_T + 37, _WINDOW, now=_T) == 37                  # an ordinary wait passes through
    assert ras(_T + _WINDOW + 1, _WINDOW, now=_T) == _WINDOW    # the ceil-vs-int overshoot is capped
    assert ras(_T, _WINDOW, now=_T) == 1                        # a reset that is now: never 0
    assert ras(_T - 5, _WINDOW, now=_T) == 1                    # a reset already past: never negative
    assert ras(_T + 2.9, _WINDOW, now=_T + 0.4) == 2            # whole seconds, as the header wants


def test_the_decorator_never_emits_a_negative_or_zero_retry_after(monkeypatch):
    # THE BUG, driven as a bug. The endpoint decorator computed `reset_time - int(now)` with no
    # clamp at all, so whenever the window had already expired between the store's answer and that
    # line -- or the clocks disagreed -- it stringified a NEGATIVE number into the Retry-After
    # header. RFC 9110 delta-seconds is non-negative; a client handed "-1" may do anything. Driven
    # through the real decorator with the limiter answering "over, and the reset was a moment
    # ago". (mutation: the decorator back to the raw subtraction -> "-3" -> red.)
    from _async_run import run_coroutine
    from app.core import rate_limiter as rl
    from fastapi import HTTPException, Request

    now = _T + 0.9
    reset_time = _T - 2                                          # expired three seconds ago by int(now)

    class _Limiter(rl.RateLimiter):
        def check_rate_limit(self, *a, **k):
            return False, 0, reset_time

    monkeypatch.setattr(rl.time, "time", lambda: now)
    monkeypatch.setattr(rl, "RateLimiter", _Limiter)

    @rl.rate_limit(limit=1, window=_WINDOW, per="ip")
    async def endpoint(request: Request):
        return "served"

    scope = {"type": "http", "method": "GET", "path": "/x", "headers": [], "client": ("10.0.0.1", 1),
             "query_string": b"", "server": ("h", 80), "scheme": "http"}
    with pytest.raises(HTTPException) as caught:
        run_coroutine(endpoint(request=Request(scope)))
    header = caught.value.headers["Retry-After"]
    assert header.lstrip("-").isdigit() and int(header) >= 1, "a malformed Retry-After left the decorator: %r" % header
    assert int(header) <= _WINDOW
    assert "Try again in %s seconds" % header in caught.value.detail


def test_the_middleware_emits_the_same_clamped_value(monkeypatch):
    # The middleware had floor 1 and no cap: the same overshoot the peek test above pins reached the
    # header as window + 1. Through the helper it is the window. (mutation: middleware back to
    # `max(1, reset - int(now))` -> 301 -> red.)
    from _async_run import run_coroutine
    from app.core import rate_limiter as rl
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse

    fake = type("_L", (), {"check_rate_limit": lambda self, *a, **k: (False, 0, reset_time),
                           "get_rate_limit_headers": lambda self, *a, **k: {}})()
    mw = rl.RateLimitMiddleware(app=lambda *a, **k: None, rate_limiter=fake)
    # The window is the RULE's for this request's class, not a constant of this test's choosing.
    rule_window = mw._static_policy["default"].window
    reset_time, now = _T + rule_window + 1, _T + 0.9
    monkeypatch.setattr(rl.time, "time", lambda: now)
    scope = {"type": "http", "method": "GET", "path": "/api/anything", "headers": [], "client": ("10.0.0.2", 1),
             "query_string": b"", "server": ("h", 80), "scheme": "http"}
    resp = run_coroutine(mw.dispatch(Request(scope), lambda r: PlainTextResponse("served")))
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == str(rule_window), resp.headers["retry-after"]


def test_no_emission_computes_its_own_wait_anywhere_in_the_application():
    # WHAT THIS CHECKS, and what it deliberately does not. The property we want is "every value that
    # reaches a Retry-After header, or a RateLimitExceeded, came from the helper". That is whole-
    # program provenance: it crosses functions (a throttle returns a tuple its caller passes on) and
    # an exception object (the 503 handler emits exc.retry_after, built three modules away), so
    # expressing it statically means writing a dataflow engine that would red on innocent
    # refactors. The previous version of this test pretended otherwise: it swept for the SPELLING
    # `reset - int(` and for arithmetic on the emission's own line, and called that total. It was
    # not -- it missed a floor-of-ZERO Retry-After on the account-lockout 403, where the arithmetic
    # sat on the line ABOVE the header, and two fail-closed waits in the DB throttle fallbacks.
    # (That is the same lesson twice: a pin that enumerates what it can see checks only that.)
    #
    # So the static half is narrowed to a property it can actually hold, everywhere and with no
    # exemptions: THE EMISSION PASSES A VALUE, IT NEVER COMPUTES ONE. No Retry-After value and no
    # retry_after= argument may contain arithmetic, a clamp, or a conditional of its own. The
    # provenance half is pinned BEHAVIOURALLY, one test per emission family, below.
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "app"
    offences, emissions, constructions = [], 0, 0
    for py in sorted(root.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))

        def computes(node):
            return any(isinstance(n, (ast.BinOp, ast.IfExp, ast.Compare)) or
                       (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                        and n.func.id in ("max", "min", "abs", "round"))
                       for n in ast.walk(node))

        for node in ast.walk(tree):
            values = []
            if isinstance(node, ast.Dict):
                values += [v for k, v in zip(node.keys, node.values)
                           if isinstance(k, ast.Constant) and k.value == "Retry-After"]
                emissions += len(values)
            if isinstance(node, ast.Call):
                kw = [k.value for k in node.keywords if k.arg == "retry_after"]
                values += kw
                constructions += len(kw)
            for v in values:
                # The helper's OWN call may of course contain the arithmetic it exists to own.
                src = ast.unparse(v)
                if "retry_after_seconds(" in src:
                    continue
                if computes(v):
                    offences.append("%s:%d: %s" % (py.relative_to(root.parent), v.lineno, src[:80]))
    assert offences == [], (
        "a Retry-After emission computing its own wait; call retry_after_seconds and pass it:\n  "
        + "\n  ".join(offences))
    # The sweep is only as good as its reach: if these counts collapse, it is finding nothing.
    assert emissions >= 20, emissions
    assert constructions >= 5, constructions


def _fake_db(monkeypatch, row):
    """Point the DB-fallback throttles at one row, the way test_device_sync_preflight does."""
    import contextlib
    from app.services import auth_service as A

    class _Exec:
        def __init__(self, row):
            self._row = row

        def first(self):
            return self._row

    class _DB:
        def execute(self, stmt):
            return _Exec(row)

    @contextlib.contextmanager
    def _ctx():
        yield _DB()

    monkeypatch.setattr(A, "get_db_context", _ctx)


@pytest.mark.parametrize("fn", ["_db_throttle_hit", "_db_throttle_peek"])
def test_a_throttle_window_that_starts_in_the_future_never_asks_for_more_than_the_window(monkeypatch, fn):
    # The emission family the old sweep could not see. Both DB fallbacks derived the wait from the
    # window's start, floored at 1 and capped at NOTHING -- so a window_start in the future (a clock
    # step, a replica's clock, a row written by a host running ahead) handed the caller a wait longer
    # than the window the limit is even defined over. The helper caps it; here the product is driven
    # with such a row and the answer is held inside [1, window].
    from datetime import datetime, timedelta
    from app.services.auth_service import AuthService
    window = 300
    ahead = datetime.utcnow() + timedelta(seconds=10 * window)     # the row's clock runs ahead
    _fake_db(monkeypatch, (99, ahead))
    allowed_or_over, retry = getattr(AuthService, fn)("id-1", "act", 5, window)
    assert 1 <= retry <= window, (fn, retry)


@pytest.mark.parametrize("fn", ["_db_throttle_hit", "_db_throttle_peek"])
def test_a_fail_closed_deny_is_also_inside_the_window(monkeypatch, fn):
    # The other half of the same family: when the fallback cannot establish the count it denies for
    # a fixed short while. That value is emitted to the same callers, so it obeys the same bound --
    # including when the window itself is shorter than the fixed deny.
    from app.services import auth_service as A
    from app.services.auth_service import AuthService

    def _boom():
        raise RuntimeError("db down too")

    monkeypatch.setattr(A, "get_db_context", _boom)
    for window in (300, 2):                                        # a window shorter than the deny
        _, retry = getattr(AuthService, fn)("id-1", "act", 5, window)
        assert 1 <= retry <= window, (fn, window, retry)


def test_a_locked_account_is_never_told_to_retry_immediately_or_past_the_lock(monkeypatch):
    # The account-lockout 403 carried `max(0, ...)`: a lock whose end had just passed, or a clock a
    # second ahead, emitted "Retry-After: 0" -- retry now, into a lock still in force. And nothing
    # capped it, so a stale locked_until from a longer-lockout era promised a wait no lock this
    # deployment can impose. Driven on the helper the endpoint now calls.
    from datetime import datetime, timedelta, timezone
    import _bare_api_env
    _bare_api_env.set_bare_api_env()
    from app.api import api_server as S
    from app.core import rate_limit_settings
    monkeypatch.setattr(rate_limit_settings, "effective", lambda key: 30 if key == "lockout_duration" else 5)
    window = 30 * 60
    now = datetime.now(timezone.utc)
    assert S._account_lock_retry_after(now + timedelta(minutes=10)) == pytest.approx(600, abs=2)
    assert S._account_lock_retry_after(now - timedelta(seconds=1)) == 1      # never 0
    assert S._account_lock_retry_after(now + timedelta(days=7)) == window    # capped at the lock
    # A permanent-lock setting (0) still caps, at the longest lockout the settings allow.
    monkeypatch.setattr(rate_limit_settings, "effective", lambda key: 0 if key == "lockout_duration" else 5)
    assert S._account_lock_retry_after(now + timedelta(days=7)) == 1440 * 60


def test_the_fixed_waits_emitted_as_headers_are_positive_and_are_their_own_window():
    # The remaining emission family is a CONSTANT wait -- the anonymous-surface lockout windows and
    # the transfer-admission slot retry. A constant cannot drift out of range, but it can be set to
    # zero or negative by an edit, which is the same "retry now" defect; and each is emitted as the
    # whole window it belongs to, so it is its own cap.
    import _bare_api_env
    _bare_api_env.set_bare_api_env()
    from app.api import api_server as S
    from app.core import auth_offload
    for value in (S._NOTELINK_FAIL_WINDOW, S._PUBLINK_FAIL_WINDOW, S._RECV_FAIL_WINDOW,
                  auth_offload._SLOT_RETRY_AFTER_SECONDS):
        assert isinstance(value, int) and value >= 1, value


def test_at_a_site_with_two_limiters_the_refusing_one_decides_both_the_reset_and_the_window():
    # Three endpoints run two limiters -- per user and per address -- and refuse if either says no.
    # They used to pick the RESET from whichever refused and then compute the wait with the OTHER
    # limiter's window on one arm (there was only one `window` name in scope), so the cap could come
    # from the wrong budget. Now each arm pairs its reset with its own window. Pinned on the source
    # of the three sites, comment-free: the `reset`/`_WINDOW` pairing on the user arm and the
    # `reset_ip`/`_IP_WINDOW` pairing on the address arm, at every site, with no mixed pairing.
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    arms = re.findall(r"_retry = \(retry_after_seconds\(reset, (_[A-Z_]+_WINDOW)\) if not allowed\s*\n\s*"
                      r"else retry_after_seconds\(reset_ip, (_[A-Z_]+_WINDOW)\)\)", code)
    assert len(arms) == 3, arms
    for user_window, ip_window in arms:
        assert not user_window.endswith("_IP_WINDOW"), arms      # the user arm never uses the address budget
        assert ip_window.endswith("_IP_WINDOW"), arms            # the address arm always uses its own
    assert "_reset = reset if not allowed else reset_ip" not in code   # the one-name shape is gone
