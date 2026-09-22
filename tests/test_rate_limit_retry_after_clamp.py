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


def test_no_emission_rolls_its_own_arithmetic_anywhere_in_the_application():
    # Repo-wide, and with no exemption list: an exemption is a hole that outlives its reason. Every
    # subtraction of the clock from a reset is the helper's; every Retry-After header and every
    # RateLimitExceeded is built from a value the helper produced. Comments are stripped first so a
    # commented-out old shape neither passes nor fails this.
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "app"
    raw = []
    emissions = 0
    for py in sorted(root.rglob("*.py")):
        code = "\n".join(ln for ln in py.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#"))
        for m in re.finditer(r"reset[a-z_]*\s*-\s*int\(", code):
            line = code[:m.start()].count("\n") + 1
            if "def retry_after_seconds" not in code[max(0, m.start() - 600):m.start()]:
                raw.append("%s:%d" % (py.relative_to(root.parent), line))
        for ln in code.splitlines():
            if '"Retry-After"' in ln and "=" in ln:
                emissions += 1
                # The header stringifies a value: the helper's call, or a name carrying what the
                # helper produced (`retry_after`, `_retry`, an exception's field). What it must
                # never hold is arithmetic of its own.
                assert not any(tok in ln for tok in (" - ", "max(", "min(")), \
                    "%s: a Retry-After with its own arithmetic: %s" % (py.name, ln.strip())
    assert raw == [], "raw retry-after arithmetic remains at: %s" % raw
    assert emissions >= 20, "the sweep found fewer header emissions than there are (%d)" % emissions
