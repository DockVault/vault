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
