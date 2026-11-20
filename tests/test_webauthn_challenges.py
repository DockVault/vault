"""The challenges a passkey ceremony signs (app/core/webauthn_challenges.py): one use, one purpose, five minutes,
fail closed without the store. Offline, against a small Redis stand-in."""
import json

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


class _Redis:
    def __init__(self):
        self.rows = {}
        self.now = 1_000.0
        self.broken = False

    def set(self, key, value, ex=None, nx=False):
        if self.broken:
            raise ConnectionError("down")
        self._expire()
        if nx and key in self.rows:
            return None
        self.rows[key] = (value, self.now + ex if ex else None)
        return True

    def getdel(self, key):
        if self.broken:
            raise ConnectionError("down")
        self._expire()
        value, _ = self.rows.pop(key, (None, None))
        return value

    def _expire(self):
        for key in [k for k, (_, until) in self.rows.items() if until is not None and until <= self.now]:
            del self.rows[key]


def _chal():
    set_bare_api_env()
    from app.core import webauthn_challenges as wc
    return wc


def test_a_challenge_is_random_bound_and_spent_by_its_first_use():
    wc = _chal()
    r = _Redis()
    c = wc.issue(wc.SIGN_IN, user_id="u1", allow_ids=["abc"], redis=r)
    assert len(c.id) == 32 and len(c.challenge_bytes) == 32 and c.purpose == "sign_in"
    assert c.user_id == "u1" and c.allow_ids == ["abc"]
    assert wc.issue(wc.SIGN_IN, redis=r).challenge != c.challenge
    (key, *_) = [k for k in r.rows if k.endswith(c.id)]
    assert key == "webauthn:chal:" + c.id
    got = wc.take(c.id, purpose=wc.SIGN_IN, redis=r)
    assert got == c
    assert wc.take(c.id, purpose=wc.SIGN_IN, redis=r) is None


def test_a_challenge_serves_one_purpose_and_is_spent_when_asked_for_another():
    wc = _chal()
    r = _Redis()
    c = wc.issue(wc.REGISTER, user_id="u1", redis=r)
    assert wc.take(c.id, purpose=wc.SIGN_IN, redis=r) is None
    assert wc.take(c.id, purpose=wc.REGISTER, redis=r) is None       # spent by the wrong-purpose attempt


def test_a_challenge_lives_five_minutes():
    wc = _chal()
    r = _Redis()
    c = wc.issue(wc.STEP_UP, redis=r)
    r.now += 299
    assert wc.take(c.id, purpose=wc.STEP_UP, redis=r) is not None
    c = wc.issue(wc.STEP_UP, redis=r)
    r.now += 300
    assert wc.take(c.id, purpose=wc.STEP_UP, redis=r) is None


def test_garbage_is_no_challenge_and_the_store_down_fails_closed():
    wc = _chal()
    r = _Redis()
    for bad in ("", None, "x" * 65, "not-hex!", "ABCDEF"):
        assert wc.take(bad, purpose=wc.SIGN_IN, redis=r) is None
    cid = "ab" * 16
    for raw in ("nope", json.dumps([1]), json.dumps({"id": cid, "purpose": "sign_in"}),
                json.dumps({"id": "other", "challenge": "Y2hhbA", "purpose": "sign_in"}),
                json.dumps({"id": cid, "challenge": "Y2hhbA", "purpose": "evil"}),
                json.dumps({"id": cid, "challenge": "Y2hhbA", "purpose": "sign_in", "allow_ids": "abc"}),
                json.dumps({"id": cid, "challenge": "Y2hhbA", "purpose": "sign_in", "user_id": 5})):
        r.rows["webauthn:chal:" + cid] = (raw, None)
        assert wc.take(cid, purpose=wc.SIGN_IN, redis=r) is None, raw
    with pytest.raises(ValueError):
        wc.issue("evil", redis=r)
    r.broken = True
    with pytest.raises(wc.Unavailable):
        wc.issue(wc.SIGN_IN, redis=r)
    with pytest.raises(wc.Unavailable):
        wc.take(cid, purpose=wc.SIGN_IN, redis=r)


@pytest.fixture
def own_store(monkeypatch):
    """The vault's own client replaced by the fake, with the outage guard and the limiter's breaker closed before
    and after."""
    _chal()
    from app.core import database, rate_limiter, redis_guard

    def closed():
        rate_limiter._cb_record_success()
        redis_guard.guard_record_success()
    closed()
    r = _Redis()
    monkeypatch.setattr(database, "redis_client", r)
    yield r
    closed()


def test_while_redis_is_known_to_be_down_the_vaults_own_store_is_not_touched(own_store, monkeypatch):
    wc = _chal()
    from app.core import redis_guard
    made = wc.issue(wc.SIGN_IN)
    calls = []
    monkeypatch.setattr(own_store, "set", lambda *a, **k: calls.append("set"))
    monkeypatch.setattr(own_store, "getdel", lambda *a, **k: calls.append("getdel"))
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda now: True)
    with pytest.raises(wc.Unavailable):
        wc.issue(wc.SIGN_IN)
    with pytest.raises(wc.Unavailable):
        wc.take(made.id, purpose=wc.SIGN_IN)
    assert calls == []                      # refused before the socket, both ways


def test_a_failure_of_the_vaults_own_store_is_remembered_for_the_next_ceremony(own_store):
    import time
    wc = _chal()
    from app.core import redis_guard
    made = wc.issue(wc.SIGN_IN)
    own_store.broken = True
    with pytest.raises(wc.Unavailable):
        wc.take("ab" * 16, purpose=wc.SIGN_IN)
    assert redis_guard.guard_private_open(time.time())
    own_store.broken = False                # the store is back, the memory is not yet over
    with pytest.raises(wc.Unavailable):
        wc.take(made.id, purpose=wc.SIGN_IN)
    redis_guard.guard_record_success()
    assert wc.take(made.id, purpose=wc.SIGN_IN) is not None     # and the refusal did not spend the challenge


def test_a_client_handed_in_is_called_whatever_the_guard_says(own_store, monkeypatch):
    wc = _chal()
    from app.core import redis_guard
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda now: True)
    r = _Redis()
    made = wc.issue(wc.SIGN_IN, redis=r)
    assert wc.take(made.id, purpose=wc.SIGN_IN, redis=r) is not None
    assert own_store.rows == {}
