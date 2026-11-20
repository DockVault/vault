"""The one-time sign-in codes (app/core/sign_in_codes.py): spent on first use, worthless without the tab's
verifier or the app's PKCE verifier, gone after sixty seconds, failing closed without the store. Offline,
against a small Redis stand-in that honours expiry and GETDEL."""
import json
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


class _Redis:
    """set(nx, ex) and getdel, with a clock the test controls; ``broken`` makes every call raise."""

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


def _codes():
    set_bare_api_env()
    from app.core import sign_in_codes
    return sign_in_codes


def _handover(**kw):
    c = _codes()
    base = dict(user_id=str(uuid.uuid4()), methods=["hwk"], client_ip="10.0.0.1")
    base.update(kw)
    return c.Handover(**base)


def test_secrets_and_digests_have_the_shapes_the_browser_and_the_app_expect():
    c = _codes()
    code = c.make_secret()
    assert len(code) == 43 and all(ch.isalnum() or ch in "-_" for ch in code)
    assert c.make_secret() != code
    assert c.digest("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    # RFC 7636 appendix B
    assert c.pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_a_code_is_spent_by_its_first_use_and_needs_the_tabs_verifier():
    c = _codes()
    r = _Redis()
    verifier = c.make_secret()
    code = c.store(_handover(verifier_hash=c.digest(verifier)), redis=r)
    # The store holds the code's digest, never the code, and the record names no session.
    (key,) = r.rows
    assert key == "signin:code:" + c.digest(code) and code not in key
    assert "session" not in r.rows[key][0] and "token" not in r.rows[key][0]
    got = c.take(code, verifier=verifier, redis=r)
    assert got is not None and got.methods == ["hwk"] and got.purpose == "sign_in"
    # Spent.
    assert c.take(code, verifier=verifier, redis=r) is None


def test_a_wrong_or_missing_verifier_spends_the_code_too():
    c = _codes()
    r = _Redis()
    verifier = c.make_secret()
    code = c.store(_handover(verifier_hash=c.digest(verifier)), redis=r)
    assert c.take(code, verifier="not-it", redis=r) is None
    assert c.take(code, verifier=verifier, redis=r) is None        # one guess, and it is gone
    code = c.store(_handover(verifier_hash=c.digest(verifier)), redis=r)
    assert c.take(code, redis=r) is None                           # no proof at all
    assert c.take(code, verifier=verifier, redis=r) is None
    # A PKCE verifier is no tab verifier.
    code = c.store(_handover(verifier_hash=c.digest(verifier)), redis=r)
    assert c.take(code, code_verifier=verifier, redis=r) is None


def test_the_app_proves_itself_with_pkce():
    c = _codes()
    r = _Redis()
    code_verifier = c.make_secret() + c.make_secret()[:20]
    code = c.store(_handover(purpose="app", code_challenge=c.pkce_challenge(code_verifier)), redis=r)
    assert c.take(code, code_verifier=code_verifier, redis=r).purpose == "app"
    assert c.take(code, code_verifier=code_verifier, redis=r) is None
    # The plain method, a short verifier and a tab verifier are refused (each spends the code).
    for wrong in ({"code_verifier": "short"}, {"verifier": code_verifier},
                  {"code_verifier": c.pkce_challenge(code_verifier)}):
        code = c.store(_handover(purpose="app", code_challenge=c.pkce_challenge(code_verifier)), redis=r)
        assert c.take(code, redis=r, **wrong) is None, wrong
        assert c.take(code, code_verifier=code_verifier, redis=r) is None


def test_a_code_lives_sixty_seconds():
    c = _codes()
    r = _Redis()
    verifier = c.make_secret()
    code = c.store(_handover(verifier_hash=c.digest(verifier)), redis=r)
    r.now += 59
    assert c.take(code, verifier=verifier, redis=r) is not None
    code = c.store(_handover(verifier_hash=c.digest(verifier)), redis=r)
    r.now += 60
    assert c.take(code, verifier=verifier, redis=r) is None


def test_a_record_needs_exactly_one_proof_and_a_known_purpose_and_a_first_proof():
    c = _codes()
    r = _Redis()
    with pytest.raises(ValueError):
        c.store(_handover(), redis=r)
    with pytest.raises(ValueError):
        c.store(_handover(verifier_hash="h", code_challenge="c"), redis=r)
    with pytest.raises(ValueError):
        c.store(_handover(verifier_hash="h", purpose="link"), redis=r)
    # A code alone is no first proof; a provider is.
    with pytest.raises(ValueError):
        c.store(_handover(verifier_hash="h", methods=[]), redis=r)
    assert c.store(_handover(verifier_hash="h", methods=[], provider_id="p1"), redis=r)


def test_a_record_read_back_must_be_plainly_typed():
    """Flags are booleans, never a truthy word; hashes and ids are strings; a code alone is no first proof."""
    c = _codes()
    r = _Redis()
    code = c.make_secret()
    base = {"user_id": "u", "methods": ["hwk"], "verifier_hash": c.digest("v")}
    for bad in ({**base, "provider_mfa_trusted": "yes"}, {**base, "user_verified": 1},
                {**base, "passwordless_allowed": "true"}, {**base, "verifier_hash": 1},
                {**base, "provider_id": 7}, {**base, "pending_id": ["x"]}, {**base, "created_at": "now"},
                {**base, "methods": [], "provider_id": None}):
        r.rows["signin:code:" + c.digest(code)] = (json.dumps(bad), None)
        assert c.take(code, verifier="v", redis=r) is None, bad
    good = {**base, "provider_mfa_trusted": True, "user_verified": False}
    r.rows["signin:code:" + c.digest(code)] = (json.dumps(good), None)
    got = c.take(code, verifier="v", redis=r)
    assert got is not None and got.provider_mfa_trusted is True and got.user_verified is False
    good = {**base, "methods": [], "provider_id": "p1"}
    r.rows["signin:code:" + c.digest(code)] = (json.dumps(good), None)
    assert c.take(code, verifier="v", redis=r).provider_id == "p1"


def test_a_pkce_verifier_is_exactly_what_the_rfc_says():
    c = _codes()
    r = _Redis()
    verifier = c.make_secret()                       # 43 unreserved characters
    challenge = c.pkce_challenge(verifier)
    # A verifier with a character outside ASCII has no challenge, so it matches nothing, even where a lax
    # encoding would have dropped the character and matched.
    assert c.pkce_challenge(verifier + "é") == ""
    code = c.store(_handover(purpose="app", code_challenge=challenge), redis=r)
    assert c.take(code, code_verifier=verifier + "é", redis=r) is None
    # Too short, even when its challenge is the stored one.
    short = "abc"
    code = c.store(_handover(purpose="app", code_challenge=c.pkce_challenge(short)), redis=r)
    assert c.take(code, code_verifier=short, redis=r) is None
    # A character outside the unreserved set, even when the challenge matches.
    odd = verifier[:-1] + "!"
    code = c.store(_handover(purpose="app", code_challenge=c.pkce_challenge(odd)), redis=r)
    assert c.take(code, code_verifier=odd, redis=r) is None
    code = c.store(_handover(purpose="app", code_challenge=challenge), redis=r)
    assert c.take(code, code_verifier=verifier, redis=r) is not None


def test_garbage_in_the_store_is_no_code():
    c = _codes()
    r = _Redis()
    code = c.make_secret()
    for raw in ("not json", json.dumps([1, 2]), json.dumps({"methods": ["pwd"]}),
                json.dumps({"user_id": "u", "methods": "pwd", "verifier_hash": c.digest("v")}),
                json.dumps({"user_id": "u", "methods": ["pwd"], "purpose": "link", "verifier_hash": c.digest("v")}),
                json.dumps({"user_id": "u", "methods": ["pwd"], "verifier_hash": c.digest("v"), "extra": 1,
                            "unknown_field": True})):
        r.rows["signin:code:" + c.digest(code)] = (raw, None)
        got = c.take(code, verifier="v", redis=r)
        if "unknown_field" in raw:
            assert got is not None and got.user_id == "u"      # unknown keys are ignored, not fatal
        else:
            assert got is None, raw
    assert c.take("", verifier="v", redis=r) is None
    assert c.take("x" * 129, verifier="v", redis=r) is None
    assert c.take(None, verifier="v", redis=r) is None


def test_without_the_store_the_exchange_fails_closed():
    c = _codes()
    r = _Redis()
    r.broken = True
    with pytest.raises(c.Unavailable):
        c.store(_handover(verifier_hash=c.digest("v")), redis=r)
    with pytest.raises(c.Unavailable):
        c.take(c.make_secret(), verifier="v", redis=r)


@pytest.fixture
def own_store(monkeypatch):
    """The vault's own client replaced by the fake, with the outage guard and the limiter's breaker closed before
    and after."""
    _codes()
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
    c = _codes()
    from app.core import redis_guard
    code = c.store(_handover(verifier_hash=c.digest("v")))
    calls = []
    monkeypatch.setattr(own_store, "set", lambda *a, **k: calls.append("set"))
    monkeypatch.setattr(own_store, "getdel", lambda *a, **k: calls.append("getdel"))
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda now: True)
    with pytest.raises(c.Unavailable):
        c.store(_handover(verifier_hash=c.digest("v")))
    with pytest.raises(c.Unavailable):
        c.take(code, verifier="v")
    assert calls == []                      # refused before the socket, both ways


def test_a_failure_of_the_vaults_own_store_is_remembered_for_the_next_call(own_store):
    c = _codes()
    from app.core import redis_guard
    code = c.store(_handover(verifier_hash=c.digest("v")))
    assert not redis_guard.guard_private_open(time.time())
    own_store.broken = True
    with pytest.raises(c.Unavailable):
        c.take(c.make_secret(), verifier="v")
    assert redis_guard.guard_private_open(time.time())     # the first failure opens the shared memory
    own_store.broken = False                                # the store is back, the memory is not yet over:
    with pytest.raises(c.Unavailable):
        c.take(code, verifier="v")                          # still refused, and the code is not spent by it
    redis_guard.guard_record_success()
    assert c.take(code, verifier="v") is not None
    assert not redis_guard.guard_private_open(time.time())


def test_a_client_handed_in_is_called_whatever_the_guard_says(own_store, monkeypatch):
    c = _codes()
    from app.core import redis_guard
    monkeypatch.setattr(redis_guard, "guard_is_open", lambda now: True)
    r = _Redis()
    code = c.store(_handover(verifier_hash=c.digest("v")), redis=r)
    assert c.take(code, verifier="v", redis=r) is not None
    assert own_store.rows == {}


def test_a_record_round_trips_through_the_pipelines_result():
    c = _codes()
    from app.core.models import PendingLogin, User
    from app.services.sign_in import SignInResult
    user = types.SimpleNamespace(id=uuid.uuid4(), username="alice", is_active=True)
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None,
                                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=3))
    result = SignInResult(user, ["hwk"], "10.0.0.1", pending=pending, provider_id="p1", user_verified=True,
                          passwordless_allowed=True)
    record = c.from_result(result, verifier_hash=c.digest("v"))
    assert record.user_id == str(user.id) and record.pending_id == str(pending.id) and record.provider_id == "p1"
    assert record.user_verified and record.passwordless_allowed and not record.provider_mfa_trusted
    db = MemoryDB({User: [user], PendingLogin: [pending]})
    back = c.to_result(db, record, client_ip="10.0.0.2")
    assert back.user is user and back.methods == ["hwk"] and back.pending is pending
    assert back.client_ip == "10.0.0.2" and back.provider_id == "p1" and back.user_verified
    # The account must still be there and active; a pending login it names must still be live.
    assert c.to_result(MemoryDB({User: [], PendingLogin: [pending]}), record) is None
    user.is_active = False
    assert c.to_result(db, record) is None
    user.is_active = True
    pending.consumed_at = datetime.now(timezone.utc)
    assert c.to_result(db, record) is None
    pending.consumed_at = None
    pending.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert c.to_result(db, record) is None
    assert c.to_result(db, c.Handover(user_id="not-a-uuid", methods=[]), client_ip=None) is None
