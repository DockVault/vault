"""The login state of a single sign-on (app/core/sso_state.py): made once, spent once, with its nonce and PKCE
verifier; the abandoned-starts cap per address; what a malformed or foreign record is worth; the return address
allow-list; the store down. Offline, against a fake store with the sorted-set operations the module uses."""
import json
import time

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


class FakeRedis:
    def __init__(self):
        self.rows, self.zsets, self.ttl = {}, {}, {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.rows:
            return None
        self.rows[key] = value
        self.ttl[key] = ex
        return True

    def getdel(self, key):
        self.getdel_calls = getattr(self, "getdel_calls", 0) + 1
        return self.rows.pop(key, None)

    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)

    def zrem(self, key, *members):
        for m in members:
            self.zsets.get(key, {}).pop(m, None)

    def zremrangebyscore(self, key, low, high):
        low = float("-inf") if low == "-inf" else float(low)
        zs = self.zsets.get(key, {})
        for m in [m for m, s in zs.items() if low <= s <= float(high)]:
            zs.pop(m)

    def zcount(self, key, low, high):
        return sum(1 for s in self.zsets.get(key, {}).values() if float(low) <= s <= float(high))

    def expire(self, key, seconds):
        self.ttl[key] = seconds


def _mod():
    set_bare_api_env()
    from app.core import sso_state
    return sso_state


def test_a_start_is_recorded_once_and_spent_once():
    st = _mod()
    r = FakeRedis()
    now = 1_800_000_000.0
    record = st.begin(provider_id="p1", purpose=st.SIGN_IN, source="203.0.113.0/24", client_ip="203.0.113.9",
                      verifier_hash="a" * 64, return_to="#profile", redis=r, now=now)
    assert len(record.state) >= 43 and len(record.nonce) >= 43 and 43 <= len(record.code_verifier) <= 128
    assert record.return_to == "#profile" and record.started_at == int(now) and record.source == "203.0.113.0/24"
    key = st.KEY_PREFIX + record.state
    assert r.ttl[key] == 600 and json.loads(r.rows[key])["purpose"] == "sign_in"
    assert r.zsets[st.STARTED_PREFIX + "203.0.113.0/24"] == {record.state: now}
    taken = st.take(record.state, redis=r)
    assert taken is not None and taken.nonce == record.nonce and taken.code_verifier == record.code_verifier
    assert taken.verifier_hash == "a" * 64 and taken.user_id is None
    # Spent: gone from the store and from the abandoned count.
    assert st.take(record.state, redis=r) is None
    assert r.zsets[st.STARTED_PREFIX + "203.0.113.0/24"] == {}
    # Unknown, malformed and over-long states are None, never an error; the malformed ones never reach the store.
    asked = r.getdel_calls
    for bad in (None, "", "x" * 65, "has space", "../etc", "a%2Fb"):
        assert st.take(bad, redis=r) is None
    assert r.getdel_calls == asked
    assert st.take("a" * 43, redis=r) is None and r.getdel_calls == asked + 1


def test_the_return_address_is_one_of_the_apps_views():
    st = _mod()
    assert st.return_to_or_default("#profile") == "#profile"
    for bad in (None, "", "https://evil.example/", "#evil", "javascript:alert(1)", "#profile/../x", 5):
        assert st.return_to_or_default(bad) == "#vaults"


def test_a_sign_in_needs_a_proof_to_finish_with_and_a_purpose_the_module_knows():
    st = _mod()
    r = FakeRedis()
    with pytest.raises(ValueError):
        st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", redis=r)
    with pytest.raises(ValueError):
        st.begin(provider_id="p1", purpose="other", source="s", verifier_hash="a" * 64, redis=r)
    # A link or a test belongs to an account and needs no tab proof.
    link = st.begin(provider_id="p1", purpose=st.LINK, source="s", user_id="u1", session_hash="h1", redis=r)
    assert st.take(link.state, redis=r).user_id == "u1"
    # A stored record a different writer made (or a tampered one) is worth nothing.
    r.rows[st.KEY_PREFIX + "forged"] = json.dumps({"state": "forged", "provider_id": "p1", "purpose": "sign_in"})
    assert st.take("forged", redis=r) is None
    r.rows[st.KEY_PREFIX + "swapped"] = json.dumps({"state": "other", "provider_id": "p1", "purpose": "sign_in",
                                                   "nonce": "n", "code_verifier": "v", "return_to": "#vaults",
                                                   "verifier_hash": "a" * 64})
    assert st.take("swapped", redis=r) is None
    r.rows[st.KEY_PREFIX + "typed"] = json.dumps({"state": "typed", "provider_id": "p1", "purpose": "sign_in",
                                                 "nonce": "n", "code_verifier": "v", "return_to": "#vaults",
                                                 "verifier_hash": ["not", "a", "string"]})
    assert st.take("typed", redis=r) is None
    r.rows[st.KEY_PREFIX + "noproof"] = json.dumps({"state": "noproof", "provider_id": "p1", "purpose": "sign_in",
                                                   "nonce": "n", "code_verifier": "v", "return_to": "#vaults"})
    assert st.take("noproof", redis=r) is None


def test_too_many_abandoned_starts_from_one_address_are_refused_but_finished_ones_never_count():
    st = _mod()
    r = FakeRedis()
    now = 1_800_000_000.0
    # 200 starts an hour ago minus a bit, left unfinished (older than a state's life): the cap.
    for i in range(200):
        st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=r, now=now - 700 - i)
    assert st.abandoned_count("s", redis=r, now=now) == 200
    with pytest.raises(st.TooManyAbandoned):
        st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=r, now=now)
    # Another address is not affected.
    st.begin(provider_id="p1", purpose=st.SIGN_IN, source="t", verifier_hash="a" * 64, redis=r, now=now)
    # Starts still inside a state's life are not abandoned yet; starts older than an hour fall out of the window.
    r2 = FakeRedis()
    recent = [st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=r2, now=now - 10)
              for _ in range(250)]
    assert st.abandoned_count("s", redis=r2, now=now) == 0
    assert st.abandoned_count("s", redis=r2, now=now + 650) == 250
    assert st.abandoned_count("s", redis=r2, now=now + 3700) == 0
    # A start that was finished (its state taken) is never abandoned.
    r3 = FakeRedis()
    done = [st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=r3, now=now - 700)
            for _ in range(200)]
    for d in done:
        st.take(d.state, redis=r3)
    assert st.abandoned_count("s", redis=r3, now=now) == 0
    st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=r3, now=now)


def test_without_the_store_nothing_is_guessed():
    st = _mod()

    class Down:
        def __getattr__(self, name):
            def _fail(*a, **kw):
                raise ConnectionError("down")
            return _fail
    with pytest.raises(st.Unavailable):
        st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=Down())
    with pytest.raises(st.Unavailable):
        st.take("a" * 43, redis=Down())
    with pytest.raises(st.Unavailable):
        st.abandoned_count("s", redis=Down())
    # A store that will not write (a second writer got there first) is unavailable too, not a silent reuse.
    class NoWrite(FakeRedis):
        def set(self, key, value, ex=None, nx=False):
            return None
    with pytest.raises(st.Unavailable):
        st.begin(provider_id="p1", purpose=st.SIGN_IN, source="s", verifier_hash="a" * 64, redis=NoWrite(),
                 now=time.time())


def test_a_stored_record_is_checked_again_when_read():
    st = _mod()
    r = FakeRedis()
    good = {"state": "s1", "provider_id": "p1", "purpose": "sign_in", "nonce": "n", "code_verifier": "v",
            "return_to": "#vaults", "verifier_hash": "a" * 64}
    r.rows[st.KEY_PREFIX + "s1"] = json.dumps(good)
    assert st.take("s1", redis=r) is not None
    for broken in ({"return_to": "#x&evil=1"}, {"return_to": "https://evil.example/"}, {"purpose": "sign_up"},
                   {"purpose": 7}, {"nonce": ""}, {"extras": []}):
        r.rows[st.KEY_PREFIX + "s2"] = json.dumps({**good, "state": "s2", **broken})
        assert st.take("s2", redis=r) is None, broken


def test_a_finished_link_or_test_waits_under_a_one_time_code():
    st = _mod()
    r = FakeRedis()
    record = {"purpose": st.LINK, "provider_id": "p1", "user_id": "u1", "session_hash": "h1", "verifier_hash": "a" * 64,
              "subject": "s", "issuer": "https://idp.example.com", "tenant_id": None, "email": "a@example.test",
              "email_verified": True, "display_name": "A"}
    code = st.store_handover(record, redis=r)
    assert len(code) >= 43
    (key,) = r.rows
    assert key.startswith(st.HANDOVER_PREFIX) and code not in key and r.ttl[key] == 60     # stored by its hash
    assert st.take_handover(code, redis=r) == record
    assert st.take_handover(code, redis=r) is None                                      # one use
    # Malformed codes never reach the store; a record of another shape is worth nothing.
    asked = r.getdel_calls
    for bad in (None, "", "x" * 129, "has space"):
        assert st.take_handover(bad, redis=r) is None
    assert r.getdel_calls == asked
    import hashlib
    for broken in ({"purpose": "sign_in"}, {"user_id": ""}, {"verifier_hash": None}, {"subject": 5}, {"tenant_id": 1},
                   {"email_verified": "true"}, {"summary": "x"}, {"purpose": st.STEP_UP}, {"purpose": st.STEP_UP, "step_up_action": ""},
                   {"purpose": st.STEP_UP, "step_up_action": 3}, {"step_up_action": 3}):
        r.rows[st.HANDOVER_PREFIX + hashlib.sha256(b"c2").hexdigest()] = json.dumps({**record, **broken})
        assert st.take_handover("c2", redis=r) is None, broken
    # A re-authentication's record names the step-up action it was made for.
    staged = {**record, "purpose": st.STEP_UP, "step_up_action": "admin.retention.write"}
    assert st.take_handover(st.store_handover(staged, redis=r), redis=r) == staged
    with pytest.raises(st.Unavailable):
        st.store_handover(record, redis=type("Down", (), {"set": lambda *a, **k: (_ for _ in ()).throw(ConnectionError())})())
