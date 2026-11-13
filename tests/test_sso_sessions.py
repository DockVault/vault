"""What a session signed in through a provider remembers and the provider's logouts (app/services/sign_in.py
_record_provider_session, app/api/sso_router.py backchannel_logout, app/services/sso_sign_in.py provider_logout_url):
the row written at the sign-in with the provider's session id and subject (the ID token encrypted only when the
provider logout option is on), also for an administrator who adds the password; a back-channel logout token ending
the sessions it names by sid, else by subject, and no others, honoured once, every bad token the same 400; the
provider's logout address answered at the vault's sign-out when the option is on. Offline."""
import time
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env
from test_oidc_client import CLIENT, ISSUER
from test_sso_resolution import Resolving, _sign_in
from test_sso_sign_in import _call, _claims, _identity, _provider, _user

pytestmark = pytest.mark.unit


class Sessions(Resolving):
    """The resolution harness plus the session rows a provider sign-in writes, and sessions revoked observed."""

    def __init__(self, monkeypatch, users, providers, identities=(), **kw):
        super().__init__(monkeypatch, users, providers, identities=identities, **kw)
        S = self.S
        from app.core import security
        from app.core.models import SsoSession
        self.db.tables.setdefault(SsoSession, [])
        monkeypatch.setattr(security, "encrypt_secret", lambda value: "enc:" + value)
        monkeypatch.setattr(security, "decrypt_secret", lambda value: value[4:] if value.startswith("enc:") else "s3cret")
        self.revoked = []
        real = S._revoke_sessions

        def revoke(db, **kw):
            self.revoked.append(kw)
            return real(db, **kw)
        monkeypatch.setattr(S, "_revoke_sessions", revoke)
        monkeypatch.setattr(S, "_force_close_after_commit", lambda db, payload, *a, **kw: None)
        # The password door's turn-taking and lockouts need the database; the memory store has none.
        from app.core import sign_in_lockout
        for name, answer in (("take_turn", None), ("release_expired", 0), ("lock_in_force", None), ("count_at_limit", None),
                             ("end_administrators_open_locks", 0), ("clear_after_success", None), ("phantom_attempt", None)):
            monkeypatch.setattr(sign_in_lockout, name, lambda *a, _answer=answer, **k: _answer)
        # The memory store sets no column defaults: rows get the id and the session its active flag as the
        # database would.
        from app.core.models import ActiveSession
        real_add = self.db.add

        def add(obj):
            if getattr(obj, "id", "no-id-column") is None:
                obj.id = uuid.uuid4()
            if isinstance(obj, ActiveSession) and obj.is_active is None:
                obj.is_active = True
            if isinstance(obj, ActiveSession) and getattr(obj, "revoked", None) is None:
                obj.revoked = False
            real_add(obj)
        self.db.add = add

    def sso_sessions(self):
        from app.core.models import SsoSession
        return self.db.rows_of(SsoSession)

    def active_sessions(self):
        from app.core.models import ActiveSession
        return self.db.rows_of(ActiveSession)

    def logout(self, provider, token):
        return _form(self.S, f"/auth/sso/{provider.id}/backchannel-logout", {"logout_token": token})

    def logout_token(self, **claims):
        now = time.time()
        body = {"iss": ISSUER, "aud": CLIENT, "iat": int(now), "exp": int(now) + 120, "jti": uuid.uuid4().hex,
                "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
        body.update(claims)
        return self.signer.token({k: v for k, v in body.items() if v is not ...})


def _form(S, path, fields):
    """A form post, as a provider sends a back-channel logout."""
    import json
    from urllib.parse import urlencode
    from _async_run import run_coroutine
    out = {}

    async def _drive():
        payload = urlencode(fields).encode()
        hdrs = [(b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(len(payload)).encode())]
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": hdrs, "client": ("203.0.113.9", 1234), "server": ("testserver", 80),
                 "scheme": "https"}
        chunks = []

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))
        await S.app(scope, receive, send)
        raw = b"".join(chunks)
        try:
            out["body"] = json.loads(raw or b"null")
        except ValueError:
            out["body"] = raw.decode("utf-8", "replace")
    run_coroutine(_drive(), timeout=30)
    return out["status"], out["body"]


def _signed_in(h, p, **claims):
    location, _ = _sign_in(h, p, **claims)
    assert location.startswith("/#sso="), location
    status, body = h.finish(location)
    assert status == 200, body
    return body


# --------------------------------------------------------------------------- the session's record

def test_a_provider_sign_in_remembers_the_providers_session_and_subject(monkeypatch):
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="idp-session-1")
    (session,) = h.active_sessions()
    (record,) = h.sso_sessions()
    assert record.session_id == session.id and record.provider_id == p.id
    assert record.idp_sid == "idp-session-1" and record.idp_sub == "subject-1" and record.auth_time is not None
    assert record.id_token_enc is None                              # the provider logout option is off: no token kept
    # With the option on, the ID token is kept encrypted, never plain.
    p.policy = {"sso_idp_logout": True}
    _signed_in(h, p, sid="idp-session-2")
    second = [r for r in h.sso_sessions() if r.idp_sid == "idp-session-2"][0]
    assert second.id_token_enc.startswith("enc:eyJ") and "." in second.id_token_enc
    # Nothing of it in the one-time code store but the encrypted token.
    for key, value in h.redis.rows.items():
        if key.startswith("signin:code:"):
            assert "eyJ" not in value or "enc:eyJ" in value


def test_an_administrator_who_adds_the_password_gets_the_record_too(monkeypatch):
    root, p = _user("root", role="admin"), _provider(policy={"sso_idp_logout": True})
    h = Sessions(monkeypatch, [root], [p], identities=[_identity(root, p)])
    from app.services import auth_service as A
    monkeypatch.setattr(A, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")
    provider_moment = int(time.time()) - 100
    location, _ = _sign_in(h, p, sid="idp-session-admin", auth_time=provider_moment)
    status, body = h.finish(location)
    assert status == 200 and body["stage"] == "password", body
    # The provider's session rides in the pre-authentication token, not in a row; the logout hint waits in the
    # store, encrypted, under the pending login.
    claims = _claims(body["pre_auth_token"])
    assert claims["idp_sid"] == "idp-session-admin" and claims["idp_auth_time"] == provider_moment
    assert h.sso_sessions() == []
    staged = [v for k, v in h.redis.rows.items() if k.startswith("sso:logout-hint:")]
    assert len(staged) == 1 and staged[0].startswith("enc:eyJ")
    # A wrong password leaves it for the retry.
    monkeypatch.setattr(A.AuthService, "_record_failed_login", lambda self, name, ip, user=None: None)
    status, _wrong, _ = _call(h.S, "POST", "/auth/login", {"username": "root", "password": "nope"},
                              headers={"Authorization": f"Bearer {body['pre_auth_token']}"})
    assert status == 401
    status, done, _ = _call(h.S, "POST", "/auth/login", {"username": "root", "password": "pw"},
                            headers={"Authorization": f"Bearer {body['pre_auth_token']}"})
    assert status == 200 and "access_token" in done, done
    (record,) = h.sso_sessions()
    assert record.idp_sid == "idp-session-admin" and record.idp_sub == "subject-1"
    assert record.id_token_enc.startswith("enc:eyJ")                                    # the provider's own logout works for them
    assert abs(record.auth_time.replace(tzinfo=None).timestamp() - datetime.utcfromtimestamp(provider_moment).timestamp()) < 2


# --------------------------------------------------------------------------- back-channel logout

def test_a_logout_token_ends_the_sessions_it_names_and_no_others(monkeypatch):
    alice, bob, p = _user(), _user("bob"), _provider()
    h = Sessions(monkeypatch, [alice, bob], [p], identities=[_identity(alice, p), _identity(bob, p, subject="subject-bob")])
    _signed_in(h, p, sid="s-alice-1")
    _signed_in(h, p, sid="s-alice-2")
    _signed_in(h, p, sid="s-bob", sub="subject-bob", email="bob@example.test")
    assert len(h.active_sessions()) == 3 and all(s.is_active for s in h.active_sessions())
    # By the provider's session id: that one session.
    status, body = h.logout(p, h.logout_token(sid="s-alice-1", sub="subject-1"))
    assert status == 200 and body == {}, body
    ended = [s for s in h.active_sessions() if not s.is_active]
    assert len(ended) == 1 and h.revoked[-1]["durable"] is True and h.revoked[-1]["actor_username"] == "provider logout"
    gone = [r for r in h.sso_sessions() if r.session_id == ended[0].id]
    assert gone and gone[0].idp_sid == "s-alice-1"
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "success" and a[2] == {"provider_id": str(p.id), "by": "sid", "sessions": 1}
               for a in h.audits), h.audits
    # By the subject (no sid): every session of that subject at this provider, nobody else's.
    status, body = h.logout(p, h.logout_token(sub="subject-1"))
    assert status == 200
    still = [s for s in h.active_sessions() if s.is_active]
    assert len(still) == 1 and [r for r in h.sso_sessions() if r.session_id == still[0].id][0].idp_sub == "subject-bob"
    # A session of another provider with the same sid is not this provider's business.
    q = _provider(name="other")
    from app.core.models import SsoProvider
    h.db.rows_of(SsoProvider).append(q)
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(_identity(bob, q, subject="subject-bob"))
    _signed_in(h, q, sid="s-bob", sub="subject-bob", email="bob@example.test")
    before = len([s for s in h.active_sessions() if s.is_active])
    h.logout(p, h.logout_token(sid="s-bob", sub="subject-bob"))
    assert len([s for s in h.active_sessions() if s.is_active]) == before - 1
    # A token id is remembered per provider: the other provider's token with the same id is its own, not a replay.
    assert h.logout(p, h.logout_token(sid="nobody", jti="shared-id"))[0] == 200
    status, body = h.logout(q, h.logout_token(sid="s-bob", sub="subject-bob", jti="shared-id"))
    assert status == 200 and not [s for s in h.active_sessions() if s.is_active], body
    # Nothing named ends nothing: the guards that keep a provider's logout from ending every session.
    _signed_in(h, p, sid="s-alice-3")
    assert h.S._revoke_sessions(h.db, session_ids=[]) == 0 and h.S._revoke_sessions(h.db) == 0
    assert len([s for s in h.active_sessions() if s.is_active]) == 1


@pytest.mark.parametrize("spoil", ["no_token", "wrong_provider", "not_a_token", "with_nonce", "no_event", "no_sid_no_sub",
                                   "empty_sid_no_sub", "old", "replayed", "option_off", "unknown_provider", "wrong_audience",
                                   "not_an_oidc_provider"])
def test_every_bad_logout_token_is_the_same_400_and_ends_nothing(monkeypatch, spoil):
    alice, p, other = _user(), _provider(), _provider(name="other", client_id="other-client")
    h = Sessions(monkeypatch, [alice], [p, other], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    token = h.logout_token(sid="s-1", sub="subject-1")
    target = p
    fields_token = token
    if spoil == "no_token":
        fields_token = ""
    elif spoil == "wrong_provider":
        target = other
    elif spoil == "not_a_token":
        fields_token = "not.a.token"
    elif spoil == "with_nonce":
        fields_token = h.logout_token(sid="s-1", nonce="n")
    elif spoil == "no_event":
        fields_token = h.logout_token(sid="s-1", events=...)
    elif spoil == "no_sid_no_sub":
        fields_token = h.logout_token()
    elif spoil == "empty_sid_no_sub":
        fields_token = h.logout_token(sid="")                 # an empty string names nothing
    elif spoil == "not_an_oidc_provider":
        p.kind = "saml"
    elif spoil == "old":
        fields_token = h.logout_token(sid="s-1", iat=int(time.time()) - 3600)
    elif spoil == "replayed":
        assert h.logout(p, token)[0] == 200
        _signed_in(h, p, sid="s-1")                      # a new session with the same provider session id
    elif spoil == "option_off":
        p.policy = {"sso_backchannel_logout": False}
    elif spoil == "unknown_provider":
        target = types.SimpleNamespace(id=uuid.uuid4())
    elif spoil == "wrong_audience":
        fields_token = h.logout_token(sid="s-1", aud="someone-else")
    active_before = len([s for s in h.active_sessions() if s.is_active])
    status, body = h.logout(target, fields_token)
    assert status == 400 and body == {"error": "invalid_request"}, (spoil, status, body)
    assert len([s for s in h.active_sessions() if s.is_active]) == active_before
    if spoil == "unknown_provider":
        # An address with no provider behind it is anyone's to type: answered alike, and nothing is recorded.
        assert not [a for a in h.audits if a[0] == "sso_backchannel_logout"], h.audits
    else:
        assert any(a[0] == "sso_backchannel_logout" and a[1] == "failure" for a in h.audits), h.audits
    assert all("subject-1" not in str(a[2].get("reason", "")) for a in h.audits if isinstance(a[2], dict))


def test_the_back_channel_limiter_keeps_a_bucket_per_provider_and_source_and_a_trace_of_what_it_refused(monkeypatch):
    """A bucket per source for each provider and one shared by every id with no provider behind it, failing closed; a
    known provider's refused logout recorded once per window for each source (another source's flood does not use the
    trace up), nothing written when the counter of those traces cannot be asked, nothing for an unknown id."""
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    token = h.logout_token(sid="s-1", sub="subject-1")
    from app.api import sso_router
    from app.core import sign_in_lockout
    from app.core.rate_limiter import RateLimiterUnavailable, rate_limiter as RL
    source = sign_in_lockout.source_of("203.0.113.9")
    asked, noted = [], []
    real = RL.check_rate_limit
    note_down = []

    def refusing(*a, **kw):
        if kw.get("prefix") == "sso_backchannel":
            asked.append((kw.get("identifier"), kw.get("limit"), kw.get("window"), kw.get("fail_open")))
            return (False, 0, 10)
        if kw.get("prefix") == "sso_backchannel_refused":
            if note_down:
                raise RateLimiterUnavailable("down")
            noted.append((kw.get("identifier"), kw.get("limit"), kw.get("window"), kw.get("fail_open")))
            return (len(noted) == 1, 0, 10)
        return real(*a, **kw)
    monkeypatch.setattr(RL, "check_rate_limit", refusing)
    assert h.logout(p, token) == (501, {"error": "logout_failed"})
    assert h.logout(p, token) == (501, {"error": "logout_failed"})
    window = sso_router.START_WINDOW
    assert asked == [(f"{source}:{p.id}", sso_router.LOGOUT_LIMIT, window, False)] * 2 and sso_router.LOGOUT_LIMIT >= 600
    assert noted == [(f"{p.id}:{source}", 1, window, False)] * 2
    limited = [a for a in h.audits if a[0] == "sso_backchannel_logout" and a[2].get("reason") == "rate_limited"]
    assert limited == [("sso_backchannel_logout", "failure", {"provider_id": str(p.id), "reason": "rate_limited"})]
    h.logout(types.SimpleNamespace(id=uuid.uuid4()), token)
    h.logout(types.SimpleNamespace(id=uuid.uuid4()), token)
    assert [a[0] for a in asked[-2:]] == [f"{source}:unknown"] * 2 and len(noted) == 2
    # The counter of traces down: nothing is written (a flood during an outage writes no row per request).
    note_down.append(True)
    before = len(h.audits)
    assert h.logout(p, token) == (501, {"error": "logout_failed"})
    assert len(h.audits) == before


def test_a_logout_the_vault_cannot_act_on_is_a_failed_logout_not_an_invalid_token(monkeypatch):
    """The specification's 400 says the token is not valid and the provider does not retry; everything the vault
    could not act on is 501, the logout failed, so it may: the state store down, the provider unreachable (and not
    asked again for a while), its address refused, its discovery no longer fitting, its keys not fetched, a
    configuration the vault cannot read, anything unexpected while verifying, every slot busy past a short wait. A
    token whose own issuer is wrong is the token's fault: 400."""
    import asyncio
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    token = h.logout_token(sid="s-1", sub="subject-1")
    from app.api import sso_router
    from app.core import sso_state
    from app.services import oidc_client as oc
    from app.services import sso_sign_in as sso

    def reasons():
        return [a[2].get("reason") for a in h.audits if a[0] == "sso_backchannel_logout" and a[1] == "failure"]
    failed = (501, {"error": "logout_failed"})
    # The state store down.
    real_seen = sso_state.seen_logout_jti
    monkeypatch.setattr(sso_state, "seen_logout_jti", lambda *a, **k: (_ for _ in ()).throw(sso_state.Unavailable("down")))
    assert h.logout(p, token) == failed and reasons()[-1] == "store_unavailable"
    monkeypatch.setattr(sso_state, "seen_logout_jti", real_seen)
    # The provider unreachable, then not asked again for a short while.
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    serving = oc.fetch_json
    fetched = []
    monkeypatch.setattr(oc, "fetch_json", lambda *a, **k: fetched.append(1) or (_ for _ in ()).throw(
        oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")))
    assert h.logout(p, token) == failed and reasons()[-1] == "temporarily_unavailable"
    monkeypatch.setattr(oc, "fetch_json", serving)
    assert h.logout(p, token) == failed and len(fetched) == 1
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    # Its address refused (a private one, not allowed for this provider).
    monkeypatch.setattr(oc, "_resolve", lambda host: ["10.0.0.7"])
    assert h.logout(p, token) == failed and reasons()[-1] == "endpoint_refused"
    monkeypatch.setattr(oc, "_resolve", lambda host: ["8.8.8.8"])
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    # Its discovery no longer fitting what the vault was configured with.
    h.discovery_overrides["issuer"] = "https://elsewhere.example.com"
    assert h.logout(p, token) == failed and reasons()[-1] == "issuer_mismatch"
    h.discovery_overrides.pop("issuer")
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    # Its keys not fetched.
    monkeypatch.setattr(oc, "fetch_json", lambda url, *a, **k: (_ for _ in ()).throw(oc.OidcError(oc.PROVIDER_ERROR, "not JSON"))
                        if url.endswith("/certs") else serving(url, *a, **k))
    assert h.logout(p, token) == failed and reasons()[-1] == "provider_error"
    monkeypatch.setattr(oc, "fetch_json", serving)
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    # A configuration the vault cannot read.
    real_config = sso.provider_config
    monkeypatch.setattr(sso, "provider_config", lambda row: (_ for _ in ()).throw(sso.Refusal("secret_unreadable", "secret")))
    assert h.logout(p, token) == failed and reasons()[-1] == "secret_unreadable"
    monkeypatch.setattr(sso, "provider_config", real_config)
    # Anything unexpected while verifying.
    real_verify = oc.verify_logout_token
    monkeypatch.setattr(oc, "verify_logout_token", lambda *a, **k: (_ for _ in ()).throw(ValueError("a key the library cannot read")))
    assert h.logout(p, token) == failed and reasons()[-1] == "verification_error"
    monkeypatch.setattr(oc, "verify_logout_token", real_verify)
    # Every slot busy past a short wait: recorded once per window.
    monkeypatch.setattr(sso_router, "_BACKCHANNEL_SLOTS", asyncio.Semaphore(0))
    monkeypatch.setattr(sso_router, "BACKCHANNEL_WAIT_SECONDS", 0.05)
    assert h.logout(p, token) == failed and reasons()[-1] == "busy"
    monkeypatch.setattr(sso_router, "_BACKCHANNEL_SLOTS", asyncio.Semaphore(sso_router.BACKCHANNEL_CONCURRENCY))
    assert 1 <= sso_router.BACKCHANNEL_CONCURRENCY <= 8 and sso_router.BACKCHANNEL_WAIT_SECONDS <= 10
    # A key the vault does not hold after a fresh fetch: the token's fault (400). Another unknown key within the
    # minute after that fetch may be newer than it: not the token's fault (501, the provider retries).
    import time as _time
    def keyed(kid):
        now = int(_time.time())
        return h.signer.token({"iss": oc_issuer(), "aud": oc_client(), "iat": now, "exp": now + 120,
                               "jti": uuid.uuid4().hex, "sid": "s-1",
                               "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}, kid=kid)
    assert h.logout(p, keyed("rotated-0")) == (400, {"error": "invalid_request"})        # the first fetch of the keys
    assert h.logout(p, keyed("rotated-1")) == (400, {"error": "invalid_request"})        # a refetch, still unknown
    assert h.logout(p, keyed("rotated-2")) == failed and reasons()[-1] == "temporarily_unavailable"
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    # A token whose own issuer is wrong: the token's fault.
    wrong = h.logout_token(sid="s-1", sub="subject-1", iss="https://elsewhere.example.com")
    assert h.logout(p, wrong) == (400, {"error": "invalid_request"}) and reasons()[-1] == "issuer_mismatch"
    # None of the failures spent the token: the provider's retry ends the session.
    assert all(s.is_active for s in h.active_sessions())
    status, body = h.logout(p, token)
    assert status == 200 and not [s for s in h.active_sessions() if s.is_active], body


def oc_issuer():
    return ISSUER


def oc_client():
    return CLIENT


def test_a_logout_waits_for_a_slot_that_frees_up(monkeypatch):
    """Every slot in use, then one freed within the wait: the logout is verified, not refused."""
    import asyncio
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    from app.api import sso_router
    released = []

    class FreedSoon:
        async def acquire(self):
            await asyncio.sleep(0.05)                # another logout gives its slot back meanwhile
            return True

        def release(self):
            released.append(True)
    monkeypatch.setattr(sso_router, "_BACKCHANNEL_SLOTS", FreedSoon())
    status, body = h.logout(p, h.logout_token(sid="s-1", sub="subject-1"))
    assert status == 200 and released == [True], body


def test_the_back_channel_logout_gives_its_connection_back_before_the_network_work(monkeypatch):
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    from app.services import oidc_client as oc
    events = []
    real_rollback, real_discover = h.db.rollback, oc.discover
    monkeypatch.setattr(h.db, "rollback", lambda: events.append("rollback") or real_rollback())
    monkeypatch.setattr(oc, "discover", lambda *a, **k: events.append("discover") or real_discover(*a, **k))
    assert h.logout(p, h.logout_token(sid="s-1", sub="subject-1"))[0] == 200
    assert "rollback" in events and events.index("rollback") < events.index("discover"), events


def test_a_session_that_cannot_be_read_counts_as_live():
    """After a failed commit the token is forgotten when a named session is still live; a read that fails counts as
    live (the provider's retry then ends the sessions: the safer side)."""
    set_bare_api_env()
    from app.api import sso_router
    rolled = []

    class Broken:
        def query(self, *a, **k):
            raise RuntimeError("the connection is gone")

        def rollback(self):
            rolled.append(True)
    assert sso_router._a_session_is_live(Broken(), [uuid.uuid4()]) is True and rolled == [True]


def test_the_hint_cleanup_asks_whether_the_table_exists():
    """A database without the provider-session table (one a test builds with only the tables it needs, or a store
    the boot has not reached yet) gives nothing to clean and no error: the revocation that asked goes on."""
    set_bare_api_env()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.services import sign_in
    engine = create_engine("sqlite://")
    db = sessionmaker(bind=engine)()
    try:
        assert sign_in.table_present(db, "sso_sessions") is False
        assert sign_in.forget_provider_logout_hints(db, [uuid.uuid4()]) == 0
        from app.core.models import SsoSession
        SsoSession.__table__.create(engine)
        assert sign_in.table_present(db, "sso_sessions") is True
        assert sign_in.forget_provider_logout_hints(db, [uuid.uuid4()]) == 0
    finally:
        db.close()


def test_an_ended_session_keeps_no_logout_hint(monkeypatch):
    """The encrypted ID token is kept for the provider's own logout at sign-out; a session the provider ended, an
    administrator revoked or that ran out makes none, so the token (with the person's claims) goes with it."""
    alice, p = _user(), _provider(policy={"sso_idp_logout": True})
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    for sid in ("s-1", "s-2", "s-3"):
        _signed_in(h, p, sid=sid)
    rows = {r.idp_sid: r for r in h.sso_sessions()}
    assert all(r.id_token_enc.startswith("enc:") for r in rows.values())
    assert h.logout(p, h.logout_token(sid="s-1", sub="subject-1"))[0] == 200
    assert rows["s-1"].id_token_enc is None and rows["s-2"].id_token_enc.startswith("enc:")
    h.S._revoke_sessions(h.db, user_id=alice.id, durable=True, except_session_token=None)
    assert rows["s-2"].id_token_enc is None and rows["s-3"].id_token_enc is None
    # (A session that simply runs out keeps its hint until the retention prune deletes the session's row, and the
    # record with it: the web app's idle clean-up marks sessions inactive, not revoked, and they may still work.)
    from app.services import auth_service as A
    # A session a password sign-in elsewhere marked inactive is not revoked and keeps working: it keeps its hint, so
    # its own sign-out still offers the provider's logout.
    _signed_in(h, p, sid="s-5")
    row5 = [r for r in h.sso_sessions() if r.idp_sid == "s-5"][0]
    session5 = [s for s in h.active_sessions() if s.id == row5.session_id][0]
    A.AuthService(h.db)._terminate_session(session5)
    assert session5.is_active is False and session5.revoked is False and row5.id_token_enc.startswith("enc:")
    # (A durable revocation's second pass revokes such a session and drops the hint: pinned on a real database in
    # tests/test_revoke_idle_sessions.py, since this store's queries are not generative.)


def test_a_second_step_after_the_provider_records_the_providers_session_whatever_route_finishes_it(monkeypatch):
    """A route that finishes the step after a provider's sign-in (the second factor, a passkey, an enrollment) may
    know nothing of providers: the pipeline carries the provider's session from the pending login, so the session's
    row names the provider's session id and subject (the back-channel logout finds it), its time and the hint."""
    alice, p = _user(), _provider(policy={"sso_idp_logout": True})
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    monkeypatch.setattr(h.S, "_login_second_factor_in_effect", lambda db, user: True)
    moment = int(time.time()) - 50
    location, _ = _sign_in(h, p, sid="idp-session-2fa", auth_time=moment)
    status, body = h.finish(location)
    assert status == 200 and body["stage"] == "second_factor", body
    from app.core.models import PendingLogin
    from app.services import sign_in as s
    claims = _claims(body["pre_auth_token"])
    (pending,) = [r for r in h.db.rows_of(PendingLogin) if str(r.id) == claims["pre_auth"]]
    s.read_pre_auth(claims, pending)
    assert h.sso_sessions() == []
    signed = s.finish(h.db, s.SignInResult(alice, s.methods_so_far(pending) + [s.TOTP], "203.0.113.9", pending=pending,
                                           provider_id=s.provider_of(pending)))
    assert isinstance(signed, s.SignedIn)
    (record,) = h.sso_sessions()
    assert record.idp_sid == "idp-session-2fa" and record.idp_sub == "subject-1" and record.id_token_enc.startswith("enc:eyJ")
    assert abs(record.auth_time.replace(tzinfo=None).timestamp() - datetime.utcfromtimestamp(moment).timestamp()) < 2
    # A field the route set itself is kept.
    result = s.SignInResult(alice, [s.TOTP], None, pending=pending, provider_id=s.provider_of(pending), provider_sid="route-sid")
    s.carry_provider_session(result)
    assert result.provider_sid == "route-sid" and result.provider_sub == "subject-1"


def test_a_logout_that_could_not_be_applied_does_not_spend_the_token(monkeypatch):
    """The token's id is recorded when it is verified; if the sessions could not be ended, the id is forgotten and
    the answer is 501, so the provider's retry of the same token ends them."""
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    token = h.logout_token(sid="s-1", sub="subject-1")
    through = h.S._revoke_sessions
    calls = []

    def failing_once(db, **kw):
        calls.append(kw)
        if len(calls) == 1:
            raise RuntimeError("the database went away")
        return through(db, **kw)
    monkeypatch.setattr(h.S, "_revoke_sessions", failing_once)
    status, body = h.logout(p, token)
    assert (status, body) == (501, {"error": "logout_failed"})
    assert all(s.is_active for s in h.active_sessions())
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "failure" and a[2].get("reason") == "revocation_failed"
               for a in h.audits), h.audits
    status, body = h.logout(p, token)
    assert status == 200 and not [s for s in h.active_sessions() if s.is_active], body


def _renewal_made_meanwhile(h, user, like):
    """A session a renewal committed while a logout ran: a new session row with the provider's session copied."""
    from app.core.models import ActiveSession, SsoSession
    new = ActiveSession(session_token=uuid.uuid4().hex, user_id=user.id, ip_address="127.0.0.1")
    h.db.add(new)
    h.db.add(SsoSession(session_id=new.id, provider_id=like.provider_id, idp_sid=like.idp_sid, idp_sub=like.idp_sub,
                        auth_time=like.auth_time, id_token_enc=None))
    return new


def test_a_logout_looks_again_for_a_session_a_renewal_made_while_it_ran(monkeypatch):
    """A renewal ("Stay signed in") makes its new session, with the provider's session copied to it, before it ends
    the old one. A logout whose first look came before that session was committed asks again after ending what it
    found, and ends the new session too."""
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    old, kept = h.active_sessions()[0], h.sso_sessions()[0]
    through = h.S._revoke_sessions
    late = []

    def revoke(db, **kw):
        out = through(db, **kw)
        if not late:
            late.append(_renewal_made_meanwhile(h, alice, kept))
        return out
    monkeypatch.setattr(h.S, "_revoke_sessions", revoke)
    status, body = h.logout(p, h.logout_token(sid="s-1", sub="subject-1"))
    assert (status, body) == (200, {})
    assert late[0].is_active is False and late[0].revoked is True and old.is_active is False
    assert [kw["session_ids"] for kw in h.revoked] == [[old.id], [late[0].id]]
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "success" and a[2]["sessions"] == 2 for a in h.audits), h.audits


def test_a_logout_stops_looking_after_a_few_looks_and_with_nothing_new_asks_once_more_only(monkeypatch):
    from app.api import sso_router
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    kept = h.sso_sessions()[0]
    # Nothing new: the sessions are asked for once more and nothing more is ended.
    asked = []
    real_query = h.db.query

    def query(*entities):
        asked.append(entities)
        return real_query(*entities)
    monkeypatch.setattr(h.db, "query", query)
    status, _ = h.logout(p, h.logout_token(sid="s-1", sub="subject-1"))
    assert status == 200 and len(h.revoked) == 1
    monkeypatch.setattr(h.db, "query", real_query)
    # A session appearing at every look (it cannot happen: a renewal comes once a session): the looks are bounded.
    _signed_in(h, p, sid="s-2")
    kept = [r for r in h.sso_sessions() if r.idp_sid == "s-2"][0]
    h.revoked.clear()
    through = h.S._revoke_sessions

    def revoke(db, **kw):
        out = through(db, **kw)
        _renewal_made_meanwhile(h, alice, kept)
        return out
    monkeypatch.setattr(h.S, "_revoke_sessions", revoke)
    status, _ = h.logout(p, h.logout_token(sid="s-2", sub="subject-1"))
    assert status == 200 and len(h.revoked) == 1 + sso_router.BACKCHANNEL_MORE_LOOKS


def test_a_second_look_that_fails_does_not_spend_the_token(monkeypatch):
    """The sessions first found are ended; the look after them fails. The answer is 501 and the token's id is
    forgotten, so the provider's retry ends the session the renewal made."""
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    old, kept = h.active_sessions()[0], h.sso_sessions()[0]
    token = h.logout_token(sid="s-1", sub="subject-1")
    through = h.S._revoke_sessions
    calls, late = [], []

    def revoke(db, **kw):
        calls.append(kw)
        if len(calls) == 2:
            raise RuntimeError("the database went away")
        out = through(db, **kw)
        if not late:
            late.append(_renewal_made_meanwhile(h, alice, kept))
        return out
    monkeypatch.setattr(h.S, "_revoke_sessions", revoke)
    status, body = h.logout(p, token)
    assert (status, body) == (501, {"error": "logout_failed"})
    assert old.is_active is False and late[0].is_active is True
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "failure" and a[2].get("reason") == "revocation_failed"
               for a in h.audits), h.audits
    status, body = h.logout(p, token)
    assert status == 200 and late[0].is_active is False


def test_a_commit_that_fails_spends_the_token_only_when_the_logout_took_effect(monkeypatch):
    """A failed commit may still have reached the database. The token is forgotten (the provider's retry works) only
    when a session it named is still live; when they are all ended, it stays spent, so a replay cannot end sessions
    made later."""
    from app.core.models import ActiveSession
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    (session,) = h.active_sessions()
    through, real_commit, real_rollback = h.S._revoke_sessions, h.db.commit, h.db.rollback
    armed, faults = [], [True, False, True]   # the commit after the first and the third revocation fails

    def revoke(db, **kw):
        armed.append(faults.pop(0) if faults else False)
        return through(db, **kw)

    def commit():
        if armed and armed[-1]:
            armed[-1] = False
            raise RuntimeError("the connection dropped during the commit")
        return real_commit()
    monkeypatch.setattr(h.S, "_revoke_sessions", revoke)
    monkeypatch.setattr(h.db, "commit", commit)
    # The commit did not reach the database: the rollback brings the session back, the token is not spent.
    reverted = []

    def rollback_the_database():
        if session.revoked and not reverted:
            reverted.append(True)
            session.is_active, session.revoked = True, False
        return real_rollback()
    monkeypatch.setattr(h.db, "rollback", rollback_the_database)
    token = h.logout_token(sid="s-1", sub="subject-1")
    assert h.logout(p, token) == (501, {"error": "logout_failed"}) and session.is_active and not session.revoked
    status, body = h.logout(p, token)
    assert status == 200 and session.revoked is True, body
    # The commit reached the database although it raised: the session is ended, and the token stays spent.
    monkeypatch.setattr(h.db, "rollback", real_rollback)
    _signed_in(h, p, sid="s-2")
    token2 = h.logout_token(sid="s-2", sub="subject-1")
    assert h.logout(p, token2) == (501, {"error": "logout_failed"})
    second = [s for s in h.active_sessions() if s is not session][0]
    assert second.revoked is True
    assert h.logout(p, token2) == (400, {"error": "invalid_request"})                # a replay, refused


def test_a_failed_revocation_is_rolled_back_before_anything_is_recorded(monkeypatch):
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    from app.api import sso_router
    events = []
    real_rollback, real_audit = h.db.rollback, sso_router._audit
    monkeypatch.setattr(h.db, "rollback", lambda: events.append("rollback") or real_rollback())
    monkeypatch.setattr(sso_router, "_audit", lambda db, action, **kw: events.append(("audit", kw.get("details", {}).get("reason")))
                        or real_audit(db, action, **kw))
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, **kw: events.append("revoke") or (_ for _ in ()).throw(
        RuntimeError("down")))
    events.clear()
    assert h.logout(p, h.logout_token(sid="s-1", sub="subject-1")) == (501, {"error": "logout_failed"})
    after = events[events.index("revoke") + 1:]
    assert after == ["rollback", ("audit", "revocation_failed")], events


def test_an_empty_session_id_falls_back_to_the_subject(monkeypatch):
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    status, body = h.logout(p, h.logout_token(sid="", sub="subject-1"))
    assert status == 200 and not [s for s in h.active_sessions() if s.is_active], body
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "success" and a[2].get("by") == "sub" for a in h.audits)


def test_the_sign_out_routes_drop_the_hint_only_after_the_provider_logout_address_is_built():
    """Both sign-out routes end the session and drop its hint; the one that answers the provider's logout address
    builds it first (dropping it before would lose the address)."""
    import inspect
    set_bare_api_env()
    import app.api.api_server as S
    source = inspect.getsource(S.sign_out)
    assert source.count("forget_provider_logout_hints(") == 1
    assert source.index("provider_logout_url(") < source.index("forget_provider_logout_hints(")
    assert inspect.getsource(S.logout).count("forget_provider_logout_hints(") == 1


def test_the_back_channel_logout_fetches_the_providers_keys_off_the_event_loop():
    """Discovery and the keys are fetched over the network (a slow provider would hold every request on the loop):
    the verification runs in the thread pool, and one limiter bucket is kept per source address."""
    import inspect
    set_bare_api_env()
    from app.api import sso_router
    source = inspect.getsource(sso_router.backchannel_logout)
    assert source.count("await run_in_threadpool(verify)") == 1
    assert 'identifier=f"{source}:{scope or \'unknown\'}"' in source
    # The database connection goes back to the pool before the body is read or anything waits; a slot is taken, with
    # a bounded wait, before the network work and given back whatever happens.
    assert source.index("db.rollback()") < source.index("await request.form()") < source.index("_BACKCHANNEL_SLOTS.acquire()")
    assert source.index("_BACKCHANNEL_SLOTS.acquire()") < source.index("run_in_threadpool(verify)")
    assert source.count("_BACKCHANNEL_SLOTS.release()") == 1 and "finally:\n        _BACKCHANNEL_SLOTS.release()" in source


def test_the_table_check_asks_the_sessions_own_connection():
    import inspect
    set_bare_api_env()
    from app.services import sign_in
    source = inspect.getsource(sign_in.table_present)
    assert source.count("inspect(connection)") == 1 and "db.connection()" in source


def test_the_provider_logout_hint_is_never_in_the_results_text_form():
    set_bare_api_env()
    from app.services import sign_in as s
    result = s.SignInResult(types.SimpleNamespace(id=uuid.uuid4(), username="alice"), [], None,
                            provider_logout_hint="eyJ.the-id-token.sig")
    assert "the-id-token" not in repr(result)


# --------------------------------------------------------------------------- the provider's logout at sign-out

def test_the_vault_sign_out_answers_the_providers_logout_address_when_the_option_is_on(monkeypatch):
    alice, p = _user(), _provider(policy={"sso_idp_logout": True})
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    h.discovery_overrides["end_session_endpoint"] = ISSUER + "/protocol/openid-connect/logout"
    body = _signed_in(h, p, sid="s-1")
    from app.services import sso_sign_in as sso
    (session,) = h.active_sessions()
    url = sso.provider_logout_url(h.db, session)
    assert url.startswith(ISSUER + "/protocol/openid-connect/logout?") and "id_token_hint=eyJ" in url
    assert "post_logout_redirect_uri=https%3A%2F%2Fvault.example.test%2F" in url and "state=" in url
    # An end-session address that already carries a query keeps it.
    from app.services import oidc_client as oc
    h.discovery_overrides["end_session_endpoint"] = ISSUER + "/logout?tenant=dv"
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    url = sso.provider_logout_url(h.db, session)
    assert url.startswith(ISSUER + "/logout?tenant=dv&id_token_hint=eyJ"), url
    h.discovery_overrides["end_session_endpoint"] = ISSUER + "/protocol/openid-connect/logout"
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    # The option off, or a provider without the address: nothing, and the vault's sign-out stands on its own.
    p.policy = {"sso_idp_logout": False}
    assert sso.provider_logout_url(h.db, session) is None
    p.policy = {"sso_idp_logout": True}
    h.discovery_overrides["end_session_endpoint"] = ...                      # the signer leaves it out
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    assert sso.provider_logout_url(h.db, session) is None
    assert sso.provider_logout_url(h.db, None) is None
