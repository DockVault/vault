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
                out["headers"] = dict(msg.get("headers") or [])
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))
        await S.app(scope, receive, send)
        raw = b"".join(chunks)
        try:
            out["body"] = json.loads(raw or b"null")
        except ValueError:
            out["body"] = raw.decode("utf-8", "replace")
    run_coroutine(_drive(), timeout=30)
    # Whatever the answer to a provider's logout says, nothing between the provider and the vault keeps it: the
    # server marks every answer of the API so, and this route's answers are held to it one by one.
    kept = [part.strip() for part in out["headers"].get(b"cache-control", b"").decode().split(",")]
    assert "no-store" in kept, (path, out["status"], out["headers"])
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


def test_the_providers_session_is_remembered_in_the_commit_that_writes_the_session(monkeypatch):
    """A turn-off of the provider, and a logout the provider sends, find the sessions to end by this record, and
    wait for a sign-in that is being written. So the record is written with the session, in one commit: written
    in a commit of its own after it, a session was live for a moment with nothing to find it by, which is the
    moment such a change wakes in."""
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    waiting, _ = _sign_in(h, p, sid="s-1")
    seen, commit = [], h.db.commit

    def committed():
        seen.append((len(h.active_sessions()), len(h.sso_sessions())))
        return commit()
    monkeypatch.setattr(h.db, "commit", committed)
    assert h.finish(waiting)[0] == 200
    assert (1, 1) in seen and all(sessions == records for sessions, records in seen), seen


def test_a_logout_hint_that_cannot_be_sealed_is_left_out_and_the_sign_in_is_whole(monkeypatch):
    alice, p = _user(), _provider(policy={"sso_idp_logout": True})
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    waiting, _ = _sign_in(h, p, sid="s-1")
    from app.core import security

    def no_key(value):
        raise RuntimeError("no key")
    monkeypatch.setattr(security, "encrypt_secret", no_key)
    assert h.finish(waiting)[0] == 200
    (record,) = h.sso_sessions()
    assert record.idp_sid == "s-1" and record.id_token_enc is None


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
    assert abs(claims["idp_at"] - time.time()) < 60        # when the vault took the provider's answer
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


def test_a_logout_reads_the_sessions_again_under_the_turn_of_the_accounts_it_names(monkeypatch):
    """A renewal ("Stay signed in") moves the provider's session to a new session row under the account's turn at
    its sessions. The logout finds whose sessions the token names, takes those accounts' turn, and reads the
    sessions again under it: a renewal that committed while the logout waited for the turn is seen whole, and the
    session it made is ended with the rest."""
    from app.core.models import ActiveSession, SsoSession
    alice, bob, p = _user(), _user("bob"), _provider()
    h = Sessions(monkeypatch, [alice, bob], [p], identities=[_identity(alice, p), _identity(bob, p, subject="subject-bob")])
    _signed_in(h, p, sid="s-1")
    _signed_in(h, p, sid="s-bob", sub="subject-bob", email="bob@example.test")
    old = [s for s in h.active_sessions() if s.user_id == alice.id][0]
    kept = [r for r in h.sso_sessions() if r.session_id == old.id][0]
    order, made = [], []

    def turn(db, user_id):
        order.append(("turn", str(user_id)))
        if not made:
            # The renewal the logout waited for: the old session ended, a new one in its place with the record.
            new = ActiveSession(session_token=uuid.uuid4().hex, user_id=alice.id, ip_address="127.0.0.1")
            h.db.add(new)
            h.db.add(SsoSession(session_id=new.id, provider_id=kept.provider_id, idp_sid=kept.idp_sid,
                                idp_sub=kept.idp_sub, auth_time=kept.auth_time, id_token_enc="enc:hint"))
            old.is_active, old.revoked, kept.id_token_enc = False, True, None
            made.append(new)
    monkeypatch.setattr(h.S, "_sessions_turn", turn)
    through = h.S._revoke_sessions

    def revoke(db, **kw):
        order.append(("revoke", sorted(str(i) for i in kw["session_ids"])))
        return through(db, **kw)
    monkeypatch.setattr(h.S, "_revoke_sessions", revoke)
    status, body = h.logout(p, h.logout_token(sid="s-1", sub="subject-1"))
    assert (status, body) == (200, {})
    # The turn of the account the token names (alice's, nobody else's), before anything is ended; then one
    # revocation of what the second read found: the old session's record and the new one's.
    assert order == [("turn", str(alice.id)), ("revoke", sorted([str(old.id), str(made[0].id)]))]
    assert made[0].is_active is False and made[0].revoked is True
    assert [s for s in h.active_sessions() if s.is_active and s.user_id == bob.id]
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "success" and a[2]["sessions"] == 1 for a in h.audits), h.audits


def test_an_unlink_reads_the_sessions_again_under_the_turn_of_the_accounts_that_own_them(monkeypatch):
    """The same for an unlink. It ends the sessions that came through the identity: it finds them, takes the turn
    of the accounts they belong to, and reads them again under it. A renewal of one of them that committed while
    the unlink waited for the turn moved the provider's record to a new session; ended by the ids read first, that
    new session would go on working until its token ran out, signed in through an identity that is gone."""
    from app.api import sso_router
    from app.core.models import ActiveSession, SsoSession
    alice, bob, p = _user(), _user("bob"), _provider()
    identity = _identity(alice, p)
    h = Sessions(monkeypatch, [alice, bob], [p], identities=[identity, _identity(bob, p, subject="subject-bob")])
    _signed_in(h, p, sid="s-1")
    _signed_in(h, p, sid="s-bob", sub="subject-bob", email="bob@example.test")
    old = [s for s in h.active_sessions() if s.user_id == alice.id][0]
    kept = [r for r in h.sso_sessions() if r.session_id == old.id][0]
    order, made = [], []

    def turn(db, user_id):
        order.append(("turn", str(user_id)))
        if not made:
            new = ActiveSession(session_token=uuid.uuid4().hex, user_id=alice.id, ip_address="127.0.0.1")
            h.db.add(new)
            h.db.add(SsoSession(session_id=new.id, provider_id=kept.provider_id, idp_sid=kept.idp_sid,
                                idp_sub=kept.idp_sub, auth_time=kept.auth_time, id_token_enc="enc:hint"))
            old.is_active, old.revoked = False, True
            h.sso_sessions().remove(kept)                       # the record moved with the renewal
            made.append(new)
    monkeypatch.setattr(h.S, "_sessions_turn", turn)
    through = h.S._revoke_sessions

    def revoke(db, **kw):
        order.append(("revoke", sorted(str(i) for i in kw["session_ids"])))
        return through(db, **kw)
    monkeypatch.setattr(h.S, "_revoke_sessions", revoke)
    sso_router._end_what_came_through(h.db, alice, identity)
    # Alice's turn, then what the second read found: the session the renewal made, not the id read before it.
    assert order == [("turn", str(alice.id)), ("revoke", [str(made[0].id)])]
    assert made[0].is_active is False and made[0].revoked is True
    assert [s for s in h.active_sessions() if s.is_active and s.user_id == bob.id]      # bob's is another identity's


def test_a_logout_that_names_several_accounts_takes_their_turns_in_one_order(monkeypatch):
    """By subject, a token can name sessions of one account only; by a session id shared across accounts it cannot
    either. The order is fixed all the same, so two logouts never wait on each other's turn."""
    from app.api import sso_router
    from app.core.models import ActiveSession
    alice, bob, p = _user(), _user("bob"), _provider()
    h = Sessions(monkeypatch, [alice, bob], [p], identities=[_identity(alice, p), _identity(bob, p, subject="subject-bob")])
    _signed_in(h, p, sid="s-1")
    _signed_in(h, p, sid="s-bob", sub="subject-bob", email="bob@example.test")
    ids = [s.id for s in h.active_sessions()]
    assert sso_router._owners_of(h.db, ids) == sorted([str(alice.id), str(bob.id)])
    assert sso_router._owners_of(h.db, list(reversed(ids))) == sorted([str(alice.id), str(bob.id)])
    assert sso_router._owners_of(h.db, []) == [] and sso_router._owners_of(h.db, [uuid.uuid4()]) == []
    # Many owners, their sessions found in no order: by the account's id all the same.
    many = sorted(uuid.uuid4() for _ in range(12))
    rows = [types.SimpleNamespace(id=uuid.uuid4(), user_id=owner, is_active=True, revoked=False)
            for owner in reversed(many)]
    rows[0], rows[5] = rows[5], rows[0]
    h.db.rows_of(ActiveSession).extend(rows)
    assert sso_router._owners_of(h.db, [r.id for r in rows]) == sorted(str(owner) for owner in many)
    del h.db.rows_of(ActiveSession)[-len(rows):]
    # A token that names no session and nobody the vault knows takes no turn and ends nothing. One that names a
    # person takes that account's turn, with or without a session of theirs: a sign-in of theirs being written is
    # waited for, and the sessions are read after it.
    turns = []
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, user_id: turns.append(str(user_id)))
    status, _ = h.logout(p, h.logout_token(sid="no-such-session", sub="nobody-here"))
    assert status == 200 and turns == [] and h.revoked == []
    status, _ = h.logout(p, h.logout_token(sid="no-such-session"))
    assert status == 200 and turns == [] and h.revoked == []
    status, _ = h.logout(p, h.logout_token(sid="no-such-session", sub="subject-1"))
    assert status == 200 and turns == [str(alice.id)] and h.revoked == []
    assert all(s.is_active for s in h.db.rows_of(ActiveSession))
    # Sessions of one account and the person named being another: both turns, in the one order.
    del turns[:]
    status, _ = h.logout(p, h.logout_token(sid="s-bob", sub="subject-1"))
    assert status == 200 and turns == sorted([str(alice.id), str(bob.id)]), turns


def test_a_logout_by_session_id_ends_the_sign_in_under_way_that_came_through_that_session(monkeypatch):
    """A sign-in waiting in its handover code, or held for a further step, carries the provider's session id and
    would record it on a new vault session that no later logout names. The logout remembers when it logged the
    session out; a sign-in the provider answered before that is refused where it is written, and the refusal is
    recorded for what it is. A sign-in the provider answers after its logout is a new one, though it carries the
    same session id (a provider may keep one): it is finished as ever."""
    from app.core import sso_state
    from app.services import sign_in
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    order = []
    lock = h.db.query

    def query(*entities):
        made = lock(*entities)
        through = made.with_for_update

        def with_for_update(**kw):
            order.append(("row", getattr(entities[0], "__tablename__", None), kw))
            return through(**kw)
        made.with_for_update = with_for_update
        return made
    monkeypatch.setattr(h.db, "query", query)
    noted = sso_state.note_logged_out
    monkeypatch.setattr(sso_state, "note_logged_out",
                        lambda **kw: (order.append(("note", kw.get("sid"), kw.get("sub"), kw["scope"])), noted(**kw))[1])
    waiting, _ = _sign_in(h, p, sid="s-held")
    other, _ = _sign_in(h, p, sid="s-other")
    del order[:]
    assert h.logout(p, h.logout_token(sid="s-held", sub="subject-1"))[0] == 200
    # The provider's row for the logout before anything else, the key left free; then the session noted, and
    # not the person: the token names one session of theirs.
    assert order[:2] == [("row", "sso_providers", {"key_share": True}), ("note", "s-held", None, str(p.id))], order
    status, body = h.finish(waiting)
    assert status == 401 and body == {"detail": "This sign-in cannot be completed; start again."}, body
    assert not h.active_sessions()
    assert ("login_failure", alice.username, sign_in.PROVIDER_LOGGED_OUT_REASON) in h.audits, h.audits
    # Another session of the provider's is another sign-in: finished as ever.
    assert h.finish(other)[0] == 200 and len(h.active_sessions()) == 1
    # The person signs in again, and the provider answers with the session id it had: a new sign-in.
    again, _ = _sign_in(h, p, sid="s-held")
    assert h.finish(again)[0] == 200 and len(h.active_sessions()) == 2
    # The same session id at another provider is not this provider's.
    assert sso_state.logged_out_since(scope=str(p.id), sid="s-held") is not None
    assert sso_state.logged_out_since(scope=str(uuid.uuid4()), sid="s-held") is None
    assert sso_state.logged_out_since(scope=str(p.id), sid="", sub=None) is None
    assert sso_state.logged_out_since(scope=str(p.id), sub="s-held") is None           # a session id is no subject
    # Kept for longer than a sign-in under way lives: the handover code's minute and a held step's five.
    assert h.redis.ttl[sso_state._logged_out_key("sid", "s-held", str(p.id))] == sso_state.LOGGED_OUT_TTL_SECONDS
    assert sso_state.LOGGED_OUT_TTL_SECONDS > sso_state.HANDOVER_TTL_SECONDS + sign_in.PRE_AUTH_TTL_MINUTES * 60


def test_a_logout_by_the_subject_ends_the_persons_sign_ins_under_way_through_the_provider_and_no_others(monkeypatch):
    """A token that names the person and no session ends every session of theirs at this provider, and no
    session id says which sign-ins under way came through one. The person is remembered as logged out at that
    moment: a sign-in of theirs the provider answered before it (waiting in its handover code, say) is refused,
    one it answers after is finished, and another person's is never touched."""
    alice, bob, p = _user(), _user("bob"), _provider()
    h = Sessions(monkeypatch, [alice, bob], [p], identities=[_identity(alice, p), _identity(bob, p, subject="subject-bob")])
    waiting, _ = _sign_in(h, p, sid="s-1")
    bobs, _ = _sign_in(h, p, sid="s-bob", sub="subject-bob", email="bob@example.test")
    turns = []
    turn = h.S._sessions_turn
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, user_id: (turns.append(str(user_id)), turn(db, user_id))[1])
    assert h.logout(p, h.logout_token(sub="subject-1"))[0] == 200
    assert str(alice.id) in turns and str(bob.id) not in turns
    del turns[:]
    status, body = h.finish(waiting)
    assert status == 401 and body == {"detail": "This sign-in cannot be completed; start again."}, body
    assert h.finish(bobs)[0] == 200
    assert [s.user_id for s in h.active_sessions()] == [bob.id]
    again, _ = _sign_in(h, p, sid="s-2")
    assert h.finish(again)[0] == 200 and len(h.active_sessions()) == 2


def test_a_held_sign_in_carries_when_the_provider_answered_and_one_that_does_not_say_is_taken_as_before(monkeypatch):
    """The moment the vault took the provider's answer rides with the sign-in: in the handover record, and in the
    token of a step that holds it. A sign-in that carries none is taken as answered before any logout."""
    import types as _types
    from app.core import sso_state
    from app.services import sign_in
    row = _types.SimpleNamespace(id=uuid.uuid4(), policy=None)
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])

    def carried(**fields):
        return _types.SimpleNamespace(pending=None, provider_sid=None, provider_sub=None, provider_answered_at=None,
                                      **fields)
    sso_state.note_logged_out(scope=str(row.id), sid="s-1", at=1000.0)
    assert sign_in.logged_out_at_the_provider(row, carried()) is False                       # names nothing
    for answered, refused in ((999.0, True), (1000.0, True), (1000.5, False), (None, True), ("1001", True), (True, True)):
        result = carried()
        result.provider_sid, result.provider_answered_at = "s-1", answered
        assert sign_in.logged_out_at_the_provider(row, result) is refused, answered
    # From the token of a held step, where the result itself says nothing.
    held = _types.SimpleNamespace(_provider_sid="s-1", _provider_sub=None, _provider_answered_at=1000.5)
    result = carried()
    result.pending = held
    assert sign_in.logged_out_at_the_provider(row, result) is False
    held._provider_answered_at = 999.0
    assert sign_in.logged_out_at_the_provider(row, result) is True
    # A later logout of the person counts beside an earlier one of the session: the later moment decides.
    sso_state.note_logged_out(scope=str(row.id), sub="subject-9", at=2000.0)
    result = carried()
    result.provider_sid, result.provider_sub, result.provider_answered_at = "s-1", "subject-9", 1500.0
    assert sign_in.logged_out_at_the_provider(row, result) is True
    result.provider_answered_at = 2000.5
    assert sign_in.logged_out_at_the_provider(row, result) is False
    # A note that cannot be read counts as a logout made now.
    h.redis.rows[sso_state._logged_out_key("sid", "s-odd", str(row.id))] = "not a moment"
    assert sso_state.logged_out_since(scope=str(row.id), sid="s-odd") >= time.time() - 5
    # The moment rides in the handover record and in the pre-authentication token.
    waiting, _ = _sign_in(h, p, sid="s-7")
    records = [v for k, v in h.redis.rows.items() if k.startswith("signin:code:")]
    import json
    assert records and abs(json.loads(records[-1])["provider_answered_at"] - time.time()) < 60
    payload = {"stage": "second_factor", "methods_so_far": [], "idp": str(p.id), "idp_sid": "s-7", "idp_at": 1234.5}
    pending = _types.SimpleNamespace()
    sign_in.read_pre_auth(payload, pending)
    assert pending._provider_answered_at == 1234.5
    assert sign_in.provider_session_of(pending)["provider_answered_at"] == 1234.5
    for odd in ("1234", True, None):
        sign_in.read_pre_auth(dict(payload, idp_at=odd), pending)
        assert pending._provider_answered_at is None, odd


def test_a_logged_out_session_is_asked_about_only_where_the_providers_logouts_are_taken(monkeypatch):
    """With the provider's logout option off nothing is noted and nothing asked; with it on, a store that cannot
    be reached refuses the sign-in as busy (whether the person was logged out cannot be told), and writes none."""
    from app.core import sso_state
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    waiting, _ = _sign_in(h, p, sid="s-1")
    again, _ = _sign_in(h, p, sid="s-2")

    def down(**kw):
        raise sso_state.Unavailable("down")
    monkeypatch.setattr(sso_state, "logged_out_since", down)
    status, body = h.finish(waiting)
    assert status == 503 and "busy" in body["detail"], body
    assert not h.active_sessions()
    p.policy = {"sso_backchannel_logout": False}
    assert h.finish(again)[0] == 200 and len(h.active_sessions()) == 1


def test_a_logout_that_cannot_note_what_it_names_fails_and_ends_nothing(monkeypatch):
    """The store down where the logout is noted: the logout failed (501), nothing is ended, and the token is not
    spent, so the provider's retry is honoured."""
    from app.core import sso_state
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _signed_in(h, p, sid="s-1")
    token = h.logout_token(sid="s-1", sub="subject-1")
    real = sso_state.note_logged_out

    def down(**kw):
        raise sso_state.Unavailable("down")
    monkeypatch.setattr(sso_state, "note_logged_out", down)
    status, body = h.logout(p, token)
    assert status == 501 and body == {"error": "logout_failed"}, body
    assert all(s.is_active for s in h.active_sessions()) and h.revoked == []
    monkeypatch.setattr(sso_state, "note_logged_out", real)
    assert h.logout(p, token)[0] == 200 and not [s for s in h.active_sessions() if s.is_active]


def test_a_sign_in_through_a_provider_holds_the_providers_row_before_the_accounts_turn(monkeypatch):
    """Where a session or a held sign-in is written: the provider's row first, shared (what turns the provider off,
    saves it or removes it takes the row for itself and waits, or is waited for), then the account's turn, then the
    account and the provider judged again as they are committed. A sign-in through no provider takes no row."""
    from app.core.models import SsoProvider
    from app.services import sign_in
    alice, p = _user(), _provider()
    h = Sessions(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    order = []
    through = h.db.query

    def query(*entities):
        made = through(*entities)
        lock = made.with_for_update

        def with_for_update(**kw):
            order.append(("row", getattr(entities[0], "__tablename__", None), kw))
            return lock(**kw)
        made.with_for_update = with_for_update
        return made
    monkeypatch.setattr(h.db, "query", query)
    turn = h.S._sessions_turn
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, user_id: (order.append(("turn", str(user_id))), turn(db, user_id))[1])
    stands = sign_in.refuse_unless_the_provider_stands
    monkeypatch.setattr(sign_in, "refuse_unless_the_provider_stands",
                        lambda db, result: (order.append(("provider judged",)), stands(db, result))[1])
    waiting, _ = _sign_in(h, p, sid="s-1")
    del order[:]
    assert h.finish(waiting)[0] == 200
    rows = [i for i, step in enumerate(order) if step[:2] == ("row", SsoProvider.__tablename__)]
    turns = [i for i, step in enumerate(order) if step[0] == "turn"]
    judged = [i for i, step in enumerate(order) if step == ("provider judged",)]
    assert rows and turns and rows[0] < turns[0], order
    assert order[rows[0]][2] == {"read": True}, order           # shared: sign-ins do not wait for each other
    assert judged and judged[-1] > turns[0], order               # judged again in the turn, after any wait
    # Turned off while the sign-in waited for its turn: refused in the turn, and nothing is written.
    another, _ = _sign_in(h, p, sid="s-2")
    before = len(h.active_sessions())

    def turned_off_meanwhile(db, user_id):
        p.state = "disabled"
    monkeypatch.setattr(h.S, "_sessions_turn", turned_off_meanwhile)
    status, body = h.finish(another)
    assert status == 401 and body == {"detail": "This sign-in cannot be completed; start again."}, body
    assert len(h.active_sessions()) == before


def test_the_providers_row_is_not_asked_for_by_a_sign_in_that_came_through_none():
    import types as _types
    from app.services import sign_in
    asked = []
    db = _types.SimpleNamespace(query=lambda *a: asked.append(a))
    sign_in.hold_the_providers_row(db, _types.SimpleNamespace(is_temporary=False, provider_id=None))
    sign_in.hold_the_providers_row(db, _types.SimpleNamespace(is_temporary=True, provider_id=str(uuid.uuid4())))
    sign_in.hold_the_providers_row(db, _types.SimpleNamespace(is_temporary=False, provider_id="not-an-id"))
    assert asked == []


def test_a_providers_row_held_too_long_refuses_the_sign_in_as_busy_and_writes_nothing(monkeypatch):
    import types as _types
    from fastapi import HTTPException
    from sqlalchemy.exc import OperationalError
    from app.services import sign_in

    class Held(Exception):
        pgcode = "55P03"

    class Other(Exception):
        pgcode = "40001"
    rolled = []

    def raising(orig):
        def query(*a):
            raise OperationalError("select", {}, orig)
        return _types.SimpleNamespace(query=query, rollback=lambda: rolled.append(1))
    dropped = []
    monkeypatch.setattr(sign_in, "delete_session_by_token", lambda db, token: dropped.append(token))
    result = _types.SimpleNamespace(is_temporary=False, provider_id=str(uuid.uuid4()), session_token="the-doors")
    with pytest.raises(HTTPException) as busy:
        sign_in.hold_the_providers_row(raising(Held()), result)
    assert busy.value.status_code == 503 and "busy" in busy.value.detail and rolled == [1]
    # A time to come back, and the session the password door made for this sign-in is deleted with it.
    assert busy.value.headers == {"Retry-After": "5"} and dropped == ["the-doors"] and result.session_token is None
    result.session_token = None
    with pytest.raises(OperationalError):
        sign_in.hold_the_providers_row(raising(Other()), result)


def test_what_ends_a_providers_sessions_spends_the_sign_ins_under_way_through_one_helper():
    """An unlink and a provider's refusal end the sessions that came through the identity, and the account's
    sign-ins under way with them: through the helper every other such place uses, which also drops a set-up left
    half-way. Counted, so a place added later is seen."""
    import inspect
    from app.api import sso_router
    from app.services import sso_freshness
    spends = "sign_in.spend_sign_ins_under_way("
    assert inspect.getsource(sso_router).count(spends) == 1          # the unlink's ending
    assert spends in inspect.getsource(sso_router._end_what_came_through)
    # A provider's logout spends none: it remembers what it names, and a sign-in the provider answered before
    # is refused where it is written (the tests of the logout above).
    assert spends not in inspect.getsource(sso_router.backchannel_logout)
    assert inspect.getsource(sso_freshness).count(spends) == 1
    for module in (sso_router, sso_freshness):
        assert "PendingLogin.consumed_at:" not in inspect.getsource(module), module.__name__
