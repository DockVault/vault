"""What a session signed in through a provider remembers and the provider's logouts (app/services/sign_in.py
_record_provider_session, app/api/sso_router.py backchannel_logout, app/services/sso_sign_in.py provider_logout_url):
the row written at the sign-in with the provider's session id and subject (the ID token encrypted only when the
provider logout option is on), also for an administrator who adds the password; a back-channel logout token ending
the sessions it names by sid, else by subject, and no others, honoured once, every bad token the same 400; the
provider's logout address answered at the vault's sign-out when the option is on. Offline."""
import time
import types
import uuid
from datetime import datetime

import pytest

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
    root, p = _user("root", role="admin"), _provider()
    h = Sessions(monkeypatch, [root], [p], identities=[_identity(root, p)])
    from app.services import auth_service as A
    monkeypatch.setattr(A, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")
    location, _ = _sign_in(h, p, sid="idp-session-admin")
    status, body = h.finish(location)
    assert status == 200 and body["stage"] == "password", body
    # The provider's session rides in the pre-authentication token, not in a row.
    assert _claims(body["pre_auth_token"])["idp_sid"] == "idp-session-admin"
    assert h.sso_sessions() == []
    status, done, _ = _call(h.S, "POST", "/auth/login", {"username": "root", "password": "pw"},
                            headers={"Authorization": f"Bearer {body['pre_auth_token']}"})
    assert status == 200 and "access_token" in done, done
    (record,) = h.sso_sessions()
    assert record.idp_sid == "idp-session-admin" and record.idp_sub == "subject-1"


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


@pytest.mark.parametrize("spoil", ["no_token", "wrong_provider", "not_a_token", "with_nonce", "no_event", "no_sid_no_sub",
                                   "old", "replayed", "option_off", "unknown_provider", "wrong_audience"])
def test_every_bad_logout_token_is_the_same_400_and_ends_nothing(monkeypatch, spoil):
    alice, p, other = _user(), _provider(), _provider(name="other")
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
    assert any(a[0] == "sso_backchannel_logout" and a[1] == "failure" for a in h.audits), h.audits
    assert all("subject-1" not in str(a[2].get("reason", "")) for a in h.audits if isinstance(a[2], dict))


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
    # The option off, or a provider without the address: nothing, and the vault's sign-out stands on its own.
    p.policy = {"sso_idp_logout": False}
    assert sso.provider_logout_url(h.db, session) is None
    p.policy = {"sso_idp_logout": True}
    h.discovery_overrides.pop("end_session_endpoint")
    from app.services import oidc_client as oc
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
    assert sso.provider_logout_url(h.db, session) is None
    assert sso.provider_logout_url(h.db, None) is None
