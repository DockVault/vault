"""Single sign-on through the routes (app/api/sso_router.py, app/services/sso_sign_in.py), against a provider
stood in by a local signer behind the OpenID Connect client's fetch: the start and its state, the callback for a
known identity (a one-time code the finish route turns into a session with the provider on the token and the
provider's auth_time), every refusal at the callback (unknown state, another provider, the provider's error, a
missing or wrong issuer parameter, no account, a disabled or locked account, another issuer or tenant, a bad
token), a link that only the tab and session that started it can claim (the login-CSRF case), an unlink and its
guards, and a test sign-in claimed by the administrator's tab. Offline: fake stores, the records observed."""
import hashlib
import json
import time
import types
import uuid
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB
from test_oidc_client import CLIENT, ISSUER, Signer
from test_sso_state import FakeRedis

pytestmark = pytest.mark.unit

BASE = "https://vault.example.test"


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


class DB(MemoryDB):
    def add(self, obj):
        super().add(obj)
        self.rows_of(type(obj)).append(obj)


def _call(S, method, url, body=None, headers=None):
    out = {}
    path, _, query = url.partition("?")

    async def _drive():
        hdrs = [(b"content-type", b"application/json")]
        for k, v in (headers or {}).items():
            hdrs.append((k.lower().encode(), v.encode()))
        scope = {"type": "http", "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
                 "query_string": query.encode(), "headers": hdrs, "client": ("203.0.113.9", 1234),
                 "server": ("testserver", 80), "scheme": "https"}
        payload = json.dumps(body).encode() if body is not None else b""
        chunks = []

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
                out["headers"] = {k.decode().lower(): v.decode() for k, v in msg["headers"]}
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))

        await S.app(scope, receive, send)
        raw = b"".join(chunks)
        try:
            out["body"] = json.loads(raw or b"null")
        except ValueError:
            out["body"] = raw.decode("utf-8", "replace")

    run_coroutine(_drive(), timeout=30)
    return out["status"], out["body"], out.get("headers", {})


def _user(username="alice", role="user", **extra):
    from app.core.models import RoleEnum
    now = datetime.utcnow()
    fields = dict(id=uuid.uuid4(), username=username, email=f"{username}@example.test", role=RoleEnum(role), is_active=True,
                  is_locked=False, locked_until=None, password_hash="x", second_factor_reset_at=None, created_at=now,
                  last_login=None, sftp_enabled=True, sftp_password_auth=True, storage_quota_bytes=None, groups=[],
                  failed_login_attempts=0, sso_only=False, _is_temp_session=False)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


def _provider(**extra):
    fields = dict(id=uuid.uuid4(), kind="oidc", state="enabled", name="contoso", label="Sign in with Contoso", icon="generic",
                  sort_order=0, show_on_sign_in=True, issuer=ISSUER, discovery_url=None, private_network=False,
                  client_id=CLIENT, client_secret_enc="enc", token_auth="client_secret_basic",
                  scopes="openid profile email", claims=None, policy=None, last_test=None)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


def _identity(user, provider, subject="subject-1", **extra):
    fields = dict(id=uuid.uuid4(), user_id=user.id, provider_id=provider.id, issuer=ISSUER, subject=subject,
                  subject_source="oidc:sub", tenant_id=None, email_at_link=None, display_name=None,
                  linked_at=datetime.utcnow(), linked_by="self", last_sign_in_at=None)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


def _claims(token):
    import base64
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


class Harness:
    def __init__(self, monkeypatch, users, providers, identities=()):
        from app.core import rate_limiter as R
        from app.core import sign_in_codes, sign_in_lockout, sso_state
        from app.core.database import get_db
        from app.core.models import (ActiveSession, ExternalIdentity, PendingLogin, SecondFactorAction, SecondFactorEnrollment,
                                     SsoProvider, SystemSetting, User)
        from app.api import sso_router
        from app.api.user_management_api import get_current_user as umg, require_interactive_admin as uma
        from app.services import oidc_client as oc
        self.S = S = _api()
        self.signer = Signer()
        self.redis = FakeRedis()
        self.providers = list(providers)
        self.db = DB({User: list(users), SsoProvider: self.providers, ExternalIdentity: list(identities), PendingLogin: [],
                      ActiveSession: [], SystemSetting: [], SecondFactorEnrollment: [], SecondFactorAction: []})
        self.current_user = users[0] if users else None
        monkeypatch.setitem(S.app.dependency_overrides, get_db, lambda: self.db)
        monkeypatch.setitem(S.app.dependency_overrides, umg, lambda: self.current_user)
        monkeypatch.setitem(S.app.dependency_overrides, uma, lambda: self.current_user)
        monkeypatch.setattr(sso_state, "_redis", lambda redis: self.redis)
        monkeypatch.setattr(sign_in_codes, "_redis", lambda redis: self.redis)
        import app.core.security as security
        monkeypatch.setattr(security, "decrypt_secret", lambda v: "s3cret")
        import app.core.public_url as public_url
        monkeypatch.setattr(public_url, "public_base_url", lambda: BASE)
        monkeypatch.setattr(oc, "_resolve", lambda host: ["8.8.8.8"])
        monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())
        # The provider: discovery and keys from the signer; the token endpoint answers what the test arranged.
        self.discovery_overrides = {"authorization_response_iss_parameter_supported": False}
        self.token_calls, self.claims_override, self.nonce = [], {}, None
        self.token_answer = None

        def fetch(url, method="GET", data=None, headers=None, **kw):
            if url.endswith("openid-configuration"):
                return self.signer.discovery(**self.discovery_overrides)
            if url.endswith("/certs"):
                return self.signer.jwks()
            if url.endswith("/token"):
                self.token_calls.append((data, headers))
                if self.token_answer is not None:
                    return self.token_answer
                return {"token_type": "Bearer", "id_token": self.id_token(), "access_token": "at"}
            raise AssertionError(url)
        monkeypatch.setattr(oc, "fetch_json", fetch)
        # The vault's own machinery, observed.
        monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: False)
        monkeypatch.setattr(S, "_second_factor_effective", lambda db, user: {"state": "optional", "in_effect": False,
                                                                                "required": False})
        monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: None)
        self.audits, self.notices, self.emails, self.step_ups = [], [], [], []

        class _Audit:
            def __init__(_self, db):
                pass

            def log_login_success(_self, user, ip, is_temporary=False, methods=None):
                self.audits.append(("login_success", user.username, list(methods or [])))

            def log_login_failure(_self, username, ip, reason, **kw):
                self.audits.append(("login_failure", username, reason))
                return None

            def log_action(_self, **kw):
                self.audits.append((kw.get("action"), kw.get("status"), dict(kw.get("details") or {})))
        import app.services.audit_logger as al
        monkeypatch.setattr(al, "AuditLogger", _Audit)
        monkeypatch.setattr(S, "AuditLogger", _Audit)
        monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: None)
        monkeypatch.setattr(S, "_fire_action_email", lambda db, key, *, email, username=None, action_context=None: (
            self.emails.append((key, email, action_context))))
        monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
            self.notices.append((list(ids), title)) or list(ids)))
        monkeypatch.setattr(S, "_enforce_step_up", lambda db, user, request, action: self.step_ups.append(action))
        self.session_hash = "sess-hash"
        monkeypatch.setattr(S, "_current_session_hash", lambda request: self.session_hash)
        self.session_claims = {"amr": ["pwd"], "mfa_at": int(time.time())}
        monkeypatch.setattr(sso_router, "_session_claims", lambda request: dict(self.session_claims))
        from app.core.rate_limiter import rate_limiter
        self.limiter = []
        monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (self.limiter.append(kw.get("prefix")) or (True, 1, 0)))
        R._cb_record_failure(time.time())

    def id_token(self, **overrides):
        now = time.time()
        claims = {"iss": ISSUER, "sub": "subject-1", "aud": CLIENT, "exp": now + 300, "iat": now - 5, "nonce": self.nonce,
                  "auth_time": int(now) - 10, "email": "alice@example.test", "email_verified": True, "name": "Alice Example"}
        claims.update(self.claims_override)
        claims.update(overrides)
        return self.signer.token({k: v for k, v in claims.items() if v is not ...})

    def start(self, provider, verifier="tab-verifier", **body):
        payload = {"verifier_hash": _h(verifier), **body}
        status, out, _ = _call(self.S, "POST", f"/auth/sso/{provider.id}/start", payload)
        return status, out

    def start_link(self, provider, verifier="link-tab"):
        return _call(self.S, "POST", f"/users/me/identities/{provider.id}/start", {"verifier_hash": _h(verifier)})[:2]

    def state_of(self, url):
        q = parse_qs(urlsplit(url).query)
        state = q["state"][0]
        record = json.loads(self.redis.rows["sso:state:" + state])
        self.nonce = record["nonce"]
        return state, record

    def callback(self, provider, state, code="c0de", **params):
        query = "&".join(f"{k}={v}" for k, v in {"state": state, "code": code, **params}.items() if v is not None)
        status, body, headers = _call(self.S, "GET", f"/auth/sso/{provider.id}/callback?{query}")
        return status, headers.get("location", ""), body

    def finish(self, location, verifier="tab-verifier"):
        code = parse_qs(location.split("#", 1)[1])["sso"][0]
        status, body, _ = _call(self.S, "POST", "/auth/finish", {"code": code, "verifier": verifier})
        return status, body

    def finish_link(self, location, verifier="link-tab"):
        code = parse_qs(location.split("#", 1)[1])["sso-linked"][0]
        status, body, _ = _call(self.S, "POST", "/users/me/identities/finish", {"code": code, "verifier": verifier})
        return status, body

    def finish_test(self, provider, location, verifier="test-tab"):
        code = parse_qs(location.split("#", 1)[1])["sso-test"][0]
        status, body, _ = _call(self.S, "POST", f"/admin/sso/providers/{provider.id}/test/finish",
                                {"code": code, "verifier": verifier})
        return status, body

    def identities(self):
        from app.core.models import ExternalIdentity
        return self.db.rows_of(ExternalIdentity)


# --------------------------------------------------------------------------- the start

def test_the_start_answers_the_authorization_url_and_keeps_the_state(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p])
    status, out = h.start(p, return_to="#profile")
    assert status == 200, out
    url = out["authorization_url"]
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert parts.scheme == "https" and parts.path.endswith("/auth")
    assert q["client_id"] == [CLIENT] and q["redirect_uri"] == [f"{BASE}/auth/sso/{p.id}/callback"]
    assert q["response_type"] == ["code"] and q["code_challenge_method"] == ["S256"] and q["scope"] == ["openid profile email"]
    state, record = h.state_of(url)
    assert q["nonce"] == [record["nonce"]] and record["purpose"] == "sign_in" and record["return_to"] == "#profile"
    assert record["verifier_hash"] == _h("tab-verifier") and record["provider_id"] == str(p.id)
    assert out["expires_in"] == 600 and "s3cret" not in url
    assert "sso_start" in h.limiter
    # A return address off the list falls back to the default; one proof, exactly one, is needed.
    status, out = h.start(p, return_to="https://evil.example/")
    assert status == 200 and h.state_of(out["authorization_url"])[1]["return_to"] == "#vaults"
    assert _call(h.S, "POST", f"/auth/sso/{p.id}/start", {})[0] == 400
    assert _call(h.S, "POST", f"/auth/sso/{p.id}/start", {"verifier_hash": "zz"})[0] == 422
    assert _call(h.S, "POST", f"/auth/sso/{p.id}/start", {"verifier_hash": _h("x"), "code_challenge": "a" * 43})[0] == 400
    # The desktop app's PKCE start is its own purpose.
    status, out, _ = _call(h.S, "POST", f"/auth/sso/{p.id}/start", {"code_challenge": "a" * 43})
    assert status == 200 and h.state_of(out["authorization_url"])[1]["purpose"] == "app"


def test_a_start_is_refused_for_an_unknown_draft_disabled_or_unconfigured_provider(monkeypatch):
    alice = _user()
    draft, off = _provider(state="draft"), _provider(state="disabled", name="off")
    saml, bare = _provider(kind="saml", name="s"), _provider(name="bare", client_secret_enc=None)
    h = Harness(monkeypatch, [alice], [draft, off, saml, bare])
    assert h.start(_provider())[0] == 404
    for p in (draft, off, saml, bare):
        status, out = h.start(p)
        assert status == 404 and out["detail"]["reason"] == "provider_disabled", (p.name, out)
    assert h.redis.rows == {}


# --------------------------------------------------------------------------- the callback: a sign-in

def test_a_known_identity_signs_in_through_a_one_time_code(monkeypatch):
    alice, p = _user(), _provider()
    identity = _identity(alice, p)
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    status, out = h.start(p, return_to="#notes")
    state, record = h.state_of(out["authorization_url"])
    provider_auth_time = int(time.time()) - 3000
    h.claims_override = {"auth_time": provider_auth_time}
    status, location, _ = h.callback(p, state, iss=ISSUER)
    assert status == 302 and location.startswith("/#sso=") and "return_to=notes" in location, location
    # The code exchange carried the PKCE verifier and the client's secret, basic style.
    (data, headers), = h.token_calls
    form = parse_qs(data.decode())
    assert form["code"] == ["c0de"] and form["code_verifier"] == [record["code_verifier"]]
    assert form["redirect_uri"] == [f"{BASE}/auth/sso/{p.id}/callback"] and headers["Authorization"].startswith("Basic ")
    # The state is spent, and nothing is stamped on the identity until the code is redeemed.
    assert h.callback(p, state)[1] == "/#sso-error=state_unknown" and identity.last_sign_in_at is None
    # The web app redeems the code with the tab's verifier: a session with the provider on the token, no password,
    # and the provider's own authentication time.
    status, body = h.finish(location)
    assert status == 200, body
    claims = _claims(body["access_token"])
    assert claims["idp"] == str(p.id) and claims["amr"] == [] and "mfa_at" not in claims and claims["sub"] == str(alice.id)
    assert abs(int(claims["auth_time"]) - provider_auth_time) <= 1
    assert ("login_success", "alice", []) in h.audits and identity.last_sign_in_at is not None
    # The code is spent too.
    assert h.finish(location)[0] == 401


def test_a_wrong_tab_verifier_cannot_redeem_the_code(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso=")
    assert h.finish(location, verifier="stolen-tab")[0] == 401
    assert all(a[0] != "login_success" for a in h.audits)


@pytest.mark.parametrize("arrange,reason", [
    ("unknown_state", "state_unknown"),
    ("other_provider", "provider_mix_up"),
    ("error", "provider_error"),
    ("no_code", "provider_error"),
    ("iss_wrong", "issuer_mismatch"),
    ("iss_required", "issuer_mismatch"),
    ("no_identity", "no_account"),
    ("other_issuer", "no_account"),
    ("other_tenant", "no_account"),
    ("other_provider_identity", "no_account"),
    ("inactive", "account_disabled"),
    ("locked", "account_disabled"),
    ("bad_nonce", "nonce_mismatch"),
    ("token_error", "provider_error"),
    ("disabled_meanwhile", "provider_disabled"),
])
def test_every_callback_refusal_is_a_reason_in_the_fragment_with_no_consequence_for_any_account(monkeypatch, arrange, reason):
    alice, p, other = _user(), _provider(), _provider(name="other")
    identities = [_identity(alice, p)]
    if arrange == "no_identity":
        identities = []
    elif arrange == "other_issuer":
        identities = [_identity(alice, p, issuer="https://other-issuer.example.com")]
    elif arrange == "other_tenant":
        identities = [_identity(alice, p, tenant_id="tenant-1")]
    elif arrange == "other_provider_identity":
        identities = [_identity(alice, other)]            # the same subject, linked on another provider
    if arrange == "inactive":
        alice.is_active = False
    if arrange == "locked":
        alice.is_locked, alice.locked_until = True, None
    h = Harness(monkeypatch, [alice], [p, other], identities=identities)
    if arrange == "iss_required":
        h.discovery_overrides = {"authorization_response_iss_parameter_supported": True}
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    kwargs, target, code = {}, p, "c0de"
    if arrange == "unknown_state":
        state = "A" * 43
    elif arrange == "other_provider":
        target = other
    elif arrange == "error":
        kwargs, code = {"error": "access_denied", "error_description": "secret%20stuff"}, None
    elif arrange == "no_code":
        code = None
    elif arrange == "iss_wrong":
        kwargs = {"iss": "https://evil.example.com"}
    elif arrange == "other_tenant":
        h.claims_override = {"tid": "tenant-2"}
    elif arrange == "bad_nonce":
        h.claims_override = {"nonce": "other"}
    elif arrange == "token_error":
        h.token_answer = {"error": "invalid_grant", "error_description": "secret stuff"}
    elif arrange == "disabled_meanwhile":
        p.state = "disabled"
    status, location, body = h.callback(target, state, code=code, **kwargs)
    assert status == 302 and location == f"/#sso-error={reason}", (location, body)
    assert "secret" not in location
    # Refused and (an unknown state apart: a public hit is only logged) recorded; nothing else: no session, no
    # code, no identity, no change to the account.
    if arrange != "unknown_state":
        assert any(a[0] == "sso_sign_in_refused" and a[1] == "failure" and a[2].get("reason") == reason for a in h.audits), h.audits
    else:
        assert all(a[0] != "sso_sign_in_refused" for a in h.audits)
    assert all(a[0] != "login_success" for a in h.audits)
    assert not [k for k in h.redis.rows if k.startswith("signin:code:") or k.startswith("sso:handover:")]
    assert alice.is_active is (arrange != "inactive") and len(h.identities()) == len(identities)


def test_an_identity_linked_before_the_provider_named_a_tenant_learns_it(monkeypatch):
    alice, p = _user(), _provider()
    identity = _identity(alice, p)
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"tid": "tenant-9"}
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso=") and identity.tenant_id == "tenant-9"
    # Pinned from now on: another tenant does not match.
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"tid": "tenant-10"}
    assert h.callback(p, state)[1] == "/#sso-error=no_account"


def test_a_provider_auth_time_the_platform_cannot_place_is_not_a_crash(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    for odd in (10 ** 11, -5, 2 ** 40, True, "yesterday"):
        status, out = h.start(p)
        state, _ = h.state_of(out["authorization_url"])
        h.claims_override = {"auth_time": odd}
        status, location, _ = h.callback(p, state)
        assert status == 302 and location.startswith("/#sso="), (odd, location)
        assert h.finish(location)[0] == 200


# --------------------------------------------------------------------------- linking

def test_a_link_is_claimed_only_by_the_tab_and_session_that_started_it(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p])
    status, out = h.start_link(p, verifier="link-tab")
    assert status == 200, out
    assert h.step_ups == ["account.second_factor"]
    state, record = h.state_of(out["authorization_url"])
    assert record["purpose"] == "link" and record["user_id"] == str(alice.id) and record["session_hash"] == "sess-hash"
    assert record["verifier_hash"] == _h("link-tab")
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked="), location
    # The callback linked nothing: the identity waits under a code.
    assert h.identities() == [] and all(a[0] != "sso_identity_linked" for a in h.audits)
    # Another tab's verifier, another session, another account: refused, and the code is spent by the first try.
    assert h.finish_link(location, verifier="other-tab")[0] == 401
    assert h.identities() == []
    status, location2, _ = h.callback(p, h.state_of(h.start_link(p)[1]["authorization_url"])[0])
    h.session_hash = "another-session"
    assert h.finish_link(location2)[0] == 401
    h.session_hash = "sess-hash"
    status, location3, _ = h.callback(p, h.state_of(h.start_link(p)[1]["authorization_url"])[0])
    h.current_user = _user("mallory")
    h.db.rows_of(type(alice)).append(h.current_user)
    assert h.finish_link(location3)[0] == 401 and h.identities() == []
    h.current_user = alice
    # The right tab and session: linked, told, listed; the code is spent.
    status, location4, _ = h.callback(p, h.state_of(h.start_link(p)[1]["authorization_url"])[0])
    status, body = h.finish_link(location4)
    assert status == 200 and body["linked"] is True, body
    (identity,) = h.identities()
    assert identity.user_id == alice.id and identity.subject == "subject-1" and identity.linked_by == "self"
    assert identity.email_at_link == "alice@example.test" and identity.display_name == "Alice Example"
    assert any(a[0] == "sso_identity_linked" for a in h.audits)
    assert h.notices[-1][1] == "A sign-in method was added to your account" and h.emails[-1][0] == "sign_in_method_changed"
    assert h.finish_link(location4)[0] == 401
    status, out, _ = _call(h.S, "GET", "/users/me/identities")
    assert status == 200 and out["identities"][0]["provider"] == "Sign in with Contoso"
    # The same provider again: already linked; and the identity now signs the person in.
    assert h.start_link(p)[0] == 409
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    assert h.callback(p, state)[1].startswith("/#sso=")


def test_login_csrf_through_the_link_callback_links_nothing(monkeypatch):
    """The attacker starts a link for their account and hands the URL to a victim, who completes it at the provider:
    the victim's identity must not land on the attacker's account."""
    mallory, victim, p = _user("mallory"), _user("victim"), _provider()
    h = Harness(monkeypatch, [mallory, victim], [p])
    status, out = h.start_link(p, verifier="mallory-tab")          # mallory's tab started it
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "victim-subject", "email": "victim@example.test"}
    status, location, _ = h.callback(p, state)                       # the victim's browser comes back
    assert location.startswith("/#sso-linked=")
    # The victim's tab has no verifier for this code and another session: nothing is linked to anyone.
    h.current_user, h.session_hash = victim, "victim-session"
    assert h.finish_link(location, verifier="victim-tab")[0] == 401
    assert h.identities() == []
    # Mallory, who knows the verifier, cannot claim it from another session either (the code is spent).
    h.current_user, h.session_hash = mallory, "sess-hash"
    assert h.finish_link(location, verifier="mallory-tab")[0] == 401 and h.identities() == []


def test_a_link_needs_a_session_that_proved_the_password_and_the_factor(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p])
    h.session_claims = {"amr": [], "mfa_at": None}
    status, out = h.start_link(p)
    assert status == 403 and out["detail"]["reason"] == "password_proof_required"
    from app.core.models import SecondFactorEnrollment
    h.db.rows_of(SecondFactorEnrollment).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, method="totp", status="active"))
    h.session_claims = {"amr": ["pwd"]}
    status, out = h.start_link(p)
    assert status == 403 and out["detail"]["reason"] == "second_factor_proof_required"
    h.session_claims = {"amr": ["pwd", "totp"], "mfa_at": 1}
    assert h.start_link(p)[0] == 200
    assert _call(h.S, "POST", f"/users/me/identities/{p.id}/start", {})[0] == 422          # the tab verifier is required
    alice._is_temp_session = True
    assert h.start_link(p)[0] == 403 and _call(h.S, "GET", "/users/me/identities")[0] == 403


def test_an_identity_already_on_another_account_is_not_linked_twice(monkeypatch):
    alice, bob, p = _user(), _user("bob"), _provider()
    h = Harness(monkeypatch, [alice, bob], [p], identities=[_identity(bob, p)])
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    assert h.callback(p, state)[1] == "/#sso-error=already_linked"
    assert len(h.identities()) == 1
    # The service's own rule: one identity per provider per account, whoever asks.
    from app.services import sso_sign_in as sso
    answer = sso.ProviderAnswer(claims={}, subject="subject-2", issuer=ISSUER, tenant_id=None, email=None,
                                email_verified=False, display_name=None, auth_time=None)
    with pytest.raises(sso.Refusal) as e:
        sso.link_identity(h.db, p, bob, answer, linked_by="self")
    assert e.value.code == "not_this_account"
    # A deactivated account cannot claim a link it started.
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "subject-3"}
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked=")
    alice.is_active = False
    assert h.finish_link(location)[0] == 401 and len(h.identities()) == 1


def test_an_unlink_is_the_owners_and_keeps_the_last_way_in_of_an_sso_only_account(monkeypatch):
    alice, bob, p = _user(sso_only=True), _user("bob"), _provider()
    identity, bobs = _identity(alice, p), _identity(bob, p, subject="bob-subject")
    h = Harness(monkeypatch, [alice, bob], [p], identities=[identity, bobs])
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 409 and "only identity" in out["detail"]
    alice.sso_only = False
    assert _call(h.S, "DELETE", f"/users/me/identities/{uuid.uuid4()}")[0] == 404
    assert _call(h.S, "DELETE", f"/users/me/identities/{bobs.id}")[0] == 404           # someone else's
    assert len(h.identities()) == 2
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 200 and out == {"removed": True} and h.identities() == [bobs]
    assert any(a[0] == "sso_identity_unlinked" for a in h.audits) and h.step_ups.count("account.second_factor") == 4
    assert h.notices[-1][1] == "A sign-in method was removed from your account"


# --------------------------------------------------------------------------- a test sign-in

def test_a_test_sign_in_is_claimed_by_the_administrators_tab_and_changes_nothing_else(monkeypatch):
    root, p = _user("root", role="admin"), _provider(state="tested")
    h = Harness(monkeypatch, [root], [p])
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    h.claims_override = {"groups": ["staff", "admins"], "amr": ["pwd", "mfa"], "acr": "2", "email_verified": "true"}
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-test="), location
    assert p.last_test is None                                    # nothing written at the callback
    assert h.finish_test(p, location, verifier="other")[0] == 401 and p.last_test is None
    # Claimed from the right tab (a fresh test: the first claim spent the code).
    url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    status, location, _ = h.callback(p, state)
    status, body = h.finish_test(p, location)
    assert status == 200, body
    summary = p.last_test
    assert summary["outcome"] == "ok" and summary["tester"] == "root" and summary["auth_time_present"] is True
    assert summary["amr"] == ["pwd", "mfa"] and summary["acr"] == "2" and summary["groups"] == ["admins", "staff"]
    assert summary["email_verified"] is False                   # a string "true" is not verified
    assert "sub" in summary["claim_names"] and "would" in summary
    assert "subject-1" not in json.dumps(summary) and "alice@example.test" not in json.dumps(summary)
    assert h.identities() == [] and not [k for k in h.redis.rows if k.startswith("signin:code:")]
    assert any(a[0] == "sso_provider_tested" for a in h.audits) and all(a[0] != "login_success" for a in h.audits)
    # A test's code cannot be claimed as a link, and vice versa.
    url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    status, location, _ = h.callback(p, state)
    code = parse_qs(location.split("#", 1)[1])["sso-test"][0]
    assert _call(h.S, "POST", "/users/me/identities/finish", {"code": code, "verifier": "test-tab"})[0] == 401


def test_a_link_or_test_state_without_its_tab_and_session_cannot_be_claimed(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p])
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    # A link state made with no tab verifier (nothing could ever claim it): the callback refuses before the handover.
    url = sso.start(p, purpose=sso_state.LINK, source="s", client_ip="203.0.113.9", user_id=alice.id, session_hash="sess-hash")
    state, record = h.state_of(url)
    assert record["verifier_hash"] is None
    status, location, _ = h.callback(p, state)
    assert location == "/#sso-error=purpose_not_ready" and not [k for k in h.redis.rows if k.startswith("sso:handover:")]
    # The same without the session that started it.
    url = sso.start(p, purpose=sso_state.LINK, source="s", client_ip="203.0.113.9", verifier_hash=_h("t"), user_id=alice.id)
    state, _ = h.state_of(url)
    assert h.callback(p, state)[1] == "/#sso-error=purpose_not_ready" and h.identities() == []


def test_a_providers_time_claim_is_bounded_before_the_platform_sees_it():
    set_bare_api_env()
    from datetime import datetime as _dt, timezone as _tz
    from app.services import sso_sign_in as sso
    assert sso._as_time(1_800_000_000) == _dt.fromtimestamp(1_800_000_000, tz=_tz.utc)
    assert sso._as_time(2 ** 33 - 1) is not None
    for bad in (-5, -1, 2 ** 33, 2 ** 40, 10 ** 11, True, False, "yesterday", None, float("nan"), float("inf")):
        assert sso._as_time(bad) is None, bad
