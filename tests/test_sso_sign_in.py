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
    """The memory store with rows filed on add, and a rollback that takes back what was added since the last
    commit (as the database would), so a refused resolution leaves no account behind in a test either."""

    def __init__(self, tables=None):
        super().__init__(tables)
        self._uncommitted = []

    def add(self, obj):
        super().add(obj)
        self.rows_of(type(obj)).append(obj)
        self._uncommitted.append(obj)

    def commit(self):
        super().commit()
        self._uncommitted = []

    def rollback(self):
        super().rollback()
        for obj in self._uncommitted:
            rows = self.rows_of(type(obj))
            if obj in rows:
                rows.remove(obj)
        self._uncommitted = []

    def expire(self, obj, attrs=None):
        pass

    def execute(self, stmt):
        """The two association-table statements the sign-in writes (department memberships), applied to the users'
        ``groups`` lists as a refresh would show them, and logged; anything else is not modelled."""
        from sqlalchemy.sql.dml import Delete, Insert
        from app.core.models import Group, User, user_groups
        rows = self.rows_of(user_groups)
        if isinstance(stmt, Insert) and stmt.table is user_groups:
            params = stmt.compile().params
            self.log.append(("execute", "insert user_groups", params["user_id"], params["group_id"]))
            if any(r.user_id == params["user_id"] and r.group_id == params["group_id"] for r in rows):
                return types.SimpleNamespace(rowcount=0)
            rows.append(types.SimpleNamespace(**params))
            user = next((u for u in self.rows_of(User) if u.id == params["user_id"]), None)
            group = next((g for g in self.rows_of(Group) if g.id == params["group_id"]), None)
            if user is not None and group is not None and group not in user.groups:
                user.groups.append(group)
            return types.SimpleNamespace(rowcount=1)
        if isinstance(stmt, Delete) and stmt.table is user_groups:
            gone = [r for r in rows if self.truth(stmt.whereclause, r) is True]
            for r in gone:
                rows.remove(r)
                user = next((u for u in self.rows_of(User) if u.id == r.user_id), None)
                if user is not None:
                    user.groups[:] = [g for g in user.groups if g.id != r.group_id]
            self.log.append(("execute", "delete user_groups", len(gone)))
            return types.SimpleNamespace(rowcount=len(gone))
        raise AssertionError(f"the test store does not model {stmt!r}")


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
                  failed_login_attempts=0, sso_only=False, _is_temp_session=False,
                  email_confirmed_at=now)          # an address an administrator set, unless the test says otherwise
    fields.update(extra)
    if "email_confirmed_for" not in fields:          # the mark is for the address the account is made with
        from app.core import email_confirmation
        fields["email_confirmed_for"] = (email_confirmation.mark_for(fields["email"])
                                         if fields.get("email") and fields.get("email_confirmed_at") else None)
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
    def __init__(self, monkeypatch, users, providers, identities=(), invitations=()):
        from app.core import rate_limiter as R
        from app.core import sign_in_codes, sign_in_lockout, sso_state
        from app.core.database import get_db
        from app.core.models import (AccountInvitation, ActiveSession, AdminGrant, AuditorGrant, CredentialChange,
                                     ExternalIdentity, Group, PendingLogin, SecondFactorAction, SecondFactorEnrollment,
                                     SsoAdminRequest, SsoGroupMapping, SsoProvider, SystemSetting, User)
        from app.api import sso_router
        from app.api.user_management_api import get_current_user as umg, require_interactive_admin as uma
        from app.services import oidc_client as oc
        self.S = S = _api()
        self.signer = Signer()
        self.redis = FakeRedis()
        self.providers = list(providers)
        self.db = DB({User: list(users), SsoProvider: self.providers, ExternalIdentity: list(identities), PendingLogin: [],
                      ActiveSession: [], SystemSetting: [], SecondFactorEnrollment: [], SecondFactorAction: [],
                      AccountInvitation: list(invitations), SsoGroupMapping: [], SsoAdminRequest: [], Group: [],
                      AdminGrant: [], CredentialChange: [], AuditorGrant: []})
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
        self.provider_fetch = fetch
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

            def build_row(_self, **kw):
                self.audits.append((kw.get("action"), kw.get("status"), dict(kw.get("details") or {})))
                return types.SimpleNamespace(**kw)
        import app.services.audit_logger as al
        monkeypatch.setattr(al, "AuditLogger", _Audit)
        monkeypatch.setattr(S, "AuditLogger", _Audit)
        monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: None)
        monkeypatch.setattr(S, "_fire_action_email", lambda db, key, *, email, username=None, action_context=None: (
            self.emails.append((key, email, action_context))))
        self.notice_bodies = []            # the same notices with what they say: (ids, title, body)
        monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
            self.notice_bodies.append((list(ids), title, body)) or self.notices.append((list(ids), title)) or list(ids)))
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
    provider_auth_time = int(time.time()) - 3 * 86400          # the provider's own session is three days old
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
    # The web app redeems the code with the tab's verifier: a session with the provider on the token, no password.
    # Its time is when the sign-in completed here (what the renewal limit counts from), never the provider's.
    status, body = h.finish(location)
    assert status == 200, body
    claims = _claims(body["access_token"])
    assert claims["idp"] == str(p.id) and claims["amr"] == [] and "mfa_at" not in claims and claims["sub"] == str(alice.id)
    assert abs(int(claims["auth_time"]) - time.time()) <= 60 and "idp_auth_time" not in claims
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
    for odd in (-5, True, "yesterday"):
        status, out = h.start(p)
        state, _ = h.state_of(out["authorization_url"])
        h.claims_override = {"auth_time": odd}
        status, location, _ = h.callback(p, state)
        assert status == 302 and location.startswith("/#sso="), (odd, location)
        assert h.finish(location)[0] == 200
    # A number too large to place is not "no time": it lies further ahead than any clock, and is refused as one.
    for ahead in (2 ** 33, 10 ** 11, 2 ** 40):
        status, out = h.start(p)
        state, _ = h.state_of(out["authorization_url"])
        h.claims_override = {"auth_time": ahead}
        assert h.callback(p, state)[1] == "/#sso-error=provider_clock_ahead", ahead


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
    # What came through the identity ends with it: the sessions made by a sign-in through it (and no other: not
    # one through another identity of the provider, not one of another provider), and the account's sign-ins under
    # way (and nobody else's).
    from app.core.models import ActiveSession, PendingLogin, SsoSession
    q = _provider(name="Fabrikam")
    through, bobs_own, elsewhere = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    h.db.rows_of(ActiveSession).extend([types.SimpleNamespace(id=through, user_id=alice.id),
                                         types.SimpleNamespace(id=bobs_own, user_id=bob.id),
                                         types.SimpleNamespace(id=elsewhere, user_id=alice.id)])
    h.db.rows_of(SsoSession).extend([
        types.SimpleNamespace(session_id=through, provider_id=p.id, idp_sub="subject-1"),
        types.SimpleNamespace(session_id=bobs_own, provider_id=p.id, idp_sub="bob-subject"),
        types.SimpleNamespace(session_id=elsewhere, provider_id=q.id, idp_sub="subject-1")])
    mine = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, consumed_at=None)
    others = types.SimpleNamespace(id=uuid.uuid4(), user_id=bob.id, consumed_at=None)
    h.db.rows_of(PendingLogin).extend([mine, others])
    revoked, turns = [], []
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, **kw: revoked.append(kw) or len(kw["session_ids"]))
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: turns.append(owner))
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 200 and out == {"removed": True, "sessions_ended": 1} and h.identities() == [bobs], out
    assert revoked == [{"session_ids": [through], "actor_username": "alice", "durable": True}] and turns == [str(alice.id)]
    assert mine.consumed_at is not None and others.consumed_at is None
    unlinked = [a for a in h.audits if a[0] == "sso_identity_unlinked"]
    assert len(unlinked) == 1 and unlinked[0][2]["sessions"] == 1 and h.step_ups.count("account.second_factor") == 4
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


# --------------------------------------------------------------------------- the provider's part, off the event loop

async def _request(S, method, url, body=None):
    """One request through the app on the running loop: (status, body, the loop time it finished)."""
    import asyncio
    out, chunks = {}, []
    path, _, query = url.partition("?")
    scope = {"type": "http", "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
             "query_string": query.encode(), "headers": [(b"content-type", b"application/json")],
             "client": ("203.0.113.9", 1234), "server": ("testserver", 80), "scheme": "https"}
    payload = json.dumps(body).encode() if body is not None else b""

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            chunks.append(msg.get("body", b""))
    await S.app(scope, receive, send)
    return out["status"], b"".join(chunks), asyncio.get_running_loop().time()


def _slow_fetch(h, monkeypatch, *, slow: str, seconds: float, release=None):
    """The harness's provider, with the endpoint ``slow`` (a URL suffix) answering after ``seconds`` (or when
    ``release`` is set); every fetch records the thread it ran on."""
    import threading
    from app.services import oidc_client as oc
    inner = h.provider_fetch
    h.fetch_threads = []

    def fetch(url, **kw):
        h.fetch_threads.append((url.rsplit("/", 1)[-1], threading.current_thread().name))
        if url.endswith(slow):
            (release or threading.Event()).wait(seconds)
        return inner(url, **kw)
    monkeypatch.setattr(oc, "fetch_json", fetch)


def test_the_provider_is_called_off_the_event_loop_in_its_own_pool(monkeypatch):
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _slow_fetch(h, monkeypatch, slow="nothing", seconds=0)
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert status == 302 and location.startswith("/#sso="), location
    names = [name for name, _ in h.fetch_threads]
    assert "openid-configuration" in names and "token" in names and "certs" in names, names
    # Every fetch ran in the provider pool: none on the loop's thread, none in the pool password sign-ins use.
    assert all(thread.startswith("sso-provider") for _, thread in h.fetch_threads), h.fetch_threads


def test_the_loop_answers_other_requests_while_a_provider_is_slow(monkeypatch):
    import asyncio
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p])
    _slow_fetch(h, monkeypatch, slow="openid-configuration", seconds=1.5)

    async def both():
        loop = asyncio.get_running_loop()
        began = loop.time()
        slow = asyncio.ensure_future(_request(h.S, "POST", f"/auth/sso/{p.id}/start", {"verifier_hash": _h("tab")}))
        await asyncio.sleep(0.1)
        quick = await _request(h.S, "GET", "/auth/sso/reasons")
        slow = await slow
        return began, quick, slow
    began, quick, slow = run_coroutine(both(), timeout=30)
    assert quick[0] == 200 and slow[0] == 200, (quick[:2], slow[:2])
    # The other request was answered while the provider was still thinking, not after it. The slow one took the
    # provider's delay (a sleep may come back a little early on a coarse timer, so the bound sits under it).
    assert quick[2] < slow[2] and slow[2] - began >= 1.4


def test_a_provider_that_does_not_answer_in_time_is_temporarily_unavailable(monkeypatch):
    import threading
    from app.api import sso_router
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    monkeypatch.setattr(sso_router, "PROVIDER_WAIT_SECONDS", 0.3)
    releases = []
    try:
        # The start: discovery hangs. A 503 with the reason, in a bounded time, and no state made.
        releases.append(threading.Event())
        _slow_fetch(h, monkeypatch, slow="openid-configuration", seconds=5, release=releases[-1])
        began = time.monotonic()
        status, out = h.start(p)
        assert status == 503 and out["detail"]["reason"] == "temporarily_unavailable", out
        assert time.monotonic() - began < 2
        assert not any(k.startswith("sso:state:") for k in h.redis.rows)
        # The callback: discovery answers, the token endpoint hangs. A reason in the fragment and a refusal row.
        releases[-1].set()
        _slow_fetch(h, monkeypatch, slow="nothing", seconds=0)
        status, out = h.start(p)
        assert status == 200, out
        state, _ = h.state_of(out["authorization_url"])
        releases.append(threading.Event())
        _slow_fetch(h, monkeypatch, slow="/token", seconds=5, release=releases[-1])
        began = time.monotonic()
        status, location, _ = h.callback(p, state)
        assert status == 302 and location == "/#sso-error=temporarily_unavailable", location
        assert time.monotonic() - began < 2
        assert ("sso_sign_in_refused", "failure",
                {"provider_id": str(p.id), "purpose": "sign_in", "reason": "temporarily_unavailable"}) in h.audits
    finally:
        for release in releases:
            release.set()


def test_calls_that_outlive_their_request_never_queue_the_next_ones(monkeypatch):
    import threading
    from app.api import sso_router
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p])
    _slow_fetch(h, monkeypatch, slow="nothing", seconds=0)
    full = threading.BoundedSemaphore(1)
    assert full.acquire(blocking=False)
    monkeypatch.setattr(sso_router, "_provider_threads", full)
    began = time.monotonic()
    status, out = h.start(p)
    assert status == 503 and out["detail"]["reason"] == "temporarily_unavailable", out
    assert time.monotonic() - began < 1 and h.fetch_threads == []
    # A place freed is a place used, and the call gives it back when it ends.
    full.release()
    status, out = h.start(p)
    assert status == 200, out
    assert full.acquire(blocking=False)
    assert sso_router.PROVIDER_THREADS >= 4 and 5 <= sso_router.PROVIDER_WAIT_SECONDS <= 30


def test_the_routes_that_reach_the_provider_hold_no_sign_in_slot_and_let_go_of_the_database(monkeypatch):
    """A slow provider must not hold what password sign-in waits on: these routes take none of the server's sign-in
    slots, and each ends its read transaction before it waits on the provider, handing the worker a plain view of
    the provider row. A full provider pool at the callback answers with the state unspent."""
    import threading
    from app.api import sso_router
    from app.core import auth_offload as ao
    from app.services import sso_sign_in as sso
    from fastapi.routing import APIRoute
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    inner, events = h.provider_fetch, []

    def fetch(url, **kw):
        events.append("fetch " + url.rsplit("/", 1)[-1])
        return inner(url, **kw)
    monkeypatch.setattr(sso.oc, "fetch_json", fetch)
    release = sso_router._release_database

    def released(db):
        events.append("released")
        release(db)
    monkeypatch.setattr(sso_router, "_release_database", released)
    # What it does: end the read transaction (here, the store's rollback).
    probe = DB({})
    release(probe)
    assert probe.log[-1] == ("rollback",)
    given = []
    real_start = sso.start
    monkeypatch.setattr(sso, "start", lambda row, **kw: given.append(row) or real_start(row, **kw))
    status, out = h.start(p)
    assert status == 200, out
    state, _ = h.state_of(out["authorization_url"])
    # The worker was handed a plain view of the row, not the session's row, and the request had let go first.
    assert given and given[0] is not p and given[0].id == p.id and given[0].issuer == p.issuer
    assert events[:2] == ["released", "fetch openid-configuration"], events
    # A full pool at the callback: a redirect into the app, the state not spent; with a place free it finishes.
    full = threading.BoundedSemaphore(1)
    assert full.acquire(blocking=False)
    monkeypatch.setattr(sso_router, "_provider_threads", full)
    status, location, _ = h.callback(p, state)
    assert status == 302 and location == "/#sso-error=temporarily_unavailable", location
    assert "sso:state:" + state in h.redis.rows
    full.release()
    events.clear()
    status, location, _ = h.callback(p, state)
    assert status == 302 and location.startswith("/#sso="), location
    assert events[:2] == ["released", "fetch token"], events
    assert h.finish(location)[0] == 200
    # None of the four routes takes a sign-in slot.
    wanted = {"start_sign_in", "sign_in_callback", "start_reauth", "start_link"}
    found = set()
    for route in sso_router.router.routes:
        if isinstance(route, APIRoute) and route.endpoint.__name__ in wanted:
            calls = {d.call for d in route.dependant.dependencies}
            assert ao.auth_offload_slot not in calls, route.path
            found.add(route.endpoint.__name__)
    assert found == wanted


def test_a_call_keeps_its_place_until_its_work_ends_and_a_call_never_run_gives_it_back(monkeypatch):
    import asyncio
    import threading
    import time as _time
    from concurrent.futures import ThreadPoolExecutor
    from app.api import sso_router
    from app.services import oidc_client as oc
    places = threading.BoundedSemaphore(2)
    monkeypatch.setattr(sso_router, "_provider_threads", places)
    release = threading.Event()
    hung = threading.Event()

    def stuck():
        hung.set()
        release.wait(10)
        return "late"

    async def timed_out():
        loop = asyncio.get_running_loop()
        try:
            await sso_router._provider_call(stuck, deadline=loop.time() + 0.2)
        except oc.OidcError as exc:
            return exc.code
    try:
        assert run_coroutine(timed_out(), timeout=10) == "temporarily_unavailable"
        assert hung.is_set()
        # The request stopped waiting; its call still runs and still holds its place.
        assert places._value == 1
    finally:
        release.set()
    for _ in range(100):
        if places._value == 2:
            break
        _time.sleep(0.02)
    assert places._value == 2
    # No time left: nothing is submitted and no place is taken.
    ran = []

    async def too_late():
        loop = asyncio.get_running_loop()
        try:
            await sso_router._provider_call(lambda: ran.append(1), deadline=loop.time() - 0.001)
        except oc.OidcError as exc:
            return exc.code
    assert run_coroutine(too_late(), timeout=10) == "temporarily_unavailable"
    assert ran == [] and places._value == 2
    # A call cancelled while it waits for a thread (the pool busy) gives its place back without ever running.
    pool = ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(sso_router, "_provider_pool", pool)
    blocker = threading.Event()
    pool.submit(blocker.wait, 10)

    async def cancelled():
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(sso_router._provider_call(lambda: ran.append(2), deadline=loop.time() + 5))
        await asyncio.sleep(0.05)
        assert places._value == 1
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return places._value
    try:
        assert run_coroutine(cancelled(), timeout=10) == 2
    finally:
        blocker.set()
        pool.shutdown(wait=True)
    assert ran == []


def test_no_route_calls_the_provider_on_the_event_loop():
    """Structural: inside every async route of the single sign-on router, a call that reaches the provider is made in
    a function handed off the loop (a lambda or a nested function), never directly; the sign-out, which may read the
    provider's discovery, is a plain function, which the framework runs in its thread pool."""
    import ast
    import inspect
    from app.api import sso_router
    reaching = {("sso", "start"), ("sso", "verified_answer"), ("sso", "provider_logout_url"), ("oc", "discover"),
                ("oc", "exchange_code"), ("oc", "verify_id_token"), ("oc", "verify_logout_token"),
                ("oc", "signing_keys"), ("oc", "userinfo"), ("oc", "fetch_json")}
    tree = ast.parse(inspect.getsource(sso_router))
    direct = []

    def walk(node, deferred):
        for child in ast.iter_child_nodes(node):
            func = child.func if isinstance(child, ast.Call) else None
            if not deferred and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                    and (func.value.id, func.attr) in reaching:
                direct.append((func.value.id + "." + func.attr, child.lineno))
            walk(child, deferred or isinstance(child, (ast.Lambda, ast.FunctionDef)))
    routes = [n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)]
    assert len(routes) >= 8
    for route in routes:
        walk(route, False)
    assert direct == [], direct
    assert not inspect.iscoroutinefunction(_api().sign_out)


def test_a_sign_in_goes_through_while_the_provider_cannot_serve_its_discovery_or_keys(monkeypatch, caplog):
    import logging
    from app.services import oidc_client as oc
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert h.finish(location)[0] == 200
    # The hour's copies lapse, and the provider's discovery and keys fail; its token endpoint still answers.
    for key in [k for k in oc._DEFAULT_CACHE._rows if k.startswith(("sso:disc:", "sso:jwks:"))]:
        oc._DEFAULT_CACHE.clear(key)
    inner = h.provider_fetch

    def broken(url, **kw):
        if url.endswith(("openid-configuration", "/certs")):
            raise oc.OidcError(oc.PROVIDER_ERROR, "the provider answered 500")
        return inner(url, **kw)
    monkeypatch.setattr(oc, "fetch_json", broken)
    caplog.set_level(logging.WARNING, logger="dockvault.sso")
    status, out = h.start(p)
    assert status == 200, out
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert status == 302 and location.startswith("/#sso="), location
    assert h.finish(location)[0] == 200
    warned = [r.getMessage() for r in caplog.records if "could not be fetched" in r.getMessage()]
    assert any("discovery document" in w for w in warned) and any("key set" in w for w in warned), warned


# --------------------------------------------------------------------------- a refusal at the provider ends access

def _refusal_world(monkeypatch, **policy):
    alice, root = _user(), _user("root", role="admin")
    p = _provider(policy={"sso_required_groups": ["vault-users"], **policy})
    identity = _identity(alice, p, refused_at=None)
    h = Harness(monkeypatch, [alice, root], [p], identities=[identity])
    h.revoked = []
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, **kw: h.revoked.append(kw) or 2)
    monkeypatch.setattr(h.S, "_active_admins", lambda db: [root])

    def callback_with(**claims):
        h.claims_override = claims
        status, out = h.start(p)
        state, _ = h.state_of(out["authorization_url"])
        return h.callback(p, state)[1]
    return h, alice, root, p, identity, callback_with


def test_a_verified_refusal_of_a_known_identity_ends_its_access_until_the_provider_admits_it(monkeypatch):
    from app.services import sso_freshness as F
    h, alice, root, p, identity, callback_with = _refusal_world(monkeypatch)
    from app.core.models import PendingLogin
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, consumed_at=None)
    others = types.SimpleNamespace(id=uuid.uuid4(), user_id=root.id, consumed_at=None)
    h.db.rows_of(PendingLogin).extend([pending, others])
    # A missing claim refuses the sign-in and ends nothing: it is not proof.
    assert callback_with(groups=...) == "/#sso-error=restriction_claim_missing"
    assert identity.refused_at is None and h.revoked == []
    # A verified token whose groups leave the person out ends their access.
    assert callback_with(groups=["sales"]) == "/#sso-error=restricted"
    assert identity.refused_at is not None
    assert h.revoked == [{"user_id": alice.id, "actor_username": "system", "durable": True}]
    assert ("sso_access_ended_by_refusal", "success",
            {"provider_id": str(p.id), "identity_id": str(identity.id), "sessions": 2}) in h.audits
    assert ("sso_sign_in_refused", "failure",
            {"provider_id": str(p.id), "purpose": "sign_in", "reason": "restricted"}) in h.audits
    assert ([str(root.id)], "contoso refused alice: sessions ended, keys paused") in h.notices
    # A sign-in already under way for alice ends with the refusal; another account's does not.
    assert pending.consumed_at is not None and others.consumed_at is None
    assert F.lapsed(h.db, alice.id) is not None
    # A sign-in the provider admits answers the refusal (a moment later: a handover keeps whole seconds, and one made
    # in the same second as a refusal counts as overtaken by it).
    from datetime import timedelta
    identity.refused_at -= timedelta(seconds=2)
    location = callback_with(groups=["vault-users"])
    assert location.startswith("/#sso="), location
    assert h.finish(location)[0] == 200
    assert F.lapsed(h.db, alice.id) is None


def test_the_callbacks_error_is_logged_as_a_code_of_the_protocol_or_not_at_all(monkeypatch, caplog):
    """Anyone can call the callback with an ``error`` of their choosing: it has no session, and the state comes
    from the start route. Only a value shaped like an error code of the protocol is written to the log; any other
    text is named, never copied, so a caller cannot write a line of their own into it."""
    import logging
    from app.api import sso_router
    alice, p = _user(), _provider()
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])

    def refused_with(error):
        status, out = h.start(p)
        state, _ = h.state_of(out["authorization_url"])
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="dockvault.sso"):
            assert h.callback(p, state, code=None, error=error)[1] == "/#sso-error=provider_error"
        return [r.getMessage() for r in caplog.records if "sso callback error" in r.getMessage()]

    assert refused_with("access_denied") == [f"sso callback error for provider {p.id}: access_denied"]
    for chosen in ("x%0d%0a2026-11-13 forged line", "Access_Denied", "a" * 41, "access denied", "<b>", "0"):
        assert refused_with(chosen) == [f"sso callback error for provider {p.id}: unrecognised"], chosen
    assert sso_router._logged_error(None) == "no code" and sso_router._logged_error("login_required") == "login_required"
    assert sso_router._logged_error("a" * 40) == "a" * 40 and sso_router._logged_error(["access_denied"]) == "unrecognised"
    assert sso_router._logged_error("access_denied\n") == "unrecognised"


def test_a_refusal_ends_nothing_when_the_option_is_off_or_the_subject_is_nobodys(monkeypatch):
    h, alice, root, p, identity, callback_with = _refusal_world(monkeypatch, sso_refusal_ends_access=False)
    assert callback_with(groups=["sales"]) == "/#sso-error=restricted"
    assert identity.refused_at is None and h.revoked == []
    assert not any(a == "sso_access_ended_by_refusal" for a, _, _ in h.audits)
    p.policy = {"sso_required_groups": ["vault-users"]}
    assert callback_with(groups=["sales"], sub="somebody-else") == "/#sso-error=restricted"
    assert identity.refused_at is None and h.revoked == []


def test_the_administrators_user_list_shows_when_keys_pause(monkeypatch):
    from datetime import timedelta
    listed = dict(password_set_by=None, password_set_by_other_at=None)
    root, alice, bob = _user("root", role="admin", **listed), _user(**listed), _user("bob", **listed)
    p = _provider(policy={"sso_freshness_days": 30})
    signed_in = datetime.utcnow() - timedelta(days=10)
    h = Harness(monkeypatch, [root, alice, bob], [p], identities=[_identity(alice, p, last_sign_in_at=signed_in)])
    import app.core.endpoint_permissions as ep
    monkeypatch.setattr(ep, "check_endpoint_permission", lambda *a, **k: None)
    rows = [r.model_dump() for r in run_coroutine(h.S.list_users(current_user=root, db=h.db))]
    by_name = {r["username"]: r for r in rows}
    assert by_name["alice"]["sso_freshness"] == {"due": (signed_in + timedelta(days=30)).isoformat() + "Z",
                                                 "provider": "contoso", "lapsed": False, "refused": False}
    assert by_name["bob"]["sso_freshness"] is None and by_name["root"]["sso_freshness"] is None


def test_an_administrator_clears_a_refusal_under_the_step_up_and_never_their_own(monkeypatch):
    from app.api import sso_admin_router as A
    from app.services import sso_freshness as F
    root, alice = _user("root", role="admin"), _user()
    p = _provider(state="disabled")
    identity = _identity(alice, p, refused_at=datetime.utcnow())
    own = _identity(root, p, subject="subject-root", refused_at=datetime.utcnow())
    h = Harness(monkeypatch, [root, alice], [p], identities=[identity, own])
    # The route is an administrator's, under the sign-in policy step-up.
    assert A._step_up.action == "admin.auth_policy.write"
    steps = []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: steps.append(user.username))
    from app.api import sso_providers_router as R
    told = []
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append((by, title, body)))
    # The provider is disabled, and the refusal it recorded still pauses alice's keys.
    assert F.lapsed(h.db, alice.id) is not None
    status, body, _ = _call(h.S, "POST", f"/admin/sso/identities/{own.id}/clear-refusal")
    assert status == 409 and body["detail"]["reason"] == "own_identity" and steps == [] and own.refused_at is not None
    status, body, _ = _call(h.S, "POST", f"/admin/sso/identities/{identity.id}/clear-refusal")
    assert status == 200 and body == {"cleared": True} and steps == ["root"]
    assert identity.refused_at is None and F.lapsed(h.db, alice.id) is None
    # Lifting it hands a person their keys back: the other administrators are told, once, and only when it was lifted.
    assert len(told) == 1 and told[0][:2] == ("root", "A single sign-on refusal was lifted")
    assert "alice" in told[0][2] and "work again" in told[0][2]
    assert ("sso_refusal_cleared", "success", {"user_id": str(alice.id), "provider_id": str(p.id),
                                               "identity_id": str(identity.id)}) in h.audits
    status, body, _ = _call(h.S, "POST", f"/admin/sso/identities/{identity.id}/clear-refusal")
    assert status == 409 and body["detail"]["reason"] == "not_refused" and steps == ["root"]
    assert _call(h.S, "POST", f"/admin/sso/identities/{uuid.uuid4()}/clear-refusal")[0] == 404
    assert _call(h.S, "POST", "/admin/sso/identities/not-an-id/clear-refusal")[0] == 404
    assert len(told) == 1


def test_an_identity_whose_provider_refused_or_lapsed_is_not_unlinked_by_its_owner(monkeypatch):
    """Unlinking would end the provider's say over the account's keys and credentials: refused while the provider's
    refusal stands or its window has lapsed, whatever the provider's state; allowed once the person signed in again."""
    from datetime import timedelta
    alice, p = _user(), _provider()
    identity = _identity(alice, p, refused_at=datetime.utcnow())
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    for state in ("enabled", "disabled"):
        p.state = state
        status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
        assert status == 409 and out["detail"]["reason"] == "sso_freshness_lapsed", out
        assert "an administrator must clear" in out["detail"]["message"]
    p.state = "enabled"
    identity.refused_at, identity.last_sign_in_at = None, datetime.utcnow() - timedelta(days=31)
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 409 and out["detail"]["message"] == "Sign in through contoso again before you unlink it."
    assert len(h.identities()) == 1
    identity.last_sign_in_at = datetime.utcnow()
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 200 and h.identities() == []


def test_a_handover_the_providers_refusal_overtook_is_not_redeemed(monkeypatch):
    """An admitted callback mints a one-time code; the provider then refuses the person at another callback. The code
    is answered as unknown: the refusal ends the sign-ins under way. A refusal made before an admitted callback is
    answered by it, as before."""
    from datetime import timedelta
    alice, p = _user(), _provider()
    identity = _identity(alice, p, refused_at=None)
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso="), location
    identity.refused_at = datetime.utcnow() + timedelta(seconds=1)
    status, body = h.finish(location)
    assert status == 401, body
    # Refused earlier, admitted since: the admitted sign-in finishes and answers the refusal.
    identity.refused_at = datetime.utcnow() - timedelta(minutes=5)
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    status, body = h.finish(location)
    assert status == 200, body
    assert identity.last_sign_in_at is not None and identity.last_sign_in_at > identity.refused_at


@pytest.mark.parametrize("ahead, refused", [(30, False), (90, True), (7 * 86400, True)])
def test_a_provider_sign_in_time_that_has_not_come_yet_is_refused_beyond_the_skew(monkeypatch, ahead, refused):
    """The provider's own sign-in time feeds the rules that read the provider's standing, so one that lies ahead of
    now by more than the skew every token check allows is refused at the callback, with a reason that names the
    clock. Within the skew it is a clock a few seconds fast, and the sign-in goes on."""
    alice, p = _user(), _provider()
    identity = _identity(alice, p)
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"auth_time": int(time.time()) + ahead}
    status, location, _ = h.callback(p, state, iss=ISSUER)
    if not refused:
        assert status == 302 and location.startswith("/#sso="), location
        return
    assert location == "/#sso-error=provider_clock_ahead", location
    assert identity.last_sign_in_at is None and all(a[0] != "login_success" for a in h.audits)
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == "provider_clock_ahead" for a in h.audits), h.audits
    from app.services import sso_sign_in as sso
    assert "clock" in sso.REASON_TEXTS["provider_clock_ahead"]
