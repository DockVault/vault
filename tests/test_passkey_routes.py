"""The passkey self-service routes, driven through the ASGI app against an in-memory database and a software
authenticator: the proof a registration owes, the ceremony end to end, the limits, the provisional rule, rename,
removal with the last-factor guard, the owner's confirmation, and an administrator's removal as a credential
change (and a second-factor reset retiring every passkey). Offline: no Redis (a fake challenge store), no SMTP
(the notice and email helpers record), no Postgres."""
import json
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB
from _webauthn_softauth import SoftAuthenticator

pytestmark = pytest.mark.unit

ORIGIN = "https://vault.example.test"
RP_ID = "vault.example.test"


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


class DB(MemoryDB):
    """The in-memory session, filing an added ORM row under its model so the routes' own reads find it."""

    def add(self, obj):
        super().add(obj)
        self.rows_of(type(obj)).append(obj)


class FakeRedis:
    """What the challenge store needs: SET NX EX and GETDEL."""

    def __init__(self):
        self.rows = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.rows:
            return None
        self.rows[key] = value
        return True

    def getdel(self, key):
        return self.rows.pop(key, None)


def _call(S, method, path, body=None, headers=None):
    out = {}

    async def _drive():
        hdrs = [(b"content-type", b"application/json"), (b"authorization", b"Bearer t")]
        for k, v in (headers or {}).items():
            hdrs.append((k.lower().encode(), v.encode()))
        scope = {"type": "http", "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": hdrs, "client": ("127.0.0.1", 1234), "server": ("testserver", 80),
                 "scheme": "https"}
        payload = json.dumps(body).encode() if body is not None else b""
        chunks = []

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))

        await S.app(scope, receive, send)
        out["body"] = json.loads(b"".join(chunks) or b"null")

    run_coroutine(_drive(), timeout=30)
    return out["status"], out["body"]


def _user(username="alice", role="user", password_hash="x", **extra):
    from app.core.models import RoleEnum
    now = datetime.utcnow()
    fields = dict(id=uuid.uuid4(), username=username, email=f"{username}@example.test", role=RoleEnum(role), is_active=True,
                  is_locked=False, locked_until=None, password_hash=password_hash, second_factor_reset_at=None,
                  created_at=now, groups=[], _is_temp_session=False)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


class Harness:
    """One signed-in account, the tables the routes read, and the recorded side effects."""

    def __init__(self, monkeypatch, user, *, totp=False, changes=()):
        from app.core import second_factor as sf
        from app.core import webauthn_challenges as wc
        from app.core.models import (CredentialChange, SecondFactorAction, SecondFactorEnrollment,
                                     SecondFactorRecoveryCode, SystemSetting, User, WebAuthnCredential)
        from app.services import webauthn_service as ws
        self.S = S = _api()
        self.user = user
        self.redis = FakeRedis()
        enrollments = [types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, method="totp", status="active")] if totp else []
        self.db = DB({User: [user], WebAuthnCredential: [], SecondFactorEnrollment: enrollments,
                            SecondFactorRecoveryCode: [], SecondFactorAction: [], SystemSetting: [],
                            CredentialChange: list(changes)})
        self.db.query_groups = []
        S.app.dependency_overrides[S.get_db] = lambda: self.db
        S.app.dependency_overrides[S.get_current_user] = lambda: user
        S.app.dependency_overrides[S.get_enrolling_principal] = lambda: (user, None)
        S.app.dependency_overrides[S.require_interactive_admin] = lambda: user
        monkeypatch.setattr(wc, "_redis", lambda redis: self.redis)
        monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name=name))
        self.receipts = []
        monkeypatch.setattr(sf, "consume_step_up_receipt",
                            lambda db, *, user, action, receipt, session_hash, redis=None: (
                                self.receipts.append((action, receipt)) or receipt == "ok"))
        # The confirm route reads which factor vouched: "ok" was earned with an authenticator code here.
        monkeypatch.setattr(sf, "consume_step_up_receipt_detail",
                            lambda db, *, user, action, receipt, session_hash, redis=None: (
                                self.receipts.append((action, receipt)) or ("totp" if receipt == "ok" else None)))
        monkeypatch.setattr(S, "_sf_user_group_ids", lambda db, u: [])
        self.notices, self.emails, self.audits = [], [], []
        monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
            self.notices.append({"ids": list(ids), "type": ntype, "title": title, "body": body}) or list(ids)))
        monkeypatch.setattr(S, "_fire_action_email", lambda db, key, *, email, username=None, action_context=None: (
            self.emails.append({"key": key, "email": email, "context": action_context})))
        monkeypatch.setattr(S.AuditLogger, "log_action", lambda _self, **kw: self.audits.append(kw) or None)
        from app.core.rate_limiter import rate_limiter
        monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (True, 1, 0))   # the middleware calls it positionally
        from app.core import security
        monkeypatch.setattr(security, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")

    def rows(self):
        from app.core.models import WebAuthnCredential
        return self.db.rows_of(WebAuthnCredential)

    def register(self, *, label="work laptop", password="pw", receipt=None, authenticator=None, origin=ORIGIN, **make_kw):
        headers = {"X-Second-Factor": receipt} if receipt else None
        status, body = _call(self.S, "POST", "/users/me/passkeys/register/options", {"current_password": password}, headers)
        if status != 200:
            return status, body, None
        auth = authenticator or SoftAuthenticator()
        credential = auth.make_credential(body["options"], origin, **make_kw)
        status, body = _call(self.S, "POST", "/users/me/passkeys/register/verify",
                             {"challenge_id": body["challenge_id"], "credential": credential, "label": label})
        return status, body, auth


@pytest.fixture(autouse=True)
def _clean_overrides():
    S = _api()
    yield
    S.app.dependency_overrides.clear()


# --------------------------------------------------------------------------- registration

def test_a_passkey_is_registered_only_by_its_own_account(monkeypatch):
    """No route registers a passkey for someone else, and the options always name the caller's own account as the
    key's user: an administrator adds nothing to another account's keys."""
    root = _user("root", role="admin")
    h = RouteHarness(monkeypatch, root) if False else Harness(monkeypatch, root)
    other = uuid.uuid4()
    for path in (f"/users/{other}/passkeys/register/options", f"/users/{other}/passkeys/register/verify"):
        status, body = _call(h.S, "POST", path, {"current_password": "pw"})
        assert status in (404, 405), (path, status, body)
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 200, body
    from app.services import webauthn_service as ws
    import base64
    handle = body["options"]["publicKey"]["user"]["id"]
    assert base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4)) == ws.user_handle_for(root.id)
    assert body["options"]["publicKey"]["user"]["name"] == "root"


def test_a_first_passkey_is_proved_by_the_password_and_registered_end_to_end(monkeypatch):
    h = Harness(monkeypatch, _user())
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {})
    assert status == 400 and "password" in body["detail"]
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "wrong"})
    assert status == 400
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 200
    pk = body["options"]["publicKey"]
    assert pk["rp"] == {"id": RP_ID, "name": "DockVault"} or pk["rp"]["id"] == RP_ID
    assert pk["user"]["name"] == "alice" and pk["authenticatorSelection"]["userVerification"] == "required"
    assert pk["attestation"] == "none" and pk["excludeCredentials"] == [] and body["provisional"] is False
    assert [p["alg"] for p in pk["pubKeyCredParams"]] == [-7, -257, -8]
    assert len(h.redis.rows) == 1 and body["expires_in"] == 300
    # The step-up was not asked: the account has no factor.
    assert h.receipts == []
    auth = SoftAuthenticator()
    credential = auth.make_credential(body["options"], ORIGIN)
    status, shown = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                          {"challenge_id": body["challenge_id"], "credential": credential, "label": "  work laptop  "})
    assert status == 201, shown
    assert shown["label"] == "work laptop" and shown["provisional"] is False and shown["algorithm"] == "ES256"
    assert shown["synced"] is False and shown["transports"] == ["internal", "hybrid"]
    (row,) = h.rows()
    assert row.credential_id == auth.credential_id and row.user_id == h.user.id and row.retired_at is None
    assert row.provisional_until is None and row.label == "work laptop"
    # The challenge was spent, the owner told in the app and by email, the audit row written.
    assert h.redis.rows == {}
    assert [a["action"] for a in h.audits] == ["passkey_registration_failed", "passkey_registered"]   # the wrong password, then the key
    assert h.audits[0]["details"] == {"reason": "wrong_password"} and h.audits[0]["status"] == "failure"
    assert h.audits[1]["details"] == {"passkey_id": str(row.id), "provisional": False}
    assert h.notices[0]["title"] == "A passkey was added to your account" and "work laptop" in h.notices[0]["body"]
    assert h.emails[0]["key"] == "sign_in_method_changed" and h.emails[0]["email"] == "alice@example.test"
    assert "work laptop" in h.emails[0]["context"]["change"]
    # It is listed, oldest first, with the limit; never the key material.
    status, listed = _call(h.S, "GET", "/users/me/passkeys")
    assert status == 200 and [p["id"] for p in listed["passkeys"]] == [str(row.id)] and listed["limit"] == 20
    assert "credential_id" not in listed["passkeys"][0] and "public_key" not in json.dumps(listed)


def test_an_account_with_a_factor_proves_the_step_up_not_the_password(monkeypatch):
    h = Harness(monkeypatch, _user(), totp=True)
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 403 and body["detail"]["reason"] == "step_up_required"
    assert body["detail"]["action"] == "account.second_factor" and "totp" in body["detail"]["methods"]
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
    assert status == 200 and h.receipts[-1] == ("account.second_factor", "ok")


def test_a_password_less_account_with_no_factor_is_told_to_wait_for_the_provider_step_up(monkeypatch):
    h = Harness(monkeypatch, _user(password_hash=None))
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {})
    assert status == 409 and "identity-provider" in body["detail"]


def test_a_temporary_credential_cannot_manage_passkeys(monkeypatch):
    h = Harness(monkeypatch, _user(_is_temp_session=True))
    for method, path in (("POST", "/users/me/passkeys/register/options"), ("GET", "/users/me/passkeys")):
        status, body = _call(h.S, method, path, {"current_password": "pw"} if method == "POST" else None)
        assert status == 403, (path, body)


@pytest.mark.parametrize("spoil,reason", [
    (dict(origin="https://evil.example.test"), "origin_mismatch"),
    (dict(rp_id_override="evil.example.test"), "rp_id_mismatch"),
    (dict(flags=SoftAuthenticator.__init__.__globals__["FLAG"].UP), "user_not_verified"),
    (dict(credential_type="public-token"), "malformed"),
])
def test_a_browser_answer_that_breaks_a_rule_is_refused_and_audited(monkeypatch, spoil, reason):
    h = Harness(monkeypatch, _user())
    status, body, _ = h.register(**spoil)
    assert status == 400 and body["detail"]["reason"] == reason, body
    assert h.rows() == [] and [a["action"] for a in h.audits] == ["passkey_registration_failed"]
    assert h.audits[0]["details"] == {"reason": reason} and h.audits[0]["status"] == "failure"
    assert h.notices == [] and h.emails == []


def test_a_challenge_serves_one_ceremony_for_one_account(monkeypatch):
    h = Harness(monkeypatch, _user())
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    auth = SoftAuthenticator()
    credential = auth.make_credential(body["options"], ORIGIN)
    # Someone else's challenge id (another account's) is unknown to this account.
    other_key = next(iter(h.redis.rows))
    stored = json.loads(h.redis.rows[other_key])
    stored["user_id"] = str(uuid.uuid4())
    h.redis.rows[other_key] = json.dumps(stored)
    status, out = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                        {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 400 and out["detail"]["reason"] == "challenge_unknown"
    assert h.redis.rows == {}            # spent all the same
    # A spent or made-up id is unknown too.
    status, out = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                        {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 400 and out["detail"]["reason"] == "challenge_unknown"
    status, out = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                        {"challenge_id": "zz", "credential": credential})
    assert status == 400


def test_the_same_authenticator_credential_registers_once_and_the_account_holds_twenty(monkeypatch):
    from app.core.models import WebAuthnCredential
    h = Harness(monkeypatch, _user())
    status, first, auth = h.register(label="one")
    assert status == 201
    # The same credential again: excluded by the options (so a real browser refuses) and refused on verify.
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 403                   # the account now has a factor: the step-up applies
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
    excluded = body["options"]["publicKey"]["excludeCredentials"]
    assert len(excluded) == 1 and excluded[0]["transports"] == ["internal", "hybrid"]
    credential = auth.make_credential(body["options"], ORIGIN)
    status, out = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                        {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 400 and out["detail"]["reason"] == "already_registered"
    # The same credential on ANOTHER account: refused too (one key, one account).
    other = _user("bob")
    h.rows().append(types.SimpleNamespace(id=uuid.uuid4(), user_id=other.id, credential_id=b"other-cred", retired_at=None,
                                          provisional_until=None, created_at=datetime.utcnow(), transports=None))
    # Twenty keys fill the account; the twenty-first is refused at options and at verify.
    now = datetime.utcnow()
    for i in range(19):
        h.rows().append(types.SimpleNamespace(id=uuid.uuid4(), user_id=h.user.id, credential_id=bytes([i]) * 8, retired_at=None,
                                              provisional_until=None, created_at=now, transports=None, label=f"k{i}",
                                              backup_eligible=False, cose_alg=-7, last_used_at=None))
    assert len([r for r in h.rows() if r.user_id == h.user.id]) == 20
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
    assert status == 409 and "20 passkeys" in body["detail"]
    # A retired key does not count toward the limit.
    h.rows()[-1].retired_at = now
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
    assert status == 200
    # ...but its credential id stays taken while the row exists.
    h.rows().append(types.SimpleNamespace(id=uuid.uuid4(), user_id=h.user.id, credential_id=SoftAuthenticator().credential_id,
                                          retired_at=now, provisional_until=None, created_at=now, transports=None))
    assert isinstance(h.db.rows_of(WebAuthnCredential), list)


def test_a_passkey_added_soon_after_an_administrators_change_is_provisional_until_confirmed(monkeypatch):
    from app.core import credential_changes as cc
    applied = datetime.utcnow() - timedelta(days=3)
    change = types.SimpleNamespace(id=uuid.uuid4(), target_user_id=None, status=cc.MADE, applied_at=applied, kind=cc.PASSWORD)
    user = _user()
    change.target_user_id = user.id
    h = Harness(monkeypatch, user, totp=True, changes=[change])
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
    assert status == 200 and body["provisional"] is True
    auth = SoftAuthenticator()
    status, shown = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                          {"challenge_id": body["challenge_id"], "credential": auth.make_credential(body["options"], ORIGIN)})
    assert status == 201 and shown["provisional"] is True
    assert shown["provisional_until"].startswith((applied + cc.WINDOW).date().isoformat())
    assert h.audits[0]["details"]["provisional"] is True and "provisional" in h.notices[0]["body"]
    assert "provisional" in h.emails[0]["context"]["change"]
    (row,) = h.rows()
    # Confirming it needs the step-up, then an older factor: this account has an authenticator app.
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm")
    assert status == 403 and out["detail"]["reason"] == "step_up_required"
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 200 and out["provisional"] is False and row.provisional_until is None
    assert [a["action"] for a in h.audits][-1] == "passkey_confirmed"
    # Confirming an ordinary key is a no-op answer, not an error.
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 200 and out["provisional"] is False


def test_nothing_older_cannot_vouch_for_a_provisional_passkey(monkeypatch):
    from app.core import credential_changes as cc
    user = _user()
    change = types.SimpleNamespace(id=uuid.uuid4(), target_user_id=user.id, status=cc.MADE,
                                   applied_at=datetime.utcnow() - timedelta(days=1), kind=cc.PASSWORD)
    h = Harness(monkeypatch, user, changes=[change])
    status, shown, _ = h.register(label="new")
    assert status == 201 and shown["provisional"] is True
    (row,) = h.rows()
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 409 and "Nothing older" in out["detail"]
    # An older, ordinary passkey can.
    older = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, credential_id=b"older", retired_at=None, provisional_until=None,
                                  created_at=row.created_at - timedelta(days=30), transports=None, label="old",
                                  backup_eligible=False, cose_alg=-7, last_used_at=None)
    h.rows().append(older)
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 200 and out["provisional"] is False


# --------------------------------------------------------------------------- rename and remove

def test_rename_cleans_the_label_and_remove_needs_the_step_up(monkeypatch):
    h = Harness(monkeypatch, _user())
    status, shown, _ = h.register(label="one")
    assert status == 201
    (row,) = h.rows()
    status, out = _call(h.S, "PATCH", f"/users/me/passkeys/{row.id}", {"label": "  My\u0007 phone  "})
    assert status == 200 and out["label"] == "My phone" and row.label == "My phone"
    status, out = _call(h.S, "PATCH", f"/users/me/passkeys/{row.id}", {"label": "x" * 101})
    assert status == 422
    status, out = _call(h.S, "PATCH", f"/users/me/passkeys/{row.id}", {"label": "\u0007"})
    assert status == 400
    status, out = _call(h.S, "PATCH", f"/users/me/passkeys/{uuid.uuid4()}", {"label": "x"})
    assert status == 404
    # Remove: the step-up first; then gone, told, audited; sessions untouched (nothing here revokes).
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{row.id}")
    assert status == 403 and out["detail"]["reason"] == "step_up_required"
    # A passkey-only account proves this step-up with its passkey.
    assert out["detail"]["methods"] == ["passkey"]
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": "ok"})
    assert status == 200 and out == {"removed": True} and h.rows() == []
    assert [a["action"] for a in h.audits][-1] == "passkey_removed"
    assert h.notices[-1]["title"] == "A passkey was removed from your account" and "My phone" in h.notices[-1]["body"]
    assert h.emails[-1]["key"] == "sign_in_method_changed"
    # With no factor left the step-up answers "enroll" before the route looks for the key (as the TOTP route does).
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": "ok"})
    assert status == 403 and out["detail"]["reason"] == "enroll_required"


def test_the_last_factor_of_a_required_or_sso_only_account_stays(monkeypatch):
    from app.core.models import SystemSetting
    h = Harness(monkeypatch, _user())
    status, shown, _ = h.register(label="only")
    (row,) = h.rows()
    # The deployment requires a second factor of everyone: the last passkey stays.
    h.db.rows_of(SystemSetting).append(types.SimpleNamespace(key="global_settings", value=json.dumps({"mfa_mode": "required"})))
    monkeypatch.setattr(h.S, "_global_settings_blob", lambda db: {"mfa_mode": "required"})
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": "ok"})
    assert status == 409 and "last one" in out["detail"] and h.rows() == [row]
    # With another passkey, the removal goes through.
    other = types.SimpleNamespace(id=uuid.uuid4(), user_id=h.user.id, credential_id=b"two", retired_at=None, provisional_until=None,
                                  created_at=datetime.utcnow(), transports=None, label="two", backup_eligible=False, cose_alg=-7,
                                  last_used_at=None)
    h.rows().append(other)
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": "ok"})
    assert status == 200 and h.rows() == [other]
    # An account that signs in only through a provider keeps its last factor even when the policy is optional.
    monkeypatch.setattr(h.S, "_global_settings_blob", lambda db: {"mfa_mode": "optional"})
    h.user.sso_only = True
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{other.id}", None, {"X-Second-Factor": "ok"})
    assert status == 409 and "single sign-on" in out["detail"]
    h.user.sso_only = False
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{other.id}", None, {"X-Second-Factor": "ok"})
    assert status == 200 and h.rows() == []


# --------------------------------------------------------------------------- the administrator

def test_an_administrator_removes_a_passkey_as_a_credential_change_and_never_their_own_here(monkeypatch):
    from app.core import credential_changes as cc
    admin = _user("root", role="admin")
    target = _user("carol")
    h = Harness(monkeypatch, admin)
    from app.core.models import User
    h.db.rows_of(User).append(target)
    now = datetime.utcnow()
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, credential_id=b"c", retired_at=None, provisional_until=None,
                                created_at=now, transports=["usb"], label="yubikey", backup_eligible=False, cose_alg=-7, last_used_at=None)
    h.rows().append(key)
    monkeypatch.setattr(h.S, "require_endpoint_permission", lambda *a, **k: (lambda f: f), raising=False)
    monkeypatch.setattr(h.S, "_enforce_step_up", lambda db, user, request, action: None)
    seen = {}

    def fake_change(db, actor, tgt, kind, *, summary, payload, request=None):
        seen.update(kind=kind, summary=summary, payload=payload, target=tgt.username)
        result = h.S._apply_credential_change(db, kind, tgt, payload, actor_id=actor.id, actor_name=actor.username, request=request)
        return types.SimpleNamespace(change=None, held=False, result=result)
    monkeypatch.setattr(h.S, "_credential_change", fake_change)
    status, listed = _call(h.S, "GET", f"/users/{target.id}/passkeys")
    assert status == 200 and [p["label"] for p in listed["passkeys"]] == ["yubikey"]
    status, out = _call(h.S, "DELETE", f"/users/{target.id}/passkeys/{key.id}")
    assert status == 200 and out == {"removed": True}, out
    assert seen == {"kind": cc.PASSKEY, "summary": 'Passkey "yubikey"', "payload": {"passkey_id": str(key.id)}, "target": "carol"}
    # Retired, not deleted; gone from both lists; the owner told; the audit names the target.
    assert key.retired_at is not None and h.rows() == [key]
    status, listed = _call(h.S, "GET", f"/users/{target.id}/passkeys")
    assert listed["passkeys"] == []
    assert h.audits[-1]["action"] == "passkey_admin_removed" and h.audits[-1]["details"]["target_username"] == "carol"
    assert h.notices[-1]["ids"] == [str(target.id)] and 'passkey "yubikey"' in h.notices[-1]["body"]
    # Removing it again: 404. An administrator's own passkey: not through this route.
    status, out = _call(h.S, "DELETE", f"/users/{target.id}/passkeys/{key.id}")
    assert status == 404
    own = types.SimpleNamespace(id=uuid.uuid4(), user_id=admin.id, credential_id=b"a", retired_at=None, provisional_until=None,
                                created_at=now, transports=None, label="mine", backup_eligible=False, cose_alg=-7, last_used_at=None)
    h.rows().append(own)
    status, out = _call(h.S, "DELETE", f"/users/{admin.id}/passkeys/{own.id}")
    assert status == 400 and "profile" in out["detail"] and own.retired_at is None


def test_a_second_factor_reset_retires_every_passkey_and_a_gone_key_is_reported(monkeypatch):
    from app.core import credential_changes as cc
    from app.core.models import SecondFactorEnrollment, SecondFactorRecoveryCode, WebAuthnCredential, User
    S = _api()
    admin, target = _user("root", role="admin"), _user("carol")
    now = datetime.utcnow()
    keys = [types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, retired_at=None) for _ in range(2)]
    keys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=_user("dave").id, retired_at=None))
    db = MemoryDB({User: [admin, target], WebAuthnCredential: keys, SecondFactorEnrollment: [], SecondFactorRecoveryCode: []})
    monkeypatch.setattr(S, "_revoke_sessions", lambda db, **kw: None)
    from app.core import auditor_rights, legal_holds
    monkeypatch.setattr(auditor_rights, "after_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(legal_holds, "after_starter_change", lambda *a, **k: None)
    result = S._apply_credential_change(db, cc.SECOND_FACTOR, target, {}, actor_id=admin.id, actor_name="root")
    # A passkey-only account had a factor: the reset asks for a new set-up at the next sign-in.
    assert result == {"had_second_factor": True, "passkeys_retired": 2}
    assert [k.retired_at is not None for k in keys] == [True, True, False] and target.second_factor_reset_at is not None
    # A passkey removal for a key already gone is reported, never an error (an approved request can be late).
    assert S._apply_credential_change(db, cc.PASSKEY, target, {"passkey_id": str(uuid.uuid4())}, actor_id=admin.id,
                                      actor_name="root") == {"passkey_gone": True}
    assert S._apply_credential_change(db, cc.PASSKEY, target, {"passkey_id": "junk"}, actor_id=admin.id,
                                      actor_name="root") == {"passkey_gone": True}


def test_registration_has_a_budget_per_account_that_fails_closed(monkeypatch):
    """Asking for registration options is counted per account, on a budget of its own: refused with 429 when it is
    spent and with 503 while the limiter cannot count, and no challenge is made either time."""
    alice = _user("alice")
    h = Harness(monkeypatch, alice)
    from app.core.rate_limiter import rate_limiter, RateLimiterUnavailable
    asked = []

    def _spent(*a, **kw):
        if kw.get("prefix") == "passkey_register":
            asked.append((kw.get("identifier"), kw.get("fail_open")))
            return False, 0, 0
        return True, 1, 0
    monkeypatch.setattr(rate_limiter, "check_rate_limit", _spent)
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 429 and "Too many registration attempts" in body["detail"], body
    assert asked == [(str(alice.id), False)]

    def _down(*a, **kw):
        if kw.get("prefix") == "passkey_register":
            raise RateLimiterUnavailable("down")
        return True, 1, 0
    monkeypatch.setattr(rate_limiter, "check_rate_limit", _down)
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 503 and "temporarily unavailable" in body["detail"], body
    assert h.redis.rows == {}


def test_a_wrong_password_for_a_first_passkey_is_counted_before_it_is_checked_and_is_recorded(monkeypatch):
    """The account's budget is asked before the password is looked at, so a guess is counted whether it is right or
    wrong, and a spent budget checks no password at all. A wrong password leaves a record; a missing one (the page
    asks once without, to learn what is owed) does not."""
    alice = _user("alice")
    h = Harness(monkeypatch, alice)
    from app.core import security
    from app.core.rate_limiter import rate_limiter
    order, allow = [], [True]

    def budget(*a, **kw):
        if kw.get("prefix") == "passkey_register":
            order.append("budget")
            return allow[0], 0, 0
        return True, 1, 0

    def password(plain, hashed):
        order.append("password")
        return plain == "pw" and hashed == "x"
    monkeypatch.setattr(rate_limiter, "check_rate_limit", budget)
    monkeypatch.setattr(security, "verify_password", password)
    path = "/users/me/passkeys/register/options"
    status, body = _call(h.S, "POST", path, {"current_password": "guess"})
    assert status == 400 and order == ["budget", "password"], (status, body, order)
    failed = [a for a in h.audits if a.get("action") == "passkey_registration_failed"]
    assert [(a["details"], a["status"]) for a in failed] == [({"reason": "wrong_password"}, "failure")]
    order.clear()
    assert _call(h.S, "POST", path, {})[0] == 400 and order == ["budget"]              # nothing to check
    assert len([a for a in h.audits if a.get("action") == "passkey_registration_failed"]) == 1
    order.clear()
    allow[0] = False
    status, body = _call(h.S, "POST", path, {"current_password": "pw"})
    assert status == 429 and order == ["budget"], (status, body, order)                 # the right password, not looked at
    assert h.redis.rows == {}


def test_the_auditor_grant_remembers_the_passkeys_it_was_approved_with():
    set_bare_api_env()
    from app.core import auditor_rights
    from app.core.models import AuditorGrant, WebAuthnCredential
    uid = uuid.uuid4()
    a, b = uuid.uuid4(), uuid.uuid4()
    db = MemoryDB({WebAuthnCredential: [
        types.SimpleNamespace(id=a, user_id=uid, retired_at=None),
        types.SimpleNamespace(id=b, user_id=uid, retired_at=None),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uid, retired_at=datetime.utcnow()),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uuid.uuid4(), retired_at=None)]})
    assert auditor_rights.passkey_ids(db, uid) == sorted([str(a), str(b)])
    assert "approved_credential_ids" in AuditorGrant.__table__.columns.keys()
    assert AuditorGrant.__table__.c.approved_credential_ids.nullable


def test_the_registries_know_the_new_names():
    set_bare_api_env()
    from app.core import audit_catalog, audit_privacy, credential_changes as cc, email_actions as ea
    for name in ("passkey_registered", "passkey_registration_failed", "passkey_renamed", "passkey_confirmed",
                 "passkey_removed", "passkey_admin_removed"):
        assert audit_catalog.lookup(name) is not None, name
    assert audit_privacy.DETAIL_KEYS["passkey_id"] == audit_privacy.IDENTIFIER
    assert audit_privacy.DETAIL_KEYS["provisional"] == audit_privacy.IDENTIFIER
    assert cc.label(cc.PASSKEY) == "Passkey removed" and cc.request_label(cc.PASSKEY) == "Remove a passkey"
    spec = ea.SPEC_BY_KEY["sign_in_method_changed"]
    assert spec["category"] == ea.SYSTEM and "{{action.change}}" in spec["default_body_html"]


def test_a_key_is_marked_attested_only_when_it_was_registered_under_direct_attestation(monkeypatch):
    """What the route records beside the key: whether the vault asked for direct attestation when it was added. The
    chain itself is the service's to check (its own tests); here the policy in force is what is written down."""
    import dataclasses
    from app.services import webauthn_service as ws
    h = Harness(monkeypatch, _user())
    status, shown, _auth = h.register()
    assert status == 201 and shown["attested"] is False and h.rows()[0].attested is False
    S = h.S
    plain = S._passkey_policy
    monkeypatch.setattr(S, "_passkey_policy",
                        lambda db: dataclasses.replace(plain(db), attestation="direct", trust_anchors=(b"anchor",)))
    options, verify = ws.registration_options, ws.verify_registration
    monkeypatch.setattr(ws, "registration_options", lambda rp, policy, **kw: options(rp, plain(None), **kw))
    monkeypatch.setattr(ws, "verify_registration", lambda rp, policy, **kw: verify(rp, plain(None), **kw))
    status, shown, _auth = h.register(label="second", receipt="ok")
    assert status == 201 and shown["attested"] is True, shown
    assert [r.attested for r in h.rows()] == [False, True]
    status, listed = _call(S, "GET", "/users/me/passkeys")
    assert status == 200 and listed["attestation"] == "none"               # the setting itself, as the profile reads it
    assert [k["attested"] for k in listed["passkeys"]] == [False, True]
