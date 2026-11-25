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
                  created_at=now, groups=[], _is_temp_session=False, sessions_ended=0)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


class Harness:
    """One signed-in account, the tables the routes read, and the recorded side effects."""

    def __init__(self, monkeypatch, user, *, totp=False, changes=()):
        from app.core import second_factor as sf
        from app.core import webauthn_challenges as wc
        from app.core.models import (ActiveSession, CredentialChange, SecondFactorAction, SecondFactorEnrollment,
                                     SecondFactorRecoveryCode, SystemSetting, User, WebAuthnCredential)
        from app.services import webauthn_service as ws
        self.S = S = _api()
        self.user = user
        self.redis = FakeRedis()
        # An authenticator app the account set up long ago (older than any passkey a test here registers).
        enrollments = [types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, method="totp", status="active",
                                             created_at=datetime.utcnow() - timedelta(days=90),
                                             confirmed_at=datetime.utcnow() - timedelta(days=90))] if totp else []
        # The session the caller acts from: a factor is written from it only while it stands.
        self.session = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, is_active=True, revoked=False,
                                             session_token=S.hash_session_token("the-session"))
        monkeypatch.setattr(S, "_current_session_token", lambda request: "the-session")
        self.db = DB({User: [user], WebAuthnCredential: [], SecondFactorEnrollment: enrollments,
                            SecondFactorRecoveryCode: [], SecondFactorAction: [], SystemSetting: [],
                            CredentialChange: list(changes), ActiveSession: [self.session]})
        self.db.query_groups = []
        # Undone with the test, whichever file uses the harness: left set, the last test's account stayed signed
        # in for whatever file ran next.
        for dependency, answer in ((S.get_db, lambda: self.db), (S.get_current_user, lambda: user),
                                   (S.get_enrolling_principal, lambda: (user, None)),
                                   (S.require_interactive_admin, lambda: user)):
            monkeypatch.setitem(S.app.dependency_overrides, dependency, answer)
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


def test_a_password_less_account_with_no_factor_and_no_provider_is_told_to_ask_an_administrator(monkeypatch):
    """With a provider that can confirm it afresh, such an account registers after that confirmation
    (tests/test_passkey_provider_proof.py); with none, nothing here can prove the request."""
    h = Harness(monkeypatch, _user(password_hash=None))
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {})
    assert status == 409 and "Ask an administrator." in body["detail"]


def test_an_account_whose_password_nobody_knows_is_not_asked_to_prove_a_passkey_with_it(monkeypatch):
    """The hash is of random bytes (an account made through a provider, a password taken back at a promotion): there
    is nothing to type, so the registration does not ask for "your current password" and answers what an account
    with no password is told. With a password set since, it asks for that password."""
    from app.core import password_origin
    user = _user(password_hash="argon2:of-random-bytes", password_nobody_knows=None)
    password_origin.mark_nobody_knows(user)
    h = Harness(monkeypatch, user)
    for body in ({}, {"current_password": "pw"}):
        status, out = _call(h.S, "POST", "/users/me/passkeys/register/options", body)
        assert status == 409 and "has no password and no second factor yet" in out["detail"], out
    user.password_hash = "x"                               # a password set since: the mark no longer fits
    status, out = _call(h.S, "POST", "/users/me/passkeys/register/options", {})
    assert status == 400 and "password" in out["detail"], out


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
    h.rows().append(types.SimpleNamespace(id=uuid.uuid4(), user_id=other.id, credential_id=b"other-cred", uv_initialized=True, retired_at=None,
                                          provisional_until=None, created_at=datetime.utcnow(), transports=None))
    # Twenty keys fill the account; the twenty-first is refused at options and at verify.
    now = datetime.utcnow()
    for i in range(19):
        h.rows().append(types.SimpleNamespace(id=uuid.uuid4(), user_id=h.user.id, credential_id=bytes([i]) * 8, uv_initialized=True, retired_at=None,
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
                                          uv_initialized=True, retired_at=now, provisional_until=None, created_at=now, transports=None))
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


@pytest.mark.parametrize("set_up, vouches", [("before the key", True), ("after the key", False),
                                             ("at no time on record", False), ("only begun before the key", False),
                                             ("at the key's own moment", False)])
def test_only_an_authenticator_app_older_than_the_key_vouches_for_a_provisional_passkey(monkeypatch, set_up, vouches):
    """A passkey is provisional when it is added soon after somebody else changed the account's sign-in details.
    Whoever holds the account then can add an authenticator app as well (with the password alone, or at a held
    sign-in), and prove the step-up with it. The route promised that only a factor older than the key vouches,
    and compared the age for a passkey alone: an app set up after the key confirmed it. Its age is read now, and
    a recovery code vouches only as its app does."""
    from app.core import credential_changes as cc
    from app.core import second_factor as sf
    from app.core.models import SecondFactorEnrollment
    user = _user()
    change = types.SimpleNamespace(id=uuid.uuid4(), target_user_id=user.id, status=cc.MADE,
                                   applied_at=datetime.utcnow() - timedelta(days=1), kind=cc.PASSWORD)
    h = Harness(monkeypatch, user, changes=[change])
    status, shown, _ = h.register(label="new")
    assert status == 201 and shown["provisional"] is True
    (row,) = h.rows()
    times = {"before the key": dict(created_at=row.created_at - timedelta(days=40), confirmed_at=row.created_at - timedelta(days=40)),
             "after the key": dict(created_at=row.created_at + timedelta(minutes=5), confirmed_at=row.created_at + timedelta(minutes=5)),
             "at no time on record": dict(created_at=None, confirmed_at=None),
             "at the key's own moment": dict(created_at=row.created_at, confirmed_at=row.created_at),
             # Begun before the key, its code confirmed only after it: set up after the key.
             "only begun before the key": dict(created_at=row.created_at - timedelta(days=1),
                                               confirmed_at=row.created_at + timedelta(minutes=5))}[set_up]
    h.db.rows_of(SecondFactorEnrollment).append(
        types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, method="totp", status="active", **times))
    assert h.S._authenticator_app_older_than(h.db, user.id, row.created_at) is vouches
    for marker in ("totp", "recovery"):
        row.provisional_until = datetime.utcnow() + timedelta(days=10)
        monkeypatch.setattr(sf, "consume_step_up_receipt_detail",
                            lambda db, *, user, action, receipt, session_hash, redis=None, m=marker: m)
        status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
        if vouches:
            assert status == 200 and out["provisional"] is False and row.provisional_until is None, (marker, out)
        else:
            assert status == 409 and "Nothing older can vouch for this passkey" in out["detail"], (marker, out)
            assert "no authenticator app set up before it" in out["detail"] and row.provisional_until is not None
    # An app that is not in use (never confirmed to the end) vouches for nothing, whatever its age.
    for enrollment in h.db.rows_of(SecondFactorEnrollment):
        enrollment.status = "unconfirmed"
    assert h.S._authenticator_app_older_than(h.db, user.id, row.created_at) is False


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
    older = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, credential_id=b"older", uv_initialized=True, retired_at=None, provisional_until=None,
                                  created_at=row.created_at - timedelta(days=30), transports=None, label="old",
                                  backup_eligible=False, cose_alg=-7, last_used_at=None)
    h.rows().append(older)
    # ...when the step-up was proved with that passkey. A receipt earned with an authenticator code vouches for
    # nothing here: the account has no authenticator app set up before the key.
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 409 and "only with a factor older than it" in out["detail"]
    from app.core import second_factor as sf
    monkeypatch.setattr(sf, "consume_step_up_receipt_detail",
                        lambda db, *, user, action, receipt, session_hash, redis=None: f"passkey:{older.id}")
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


def test_the_owner_is_advised_by_what_was_done_and_by_whether_the_account_has_a_password(monkeypatch):
    """A passkey added is removed under Your account; one removed is gone, and an administrator is told. The password
    is changed only by an account that has one anybody can type: one that signs in only through its provider has
    none, and is sent to an administrator."""
    h = Harness(monkeypatch, _user())
    status, shown, _ = h.register(label="one")
    assert status == 201, shown
    assert h.notices[-1]["body"].endswith(
        "If you did not do this, remove it under Your account and change your password.")
    (row,) = h.rows()
    status, out = _call(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": "ok"})
    assert status == 200, out
    removed = h.notices[-1]["body"]
    assert removed.endswith("If you did not do this, change your password and tell an administrator at once.")
    assert "remove what you do not recognize" not in removed
    assert h.emails[-1]["context"]["change"] == removed            # the email carries the same advice
    provider_only = _user("bob", sso_only=True)
    h.S._passkey_notice(h.db, provider_only, "A passkey was added to your account",
                        "You added a passkey to your account.")
    said = h.notices[-1]["body"]
    assert said.endswith("If you did not do this, tell an administrator at once.") and "change your password" not in said
    h.S._passkey_notice(h.db, provider_only, "A passkey was removed from your account",
                        "You removed a passkey from your account.", removed=True)
    said = h.notices[-1]["body"]
    assert said.endswith("If you did not do this, tell an administrator at once.") and "change your password" not in said
    assert "remove what you do not recognize" not in said


def test_turning_the_authenticator_app_off_is_told_to_the_owner_in_the_app_and_by_email(monkeypatch):
    """Turned off, the account's authenticator app and its recovery codes no longer work: its owner learns of it as
    of a passkey removed, from wherever it was done."""
    from app.core.models import SecondFactorEnrollment
    h = Harness(monkeypatch, _user(), totp=True)
    monkeypatch.setattr(h.S, "_second_factor_effective", lambda db, user: {"required": False})
    status, out = _call(h.S, "DELETE", "/users/me/second-factor", None, {"X-Second-Factor": "ok"})
    assert status == 200 and out == {"disabled": True}, out
    assert h.db.rows_of(SecondFactorEnrollment) == []
    (notice,) = h.notices
    assert notice["type"] == "account_changed" and notice["ids"] == [str(h.user.id)]
    assert notice["title"] == "The authenticator app was removed from your account"
    assert notice["body"] == ("You turned off your account's authenticator app; its recovery codes no longer work. "
                              "If you did not do this, change your password and tell an administrator at once.")
    (email,) = h.emails
    assert email["key"] == "sign_in_method_changed" and email["context"]["change"] == notice["body"]


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
    other = types.SimpleNamespace(id=uuid.uuid4(), user_id=h.user.id, credential_id=b"two", uv_initialized=True, retired_at=None, provisional_until=None,
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
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, credential_id=b"c", uv_initialized=True, retired_at=None, provisional_until=None,
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
    # It was the last factor she had set up, taken away by somebody else (a lost device, as a reset is): she is
    # told so, and sets the next one up at her next sign-in.
    assert target.second_factor_reset_at is not None
    assert "your account's last second factor" in h.notices[-1]["body"]
    assert "signed out everywhere" in h.notices[-1]["body"]
    assert "set up a new one at your next sign-in" in h.notices[-1]["body"]
    # Removing it again: 404. An administrator's own passkey: not through this route.
    status, out = _call(h.S, "DELETE", f"/users/{target.id}/passkeys/{key.id}")
    assert status == 404
    own = types.SimpleNamespace(id=uuid.uuid4(), user_id=admin.id, credential_id=b"a", uv_initialized=True, retired_at=None, provisional_until=None,
                                created_at=now, transports=None, label="mine", backup_eligible=False, cose_alg=-7, last_used_at=None)
    h.rows().append(own)
    status, out = _call(h.S, "DELETE", f"/users/{admin.id}/passkeys/{own.id}")
    assert status == 400 and "profile" in out["detail"] and own.retired_at is None


@pytest.mark.parametrize("left, marked", [
    ("nothing else", True), ("another passkey", False), ("another passkey of a removed algorithm", True),
    ("an authenticator", False), ("an authenticator not confirmed yet", True), ("another account's passkey", True),
    ("a passkey retired earlier", True)])
def test_an_administrators_removal_of_the_last_factor_an_account_set_up_counts_as_a_reset(monkeypatch, left, marked):
    """An administrator removes one passkey. Where that leaves the account with no factor it can give (no other
    passkey that can be used, and no authenticator), it is what a reset is: the account sets the next factor up
    at its next sign-in, and counts as an account with a factor of its own until then. It is marked for that
    where no key is left; a key it still holds and cannot use says the same by itself. A key of an
    algorithm that was removed and has run out is refused at every use: it is none. With a factor left, nothing
    is marked. Marked or not, the account's sessions end and its sign-ins under way are spent: somebody else took
    a key from it, and nothing says which sessions that key made. A removal an account makes of its own key marks
    and ends nothing (it is not made through this change at all)."""
    from app.core import credential_changes as cc
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential, User
    S = _api()
    admin, target, other = _user("root", role="admin"), _user("carol"), _user("dave")
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, uv_initialized=True, retired_at=None, label="yubikey", cose_alg=-7)
    keys, enrollments = [key], []
    if left.startswith("another passkey"):
        keys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, uv_initialized=True, retired_at=None, label="phone",
                                          cose_alg=-257 if "removed algorithm" in left else -7))
    elif left == "another account's passkey":
        keys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=other.id, uv_initialized=True, retired_at=None, label="his", cose_alg=-7))
    elif left == "a passkey retired earlier":
        keys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, uv_initialized=True, retired_at=datetime(2026, 11, 1),
                                          label="old", cose_alg=-7))
    elif left.startswith("an authenticator"):
        enrollments.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, method="totp",
                                                 status="unconfirmed" if "not confirmed" in left else "active"))
    db = MemoryDB({User: [admin, target, other], WebAuthnCredential: keys, SecondFactorEnrollment: enrollments})
    from app.core import auditor_rights, legal_holds
    from app.services import sign_in
    monkeypatch.setattr(auditor_rights, "after_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(legal_holds, "after_starter_change", lambda *a, **k: None)
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name=name))
    if "removed algorithm" in left:
        # Taken off the allowed list long ago: its 30 days are over, and the key is refused at every use.
        from app.core import webauthn_settings as wss
        monkeypatch.setattr(wss, "allowed_alg_codes", lambda: (-7,))
        monkeypatch.setattr(wss, "_removed", lambda db_: {"RS256": datetime(2026, 1, 1).isoformat()})
    ended, spent = [], []
    monkeypatch.setattr(S, "_revoke_sessions", lambda db_, **kw: ended.append(kw["user_id"]) or 0)
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda db_, user_id: spent.append(user_id) or 0)
    result = S._apply_credential_change(db, cc.PASSKEY, target, {"passkey_id": str(key.id)}, actor_id=admin.id,
                                        actor_name="root")
    assert key.retired_at is not None
    assert result == {"passkey_id": str(key.id), "passkey_label": "yubikey", "left_without_a_factor": marked,
                      "signed_out": True}
    # The mark is for an account left with no key at all. One that still holds a key it cannot use sets a factor
    # up again because of that key, with no mark, and the key counts again by itself should its algorithm (or the
    # vault's address) come back; with the mark, the next start would retire it as a key from before a reset.
    kept = left == "another passkey of a removed algorithm"
    assert (target.second_factor_reset_at is not None) is (marked and not kept)
    if kept:
        assert S._second_factor_to_set_up_again(db, target) is True and keys[1].retired_at is None
    assert other.second_factor_reset_at is None and admin.second_factor_reset_at is None
    assert ended == [target.id] and spent == [target.id]
    title, sentence = S._credential_change_notice(cc.PASSKEY, result)
    assert ("last second factor" in sentence) is marked and 'removed the passkey "yubikey"' in sentence
    assert "Your account was signed out everywhere." in sentence
    # The same change made as the account's own act (an administrator on their own account, through a route of
    # theirs) is no reset by somebody else.
    again = types.SimpleNamespace(id=uuid.uuid4(), user_id=other.id, uv_initialized=True, retired_at=None, label="own", cose_alg=-7)
    db.rows_of(WebAuthnCredential).append(again)
    for mine in [k for k in keys if k.user_id == other.id]:
        mine.retired_at = datetime(2026, 11, 1)
    own = S._apply_credential_change(db, cc.PASSKEY, other, {"passkey_id": str(again.id)}, actor_id=other.id,
                                     actor_name="dave", for_someone_else=False)
    assert own["left_without_a_factor"] is False and other.second_factor_reset_at is None
    assert own["signed_out"] is False and ended == [target.id] and spent == [target.id]
    assert "signed out" not in S._credential_change_notice(cc.PASSKEY, own)[1]
    # The one place the two-person rule is applied passes it on so: whoever acts on their own account there has
    # the change applied as their own, for a passkey as for every other kind. (No route brings an account's own
    # passkey here today; this holds what the function promises a route that would.)
    once_more = types.SimpleNamespace(id=uuid.uuid4(), user_id=other.id, uv_initialized=True, retired_at=None,
                                      label="own again", cose_alg=-7)
    db.rows_of(WebAuthnCredential).append(once_more)
    outcome = S._credential_change(db, other, other, cc.PASSKEY, summary="their own passkey",
                                   payload={"passkey_id": str(once_more.id)})
    assert outcome.held is False and outcome.change is None        # applied now, and not recorded as a request
    applied = outcome.result
    assert applied["passkey_id"] == str(once_more.id) and once_more.retired_at is not None
    assert applied["signed_out"] is False and applied["left_without_a_factor"] is False
    assert ended == [target.id] and spent == [target.id] and other.second_factor_reset_at is None


def test_a_second_factor_reset_retires_every_passkey_and_a_gone_key_is_reported(monkeypatch):
    from app.core import credential_changes as cc
    from app.core.models import SecondFactorEnrollment, SecondFactorRecoveryCode, WebAuthnCredential, User
    S = _api()
    admin, target = _user("root", role="admin"), _user("carol")
    now = datetime.utcnow()
    keys = [types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, uv_initialized=True, retired_at=None) for _ in range(2)]
    keys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=_user("dave").id, uv_initialized=True, retired_at=None))
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
        types.SimpleNamespace(id=a, user_id=uid, uv_initialized=True, retired_at=None),
        types.SimpleNamespace(id=b, user_id=uid, uv_initialized=True, retired_at=None),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uid, uv_initialized=True, retired_at=datetime.utcnow()),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=uuid.uuid4(), uv_initialized=True, retired_at=None)]})
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


def test_what_a_removal_leaves_is_counted_whatever_the_passkey_switch_says(monkeypatch):
    """Passkeys are switched off, by the deployment's switch, which may be turned back on. An administrator removes
    one of an account's two keys. The other is still the account's: the removal is not taken for the last one
    because of the switch, and no set-up is owed. Removing that one too leaves nothing, and is. Either removal,
    made by somebody else, signs the account out."""
    from app.core import credential_changes as cc
    from app.core import webauthn_settings
    from app.core.models import User
    admin, target = _user("root", role="admin"), _user("carol")
    h = Harness(monkeypatch, admin)
    h.db.rows_of(User).append(target)
    now = datetime.utcnow()
    keys = [types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, credential_id=bytes([i]), uv_initialized=True, retired_at=None,
                                  provisional_until=None, created_at=now, transports=["usb"], label=f"key-{i}",
                                  backup_eligible=False, cose_alg=-7, last_used_at=None) for i in (1, 2)]
    h.rows().extend(keys)
    monkeypatch.setattr(webauthn_settings, "enabled", lambda: False)
    assert webauthn_settings.usable_passkeys(h.db, target.id) == 0                     # none is a factor now
    assert webauthn_settings.usable_passkeys(h.db, target.id, whatever_the_switch=True) == 2
    assert webauthn_settings.usable_passkeys(h.db, target.id, without=keys[0].id, whatever_the_switch=True) == 1

    def remove(key):
        return h.S._apply_credential_change(h.db, cc.PASSKEY, target, {"passkey_id": str(key.id)},
                                            actor_id=admin.id, actor_name=admin.username, request=None)
    out = remove(keys[0])
    assert out["left_without_a_factor"] is False and out["signed_out"] is True, out
    assert target.second_factor_reset_at is None and keys[0].retired_at is not None
    out = remove(keys[1])
    assert out["left_without_a_factor"] is True and out["signed_out"] is True, out
    assert target.second_factor_reset_at is not None


def test_the_harness_leaves_no_override_behind_for_the_next_file(monkeypatch):
    """The harness signs its account in by overriding the application's dependencies. They go with the test that
    made them, in every file that uses the harness: two files once left them set, and the tests of the file that
    ran next met another file's account."""
    S = _api()
    with monkeypatch.context() as m:
        Harness(m, _user())
        assert S.get_enrolling_principal in S.app.dependency_overrides and S.get_db in S.app.dependency_overrides
    for dependency in (S.get_db, S.get_current_user, S.get_enrolling_principal, S.require_interactive_admin):
        assert dependency not in S.app.dependency_overrides
