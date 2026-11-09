"""Signing in with a passkey, through the ASGI app against an in-memory database and a software authenticator:
the one-shape challenge answer, the pipeline's table row by row (a user-verified passkey of a user is the whole
sign-in; an administrator, an auditor and a key without user verification add the password), the refusals
(unknown key, another account's challenge, replay, a lockout in force), the key's counters after a sign-in, and
the challenge limiter. Offline: a fake challenge store, the records observed."""
import json
import time
import types
import uuid
from datetime import datetime

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB
from _webauthn_softauth import FLAG, SoftAuthenticator

pytestmark = pytest.mark.unit

ORIGIN = "https://vault.example.test"
RP_ID = "vault.example.test"


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


class DB(MemoryDB):
    def add(self, obj):
        super().add(obj)
        # A row gets its id as a flush would give it (the model's default), so a token can name it.
        if getattr(obj, "id", None) is None and hasattr(type(obj), "id"):
            obj.id = uuid.uuid4()
        self.rows_of(type(obj)).append(obj)


class FakeRedis:
    def __init__(self):
        self.rows = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.rows:
            return None
        self.rows[key] = value
        return True

    def getdel(self, key):
        return self.rows.pop(key, None)


def _call(S, method, path, body=None):
    out = {}

    async def _drive():
        hdrs = [(b"content-type", b"application/json")]
        scope = {"type": "http", "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": hdrs, "client": ("203.0.113.9", 1234), "server": ("testserver", 80),
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


def _claims(token):
    import base64
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _user(username="alice", role="user", **extra):
    from app.core.models import RoleEnum
    now = datetime.utcnow()
    fields = dict(id=uuid.uuid4(), username=username, email=f"{username}@example.test", role=RoleEnum(role), is_active=True,
                  is_locked=False, locked_until=None, password_hash="x", second_factor_reset_at=None, created_at=now,
                  last_login=None, sftp_enabled=True, sftp_password_auth=True, storage_quota_bytes=None, groups=[],
                  failed_login_attempts=0)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


class Harness:
    def __init__(self, monkeypatch, users, *, lock=None, auditor=False):
        from app.core import rate_limiter as R
        from app.core import sign_in_lockout, webauthn_challenges as wc
        from app.core.database import get_db
        from app.core.models import (ActiveSession, PendingLogin, SecondFactorAction, SecondFactorEnrollment,
                                     SecondFactorRecoveryCode, SystemSetting, User, WebAuthnCredential)
        from app.services import webauthn_service as ws
        from app.services.auth_service import AuthService
        self.S = S = _api()
        self.users = users
        self.redis = FakeRedis()
        self.db = DB({User: list(users), WebAuthnCredential: [], SecondFactorEnrollment: [], SecondFactorRecoveryCode: [],
                      SecondFactorAction: [], SystemSetting: [], PendingLogin: [], ActiveSession: []})
        monkeypatch.setitem(S.app.dependency_overrides, get_db, lambda: self.db)
        monkeypatch.setattr(wc, "_redis", lambda redis: self.redis)
        monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name="DockVault"))
        monkeypatch.setattr(S, "_login_identifier", lambda db: "username")
        monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: False)
        monkeypatch.setattr(S, "_second_factor_effective", lambda db, user: {"state": "optional", "in_effect": False,
                                                                                "required": False})
        monkeypatch.setattr(S, "_sf_user_group_ids", lambda db, u: [])
        monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: lock)
        monkeypatch.setattr(sign_in_lockout, "count_at_limit", lambda db, user_id, address, **kw: None)
        from app.core import auditor_rights
        monkeypatch.setattr(auditor_rights, "auditor_live", lambda db, user, now=None: types.SimpleNamespace(live=auditor))
        monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: (
            types.SimpleNamespace(status="active", approved_credential_ids=[]) if auditor else None))
        self.failures, self.audits, self.counted, self.monitor = [], [], [], []

        class _Audit:
            def __init__(_self, db):
                pass

            def log_login_success(_self, user, ip, is_temporary=False, methods=None):
                self.audits.append(("success", user.username, list(methods or [])))

            def log_login_failure(_self, username, ip, reason, **kw):
                self.failures.append((username, reason, kw.get("login_identifier")))
                return None

            def log_action(_self, **kw):
                self.audits.append(("action", kw.get("action")))

            def log_second_factor_failure(_self, user, ip_address=None, details=None):
                self.audits.append(("action", "second_factor_failed"))
        monkeypatch.setattr(S, "AuditLogger", _Audit)
        monkeypatch.setattr(AuthService, "_record_failed_login", lambda _self, name, ip, user=None: self.counted.append(name))
        monkeypatch.setattr(S, "_record_failed_login_bg", lambda *a, **k: self.monitor.append(a[:3]))
        monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: fn(*a, **kw) if fn is S._record_failed_login_bg else None)
        monkeypatch.setattr(S, "_fire_action_email", lambda *a, **kw: None)
        monkeypatch.setattr(S, "_notify_users", lambda *a, **kw: None)
        self.limiter = []
        from app.core.rate_limiter import rate_limiter
        monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (self.limiter.append(kw.get("prefix")) or (True, 1, 0)))
        R._cb_record_failure(time.time())

    def enroll(self, user, *, backup_eligible=False, label="key", sign_count=0, provisional=False):
        """A registered passkey for ``user`` made by a fresh software authenticator (flags as registered)."""
        from app.core.models import WebAuthnCredential
        from fido2.cose import CoseKey
        auth = SoftAuthenticator()
        auth.user_handle = user.id.bytes
        cose = auth.cose_public_key
        row = WebAuthnCredential(id=uuid.uuid4(), user_id=user.id, credential_id=auth.credential_id,
                                 public_key_cose=__import__("fido2.cbor", fromlist=["encode"]).encode(dict(cose)),
                                 cose_alg=cose.ALGORITHM, sign_count=sign_count, transports=["internal"], aaguid=None,
                                 backup_eligible=backup_eligible, backup_state=backup_eligible, uv_initialized=True,
                                 discoverable=True, label=label, created_at=datetime.utcnow(), last_used_at=None,
                                 created_by_session=None, provisional_until=datetime(2999, 1, 1) if provisional else None,
                                 retired_at=None, prf_slot_id=None)
        self.db.rows_of(WebAuthnCredential).append(row)
        return auth, row

    def options(self, username=None):
        return _call(self.S, "POST", "/auth/passkeys/sign-in/options", {"username": username} if username else {})

    def sign_in(self, auth, *, username=None, flags=FLAG.UP | FLAG.UV, sign_count=1, origin=ORIGIN, **kw):
        status, body = self.options(username)
        assert status == 200, body
        credential = auth.get_assertion(body["options"], origin, flags=flags, sign_count=sign_count, **kw)
        return _call(self.S, "POST", "/auth/passkeys/sign-in/verify",
                     {"challenge_id": body["challenge_id"], "credential": credential})


# --------------------------------------------------------------------------- the challenge

def test_the_challenge_answer_has_one_shape_for_every_name(monkeypatch):
    alice, bob = _user(), _user("bob")
    h = Harness(monkeypatch, [alice, bob])
    auth, row = h.enroll(alice)
    for name in (None, "nobody", "bob"):            # no name, an unknown name, a name without keys
        status, body = h.options(name)
        assert status == 200, body
        pk = body["options"]["publicKey"]
        assert pk["allowCredentials"] == [] and pk["rpId"] == RP_ID and pk["userVerification"] == "required"
        assert set(body) == {"challenge_id", "options", "expires_in"} and body["expires_in"] == 300
    status, body = h.options("alice")
    allowed = body["options"]["publicKey"]["allowCredentials"]
    assert len(allowed) == 1 and allowed[0]["transports"] == ["internal"]
    # The challenge remembers whose keys it offered; one without a name is bound to no account.
    stored = [json.loads(v) for v in h.redis.rows.values()]
    assert sorted(s["user_id"] is not None for s in stored) == [False, False, False, True]
    assert all(s["purpose"] == "sign_in" for s in stored)
    # Its own limiter, not the login throttle.
    assert h.limiter.count("passkey_challenge") == 4


def test_a_retired_key_is_not_offered_and_a_name_is_read_by_the_identifier_policy(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    row.retired_at = datetime.utcnow()
    assert h.options("alice")[1]["options"]["publicKey"]["allowCredentials"] == []
    row.retired_at = None
    monkeypatch.setattr(h.S, "_login_identifier", lambda db: "either")
    from app.core import email_identity
    monkeypatch.setattr(email_identity, "find_user_by_email", lambda db, email: alice if email == alice.email else None)
    assert len(h.options("alice@example.test")[1]["options"]["publicKey"]["allowCredentials"]) == 1
    monkeypatch.setattr(h.S, "_login_identifier", lambda db: "username")
    assert h.options("alice@example.test")[1]["options"]["publicKey"]["allowCredentials"] == []


# --------------------------------------------------------------------------- the table

def test_a_user_verified_passkey_of_a_user_is_the_whole_sign_in(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice, backup_eligible=True)
    # A synced key asserts with the backup flags set (eligible and backed up), as it was registered.
    status, body = h.sign_in(auth, username="alice", sign_count=0, flags=FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS)
    assert status == 200, body
    assert "access_token" in body and body["is_temporary"] is False and body["user"]["username"] == "alice"
    claims = _claims(body["access_token"])
    # A user-verified passkey is two kinds of proof in one (possession and the person): mfa_at is set.
    assert claims["amr"] == ["swk"] and "mfa_at" in claims and claims["sub"] == str(alice.id)
    assert h.audits == [("success", "alice", ["swk"])] and h.failures == []
    # The key remembers the sign-in: the synced flag as seen, the counter, the time.
    assert row.last_used_at is not None and row.backup_state is True and row.sign_count == 0
    # A device-bound key is hwk.
    carol = _user("carol")
    h2 = Harness(monkeypatch, [carol])
    auth2, row2 = h2.enroll(carol, backup_eligible=False)
    status, body = h2.sign_in(auth2, sign_count=7)          # discoverable: no name, the user handle names the owner
    assert status == 200 and _claims(body["access_token"])["amr"] == ["hwk"] and row2.sign_count == 7


def test_an_administrator_always_adds_the_password(monkeypatch):
    root = _user("root", role="admin")
    h = Harness(monkeypatch, [root])
    auth, row = h.enroll(root)
    status, body = h.sign_in(auth, username="root")
    assert status == 200, body
    assert body["stage"] == "password" and body["second_factor_required"] is True and body["access_token"] is None
    assert body["username"] == "root"
    from app.core.models import PendingLogin
    (pending,) = h.db.rows_of(PendingLogin)
    assert pending.user_id == root.id
    assert h.audits == [] or all(a[0] != "success" for a in h.audits)
    # A wrong password at that stage counts against the account's lockouts like one typed at the form, and
    # against the pending login's own cap; the token is still usable until the cap.
    from app.core import security
    monkeypatch.setattr(security, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")
    from app.services import auth_service as A
    monkeypatch.setattr(A, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")
    from app.core import sign_in_lockout
    # The memory store has no advisory lock and no lockout rows: the lockouts' own writes are stand-ins here; what
    # the pin wants is that the stage goes through the service, which counts a wrong password against the account.
    for name in ("take_turn", "end_administrators_open_locks", "clear_after_success"):
        monkeypatch.setattr(sign_in_lockout, name, lambda *a, **k: None)
    monkeypatch.setattr(sign_in_lockout, "release_expired", lambda *a, **k: 0)
    monkeypatch.setattr(sign_in_lockout, "phantom_attempt", lambda *a, **k: None)
    headers = {"Authorization": f"Bearer {body['pre_auth_token']}"}
    status, wrong = _call_h(h.S, "POST", "/auth/login", {"username": "root", "password": "nope"}, headers)
    assert status == 401, wrong
    assert h.counted == ["root"] and pending.attempts == 1 and pending.consumed_at is None
    status, right = _call_h(h.S, "POST", "/auth/login", {"username": "root", "password": "pw"}, headers)
    assert status == 200 and "access_token" in right, right
    assert _claims(right["access_token"])["amr"] == ["hwk", "pwd"] and pending.consumed_at is not None


def test_a_key_registered_at_another_address_is_refused_and_kept(monkeypatch):
    """The relying-party id is the public address's host: a key made at one address never signs in at another, and
    the rows stay (a host name change strands them until it is changed back; nothing is deleted)."""
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(rp_id="other.example.test",
                                                                          origin="https://other.example.test", name="DockVault"))
    status, body = h.sign_in(auth, username="alice")
    assert status == 401 and "access_token" not in body, body
    assert h.failures and row.retired_at is None and h.db.rows_of(type(row)) == [row]
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name="DockVault"))
    status, body = h.sign_in(auth, username="alice", sign_count=2)
    assert status == 200 and "access_token" in body, body


def _call_h(S, method, path, body=None, headers=None):
    """The module's caller, with headers."""
    import json
    from _async_run import run_coroutine
    out = {}

    async def _drive():
        hdrs = [(b"content-type", b"application/json")]
        for k, v in (headers or {}).items():
            hdrs.append((k.lower().encode(), v.encode()))
        scope = {"type": "http", "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": hdrs, "client": ("203.0.113.9", 1234), "server": ("testserver", 80),
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


def test_an_auditor_and_a_key_without_user_verification_add_the_password(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice], auditor=True)
    auth, row = h.enroll(alice)
    status, body = h.sign_in(auth, username="alice")
    assert status == 200 and body.get("stage") == "password", body
    bob = _user("bob")
    h2 = Harness(monkeypatch, [bob])
    auth2, row2 = h2.enroll(bob)
    # Without user verification the service refuses under the default policy (UV required); with the policy
    # relaxed the key is one possession factor and the password follows.
    status, body = h2.sign_in(auth2, username="bob", flags=FLAG.UP)
    assert status == 401
    from app.services import webauthn_service as ws
    monkeypatch.setattr(h2.S, "_passkey_policy", lambda db: ws.PasskeyPolicy(require_uv=False))
    status, body = h2.sign_in(auth2, username="bob", flags=FLAG.UP, sign_count=2)
    assert status == 200 and body.get("stage") == "password", body


# --------------------------------------------------------------------------- refusals

def test_an_unknown_key_is_refused_counted_against_the_address_and_never_names_an_account(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    stranger = SoftAuthenticator()
    stranger.user_handle = alice.id.bytes
    status, body = h.sign_in(stranger)
    assert status == 401 and body["detail"] == "That passkey was not accepted."
    assert h.failures == [("", "unknown passkey", "passkey")] and h.counted == []
    assert h.monitor == [("", "203.0.113.9", "unknown passkey")]
    # A spent or made-up challenge: the same refusal, before any key is read.
    status, body = _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": "0" * 32, "credential": {}})
    assert status == 401 and h.failures[-1][1] == "passkey challenge unknown or expired"


def test_a_known_keys_failure_counts_against_its_account(monkeypatch):
    alice, bob = _user(), _user("bob")
    h = Harness(monkeypatch, [alice, bob])
    auth, row = h.enroll(alice, sign_count=5)
    # Replay: a counter that did not move on a device-bound key.
    status, body = h.sign_in(auth, username="alice", sign_count=5)
    assert status == 401
    assert h.failures == [("alice", "passkey refused: sign_count_regressed", "passkey")] and h.counted == ["alice"]
    assert row.sign_count == 5 and row.last_used_at is None
    # A challenge made for bob's keys answered with alice's key.
    bauth, brow = h.enroll(bob)
    status, body = h.options("bob")
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=9)
    status, out = _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 401 and h.failures[-1] == ("alice", "passkey of another account", "passkey")
    assert h.counted == ["alice"]            # no proof was made: the address paid, not alice
    # A discoverable sign-in whose user handle names someone else.
    status, body = h.options()
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=10, user_handle_override=bob.id.bytes)
    status, out = _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 401 and h.failures[-1][1] == "passkey refused: user_handle_mismatch"
    # The wrong origin.
    status, body = h.sign_in(auth, username="alice", sign_count=11, origin="https://evil.example.test")
    assert status == 401 and h.failures[-1][1] == "passkey refused: origin_mismatch"
    assert h.counted == ["alice"] * 3


def test_a_lockout_in_force_refuses_before_the_signature_is_read(monkeypatch):
    from app.core.sign_in_lockout import Lock
    alice = _user()
    h = Harness(monkeypatch, [alice], lock=Lock("address", datetime(2999, 1, 1), "203.0.113.0/24"))
    auth, row = h.enroll(alice)
    status, body = h.sign_in(auth, username="alice")
    assert status == 403 and "network address" in body["detail"]
    assert h.failures == [] and row.last_used_at is None


def test_an_inactive_account_is_refused_by_the_pipeline_after_the_proof(monkeypatch):
    alice = _user(is_active=False)
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    status, body = h.sign_in(auth, username="alice")
    assert status == 401
    from app.core.models import ActiveSession
    assert h.db.rows_of(ActiveSession) == []


def test_a_refusal_that_the_sign_in_must_come_through_a_provider_counts_nothing(monkeypatch):
    """When the pipeline refuses the account because it signs in only through its provider, the passkey's proof was
    good: the key keeps its counter and flags, the throttle gives the attempt back, no failure is recorded here (the
    pipeline writes the one row), no session is made, and the 403 carries the pipeline's message."""
    from app.services import auth_service as A
    from app.services import sign_in as s
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice, backup_eligible=True)
    given_back = []
    monkeypatch.setattr(A.AuthService, "_give_back", classmethod(lambda cls, throttle: given_back.append(throttle)))
    message = "Your organisation signs this account in through Contoso."

    def provider_only(db, result):
        raise s.ProviderOnly(message)
    monkeypatch.setattr(s, "finish", provider_only)
    status, body = h.sign_in(auth, username="alice", sign_count=4, flags=FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS)
    assert status == 403 and body["detail"] == message, body
    assert row.sign_count == 4 and row.backup_state is True and row.last_used_at is None
    assert len(given_back) == 1 and h.failures == []
    from app.core.models import ActiveSession
    assert h.db.rows_of(ActiveSession) == []


def test_without_a_public_address_the_routes_say_so_and_the_policy_hides_the_button(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: None)
    status, body = h.options("alice")
    assert status == 409
    assert h.S._sign_in_methods(h.db)["passkeys"] is False
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name="x"))
    assert h.S._sign_in_methods(h.db)["passkeys"] is True


def test_the_challenge_limiter_and_the_store_fail_closed(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    from app.core.rate_limiter import rate_limiter, RateLimiterUnavailable
    # Only the challenge limiter answers "no": the middleware's own calls (other prefixes) stay open.
    monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (
        (False, 0, time.time() + 30) if kw.get("prefix") == "passkey_challenge" else (True, 1, 0)))
    status, body = h.options("alice")
    assert status == 429
    def _down(*a, **kw):
        if kw.get("prefix") == "passkey_challenge":
            raise RateLimiterUnavailable("no redis")
        return (True, 1, 0)
    monkeypatch.setattr(rate_limiter, "check_rate_limit", _down)
    assert h.options("alice")[0] == 503
    monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (True, 1, 0))
    from app.core import webauthn_challenges as wc
    def _no_store(redis):
        raise wc.Unavailable("down")
    monkeypatch.setattr(wc, "_redis", lambda redis: types.SimpleNamespace(set=_no_store, getdel=_no_store))
    assert h.options("alice")[0] == 503
    assert _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": "0" * 32, "credential": {}})[0] == 503
