"""The password stage of POST /auth/login, driven in-process through the ASGI app (the suite has no
TestClient): a sign-in that proved a passkey or a provider identity adds the account password here.

Pins: the account is the pending login's own (another name, or a temporary credential's name, is refused
and counted); a right password finishes the sign-in with both proofs on the token; a second-factor-stage
token at this route is ignored and the form sign-in proceeds as always; a spent pending login is refused.
"""
import contextlib
import json
import threading
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _the_provider_stands(monkeypatch):
    """These tests name a provider by a made-up id. Whether a provider is still on, and the account still linked to
    it, when a sign-in finishes is pinned in tests/test_sso_only.py; here that check is out of the way."""
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.services import sign_in
    monkeypatch.setattr(sign_in, "refuse_unless_the_provider_stands", lambda db, result: None)


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _claims(token):
    import base64
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def _post_login(S, body, token=None):
    """POST /auth/login through the ASGI app; returns (status, parsed body)."""
    out = {}

    async def _drive():
        headers = [(b"content-type", b"application/json")]
        if token:
            headers.append((b"authorization", b"Bearer " + token.encode()))
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": "/auth/login",
                 "raw_path": b"/auth/login", "query_string": b"", "headers": headers,
                 "client": ("127.0.0.1", 1234), "server": ("testserver", 80), "scheme": "http"}
        payload = json.dumps(body).encode()
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


def _user(role="user", username="alice"):
    from app.core.models import RoleEnum
    now = datetime.now(timezone.utc)
    return types.SimpleNamespace(id=uuid.uuid4(), username=username, email=f"{username}@example.test",
                                 role=RoleEnum(role), is_active=True, is_locked=False, locked_until=None, sftp_enabled=True,
                                 sftp_password_auth=True, storage_quota_bytes=None, created_at=now, last_login=None,
                                 groups=[], password_hash="x")


def _pending(user, minutes=3):
    return types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None, attempts=0, enrollment_required=False,
                                 expires_at=datetime.now(timezone.utc) + timedelta(minutes=minutes))


@pytest.fixture
def stage(monkeypatch):
    """The app with a quiet backend: an in-memory database, a stubbed password check (the account's password
    is "right"), no second factor in effect, the records observed instead of made."""
    S = _api()
    from app.core import rate_limiter as R
    from app.core.database import get_db
    from app.core.models import ActiveSession, PendingLogin, SystemSetting, User
    from app.services.auth_service import AuthService, InvalidCredentialsError

    alice, bob = _user(), _user(username="bob")
    db = MemoryDB({User: [alice, bob], PendingLogin: [], ActiveSession: [], SystemSetting: []})
    calls = {"authenticate": [], "failures": [], "audit": []}

    def _fake_db():
        yield db

    def _authenticate(self, username, password, client_ip, *, login_identifier="username", channel="web"):
        calls["authenticate"].append((username, login_identifier))
        who = next((u for u in (alice, bob) if u.username == username), None)
        if who is None or password != "right":
            raise InvalidCredentialsError("Invalid username or password")
        return who, "sess-" + who.username

    class _Audit:
        def __init__(self, db):
            pass

        def log_login_success(self, user, ip, is_temporary=False, methods=None):
            calls["audit"].append(("success", user.username, methods))

        def log_login_failure(self, username, ip, reason, **kw):
            calls["failures"].append(username)
            return None

        def log_action(self, **kw):
            calls["audit"].append(("action", kw.get("action")))

    monkeypatch.setitem(S.app.dependency_overrides, get_db, _fake_db)
    monkeypatch.setattr(AuthService, "authenticate_user", _authenticate)
    monkeypatch.setattr(S, "AuditLogger", _Audit)
    monkeypatch.setattr(S, "_login_identifier", lambda db: "username")
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: False)
    from app.core import sign_in_lockout
    monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: None)
    monkeypatch.setattr(S, "_record_failed_login_bg", lambda *a, **k: None)
    monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: None)
    monkeypatch.setattr(S, "_fire_action_email", lambda *a, **kw: None)
    monkeypatch.setattr(S, "_notify_users", lambda *a, **kw: None)
    # The general rate limiter skips Redis while its breaker is open (there is no Redis here).
    R._cb_record_failure(time.time())
    try:
        yield types.SimpleNamespace(S=S, db=db, alice=alice, bob=bob, calls=calls, PendingLogin=PendingLogin)
    finally:
        R._cb_record_success()


def _stage_token(S, user, pending, methods=("hwk",), stage="password", **extra):
    from app.core.security import create_access_token
    claims = {"sub": str(user.id), "username": user.username, "stage": stage, "pre_auth": str(pending.id),
              "methods_so_far": list(methods), "ended": 0, **extra}
    return create_access_token(claims, expires_delta=timedelta(minutes=5))


def test_the_right_password_for_the_pending_account_finishes_the_sign_in_with_both_proofs(stage):
    pending = _pending(stage.alice)
    stage.db.tables[stage.PendingLogin].append(pending)
    token = _stage_token(stage.S, stage.alice, pending)
    status, body = _post_login(stage.S, {"username": "alice", "password": "right"}, token)
    assert status == 200, body
    assert set(body) == {"access_token", "token_type", "user", "is_temporary", "is_scoped_temp"}
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["hwk", "pwd"] and "mfa_at" in claims and claims["session_token"] == "sess-alice"
    assert pending.consumed_at is not None
    assert ("success", "alice", ["hwk", "pwd"]) in stage.calls["audit"]
    # The password was checked by the one password check the form uses, as the account's exact username.
    assert stage.calls["authenticate"] == [("alice", "username")]
    # Spent: the same token is refused now.
    status, body = _post_login(stage.S, {"username": "alice", "password": "right"}, token)
    assert status == 401


def test_another_accounts_name_or_a_temporary_credential_is_refused_and_counted(stage):
    pending = _pending(stage.alice)
    stage.db.tables[stage.PendingLogin].append(pending)
    token = _stage_token(stage.S, stage.alice, pending)
    # Bob's right password under Alice's pending login: refused before any password check, counted.
    status, body = _post_login(stage.S, {"username": "bob", "password": "right"}, token)
    assert status == 401 and pending.attempts == 1 and pending.consumed_at is None
    assert stage.calls["authenticate"] == []
    # A temporary credential's name with the token: refused, counted; the credential path is never entered.
    status, body = _post_login(stage.S, {"username": "temp_abc", "password": "right"}, token)
    assert status == 401 and pending.attempts == 2
    # A wrong password for the right name: refused by the password check, counted.
    status, body = _post_login(stage.S, {"username": "alice", "password": "wrong"}, token)
    assert status == 401 and pending.attempts == 3 and stage.calls["authenticate"] == [("alice", "username")]
    # The right password still finishes it: the cap is five.
    status, body = _post_login(stage.S, {"username": "alice", "password": "right"}, token)
    assert status == 200 and pending.consumed_at is not None


def test_five_wrong_answers_spend_the_pending_login(stage):
    pending = _pending(stage.alice)
    stage.db.tables[stage.PendingLogin].append(pending)
    token = _stage_token(stage.S, stage.alice, pending)
    for n in range(1, 6):
        status, _ = _post_login(stage.S, {"username": "alice", "password": "wrong"}, token)
        assert status == 401 and pending.attempts == n
    assert pending.consumed_at is not None
    status, _ = _post_login(stage.S, {"username": "alice", "password": "right"}, token)
    assert status == 401


def test_a_spent_or_expired_pending_login_is_refused(stage):
    spent = _pending(stage.alice)
    spent.consumed_at = datetime.now(timezone.utc)
    expired = _pending(stage.alice, minutes=-1)
    stage.db.tables[stage.PendingLogin].extend([spent, expired])
    for pending in (spent, expired):
        status, body = _post_login(stage.S, {"username": "alice", "password": "right"},
                                   _stage_token(stage.S, stage.alice, pending))
        assert status == 401, body
    assert stage.calls["authenticate"] == []


def test_a_second_factor_stage_token_here_is_ignored_and_the_form_sign_in_proceeds(stage):
    pending = _pending(stage.alice)
    stage.db.tables[stage.PendingLogin].append(pending)
    token = _stage_token(stage.S, stage.alice, pending, methods=("pwd",), stage="second_factor")
    status, body = _post_login(stage.S, {"username": "bob", "password": "right"}, token)
    assert status == 200 and _claims(body["access_token"])["amr"] == ["pwd"]
    assert body["user"]["username"] == "bob" and pending.consumed_at is None and pending.attempts == 0


def test_an_ordinary_account_held_for_its_password_after_a_provider_goes_on_to_set_its_passkey_up(stage, monkeypatch):
    """A role must hold a passkey, the grace is over, and the account (no administrator, no factor of its own) came
    in through a provider: the sign-in was held for the account's password, since a passkey is set up on no less
    than Your account asks. The password given, the sign-in stops at the passkey's enrollment, with both proofs
    carried; the wrong password gets nowhere."""
    from app.core import webauthn_settings as wss
    overdue = wss.Requirement(True, overdue=True)
    monkeypatch.setattr(stage.S, "_passkey_requirement", lambda db, user: overdue)
    monkeypatch.setattr(stage.S, "_passkey_mark_required", lambda user: False)
    pending = _pending(stage.alice)
    stage.db.tables[stage.PendingLogin].append(pending)
    token = _stage_token(stage.S, stage.alice, pending, methods=(), idp="p1")
    status, body = _post_login(stage.S, {"username": "alice", "password": "wrong"}, token)
    assert status == 401 and pending.consumed_at is None, body
    status, body = _post_login(stage.S, {"username": "alice", "password": "right"}, token)
    assert status == 200 and body.get("access_token") is None, body
    assert body["stage"] == "second_factor" and body["enrollment_required"] is True, body
    assert body["enrollment_methods"] == ["passkey"] and body["pre_auth_token"]
    held = _claims(body["pre_auth_token"])
    assert held["methods_so_far"] == ["pwd"] and held["idp"] == "p1" and held["stage"] == "second_factor"


def test_a_trusted_provider_mfa_carried_by_the_stage_finishes_an_administrator_without_a_code(stage, monkeypatch):
    admin = _user(role="admin", username="root")
    from app.core.models import User
    stage.db.tables[User].append(admin)
    stage.S  # the stub password check knows alice and bob only; teach it root
    from app.services.auth_service import AuthService, InvalidCredentialsError

    def _authenticate(self, username, password, client_ip, *, login_identifier="username", channel="web"):
        if username == "root" and password == "right":
            return admin, "sess-root"
        raise InvalidCredentialsError("Invalid username or password")

    monkeypatch.setattr(AuthService, "authenticate_user", _authenticate)
    # The vault's factor is in effect for the administrator; the provider's trusted MFA makes it two kinds.
    monkeypatch.setattr(stage.S, "_login_second_factor_in_effect", lambda db, user: True)
    monkeypatch.setattr(stage.S, "_second_factor_effective", lambda db, user: {"state": "setup", "in_effect": True})
    pending = _pending(admin)
    stage.db.tables[stage.PendingLogin].append(pending)
    token = _stage_token(stage.S, admin, pending, methods=(), idp="p1", provider_mfa=True)
    status, body = _post_login(stage.S, {"username": "root", "password": "right"}, token)
    assert status == 200, body
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["pwd"] and claims["idp"] == "p1" and "mfa_at" in claims
    # Without the carried fact the same administrator would be held for the vault's code.
    pending2 = _pending(admin)
    stage.db.tables[stage.PendingLogin].append(pending2)
    token2 = _stage_token(stage.S, admin, pending2, methods=(), idp="p1")
    status, body = _post_login(stage.S, {"username": "root", "password": "right"}, token2)
    assert status == 200 and body["access_token"] is None and body["stage"] == "second_factor", body
    assert _claims(body["pre_auth_token"])["methods_so_far"] == ["pwd"]


def test_the_form_sign_in_is_handed_on_with_what_the_door_read_of_the_account(stage, monkeypatch):
    """The password door reads how often the account's sessions were ended, in its turn, and writes its session
    there. The sign-in is handed on with that count, so a change that ended the account's sessions after the
    door's commit is seen where the sign-in is written. Read again where the sign-in is handed on, the count
    would be the later one, and that change would go unseen."""
    from app.services import sign_in
    from app.services.auth_service import AuthService
    S, alice = stage.S, stage.alice
    alice.sessions_ended = 4

    def door(self, username, password, client_ip, *, login_identifier="username", channel="web"):
        self.sessions_ended_as_read = 4            # what the door read in its turn
        alice.sessions_ended = 5                   # the sessions ended again, after the door's commit
        return alice, "sess-alice"
    monkeypatch.setattr(AuthService, "authenticate_user", door)
    handed, finish = [], sign_in.finish
    monkeypatch.setattr(sign_in, "finish", lambda db, result: (handed.append(result.sessions_ended), finish(db, result))[1])
    status, body = _post_login(S, {"username": "alice", "password": "right"})
    assert handed == [4]
    assert status == 401 and body["detail"] == sign_in.EXPIRED, body
