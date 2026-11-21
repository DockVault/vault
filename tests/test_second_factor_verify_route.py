"""POST /auth/second-factor/verify through the ASGI app: a right code finishes the sign-in through the pipeline,
which asks its table once more with the code added, so an account made an administrator during its own
provider sign-in still types the password instead of getting a session."""
import json
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _claims(token):
    import base64
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def _post(S, path, body, token):
    out = {}

    async def _drive():
        headers = [(b"content-type", b"application/json"), (b"authorization", b"Bearer " + token.encode())]
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": headers, "client": ("127.0.0.1", 1234),
                 "server": ("testserver", 80), "scheme": "http"}
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


def _user(role="user"):
    from app.core.models import RoleEnum
    now = datetime.now(timezone.utc)
    return types.SimpleNamespace(id=uuid.uuid4(), username="alice", email="alice@example.test", role=RoleEnum(role),
                                 is_active=True, is_locked=False, locked_until=None, sftp_enabled=True,
                                 sftp_password_auth=True, storage_quota_bytes=None, created_at=now, last_login=None,
                                 groups=[], password_hash="x")


@pytest.mark.parametrize("state", ["locked", "turned off", "locked out here", "in order"])
def test_a_held_sign_in_makes_no_factor_active_for_an_account_that_may_not_sign_in(monkeypatch, state):
    """A sign-in held for a required enrollment stays open five minutes. An account locked or turned off in that
    time (an incident) is refused by the pipeline, but only after the enrollment was made active: the factor would
    stand on the account after the refusal. The refusal comes first: nothing is made active, nothing is written,
    and the pipeline is not asked. With a session, and for an account in order, the enrollment goes on as before."""
    from fastapi import HTTPException
    S = _api()
    from app.core import sign_in_lockout
    from app.core.models import PendingLogin, SecondFactorEnrollment, User
    from app.services import sign_in
    user = _user()
    user.second_factor_reset_at = None
    enrollment = types.SimpleNamespace(user_id=user.id, status="unconfirmed", method="totp",
                                       confirmed_at=datetime.utcnow())
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None, _methods_so_far=("password",))
    db = MemoryDB({User: [user], SecondFactorEnrollment: [enrollment], PendingLogin: [pending]})   # still held
    asked = []
    monkeypatch.setattr(S, "_sf_recovery_remaining", lambda db, user_id: 10)
    monkeypatch.setattr(S, "get_client_ip", lambda request: "203.0.113.9")
    monkeypatch.setattr(sign_in, "finish", lambda db, result: asked.append(result.methods) or sign_in.SignedIn("token", user))
    monkeypatch.setattr(S.AuditLogger, "build_row", lambda self, **kw: ("the record", kw["action"]))
    lock = types.SimpleNamespace(locked_until=datetime.utcnow() + timedelta(minutes=5), scope="address")
    monkeypatch.setattr(sign_in_lockout, "lock_in_force",
                        lambda db, user_id, ip: lock if state == "locked out here" and ip == "203.0.113.9" else None)
    if state == "locked":
        user.is_locked = True
    elif state == "turned off":
        user.is_active = False

    def acknowledge(principal):
        return run_coroutine(S.acknowledge_recovery_codes(request=None, principal=principal, db=db), timeout=30)

    if state == "in order":
        out = acknowledge((user, pending))
        assert out["enrolled"] is True and out["access_token"] == "token" and enrollment.status == "active"
        assert asked == [["password", "totp"]]
        return
    with pytest.raises(HTTPException) as refused:
        acknowledge((user, pending))
    assert refused.value.status_code == (401 if state == "turned off" else 403)
    assert enrollment.status == "unconfirmed" and asked == [] and ("commit",) not in db.log
    # With a session of its own, the account is not held to this: the session is the proof, and it is checked
    # where sessions are (an account locked or turned off has none).
    monkeypatch.setattr(S, "_revoke_sessions", lambda *a, **kw: 0)
    monkeypatch.setattr(S, "_current_session_token", lambda request: "the-session")
    out = acknowledge((user, None))
    assert out["enrolled"] is True and enrollment.status == "active" and asked == []


@pytest.fixture
def verify(monkeypatch):
    S = _api()
    from app.core import rate_limiter as R, second_factor as sf, sign_in_lockout
    from app.core.database import get_db
    from app.core.models import ActiveSession, PendingLogin, SecondFactorEnrollment, SystemSetting, User
    from app.core.rate_limiter import rate_limiter as _rl
    from app.services.auth_service import AuthService

    user = _user()
    db = MemoryDB({User: [user], PendingLogin: [], ActiveSession: [], SystemSetting: [],
                   SecondFactorEnrollment: [types.SimpleNamespace(user_id=user.id, status="active", method="totp")]})
    made = {"sessions": []}

    def _fake_db():
        yield db

    class _Audit:
        def __init__(self, db):
            pass

        def log_login_success(self, *a, **kw):
            pass

        def log_action(self, **kw):
            pass

        def log_second_factor_failure(self, *a, **kw):
            pass

    monkeypatch.setitem(S.app.dependency_overrides, get_db, _fake_db)
    monkeypatch.setattr(AuthService, "_create_session",
                        lambda self, u, t, ip, expires_at=None, channel=None, commit=True:
                        made["sessions"].append(u.username) or "sess")
    monkeypatch.setattr(S, "AuditLogger", _Audit)
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: True)
    monkeypatch.setattr(S, "_second_factor_effective", lambda db, user: {"state": "setup", "in_effect": True})
    monkeypatch.setattr(S, "_sf_recovery_remaining", lambda db, uid: 10)
    monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: None)
    monkeypatch.setattr(S, "_fire_action_email", lambda *a, **kw: None)
    monkeypatch.setattr(S, "_notify_users", lambda *a, **kw: None)
    monkeypatch.setattr(sf, "check_second_factor", lambda db, **kw: kw.get("code") == "123456")
    monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: None)
    monkeypatch.setattr(_rl, "check_rate_limit", lambda *a, **kw: (True, 0, 0))
    R._cb_record_failure(time.time())
    try:
        yield types.SimpleNamespace(S=S, db=db, user=user, made=made, PendingLogin=PendingLogin)
    finally:
        R._cb_record_success()


def _pending_token(S, user, methods, **extra):
    from app.core.security import create_access_token
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None, attempts=0,
                                    enrollment_required=False,
                                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=3))
    token = create_access_token({"sub": str(user.id), "username": user.username, "stage": "second_factor",
                                 "pre_auth": str(pending.id), "methods_so_far": list(methods), "ended": 0, **extra},
                                expires_delta=timedelta(minutes=5))
    return pending, token


def test_the_code_after_the_password_finishes_the_sign_in(verify):
    v = verify
    pending, token = _pending_token(v.S, v.user, ["pwd"])
    v.db.tables[v.PendingLogin].append(pending)
    status, body = _post(v.S, "/auth/second-factor/verify", {"method": "totp", "code": "123456"}, token)
    assert status == 200, body
    assert set(body) == {"access_token", "token_type", "recovery_code_used", "recovery_codes_remaining"}
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["pwd", "totp"] and "mfa_at" in claims and pending.consumed_at is not None
    assert v.made["sessions"] == ["alice"]
    # A wrong code finishes nothing.
    pending2, token2 = _pending_token(v.S, v.user, ["pwd"])
    v.db.tables[v.PendingLogin].append(pending2)
    assert _post(v.S, "/auth/second-factor/verify", {"method": "totp", "code": "000000"}, token2)[0] == 401
    assert pending2.attempts == 1 and v.made["sessions"] == ["alice"]


def test_the_code_after_a_provider_finishes_a_users_sign_in_and_names_no_password(verify):
    v = verify
    pending, token = _pending_token(v.S, v.user, [], idp="p1")
    v.db.tables[v.PendingLogin].append(pending)
    status, body = _post(v.S, "/auth/second-factor/verify", {"method": "totp", "code": "123456"}, token)
    assert status == 200, body
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["totp"] and claims["idp"] == "p1" and "mfa_at" not in claims


def test_an_account_made_an_administrator_mid_sign_in_still_types_the_password(verify):
    v = verify
    from app.core.models import RoleEnum
    pending, token = _pending_token(v.S, v.user, [], idp="p1")
    v.db.tables[v.PendingLogin].append(pending)
    v.user.role = RoleEnum.ADMIN                      # promoted after the provider sign-in began
    status, body = _post(v.S, "/auth/second-factor/verify", {"method": "totp", "code": "123456"}, token)
    assert status == 200, body
    assert body["access_token"] is None and body["stage"] == "password" and body["username"] == "alice"
    assert _claims(body["pre_auth_token"])["methods_so_far"] == ["totp"]
    assert pending.consumed_at is not None and v.made["sessions"] == []


@pytest.mark.parametrize("then", ["a session", "another step", "a refusal"])
def test_an_authenticator_set_up_at_a_held_sign_in_is_recorded_whatever_the_sign_in_then_does(monkeypatch, then):
    """The enrollment is made active and committed, and only then does the sign-in go on. It may be held for
    another step (the password, for an account made an administrator meanwhile; a passkey its role owes) or be
    refused: the factor stands all the same. Its record is written with it, in one transaction, and not after
    the sign-in finished, where those two ways out never reached it."""
    from fastapi import HTTPException
    S = _api()
    from app.core.models import SecondFactorEnrollment, User
    from app.services import sign_in
    user = _user()
    user.second_factor_reset_at = None
    enrollment = types.SimpleNamespace(user_id=user.id, status="unconfirmed", method="totp",
                                       confirmed_at=datetime.utcnow())
    db = MemoryDB({User: [user], SecondFactorEnrollment: [enrollment]})
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, _methods_so_far=("password",))
    monkeypatch.setattr(S, "_sf_recovery_remaining", lambda db, user_id: 10)
    monkeypatch.setattr(S, "get_client_ip", lambda request: "203.0.113.9")
    monkeypatch.setattr(sign_in, "refuse_a_factor_the_sign_in_could_not_finish", lambda *a, **k: None)
    built, logged = [], []
    monkeypatch.setattr(S.AuditLogger, "build_row", lambda self, **kw: built.append(kw) or ("the record", kw["action"]))
    monkeypatch.setattr(S.AuditLogger, "log_action", lambda self, **kw: logged.append(kw))

    def finish(db_, result):
        # By now the enrollment and its record are committed together.
        assert db.log.index(("add", ("the record", "second_factor_enrolled"))) < db.log.index(("commit",))
        if then == "another step":
            return sign_in.PendingStep("password", {"stage": "password", "pre_auth_token": "held-again"})
        if then == "a refusal":
            raise HTTPException(status_code=403, detail="This account signs in through its provider.")
        return sign_in.SignedIn("token", user)
    monkeypatch.setattr(sign_in, "finish", finish)

    def acknowledge():
        return run_coroutine(S.acknowledge_recovery_codes(request=None, principal=(user, pending), db=db), timeout=30)
    if then == "a refusal":
        with pytest.raises(HTTPException):
            acknowledge()
    else:
        out = acknowledge()
        assert out["enrolled"] is True and out["method"] == "totp"
        assert (out.get("access_token") == "token") is (then == "a session")
        assert (out.get("stage") == "password") is (then == "another step")
    assert enrollment.status == "active"
    (row,) = built
    assert row["action"] == "second_factor_enrolled" and row["status"] == "success" and row["user"] is user
    assert row["ip_address"] == "203.0.113.9" and row["details"] == {"method": "totp", "forced": True}
    assert logged == [], "written once, with the enrollment"
    # From a session there is no held sign-in to go on: recorded after the other sessions are ended, as before.
    del built[:]
    enrollment.status = "unconfirmed"
    monkeypatch.setattr(S, "_revoke_sessions", lambda *a, **kw: 0)
    monkeypatch.setattr(S, "_current_session_token", lambda request: "the-session")
    out = run_coroutine(S.acknowledge_recovery_codes(request=None, principal=(user, None), db=db), timeout=30)
    assert out == {"enrolled": True, "method": "totp"} and built == []
    (row,) = logged
    assert row["action"] == "second_factor_enrolled" and row["details"] == {"method": "totp"}
