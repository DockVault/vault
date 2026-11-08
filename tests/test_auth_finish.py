"""POST /auth/finish, driven in-process through the ASGI app: a one-time sign-in code becomes the sign-in it
stands for (the session, or the step that still follows), is spent by its first use, and needs the tab's
verifier or the app's PKCE verifier; without the code store the exchange is unavailable, never guessed."""
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


def _post(S, path, body):
    out = {}

    async def _drive():
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": path,
                 "raw_path": path.encode(), "query_string": b"",
                 "headers": [(b"content-type", b"application/json")],
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


class _Redis:
    def __init__(self):
        self.rows = {}
        self.broken = False

    def set(self, key, value, ex=None, nx=False):
        if self.broken:
            raise ConnectionError("down")
        if nx and key in self.rows:
            return None
        self.rows[key] = value
        return True

    def getdel(self, key):
        if self.broken:
            raise ConnectionError("down")
        return self.rows.pop(key, None)


def _user(role="user", username="alice"):
    from app.core.models import RoleEnum
    now = datetime.now(timezone.utc)
    return types.SimpleNamespace(id=uuid.uuid4(), username=username, email=f"{username}@example.test",
                                 role=RoleEnum(role), is_active=True, is_locked=False, locked_until=None, sftp_enabled=True,
                                 sftp_password_auth=True, storage_quota_bytes=None, created_at=now, last_login=None,
                                 groups=[], password_hash="x")


@pytest.fixture
def finish(monkeypatch):
    S = _api()
    from app.core import rate_limiter as R, sign_in_codes
    from app.core.database import get_db
    from app.core.models import ActiveSession, PendingLogin, SystemSetting, User
    from app.core.rate_limiter import rate_limiter as _rl

    alice = _user()
    db = MemoryDB({User: [alice], PendingLogin: [], ActiveSession: [], SystemSetting: []})
    redis = _Redis()
    made = {"sessions": [], "audit": []}

    def _fake_db():
        yield db

    class _Audit:
        def __init__(self, db):
            pass

        def log_login_success(self, user, ip, is_temporary=False, methods=None):
            made["audit"].append(("success", user.username, methods))

        def log_action(self, **kw):
            made["audit"].append(("action", kw.get("action")))

    def _create_session(self, user, temp_credential_id, ip, expires_at=None, channel=None):
        made["sessions"].append((user.username, ip, channel))
        return "sess-" + user.username

    from app.services.auth_service import AuthService
    monkeypatch.setitem(S.app.dependency_overrides, get_db, _fake_db)
    monkeypatch.setattr(sign_in_codes, "_redis", lambda redis_arg: redis)
    monkeypatch.setattr(AuthService, "_create_session", _create_session)
    monkeypatch.setattr(S, "AuditLogger", _Audit)
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: False)
    from app.core import sign_in_lockout
    monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: None)
    monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: None)
    monkeypatch.setattr(S, "_fire_action_email", lambda *a, **kw: None)
    monkeypatch.setattr(S, "_notify_users", lambda *a, **kw: None)
    # No Redis here: the general limiter skips while its breaker is open, and the route's own fail-closed
    # limiter is answered by hand.
    monkeypatch.setattr(_rl, "check_rate_limit", lambda *a, **kw: (True, 0, 0))
    R._cb_record_failure(time.time())
    try:
        yield types.SimpleNamespace(S=S, db=db, redis=redis, alice=alice, made=made, codes=sign_in_codes,
                                    PendingLogin=PendingLogin)
    finally:
        R._cb_record_success()


def _code(f, user, methods=("hwk",), **kw):
    verifier = f.codes.make_secret()
    record = f.codes.Handover(user_id=str(user.id), methods=list(methods), client_ip="10.0.0.1",
                              verifier_hash=f.codes.digest(verifier), **kw)
    return f.codes.store(record, redis=f.redis), verifier


def test_a_user_verified_passkey_code_becomes_a_session_once(finish):
    f = finish
    code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 200, body
    assert set(body) == {"access_token", "token_type", "user", "is_temporary", "is_scoped_temp"}
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["hwk"] and "mfa_at" in claims and claims["session_token"] == "sess-alice"
    assert body["user"]["username"] == "alice" and body["is_temporary"] is False
    assert f.made["sessions"] == [("alice", "127.0.0.1", "web")]      # the request's address, not the record's
    assert ("success", "alice", ["hwk"]) in f.made["audit"]
    # Spent.
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 401 and f.made["sessions"] == [("alice", "127.0.0.1", "web")]


def test_a_passkey_without_user_verification_is_held_for_the_password(finish):
    f = finish
    code, verifier = _code(f, f.alice)
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 200, body
    assert body["access_token"] is None and body["stage"] == "password" and body["methods"] == ["password"]
    assert body["username"] == "alice" and _claims(body["pre_auth_token"])["methods_so_far"] == ["hwk"]
    assert f.made["sessions"] == []
    (pending,) = f.db.added
    assert pending.user_id == f.alice.id and pending.consumed_at is None


def test_a_wrong_or_missing_proof_spends_the_code_and_answers_alike(finish):
    f = finish
    code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": "not-it"})
    assert status == 401
    status, _ = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 401                                              # the one guess was spent
    code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
    assert _post(f.S, "/auth/finish", {"code": code})[0] == 401
    assert _post(f.S, "/auth/finish", {"code": "unknown", "verifier": "v"})[0] == 401
    assert _post(f.S, "/auth/finish", {"code": "", "verifier": "v"})[0] == 422
    assert f.made["sessions"] == []


def test_a_code_for_an_account_that_is_gone_or_inactive_is_refused_the_same_way(finish):
    f = finish
    code, verifier = _code(f, _user(username="ghost"), user_verified=True, passwordless_allowed=True)
    assert _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})[0] == 401
    f.alice.is_active = False
    code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
    assert _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})[0] == 401
    assert f.made["sessions"] == []


def test_without_the_code_store_the_exchange_is_unavailable(finish):
    f = finish
    f.redis.broken = True
    status, body = _post(f.S, "/auth/finish", {"code": "x" * 43, "verifier": "v"})
    assert status == 503 and "unavailable" in body["detail"]


def test_the_limiter_refuses_too_many_tries_and_fails_closed_when_the_cache_is_down(finish, monkeypatch):
    f = finish
    from app.core.rate_limiter import RateLimiterUnavailable, rate_limiter as _rl
    code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
    # Only the route's own bucket answers; the general limiter in the middleware keeps allowing.
    def _refuse(*a, **kw):
        return (False, 0, time.time() + 120) if kw.get("prefix") == "sign_in_finish" else (True, 0, 0)

    monkeypatch.setattr(_rl, "check_rate_limit", _refuse)
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 429 and f.redis.rows                   # refused before the code was spent

    def _down(*a, **kw):
        if kw.get("prefix") == "sign_in_finish":
            raise RateLimiterUnavailable("cache down")
        return (True, 0, 0)

    monkeypatch.setattr(_rl, "check_rate_limit", _down)
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 503 and "unavailable" in body["detail"] and f.redis.rows


def test_a_code_does_not_finish_a_sign_in_for_a_locked_account(finish):
    """A lock set after the proof and before the finish (an administrator's, a timed one, an automatic one from
    this address) refuses the finish with the lock's own answer, as the sign-in form would."""
    f = finish
    from app.core import sign_in_lockout
    from app.core.sign_in_lockout import Lock
    f.alice.is_locked = True
    code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
    status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 403 and "locked" in body["detail"].lower() and f.made["sessions"] == []
    f.alice.is_locked = False
    lock = Lock(scope="address", locked_until=datetime.now(timezone.utc) + timedelta(minutes=5), source="x")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: lock)
        code, verifier = _code(f, f.alice, user_verified=True, passwordless_allowed=True)
        status, body = _post(f.S, "/auth/finish", {"code": code, "verifier": verifier})
    assert status == 403 and f.made["sessions"] == []


def test_the_desktop_app_proves_itself_with_pkce(finish):
    f = finish
    code_verifier = f.codes.make_secret() + f.codes.make_secret()[:10]
    record = f.codes.Handover(user_id=str(f.alice.id), methods=["hwk"], client_ip=None, purpose="app",
                              user_verified=True, passwordless_allowed=True,
                              code_challenge=f.codes.pkce_challenge(code_verifier))
    code = f.codes.store(record, redis=f.redis)
    assert _post(f.S, "/auth/finish", {"code": code, "verifier": code_verifier})[0] == 401   # wrong kind of proof
    code = f.codes.store(record, redis=f.redis)
    status, body = _post(f.S, "/auth/finish", {"code": code, "code_verifier": code_verifier})
    assert status == 200 and _claims(body["access_token"])["amr"] == ["hwk"]
