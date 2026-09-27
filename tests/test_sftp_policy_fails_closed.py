"""An SFTP sign-in is refused when its temporary-credential policy cannot be checked.

Two admin policies can require a temporary credential for SFTP instead of a password or SSH key: one
per department, and one for users whose second factor is in effect (``mfa_sftp_policy``). Both
checks caught every error and answered "not required", so a check that failed let a password or key
sign-in through the very policy it enforces. The only error anyone could trigger, a database one,
happened to end in a refusal anyway (the transaction was left aborted and the next write failed), but
that was an accident: any other error, or a later change to what follows the check, let the sign-in
in.

Now the password and key sign-ins ask with ``fail_closed=True``: a check that cannot run refuses the
sign-in, logs the exception class, and the password sign-in records the refusal as such. A live
session's per-operation re-check still answers "not required" when it cannot run, so a brief database
problem does not cut every open connection; that session passed the fail-closed check when it signed
in.

The sign-ins run for real here, with the database, the password check and the audit log replaced by
stand-ins.
"""
import re
import types
import uuid
from contextlib import contextmanager
from pathlib import Path

import paramiko
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.core.second_factor_policy as pol  # noqa: E402
import app.sftp.sftp_server as S  # noqa: E402
from app.core.models import ActiveSession, SecondFactorEnrollment, SystemSetting, User, UserSSHKey  # noqa: E402

pytestmark = pytest.mark.unit

SFTP_SRC = Path(__file__).resolve().parent.parent / "app" / "sftp" / "sftp_server.py"
KEY_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIPolicyProbeKey"


class _Query:
    def __init__(self, db, entity):
        self.db, self.entity = db, entity

    def filter(self, *args):
        return self

    def first(self):
        return self.db.first.get(self.entity)

    def all(self):
        return list(self.db.all.get(self.entity, []))

    def update(self, values, **kw):
        self.db.updates.append((self.entity, values))
        return 1


class _DB:
    """Just enough of a session for the sign-in paths and the two policy checks."""

    def __init__(self, settings, user=None, keys=(), execute_error=None):
        self.first = {SystemSetting: types.SimpleNamespace(value=settings), User: user,
                      SecondFactorEnrollment: None}
        self.all = {UserSSHKey: list(keys)}
        self.execute_error = execute_error
        self.updates, self.rollbacks, self.commits = [], 0, 0

    def query(self, entity):
        return _Query(self, getattr(entity, "class_", entity))

    def execute(self, stmt):
        if self.execute_error is not None:
            raise self.execute_error
        return types.SimpleNamespace(fetchall=lambda: [])

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _Audit:
    calls = []

    def __init__(self, db):
        pass

    def log_login_failure(self, username, ip, reason):
        _Audit.calls.append(("failure", username, reason))

    def log_login_success(self, user, ip, is_temporary=False):
        _Audit.calls.append(("success", user.username, None))


def _user():
    return types.SimpleNamespace(id=uuid.uuid4(), username="alice", sftp_enabled=True,
                                 sftp_password_auth=True, is_active=True, is_locked=False,
                                 locked_until=None)


@pytest.fixture
def world(monkeypatch):
    """Patch the collaborators; return a function that installs a database for the next sign-in."""
    _Audit.calls = []
    state = {}

    @contextmanager
    def ctx():
        yield state["db"]

    class _Auth:
        def __init__(self, db):
            pass

        def authenticate_user(self, username, password, ip):
            return state["user"], "session-token"

    monkeypatch.setattr(S, "get_db_context", ctx)
    monkeypatch.setattr(S, "AuthService", _Auth)
    monkeypatch.setattr(S, "AuditLogger", _Audit)
    monkeypatch.setattr(S, "_sftp_key_throttled", lambda ip, username: False)
    monkeypatch.setattr(S, "_sftp_key_clear", lambda ip, username: None)

    def install(settings, **kw):
        user = _user()
        key = types.SimpleNamespace(id=uuid.uuid4(), public_key=f"ssh-ed25519 {KEY_B64} probe")
        state["user"] = user
        state["db"] = _DB(settings, user=user, keys=[key], **kw)
        return state["db"]

    return install


@pytest.fixture
def broken_policy(monkeypatch):
    """The second-factor policy raising where a real deployment never saw it raise. Not a database
    error: an error of any kind must refuse."""
    def boom(**kw):
        raise RuntimeError("policy evaluation failed")
    monkeypatch.setattr(pol, "effective_second_factor", boom)


def _password(db=None):
    return S.SFTPServer("203.0.113.9").check_auth_password("alice", "right-password")


def _key():
    key = types.SimpleNamespace(get_base64=lambda: KEY_B64)
    return S.SFTPServer("203.0.113.9").check_auth_publickey("alice", key)


TEMP_ONLY = {"mfa_sftp_policy": "temp_credential_only"}


# --------------------------------------------------------------------------- the harness works

def test_with_the_policy_readable_both_sign_ins_succeed(world):
    world({"mfa_sftp_policy": "allow"})
    assert _password() == paramiko.AUTH_SUCCESSFUL
    world({"mfa_sftp_policy": "allow"})
    assert _key() == paramiko.AUTH_SUCCESSFUL


def test_with_the_policy_readable_it_is_enforced(world, monkeypatch):
    monkeypatch.setattr(pol, "effective_second_factor", lambda **kw: {"in_effect": True})
    world(TEMP_ONLY)
    assert _password() == paramiko.AUTH_FAILED
    assert _Audit.calls[-1] == ("failure", "alice", "SFTP requires a temporary credential for this account")
    world(TEMP_ONLY)
    assert _key() == paramiko.AUTH_FAILED


# --------------------------------------------------------------------------- a check that cannot run

def test_a_password_sign_in_is_refused_when_the_second_factor_policy_raises(world, broken_policy, capsys):
    db = world(TEMP_ONLY)
    server = S.SFTPServer("203.0.113.9")
    assert server.check_auth_password("alice", "right-password") == paramiko.AUTH_FAILED
    assert server.user is None and server.session_token is None
    # The session the password check opened is revoked, and the refusal says why.
    assert db.updates == [(ActiveSession, {"is_active": False})]
    assert db.rollbacks == 1, "the aborted transaction is rolled back before the refusal is written"
    assert _Audit.calls == [("failure", "alice", "SFTP sign-in policy could not be checked")]
    out = capsys.readouterr().out
    assert "event auth.policy-check.failed" in out and "err=RuntimeError" in out
    assert "policy evaluation failed" not in out, "the exception text is never logged"


def test_a_key_sign_in_is_refused_when_the_second_factor_policy_raises(world, broken_policy, capsys):
    world(TEMP_ONLY)
    server = S.SFTPServer("203.0.113.9")
    key = types.SimpleNamespace(get_base64=lambda: KEY_B64)
    assert server.check_auth_publickey("alice", key) == paramiko.AUTH_FAILED
    assert server.user is None
    assert "err=RuntimeError" in capsys.readouterr().out


def test_a_database_error_in_the_department_check_refuses_both_sign_ins(world):
    class OperationalError(Exception):
        pass
    groups = {"sftp_require_temp_cred_groups": [str(uuid.uuid4())]}
    world(groups, execute_error=OperationalError("connection lost"))
    assert _password() == paramiko.AUTH_FAILED
    assert _Audit.calls[-1] == ("failure", "alice", "SFTP sign-in policy could not be checked")
    world(groups, execute_error=OperationalError("connection lost"))
    assert _key() == paramiko.AUTH_FAILED


def test_a_live_sessions_recheck_still_lets_it_carry_on(world, broken_policy):
    """The per-operation re-check keeps failing open, and touches nothing on the session."""
    db = world(TEMP_ONLY)
    assert S._user_requires_temp_cred_for_sftp(db, _user()) is False
    assert db.rollbacks == 0
    with pytest.raises(S._PolicyUnreadable):
        S._user_requires_temp_cred_for_sftp(db, _user(), fail_closed=True)


# --------------------------------------------------------------------------- wiring

def _method(name):
    src = SFTP_SRC.read_text(encoding="utf-8")
    start = src.index(f"    def {name}(")
    end = re.compile(r"^    def ", re.M).search(src, start + 10)
    return src[start:end.start()]


def test_both_sign_ins_ask_failing_closed_and_the_recheck_does_not():
    src = SFTP_SRC.read_text(encoding="utf-8")
    calls = re.findall(r"(?<!def )_user_requires_temp_cred_for_sftp\(db, user(.*?)\)", src)
    assert sorted(calls) == ["", ", fail_closed=True", ", fail_closed=True"], calls
    for name in ("check_auth_password", "check_auth_publickey"):
        body = _method(name)
        assert "_user_requires_temp_cred_for_sftp(db, user, fail_closed=True)" in body, name
        assert "except _PolicyUnreadable:" in body, name
    assert "_user_requires_temp_cred_for_sftp(db, user)" in _method("_load_principal")
