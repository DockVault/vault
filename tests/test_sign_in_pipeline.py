"""The sign-in pipeline (app/services/sign_in.py): the one table that says what follows a proof, the
pre-authentication token's stage and proofs, the pending answer, and the finished token's claims.

Offline: the policy table is pure; the pending and finishing paths run against the in-memory
database (tests/_memory_db.py) with the record-making patched out and observed.
"""
import base64
import json
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


def _sign_in():
    set_bare_api_env()
    from app.services import sign_in
    return sign_in


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _claims(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def _user(role="user"):
    from app.core.models import RoleEnum
    return types.SimpleNamespace(id=uuid.uuid4(), username="alice", email="alice@example.test",
                                 role=RoleEnum(role), is_active=True, is_locked=False, locked_until=None)


# --- second_factor_due: the table -----------------------------------------------------------------

def _due(methods, role="user", **kw):
    s = _sign_in()
    kw.setdefault("factor_in_effect", False)
    kw.setdefault("enrollment_pending", False)
    return s.second_factor_due(_user(role), methods, **kw)


def test_a_password_alone_follows_todays_rule():
    s = _sign_in()
    assert _due(["pwd"]) == s.DONE
    assert _due(["pwd"], factor_in_effect=True) == s.STAGE_SECOND_FACTOR
    assert _due(["pwd"], factor_in_effect=True, enrollment_pending=True) == s.ENROLL
    # An administrator's password alone is no different: the vault's rule decides.
    assert _due(["pwd"], role="admin", factor_in_effect=True) == s.STAGE_SECOND_FACTOR


def test_a_temporary_credential_never_has_a_step():
    s = _sign_in()
    assert _due(["pwd"], factor_in_effect=True, enrollment_pending=True, is_temporary=True) == s.DONE


def test_the_password_and_a_second_kind_are_done():
    s = _sign_in()
    for second in ("totp", "recovery", "hwk", "swk"):
        assert _due(["pwd", second], factor_in_effect=True, enrollment_pending=True) == s.DONE, second
        assert _due([second, "pwd"], role="admin", factor_in_effect=True) == s.DONE, second
    # ... and the password with a trusted provider MFA, which counts only when a provider was there.
    assert _due(["pwd"], factor_in_effect=True, provider_mfa_trusted=True, provider_id="p1") == s.DONE
    assert _due(["pwd"], factor_in_effect=True, provider_mfa_trusted=True) == s.STAGE_SECOND_FACTOR


def test_an_administrator_without_the_password_always_types_it():
    s = _sign_in()
    # Whatever proved them, however strong: a user-verified passkey allowed for users, a trusted provider.
    assert _due(["hwk"], role="admin", user_verified=True, passwordless_allowed=True) == s.STAGE_PASSWORD
    assert _due([], role="admin", provider_mfa_trusted=True, provider_id="p1") == s.STAGE_PASSWORD
    assert _due(["swk"], role="admin") == s.STAGE_PASSWORD


def test_a_passkey_without_user_verification_is_followed_by_the_password_never_a_code():
    s = _sign_in()
    # Even for an account whose second factor is in effect: a code would be a second possession factor.
    assert _due(["hwk"], factor_in_effect=True) == s.STAGE_PASSWORD
    assert _due(["swk"], factor_in_effect=True, enrollment_pending=True) == s.STAGE_PASSWORD
    # User verification without the policy's leave, or the policy's leave without user verification:
    # the password follows.
    assert _due(["hwk"], user_verified=True) == s.STAGE_PASSWORD
    assert _due(["hwk"], passwordless_allowed=True) == s.STAGE_PASSWORD


def test_a_user_verified_passkey_alone_is_the_whole_sign_in_when_allowed():
    s = _sign_in()
    assert _due(["hwk"], user_verified=True, passwordless_allowed=True, factor_in_effect=True) == s.DONE
    assert _due(["swk"], user_verified=True, passwordless_allowed=True) == s.DONE


def test_single_sign_on_takes_the_vaults_rule_unless_the_providers_mfa_is_trusted():
    s = _sign_in()
    sso = {"provider_id": "p1"}
    assert _due([], **sso) == s.DONE
    assert _due([], factor_in_effect=True, **sso) == s.STAGE_SECOND_FACTOR
    assert _due([], factor_in_effect=True, enrollment_pending=True, **sso) == s.ENROLL
    assert _due([], factor_in_effect=True, provider_mfa_trusted=True, **sso) == s.DONE
    # The vault's own code after the provider finishes the sign-in: the second-factor stage is the last step.
    assert _due(["totp"], factor_in_effect=True, **sso) == s.DONE
    assert _due(["recovery"], factor_in_effect=True, enrollment_pending=True, **sso) == s.DONE
    # ... unless the account became an administrator meanwhile: then the password still follows.
    assert _due(["totp"], role="admin", factor_in_effect=True, **sso) == s.STAGE_PASSWORD
    # A passkey after the provider is the second kind too, verified by the person or not: the provider proved who
    # they are, and an account that signs in only through its provider has no password to give.
    assert _due(["hwk"], factor_in_effect=True, **sso) == s.DONE
    assert _due(["swk"], factor_in_effect=True, enrollment_pending=True, **sso) == s.DONE
    assert _due(["hwk"], **sso) == s.DONE
    assert _due(["hwk"], role="admin", factor_in_effect=True, user_verified=True, passwordless_allowed=True,
                **sso) == s.STAGE_PASSWORD
    # Without a provider the passkey is the first proof, and its own row answers.
    assert _due(["hwk"], factor_in_effect=True) == s.STAGE_PASSWORD
    assert _due(["hwk"], factor_in_effect=True, user_verified=True, passwordless_allowed=True) == s.DONE
    # An administrator's password after a trusted provider MFA: done, no code on top.
    assert _due(["pwd"], role="admin", factor_in_effect=True, provider_mfa_trusted=True, **sso) == s.DONE


def test_a_sign_in_needs_a_first_proof():
    """A code alone, or nothing at all, proves nothing about who the person is: the table refuses to answer,
    and the pipeline turns that into a refusal, never a session."""
    s = _sign_in()
    for methods in ([], ["totp"], ["recovery"], ["totp", "recovery"]):
        with pytest.raises(s.NoFirstProof):
            _due(methods)
        with pytest.raises(s.NoFirstProof):
            _due(methods, factor_in_effect=True, provider_mfa_trusted=True)
    # The password, a passkey or a provider is a first proof.
    assert _due(["pwd"]) == s.DONE
    assert _due(["hwk"]) == s.STAGE_PASSWORD
    assert _due(["totp"], provider_id="p1") == s.DONE


# --- the pre-authentication token's stage and proofs ------------------------------------------------

def test_a_second_factor_stage_a_passkey_reached_without_the_password_is_refused():
    s = _sign_in()
    pending = types.SimpleNamespace()
    with pytest.raises(HTTPException) as e:
        s.read_pre_auth({"stage": "second_factor", "pre_auth": "x", "methods_so_far": ["hwk"]}, pending)
    assert e.value.status_code == 401
    # The same proofs at the password stage are what the rule wants.
    s.read_pre_auth({"stage": "password", "pre_auth": "x", "methods_so_far": ["hwk"]}, pending)
    assert pending._methods_so_far == ("hwk",) and pending._stage == "password"
    # Single sign-on at the second-factor stage (no password, no passkey) is allowed.
    s.read_pre_auth({"stage": "second_factor", "pre_auth": "x", "methods_so_far": [], "idp": "p1"}, pending)
    assert pending._methods_so_far == () and pending._provider_id == "p1"


def test_an_empty_proof_list_is_a_real_answer_not_the_password():
    """A single sign-on at the second-factor stage proved nothing of the vault's own yet: the list is empty,
    and the finished token must not claim a password that was never typed."""
    s = _sign_in()
    pending = types.SimpleNamespace()
    s.read_pre_auth({"stage": "second_factor", "pre_auth": "x", "methods_so_far": [], "idp": "p1"}, pending)
    assert s.methods_so_far(pending) == []
    assert s.methods_so_far(pending) + ["totp"] == ["totp"]
    assert s.provider_mfa_of(pending) is False
    s.read_pre_auth({"stage": "password", "pre_auth": "x", "methods_so_far": [], "idp": "p1", "provider_mfa": True},
                    pending)
    assert s.methods_so_far(pending) == [] and s.provider_mfa_of(pending) is True
    # Only the boolean true counts.
    s.read_pre_auth({"stage": "password", "pre_auth": "x", "methods_so_far": [], "provider_mfa": "true"}, pending)
    assert s.provider_mfa_of(pending) is False
    assert s.provider_mfa_of(None) is False


def test_a_token_from_before_the_field_counts_as_a_password_proof():
    s = _sign_in()
    pending = types.SimpleNamespace()
    s.read_pre_auth({"stage": "second_factor", "pre_auth": "x"}, pending)
    assert s.methods_so_far(pending) == ["pwd"]
    # Garbage in the field is not a list of proofs either.
    s.read_pre_auth({"stage": "second_factor", "pre_auth": "x", "methods_so_far": "hwk"}, pending)
    assert s.methods_so_far(pending) == ["pwd"]
    s.read_pre_auth({"stage": "second_factor", "pre_auth": "x", "methods_so_far": [1, None]}, pending)
    assert s.methods_so_far(pending) == ["pwd"]
    # A pending login nothing read: the password. No pending login (the sign-in form): nothing yet.
    assert s.methods_so_far(types.SimpleNamespace()) == ["pwd"]
    assert s.methods_so_far(None) == [] and s.provider_of(None) is None


def test_two_kinds_present():
    s = _sign_in()
    user = _user()

    def present(methods, **kw):
        return s.second_kind_present(s.SignInResult(user, methods, "10.0.0.1", **kw))

    assert not present(["pwd"])
    assert present(["pwd", "totp"]) and present(["pwd", "recovery"]) and present(["hwk", "pwd"])
    assert not present(["hwk"]) and present(["hwk"], user_verified=True)
    assert not present([]) and present([], provider_mfa_trusted=True)


# --- begin_pending: the pending answer and its token --------------------------------------------------

def _pending_db(user, enrollment=None):
    from app.core.models import PendingLogin, SecondFactorEnrollment
    rows = {PendingLogin: [], SecondFactorEnrollment: []}
    if enrollment:
        rows[SecondFactorEnrollment].append(types.SimpleNamespace(user_id=user.id, status="active", method=enrollment))
    return MemoryDB(rows)


def test_the_second_factor_stage_answers_as_it_always_did_plus_the_stage_and_what_to_enroll():
    s = _sign_in()
    user = _user()
    db = _pending_db(user, enrollment="totp")
    step = s.begin_pending(db, s.SignInResult(user, ["pwd"], "10.0.0.1"), s.STAGE_SECOND_FACTOR)
    body = step.body
    assert set(body) == {"access_token", "second_factor_required", "stage", "enrollment_required", "methods",
                         "enrollment_methods", "pre_auth_token"}
    assert body["access_token"] is None and body["second_factor_required"] is True
    assert body["stage"] == "second_factor" and body["enrollment_required"] is False
    assert body["methods"] == ["totp", "recovery"] and body["enrollment_methods"] == []
    claims = _claims(body["pre_auth_token"])
    assert claims["stage"] == "second_factor" and claims["methods_so_far"] == ["pwd"]
    assert claims["pre_auth"] and "session_token" not in claims and "idp" not in claims
    assert claims["sub"] == str(user.id) and claims["username"] == "alice"
    # The row the token names was written, unspent, with the address, for five minutes.
    (pending,) = db.added
    assert str(pending.id) == claims["pre_auth"] and pending.client_ip == "10.0.0.1"
    assert pending.enrollment_required is False and pending.consumed_at is None
    assert timedelta(minutes=4) < pending.expires_at - datetime.now(timezone.utc) <= timedelta(minutes=5)


def test_an_enrollment_offers_no_method_and_says_what_may_be_enrolled():
    s = _sign_in()
    user = _user()
    step = s.begin_pending(_pending_db(user), s.SignInResult(user, ["pwd"], None), s.STAGE_SECOND_FACTOR,
                           enrollment_required=True)
    assert step.body["enrollment_required"] is True and step.body["methods"] == []
    assert step.body["enrollment_methods"] == ["totp"]


def test_the_password_stage_names_the_account_and_carries_the_proofs_and_the_provider():
    s = _sign_in()
    user = _user(role="admin")
    step = s.begin_pending(_pending_db(user), s.SignInResult(user, ["hwk"], None, provider_id=None),
                           s.STAGE_PASSWORD)
    assert step.body["stage"] == "password" and step.body["methods"] == ["password"]
    assert step.body["username"] == "alice" and step.body["enrollment_required"] is False
    claims = _claims(step.body["pre_auth_token"])
    assert claims["stage"] == "password" and claims["methods_so_far"] == ["hwk"]
    step = s.begin_pending(_pending_db(user), s.SignInResult(user, [], None, provider_id="p1"), s.STAGE_PASSWORD)
    pre = _claims(step.body["pre_auth_token"])
    assert pre["idp"] == "p1" and pre["methods_so_far"] == [] and "provider_mfa" not in pre
    # The trusted provider MFA travels with the stage, so the password after it finishes the sign-in.
    step = s.begin_pending(_pending_db(user), s.SignInResult(user, [], None, provider_id="p1", provider_mfa_trusted=True),
                           s.STAGE_PASSWORD)
    assert _claims(step.body["pre_auth_token"])["provider_mfa"] is True
    pending = types.SimpleNamespace()
    s.read_pre_auth(_claims(step.body["pre_auth_token"]), pending)
    assert s.provider_mfa_of(pending) is True and s.methods_so_far(pending) == []


def test_a_pending_login_the_result_continues_is_spent_first():
    s = _sign_in()
    user = _user()
    from app.core.models import PendingLogin
    earlier = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None, attempts=0)
    db = _pending_db(user)
    db.tables[PendingLogin].append(earlier)
    s.begin_pending(db, s.SignInResult(user, ["hwk", "pwd"], None, pending=earlier), s.STAGE_SECOND_FACTOR)
    assert earlier.consumed_at is not None
    # Spent already: a second completion is refused.
    with pytest.raises(HTTPException) as e:
        s.begin_pending(db, s.SignInResult(user, ["hwk", "pwd"], None, pending=earlier), s.STAGE_SECOND_FACTOR)
    assert e.value.status_code == 401


def test_only_the_two_stages_can_be_pending():
    s = _sign_in()
    user = _user()
    with pytest.raises(ValueError):
        s.begin_pending(_pending_db(user), s.SignInResult(user, ["pwd"], None), s.DONE)


# --- complete_sign_in: the token's claims and the records -----------------------------------------------

@pytest.fixture
def quiet_records(monkeypatch):
    """The records of a finished sign-in, observed instead of made."""
    S = _api()
    made = {"audit": [], "events": [], "notices": [], "emails": []}

    class _Audit:
        def __init__(self, db):
            pass

        def log_login_success(self, user, ip, is_temporary=False, methods=None):
            made["audit"].append((user.username, ip, is_temporary, methods))

        def log_action(self, **kw):
            made["audit"].append(("action", kw.get("action")))

    monkeypatch.setattr(S, "AuditLogger", _Audit)
    monkeypatch.setattr(S, "_fire_offloop", lambda fn, *a, **kw: made["events"].append((fn, a, kw)))
    monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, **kw: made["notices"].append((ids, ntype, kw)))
    monkeypatch.setattr(S, "_fire_action_email", lambda db, key, **kw: made["emails"].append((key, kw)))
    return made


def _complete(user, methods, quiet_records, **kw):
    s = _sign_in()
    from app.core.models import SystemSetting
    db = MemoryDB({SystemSetting: []})
    kw.setdefault("session_token", "sess-" + uuid.uuid4().hex)
    signed = s.complete_sign_in(db, s.SignInResult(user, methods, "10.0.0.9", **kw))
    return signed, _claims(signed.access_token)


def test_a_finished_sign_in_stamps_the_accounts_last_sign_in_time(quiet_records):
    """Every door: a passkey alone, a provider alone, and the password path that already made the session."""
    for methods, kw in ((["hwk"], {}), ([], {"provider_id": "p1"}), (["pwd", "totp"], {"session_token": "sess-pwd"})):
        user = _user()
        user.last_login = None
        _complete(user, methods, quiet_records, **kw)
        assert user.last_login is not None and abs((user.last_login - datetime.now(timezone.utc)).total_seconds()) < 60


def test_a_finished_token_carries_the_claims_it_always_did_plus_the_proofs(quiet_records):
    user = _user()
    signed, claims = _complete(user, ["pwd"], quiet_records, session_token="sess-1")
    assert signed.user is user and signed.is_temporary is False
    assert set(claims) == {"sub", "username", "session_token", "is_temporary", "amr", "auth_time", "sign_in_id",
                           "exp", "iat"}
    assert claims["sub"] == str(user.id) and claims["username"] == "alice"
    assert claims["session_token"] == "sess-1" and claims["is_temporary"] is False
    assert claims["amr"] == ["pwd"]
    assert abs(claims["auth_time"] - datetime.now(timezone.utc).timestamp()) < 60
    # mfa_at only when two kinds were present; idp only for a single sign-on.
    _, claims = _complete(user, ["pwd", "totp"], quiet_records)
    assert claims["amr"] == ["pwd", "totp"] and abs(claims["mfa_at"] - datetime.now(timezone.utc).timestamp()) < 60
    _, claims = _complete(user, [], quiet_records, provider_id="p1")
    assert claims["amr"] == [] and claims["idp"] == "p1" and "mfa_at" not in claims


def test_every_sign_in_gets_a_sign_in_id_of_its_own_whatever_its_time(quiet_records):
    """A renewal keeps the id, and a page tells its own sign-in by it. Two sign-ins of one person through one
    provider session share a time, so the id is made by the vault for each, never read from what came in."""
    user = _user()
    at = datetime.now(timezone.utc) - timedelta(minutes=5)
    ids = []
    for methods, extra in ((["pwd"], {}), (["pwd", "totp"], {}), ([], {"provider_id": "p1", "auth_time": at}),
                           ([], {"provider_id": "p1", "auth_time": at}), (["pwd"], {"is_temporary": True})):
        _, claims = _complete(user, methods, quiet_records, **extra)
        assert isinstance(claims["sign_in_id"], str) and len(claims["sign_in_id"]) >= 16
        ids.append(claims["sign_in_id"])
    assert len(set(ids)) == len(ids)
    same_time = [_complete(user, [], quiet_records, provider_id="p1", auth_time=at)[1] for _ in range(2)]
    assert same_time[0]["auth_time"] == same_time[1]["auth_time"]
    assert same_time[0]["sign_in_id"] != same_time[1]["sign_in_id"]
    # The vault's own helper is what makes it: one place, the one every other sign-in uses.
    S = _api()
    quiet = S._new_sign_in_id
    try:
        S._new_sign_in_id = lambda: "made-by-the-vault"
        assert _complete(user, ["pwd"], quiet_records)[1]["sign_in_id"] == "made-by-the-vault"
    finally:
        S._new_sign_in_id = quiet


def test_the_records_are_the_same_for_every_method(quiet_records):
    S = _api()
    user = _user()
    _complete(user, ["pwd", "totp"], quiet_records)
    assert quiet_records["audit"] == [("alice", "10.0.0.9", False, ["pwd", "totp"])]
    ((fn, args, kw),) = quiet_records["events"]
    assert fn is S.broadcast_event and kw == {"include_metrics": False}
    event = args[0]["event"]
    assert event["type"] == "login" and event["user"] == "alice" and event["is_temporary"] is False
    assert "temp_username" not in event
    assert quiet_records["notices"] == []
    assert quiet_records["emails"] == [("login_alert", {"email": "alice@example.test", "username": "alice"})]


def test_a_temporary_credential_tells_its_owner_and_keeps_the_default_token_life(quiet_records):
    user = _user()
    signed, claims = _complete(user, ["pwd"], quiet_records, is_temporary=True, temp_username="temp_abc")
    assert signed.is_temporary is True and claims["is_temporary"] is True and claims["amr"] == ["pwd"]
    ((ids, ntype, kw),) = quiet_records["notices"]
    assert ids == [str(user.id)] and ntype == "temp_login" and "temp_abc" in kw["body"]
    assert quiet_records["emails"] == []
    event = quiet_records["events"][0][1][0]["event"]
    assert event["temp_username"] == "temp_abc" and event["owner_user_id"] == str(user.id)


def test_a_finished_pending_login_is_spent_once(quiet_records):
    s = _sign_in()
    user = _user()
    from app.core.models import PendingLogin, SystemSetting
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None, attempts=0)
    db = MemoryDB({SystemSetting: [], PendingLogin: [pending]})
    s.complete_sign_in(db, s.SignInResult(user, ["pwd", "totp"], None, session_token="s", pending=pending))
    assert pending.consumed_at is not None
    with pytest.raises(HTTPException) as e:
        s.complete_sign_in(db, s.SignInResult(user, ["pwd", "totp"], None, session_token="s", pending=pending))
    assert e.value.status_code == 401


# --- finish: a step follows, or the sign-in is whole ----------------------------------------------------

def _finish_db(user, *, session_token=None, pending=None, enrollment=None):
    from app.core.models import ActiveSession, PendingLogin, SecondFactorEnrollment, SystemSetting
    from app.core.session_hash_utils import hash_session_token
    rows = {ActiveSession: [], PendingLogin: [], SecondFactorEnrollment: [], SystemSetting: []}
    if session_token:
        rows[ActiveSession].append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id,
                                                         session_token=hash_session_token(session_token)))
    if pending is not None:
        rows[PendingLogin].append(pending)
    if enrollment:
        rows[SecondFactorEnrollment].append(types.SimpleNamespace(user_id=user.id, status="active", method=enrollment))
    return MemoryDB(rows)


def _policy(monkeypatch, *, in_effect, state="setup", lock=None):
    S = _api()
    from app.core import sign_in_lockout
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: in_effect)
    monkeypatch.setattr(S, "_second_factor_effective", lambda db, user: {"state": state, "in_effect": in_effect})
    monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda db, user_id, address, **kw: lock)


def test_a_proof_does_not_finish_a_sign_in_for_an_account_that_may_not_sign_in(quiet_records, monkeypatch):
    """The password check refuses an inactive or locked account before anything else; every other way in
    (a passkey, a provider, a one-time code) is refused the same way when it reaches the pipeline."""
    s = _sign_in()
    from app.core.sign_in_lockout import Lock
    user = _user()
    _policy(monkeypatch, in_effect=False)
    user.is_active = False
    with pytest.raises(HTTPException) as e:
        s.finish(_finish_db(user), s.SignInResult(user, ["hwk"], "10.0.0.1", user_verified=True, passwordless_allowed=True))
    assert e.value.status_code == 401
    user.is_active = True
    # An administrator's lock (no end) and a timed lock.
    user.is_locked = True
    with pytest.raises(HTTPException) as e:
        s.finish(_finish_db(user), s.SignInResult(user, [], "10.0.0.1", provider_id="p1"))
    assert e.value.status_code == 403 and "locked" in str(e.value.detail).lower()
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with pytest.raises(HTTPException) as e:
        s.finish(_finish_db(user), s.SignInResult(user, [], "10.0.0.1", provider_id="p1"))
    assert e.value.status_code == 403
    user.is_locked, user.locked_until = False, None
    # An automatic sign-in lock from this address.
    _policy(monkeypatch, in_effect=False,
            lock=Lock(scope="address", locked_until=datetime.now(timezone.utc) + timedelta(minutes=5), source="x"))
    with pytest.raises(HTTPException) as e:
        s.finish(_finish_db(user), s.SignInResult(user, ["hwk"], "10.0.0.1", user_verified=True, passwordless_allowed=True))
    assert e.value.status_code == 403
    assert quiet_records["events"] == []       # nothing was finished
    # A temporary credential has its own checks in the credential path and is not re-judged here.
    _policy(monkeypatch, in_effect=False, lock=Lock(scope="address", locked_until=None, source="x"))
    outcome = s.finish(_finish_db(user), s.SignInResult(user, ["pwd"], None, session_token="t", is_temporary=True,
                                                        temp_username="temp_x"))
    assert isinstance(outcome, s.SignedIn)


def test_a_step_that_follows_deletes_the_session_the_password_made_and_records_the_password(quiet_records, monkeypatch):
    s = _sign_in()
    from app.core.models import ActiveSession
    user = _user()
    _policy(monkeypatch, in_effect=True)
    db = _finish_db(user, session_token="sess-1", enrollment="totp")
    outcome = s.finish(db, s.SignInResult(user, ["pwd"], "10.0.0.1", session_token="sess-1"))
    assert isinstance(outcome, s.PendingStep) and outcome.stage == "second_factor"
    assert outcome.body["methods"] == ["totp", "recovery"] and outcome.body["enrollment_required"] is False
    # No usable session stands while the step is pending.
    assert db.tables[ActiveSession] == []
    assert ("action", "login_password_ok") in quiet_records["audit"]
    # ... and nothing of a finished sign-in was recorded.
    assert quiet_records["events"] == [] and quiet_records["emails"] == []
    assert not [a for a in quiet_records["audit"] if a[0] == "alice"]


def test_an_enrollment_step_follows_when_the_factor_is_required_but_not_set_up(quiet_records, monkeypatch):
    s = _sign_in()
    user = _user()
    _policy(monkeypatch, in_effect=True, state="pending")
    outcome = s.finish(_finish_db(user), s.SignInResult(user, ["pwd"], None))
    assert isinstance(outcome, s.PendingStep)
    assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["totp"]


def test_no_step_follows_when_no_factor_is_in_effect(quiet_records, monkeypatch):
    s = _sign_in()
    user = _user()
    _policy(monkeypatch, in_effect=False)
    outcome = s.finish(_finish_db(user, session_token="sess-1"),
                       s.SignInResult(user, ["pwd"], "10.0.0.1", session_token="sess-1"))
    assert isinstance(outcome, s.SignedIn)
    assert _claims(outcome.access_token)["amr"] == ["pwd"] and _claims(outcome.access_token)["session_token"] == "sess-1"
    assert ("alice", "10.0.0.1", False, ["pwd"]) in quiet_records["audit"]
    assert ("action", "login_password_ok") not in quiet_records["audit"]


def test_a_temporary_credential_never_waits(quiet_records, monkeypatch):
    s = _sign_in()
    user = _user()
    _policy(monkeypatch, in_effect=True, state="pending")
    outcome = s.finish(_finish_db(user), s.SignInResult(user, ["pwd"], None, session_token="t", is_temporary=True,
                                                        temp_username="temp_x"))
    assert isinstance(outcome, s.SignedIn) and outcome.is_temporary


def test_an_administrators_password_after_a_trusted_provider_finishes_with_two_kinds(quiet_records, monkeypatch):
    s = _sign_in()
    admin = _user(role="admin")
    _policy(monkeypatch, in_effect=True)
    pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=admin.id, consumed_at=None, attempts=0)
    db = _finish_db(admin, session_token="sess-2", pending=pending)
    # Without the carried fact the vault's own code would be asked; with it the password is the last step.
    outcome = s.finish(db, s.SignInResult(admin, ["pwd"], None, session_token="sess-2", pending=pending,
                                          provider_id="p1", provider_mfa_trusted=True))
    assert isinstance(outcome, s.SignedIn)
    claims = _claims(outcome.access_token)
    assert claims["amr"] == ["pwd"] and claims["idp"] == "p1" and "mfa_at" in claims
    assert pending.consumed_at is not None


def test_the_pending_logins_own_cap_on_wrong_answers():
    s = _sign_in()
    from app.core.models import PendingLogin
    pending = types.SimpleNamespace(id=uuid.uuid4(), consumed_at=None, attempts=0)
    db = MemoryDB({PendingLogin: [pending]})
    for n in range(1, s.MAX_PENDING_ATTEMPTS):
        s.count_failed_attempt(db, pending)
        assert pending.attempts == n and pending.consumed_at is None
        s.too_many_attempts(db, pending)   # still allowed
    s.count_failed_attempt(db, pending)
    assert pending.attempts == s.MAX_PENDING_ATTEMPTS and pending.consumed_at is not None
    with pytest.raises(HTTPException) as e:
        s.too_many_attempts(db, pending)
    assert e.value.status_code == 401


def test_the_password_stage_token_is_read_only_at_that_stage():
    s = _sign_in()
    from app.core.models import PendingLogin
    live = types.SimpleNamespace(id=uuid.uuid4(), consumed_at=None, attempts=0,
                                 expires_at=datetime.now(timezone.utc) + timedelta(minutes=3))
    spent = types.SimpleNamespace(id=uuid.uuid4(), consumed_at=datetime.now(timezone.utc), attempts=0,
                                  expires_at=datetime.now(timezone.utc) + timedelta(minutes=3))
    db = MemoryDB({PendingLogin: [live, spent]})
    assert s.read_password_stage(None, db) is None
    assert s.read_password_stage({"stage": "second_factor", "pre_auth": str(live.id)}, db) is None
    assert s.read_password_stage({"stage": "password"}, db) is None
    got = s.read_password_stage({"stage": "password", "pre_auth": str(live.id), "methods_so_far": ["swk"]}, db)
    assert got is live and s.methods_so_far(live) == ["swk"]
    for bad in (str(spent.id), str(uuid.uuid4())):
        with pytest.raises(HTTPException) as e:
            s.read_password_stage({"stage": "password", "pre_auth": bad}, db)
        assert e.value.status_code == 401
