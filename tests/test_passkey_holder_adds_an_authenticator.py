"""An account that holds a passkey adds an authenticator app from a session only behind that passkey
(app/api/api_server.py: enroll_totp, acknowledge_recovery_codes, _factor_before_another_from_a_session). With the
password alone, whoever knew the password of an account that holds only passkeys enrolled an authenticator of
their own and met every step-up with it. Offline: the routes called as functions, the step-up and the account's
factors stood in for."""
import types
import uuid

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


@pytest.fixture
def world(monkeypatch):
    set_bare_api_env()
    from app.api import api_server as api
    from app.core import active_factors as af
    from app.core.models import User
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice", password_hash="hash", _is_temp_session=False)
    out = types.SimpleNamespace(api=api, alice=alice, db=MemoryDB({User: [alice]}), holds=True, asked=[])
    monkeypatch.setattr(af, "active_factors", lambda db, user_id: types.SimpleNamespace(any=out.holds))

    def step_up(db, user, request, action):
        out.asked.append((user.username, action))
        raise HTTPException(status_code=403, detail={"second_factor_required": True, "action": action})
    monkeypatch.setattr(api, "_enforce_step_up", step_up)
    monkeypatch.setattr(api, "_sf_enrollment", lambda db, user_id, status=None: None)
    return out


def _enroll(world, pending=None):
    body = world.api.TotpEnrollRequest(current_password="the-password-nobody-checks-yet")
    return run_coroutine(world.api.enroll_totp(body=body, request=types.SimpleNamespace(headers={}),
                                               principal=(world.alice, pending), db=world.db))


def _acknowledge(world, pending=None):
    return run_coroutine(world.api.acknowledge_recovery_codes(request=types.SimpleNamespace(headers={}),
                                                              principal=(world.alice, pending), db=world.db))


def test_a_session_of_an_account_that_holds_a_factor_gives_it_before_an_authenticator_is_added(world):
    for act in (_enroll, _acknowledge):
        del world.asked[:]
        with pytest.raises(HTTPException) as refused:
            act(world)
        assert refused.value.status_code == 403 and refused.value.detail["action"] == "account.second_factor"
        assert world.asked == [("alice", "account.second_factor")]


def test_an_account_with_no_factor_enrolls_with_its_password_as_before(world, monkeypatch):
    from app.core import security
    world.holds = False
    monkeypatch.setattr(security, "verify_password", lambda given, stored: False)
    with pytest.raises(HTTPException) as refused:
        _enroll(world)
    assert refused.value.status_code == 400 and "current password" in refused.value.detail      # the password's turn
    assert world.asked == []


def test_at_a_held_sign_in_the_factor_is_asked_where_it_is_stored_and_not_here(world, monkeypatch):
    from app.core import security
    from app.services import sign_in
    monkeypatch.setattr(security, "verify_password", lambda given, stored: False)
    held = types.SimpleNamespace(id=uuid.uuid4())
    # The hold's own check asks (an account that holds a factor gives it first; stood in for here)...
    seen = []
    monkeypatch.setattr(sign_in, "refuse_enrollment_before_the_accounts_factor",
                        lambda db, user, pending: seen.append(pending))
    monkeypatch.setattr(sign_in, "provider_proves_an_enrollment", lambda user, pending: False)
    with pytest.raises(HTTPException) as refused:
        _enroll(world, pending=held)
    # ...and the session's question is not put to it: the password's turn follows.
    assert refused.value.status_code == 400 and world.asked == [] and seen == [held]
    # The helper by itself: a session asks, a held sign-in does not, an account without a factor does not.
    ask = world.api._factor_before_another_from_a_session
    request = types.SimpleNamespace(headers={})
    ask(world.db, world.alice, request, types.SimpleNamespace())
    assert world.asked == []
    with pytest.raises(HTTPException):
        ask(world.db, world.alice, request, None)
    world.holds = False
    ask(world.db, world.alice, request, None)
    assert world.asked == [("alice", "account.second_factor")]


def test_an_account_with_no_password_of_its_own_is_told_so_before_its_factor_is_asked_for(world, monkeypatch):
    """Under Your account, an account whose password nobody can type sets no authenticator up: it is told where
    one is set up. Its passkey is not asked for first, to be given for an answer that writes nothing."""
    from app.services import sign_in
    monkeypatch.setattr(sign_in, "has_a_password_it_can_type", lambda user: False)
    with pytest.raises(HTTPException) as refused:
        _enroll(world)
    assert refused.value.status_code == 409 and "no password of its own" in refused.value.detail
    assert world.asked == []
    # With a password it can type, the same account gives its factor first.
    monkeypatch.setattr(sign_in, "has_a_password_it_can_type", lambda user: True)
    with pytest.raises(HTTPException) as refused:
        _enroll(world)
    assert refused.value.status_code == 403 and world.asked == [("alice", "account.second_factor")]
