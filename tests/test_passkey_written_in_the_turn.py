"""A passkey is written in the account's turn at its sessions, by a session that still stands or a sign-in that
still holds, and the passkey door notes what it read before it checks anything (offline; the turn is stood in for by
what another transaction holding it would have done before letting go; test_passkey_lock_order_live.py forces the
same on PostgreSQL).

- A key stored from a session in the moment of a second-factor reset stayed on the account, unretired, though the
  session that stored it was one the reset ended. The store takes the turn and reads the session again in it.
- The marks a new key answers (a reset to set a factor up again, the day a role's requirement began) are cleared
  in the key's own transaction. Cleared after it, a reset that came in between had its own mark cleared.
- A sign-in with a passkey notes the account's count when it reads the account, then reads the key again: a reset
  that retired the key before is seen at the key, one after it at the count.
"""
import types
from datetime import datetime

import pytest

from _webauthn_softauth import SoftAuthenticator
# The route harness sets the application's overrides itself: cleared after every test here, as in its own file.
from test_passkey_routes import ORIGIN, Harness as RouteHarness, _call, _clean_overrides  # noqa: F401
from test_passkey_sign_in import Harness as SignInHarness, _user

pytestmark = pytest.mark.unit

ENDED = "Session has been terminated. Please login again."


@pytest.mark.parametrize("found", ["revoked", "gone"])
def test_a_key_is_stored_from_a_session_only_while_the_session_stands(monkeypatch, found):
    """The session passed its check when the request came in. An administrator's reset then took the account's
    turn, retired the keys, ended the sessions and let go. The store reads the session again in the turn and is
    refused: no key is stored after the reset that was meant to leave none."""
    from app.core.models import ActiveSession
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    status, body = _call(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 200, body
    credential = SoftAuthenticator().make_credential(body["options"], ORIGIN)
    turns = []

    def a_reset_held_the_turn_first(db, user_id):
        turns.append((user_id, h.session.revoked))
        if found == "revoked":
            h.session.revoked = True
        else:
            db.rows_of(ActiveSession).remove(h.session)
    monkeypatch.setattr(h.S, "_sessions_turn", a_reset_held_the_turn_first)
    status, out = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                        {"challenge_id": body["challenge_id"], "credential": credential, "label": "late"})
    assert (status, out["detail"]) == (401, ENDED), out
    assert turns == [(alice.id, False)] and h.rows() == []


def test_a_session_that_is_only_idle_stores_a_key(monkeypatch):
    """The periodic cleanup marks a web session inactive after an hour idle, and its token goes on working: it is
    the account's own session still, and stores a key like any other."""
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    h.session.is_active = False
    status, shown, _auth = h.register(label="after lunch")
    assert status == 201 and len(h.rows()) == 1, shown


def test_the_marks_a_new_key_answers_are_cleared_in_the_keys_own_transaction(monkeypatch):
    alice = _user(second_factor_reset_at=datetime(2026, 11, 20), passkey_required_since=datetime(2026, 11, 1))
    h = RouteHarness(monkeypatch, alice)
    seen, commit = [], h.db.commit

    def committed():
        seen.append((len(h.rows()), alice.second_factor_reset_at, alice.passkey_required_since))
        return commit()
    monkeypatch.setattr(h.db, "commit", committed)
    status, shown, _auth = h.register(label="the answer")
    assert status == 201, shown
    with_the_key = [state for state in seen if state[0] == 1]
    assert with_the_key and with_the_key[0] == (1, None, None), seen


def test_a_reset_that_comes_after_the_keys_commit_keeps_its_mark(monkeypatch):
    """The reset lands between the key's commit and what the route does next (the owner's notice). Its mark was
    read back and cleared there; the account then held no factor and owed none."""
    alice = _user(second_factor_reset_at=datetime(2026, 11, 20))
    h = RouteHarness(monkeypatch, alice)
    reset_at = datetime(2026, 11, 21, 12, 0)

    def the_reset_lands_here(db, user, title, change):
        for row in h.rows():
            row.retired_at = reset_at
        user.second_factor_reset_at = reset_at
    monkeypatch.setattr(h.S, "_passkey_notice", the_reset_lands_here)
    status, shown, _auth = h.register(label="raced")
    assert status == 201, shown
    assert alice.second_factor_reset_at == reset_at and [row.retired_at for row in h.rows()] == [reset_at]


def test_an_authenticator_is_made_active_from_a_session_only_while_the_session_stands(monkeypatch):
    from _async_run import run_coroutine
    from _memory_db import MemoryDB
    from app.core.models import ActiveSession, SecondFactorEnrollment, User
    from test_passkey_sign_in import _api
    import uuid
    S = _api()
    alice = _user()
    begun = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, method="totp", status="unconfirmed",
                                  confirmed_at=datetime.utcnow())
    session = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, is_active=True, revoked=False,
                                    session_token=S.hash_session_token("the-session"))
    db = MemoryDB({User: [alice], SecondFactorEnrollment: [begun], ActiveSession: [session]})
    monkeypatch.setattr(S, "_sf_recovery_remaining", lambda db_, user_id: 10)
    monkeypatch.setattr(S, "_current_session_token", lambda request: "the-session")
    monkeypatch.setattr(S, "get_client_ip", lambda request: "203.0.113.9")
    monkeypatch.setattr(S, "_sessions_turn", lambda db_, user_id: setattr(session, "revoked", True))
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as refused:
        run_coroutine(S.acknowledge_recovery_codes(request=None, principal=(alice, None), db=db), timeout=30)
    assert (refused.value.status_code, refused.value.detail) == (401, ENDED)
    assert begun.status == "unconfirmed" and ("commit",) not in db.log


# ------------------------------------------------------------------------------------------------- the passkey door

def test_a_sign_in_with_a_passkey_is_not_written_after_the_accounts_sessions_were_ended(monkeypatch):
    """The key was read, the account was read, the assertion checked. A reset then took the turn, retired the
    key, counted itself on the account and let go. The sign-in reads the account again in the turn before it
    writes its session, finds the count moved, and writes none."""
    from app.core.models import ActiveSession
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    turns = []

    def a_reset_held_the_turn_first(db, user_id):
        turns.append(user_id)
        row.retired_at = datetime.utcnow()
        alice.sessions_ended += 1
    monkeypatch.setattr(h.S, "_sessions_turn", a_reset_held_the_turn_first)
    status, body = h.sign_in(auth)[:2]
    assert (status, body["detail"]) == (401, "This login attempt has expired; start again."), body
    assert turns == [alice.id] and h.db.rows_of(ActiveSession) == []
    # Nothing ended meanwhile: the same key signs in.
    row.retired_at = None
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, user_id: None)
    status, body = h.sign_in(auth, sign_count=2)[:2]
    assert status == 200 and body["access_token"], body


def test_the_passkey_door_reads_the_key_again_after_the_account(monkeypatch):
    """A reset that retired the key before the account was read left a count the sign-in would match. The key is
    read again after the account, so that reset is seen at the key."""
    from app.core.models import ActiveSession
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    read_again = []

    def as_committed(obj):
        read_again.append(obj)
        if obj is row:
            row.retired_at = datetime.utcnow()             # what a reset committed before the account was read
    monkeypatch.setattr(h.db, "refresh", as_committed, raising=False)
    status, body = h.sign_in(auth)[:2]
    assert status == 401 and row in read_again, body
    assert h.db.rows_of(ActiveSession) == []


def test_the_passkey_door_hands_on_what_it_read_of_the_account_before_the_key(monkeypatch):
    """The count of the account's ended sessions is taken where the account is read, before the key is read again
    and the assertion checked. A change that is committed in that time has counted itself: the sign-in carries
    the earlier count, and the compare in the turn refuses it. Taken where the sign-in is handed on, the count
    would be the later one, and that change would go unseen."""
    from app.core.models import ActiveSession
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    auth, row = h.enroll(alice)

    def as_committed(obj):
        if obj is row:
            alice.sessions_ended += 1                      # a change committed while the key was read again
    monkeypatch.setattr(h.db, "refresh", as_committed, raising=False)
    status, body = h.sign_in(auth)[:2]
    assert (status, body["detail"]) == (401, "This login attempt has expired; start again."), body
    assert h.db.rows_of(ActiveSession) == []


@pytest.mark.parametrize("ends_in", ["a session", "a held sign-in"])
@pytest.mark.parametrize("grace", ["begins", "ends"])
def test_the_day_a_passkey_requirement_began_is_written_with_the_sign_in_on_a_real_database(monkeypatch, grace, ends_in):
    """The sign-in reads the account again in its turn before it writes. What it had decided about the day the
    role's passkey requirement began (it begins at the first sign-in under the requirement; it ends where the
    requirement waits or is met again) is written after that read, with the sign-in, in one commit. Written on
    the account before the read, it was lost with every sign-in that ended in a session at once: no day was ever
    kept, so the requirement was never overdue. Read here from another connection: only what was committed counts."""
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from _kept_db import kept_database
    from app.core import webauthn_settings as wss
    from app.core.models import RoleEnum, User
    from app.core.security import hash_password
    from app.services import sign_in
    from test_passkey_sign_in import _api
    S = _api()
    monkeypatch.setattr(S, "_force_close_after_commit", lambda *a, **k: None)
    monkeypatch.setattr(sign_in, "_record", lambda *a, **k: None)
    held = ends_in == "a held sign-in"
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db_, u: held)
    monkeypatch.setattr(S, "_second_factor_effective", lambda db_, u: {"state": "active", "in_effect": held})
    monkeypatch.setattr(sign_in, "holds_a_factor", lambda db_, u: True)
    before = datetime(2026, 11, 1) if grace == "ends" else None
    need = wss.Requirement(False, paused=True) if grace == "ends" else wss.Requirement(True, since=None)
    monkeypatch.setattr(S, "_passkey_requirement", lambda db_, u: need)
    with kept_database() as (make, _engine):
        with make() as db:
            alice = User(username="alice", email=None, password_hash=hash_password("Old-Password-8x!"),
                         role=RoleEnum.USER, is_active=True, is_locked=False, passkey_required_since=before)
            db.add(alice)
            db.commit()

            def committed():
                other = sessionmaker(bind=db.get_bind())()
                try:
                    return other.execute(sa.text("SELECT passkey_required_since FROM users WHERE id = :id"),
                                         {"id": alice.id.hex}).fetchall()[0][0]
                finally:
                    other.close()
            outcome = sign_in.finish(db, sign_in.SignInResult(alice, [sign_in.PASSWORD], "192.0.2.1"))
            assert isinstance(outcome, sign_in.PendingStep if held else sign_in.SignedIn), outcome
            assert (committed() is not None) is (grace == "begins"), committed()
            if grace == "begins":
                # The grace runs once: a second sign-in does not move the day.
                first = committed()
                sign_in.finish(db, sign_in.SignInResult(alice, [sign_in.PASSWORD], "192.0.2.1"))
                assert committed() == first


def test_a_passkey_alone_taken_before_a_promotion_is_refused_in_the_accounts_turn(monkeypatch):
    """A passkey by itself signs in an account whose role lets one in alone. Taken while the account was a user's
    and written after it was made an administrator (or given the auditor right), it would be an administrator's
    session without the password: in the account's turn the rule is asked again of the account as it is."""
    import uuid
    from fastapi import HTTPException
    from app.api import api_server as api
    from app.services import sign_in
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice", sessions_ended=0)
    dropped, allowed = [], [False]
    monkeypatch.setattr(api, "_sessions_turn", lambda db, user_id: None)
    monkeypatch.setattr(api, "_passkey_passwordless_allowed", lambda db, user: allowed[0])
    monkeypatch.setattr(sign_in, "drop_the_session_the_proof_made", lambda db, result: dropped.append(result))
    monkeypatch.setattr(sign_in, "refuse_unless_the_account_may_sign_in", lambda db, user, ip: None)
    monkeypatch.setattr(sign_in, "write_the_passkey_grace", lambda result: None)
    # What else the turn asks where a sign-in can come through a provider is not this test's.
    for asked in ("hold_the_providers_row", "refuse_without_the_provider", "refuse_unless_the_provider_stands"):
        monkeypatch.setattr(sign_in, asked, lambda db, result: None, raising=False)

    def taken(methods, **more):
        return sign_in.SignInResult(alice, list(methods), "192.0.2.1", sessions_ended=0, **more)
    alone = taken([sign_in.HARDWARE_KEY], passwordless_allowed=True, user_verified=True)
    with pytest.raises(HTTPException) as refused:
        sign_in.in_the_accounts_turn(types.SimpleNamespace(), alone)
    assert refused.value.status_code == 401 and refused.value.detail == sign_in.EXPIRED and dropped == [alone]
    # Still a role a passkey signs in alone: written.
    allowed[0] = True
    sign_in.in_the_accounts_turn(types.SimpleNamespace(), alone)
    assert dropped == [alone]
    # With the password, or after a provider, the passkey was not the whole sign-in: nothing more is asked here.
    allowed[0] = False
    for other in (taken([sign_in.PASSWORD, sign_in.HARDWARE_KEY], passwordless_allowed=True, user_verified=True),
                  taken([sign_in.SOFTWARE_KEY], passwordless_allowed=True, provider_id=str(uuid.uuid4())),
                  taken([sign_in.SOFTWARE_KEY], passwordless_allowed=False), taken([sign_in.PASSWORD])):
        assert sign_in.a_passkey_alone(other) is False
        sign_in.in_the_accounts_turn(types.SimpleNamespace(), other)
    assert sign_in.a_passkey_alone(alone) is True and dropped == [alone]

