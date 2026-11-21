"""A session and a held sign-in are written in the account's turn at its sessions, only while what the sign-in was
proved by still stands (app/services/sign_in.py, in_the_accounts_turn), offline on a real database.

What ends an account's sessions as a whole counts itself on the account (``users.sessions_ended``) under that turn.
A sign-in notes the count its first proof read, a held sign-in carries it in its token, and the two writers
(``begin_pending``, ``complete_sign_in``) take the turn, read the account again and compare before they write, in
one transaction with one commit. The turn itself is stood in for here by what another transaction holding it would
have done before letting go; test_sign_in_lock_order_live.py forces the same on PostgreSQL with two connections.
"""
import ast
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import sign_in_lockout  # noqa: E402
from app.core.models import ActiveSession, PendingLogin, RoleEnum, User  # noqa: E402
from app.core.security import hash_password, verify_access_token  # noqa: E402
from app.services import auth_service as auth_mod  # noqa: E402
from app.services import sign_in  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
OLD, NEW = "Old-Password-8x!", "New-Password-9y!"
IP = "192.0.2.44"


@pytest.fixture
def db(monkeypatch):
    """A database with every table of the model; what is not the database stands still."""
    from _kept_db import kept_database
    monkeypatch.setattr(api, "_force_close_after_commit", lambda *a, **k: None)
    monkeypatch.setattr(sign_in, "_record", lambda *a, **k: None)
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def _user(db, name, role=RoleEnum.USER):
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password(OLD), role=role,
                is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _elsewhere(db, statement, **values):
    """What another transaction did and committed, on a connection of its own."""
    other = sessionmaker(bind=db.get_bind())()
    try:
        found = other.execute(sa.text(statement), values)
        rows = found.fetchall() if found.returns_rows else None
        other.commit()
        return rows
    finally:
        other.close()


def _count(db, user) -> int:
    return _elsewhere(db, "SELECT sessions_ended FROM users WHERE id = :id", id=user.id.hex)[0][0]


def _rows(db, table, user) -> int:
    return _elsewhere(db, f"SELECT count(*) FROM {table} WHERE user_id = :id", id=user.id.hex)[0][0]


def test_ending_an_accounts_sessions_counts_on_the_account(db):
    alice, bob = _user(db, "alice"), _user(db, "bob")
    assert (_count(db, alice), _count(db, bob)) == (0, 0)
    api._revoke_sessions(db, user_id=alice.id)
    db.commit()
    api._revoke_sessions(db, user_id=alice.id, except_session_token="the-callers-own")
    db.commit()
    assert (_count(db, alice), _count(db, bob)) == (2, 0)
    # Not the account's sessions as a whole: a temporary credential's alone, and a cut of live transports that
    # leaves the web sessions standing.
    api._revoke_sessions(db, temp_credential_id=uuid.uuid4())
    api._revoke_sessions(db, user_id=alice.id, durable=False)
    db.commit()
    assert _count(db, alice) == 2


@pytest.mark.parametrize("written", ["a session", "a held sign-in"])
def test_a_sign_in_read_before_the_accounts_sessions_were_ended_writes_nothing(db, monkeypatch, written):
    """Mallory's sign-in read Alice's account, then waited for the account's turn while an administrator's new
    password ended her sessions. It reads the account again in the turn, finds the count moved, and writes
    neither a session nor a held sign-in. With nothing ended meanwhile it writes."""
    alice = _user(db, "alice")
    write = (sign_in.complete_sign_in if written == "a session"
             else lambda db_, result: sign_in.begin_pending(db_, result, sign_in.STAGE_SECOND_FACTOR))
    table = "active_sessions" if written == "a session" else "pending_logins"
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(alice))
    turns = []

    def a_change_held_the_turn_first(db_, user_id):
        turns.append((user_id, _rows(db, table, alice)))
        _elsewhere(db, "UPDATE users SET sessions_ended = sessions_ended + 1 WHERE id = :id", id=alice.id.hex)
    monkeypatch.setattr(api, "_sessions_turn", a_change_held_the_turn_first)
    with pytest.raises(HTTPException) as refused:
        write(db, result)
    assert (refused.value.status_code, refused.value.detail) == (401, sign_in.EXPIRED)
    assert turns == [(alice.id, 0)], "the turn is taken before anything is written"
    db.rollback()
    assert _rows(db, table, alice) == 0
    # Nothing ended since this one was read: it is written.
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: turns.append((user_id, "quiet")))
    again = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=_count(db, alice))
    write(db, again)
    assert _rows(db, table, alice) == 1 and turns[-1] == (alice.id, "quiet")


def test_a_sign_in_that_does_not_say_what_it_read_is_taken_as_read_where_it_was_made(db):
    alice = _user(db, "alice")
    assert sign_in.SignInResult(alice, [sign_in.PASSWORD], IP).sessions_ended == 0
    api._revoke_sessions(db, user_id=alice.id)
    db.commit()
    assert sign_in.SignInResult(alice, [sign_in.PASSWORD], IP).sessions_ended == 1
    assert sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=0).sessions_ended == 0


def test_a_held_sign_in_carries_what_its_first_proof_read_and_one_that_carries_nothing_starts_again(db):
    alice = _user(db, "alice")
    api._revoke_sessions(db, user_id=alice.id)
    db.commit()
    step = sign_in.begin_pending(db, sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=1),
                                 sign_in.STAGE_SECOND_FACTOR)
    claims = verify_access_token(step.body["pre_auth_token"])
    assert claims["ended"] == 1
    held = db.query(PendingLogin).filter(PendingLogin.id == uuid.UUID(claims["pre_auth"])).one()
    sign_in.read_pre_auth(claims, held)
    assert sign_in.ended_of(held) == 1
    # A token from before the count was kept, or one that says something else than a number: no account matches.
    for said in ({}, {"ended": "1"}, {"ended": True}, {"ended": None}):
        sign_in.read_pre_auth({**{k: v for k, v in claims.items() if k != "ended"}, **said}, held)
        assert sign_in.ended_of(held) == -1
        with pytest.raises(HTTPException) as refused:
            sign_in.complete_sign_in(db, sign_in.SignInResult(alice, [sign_in.PASSWORD, sign_in.TOTP], IP,
                                                               pending=held, sessions_ended=sign_in.ended_of(held)))
        assert (refused.value.status_code, refused.value.detail) == (401, sign_in.EXPIRED)
        db.rollback()
    assert _rows(db, "active_sessions", alice) == 0
    assert _elsewhere(db, "SELECT consumed_at FROM pending_logins WHERE id = :id", id=held.id.hex)[0][0] is None
    # The held sign-in as its token reads: completed, with a session.
    sign_in.read_pre_auth(claims, held)
    sign_in.complete_sign_in(db, sign_in.SignInResult(alice, [sign_in.PASSWORD, sign_in.TOTP], IP, pending=held,
                                                      sessions_ended=sign_in.ended_of(held)))
    assert _rows(db, "active_sessions", alice) == 1


def test_the_completion_spends_the_held_sign_in_and_writes_the_session_in_one_commit(db):
    """Committed apart, a change that fell between the two found no held sign-in to spend and no session to end.
    At every commit the held sign-in is spent exactly when the session is there."""
    alice = _user(db, "alice")
    step = sign_in.begin_pending(db, sign_in.SignInResult(alice, [sign_in.PASSWORD], IP), sign_in.STAGE_SECOND_FACTOR)
    claims = verify_access_token(step.body["pre_auth_token"])
    held = db.query(PendingLogin).filter(PendingLogin.id == uuid.UUID(claims["pre_auth"])).one()
    sign_in.read_pre_auth(claims, held)
    seen = []

    @sa.event.listens_for(db, "after_commit")
    def _state(_session):
        spent = _elsewhere(db, "SELECT consumed_at FROM pending_logins WHERE id = :id", id=held.id.hex)[0][0]
        seen.append((spent is not None, _rows(db, "active_sessions", alice)))
    sign_in.complete_sign_in(db, sign_in.SignInResult(alice, [sign_in.PASSWORD, sign_in.TOTP], IP, pending=held,
                                                      sessions_ended=sign_in.ended_of(held)))
    assert seen == [(True, 1)]


def test_a_held_sign_in_that_goes_on_to_another_step_is_spent_with_the_next_one_written(db):
    alice = _user(db, "alice")
    first = sign_in.begin_pending(db, sign_in.SignInResult(alice, [sign_in.HARDWARE_KEY], IP), sign_in.STAGE_PASSWORD)
    claims = verify_access_token(first.body["pre_auth_token"])
    held = db.query(PendingLogin).filter(PendingLogin.id == uuid.UUID(claims["pre_auth"])).one()
    sign_in.read_pre_auth(claims, held)
    seen = []

    @sa.event.listens_for(db, "after_commit")
    def _state(_session):
        rows = _elsewhere(db, "SELECT consumed_at FROM pending_logins WHERE user_id = :id", id=alice.id.hex)
        seen.append(sorted(spent is not None for (spent,) in rows))
    sign_in.begin_pending(db, sign_in.SignInResult(alice, [sign_in.HARDWARE_KEY, sign_in.PASSWORD], IP, pending=held,
                                                   sessions_ended=sign_in.ended_of(held)), sign_in.STAGE_SECOND_FACTOR)
    assert seen == [[False, True]]


# ------------------------------------------------------------------------------------------------- the password door

@pytest.fixture
def door(db, monkeypatch):
    monkeypatch.setattr(auth_mod.AuthService, "_check_rate_limit", lambda self, *a, **k: None, raising=False)
    monkeypatch.setattr(auth_mod.AuthService, "_give_back", lambda self, *a, **k: None, raising=False)
    return auth_mod.AuthService(db)


def test_the_password_door_takes_the_sessions_turn_after_its_own_and_reads_the_account_again(db, door, monkeypatch):
    """An attempt loads the account, then waits for its turn. A new password set meanwhile is the one it checks:
    the old one is wrong now, however long the attempt waited."""
    alice = _user(db, "alice")
    order = []
    monkeypatch.setattr(sign_in_lockout, "take_turn", lambda db_, user_id: order.append("the turn at signing in"))

    def the_password_changed_meanwhile(db_, user_id, busy=False):
        order.append(("the turn at its sessions", busy))
        _elsewhere(db, "UPDATE users SET password_hash = :new WHERE id = :id", new=hash_password(NEW), id=alice.id.hex)
    monkeypatch.setattr(sign_in_lockout, "take_sessions_turn", the_password_changed_meanwhile)
    with pytest.raises(auth_mod.InvalidCredentialsError):
        door.authenticate_user("alice", OLD, IP)
    assert order == ["the turn at signing in", ("the turn at its sessions", True)]
    assert _rows(db, "active_sessions", alice) == 0
    user, token = door.authenticate_user("alice", NEW, IP)
    assert user.id == alice.id and token and _rows(db, "active_sessions", alice) == 1


def test_the_password_door_notes_what_it_read_and_ends_the_earlier_session_with_its_own(db, door):
    alice = _user(db, "alice")
    api._revoke_sessions(db, user_id=alice.id)
    db.commit()
    door.authenticate_user("alice", OLD, IP)
    assert door.sessions_ended_as_read == 1
    seen, alice_id = [], alice.id.hex

    @sa.event.listens_for(db, "after_commit")
    def _state(_session):
        seen.append(tuple(sorted(bool(active) for (active,) in _elsewhere(
            db, "SELECT is_active FROM active_sessions WHERE user_id = :id", id=alice_id))))
    door.authenticate_user("alice", OLD, IP)
    # One web session at a time: the earlier one is marked ended in the commit that brings the new one, never
    # before it (a commit before would let the turns go with the new session not yet written).
    assert seen and all(state == (False, True) for state in seen), seen


def test_a_busy_turn_at_its_sessions_refuses_the_attempt_as_busy(db, door, monkeypatch):
    _user(db, "alice")

    def busy(db_, user_id, busy=False):
        raise sign_in_lockout.Busy()
    monkeypatch.setattr(sign_in_lockout, "take_sessions_turn", busy)
    with pytest.raises(auth_mod.RateLimitExceededError) as refused:
        door.authenticate_user("alice", OLD, IP)
    assert refused.value.retry_after == sign_in_lockout.BUSY_RETRY_SECONDS


# ------------------------------------------------------------------------------------------------- the order

def test_a_credential_change_takes_the_accounts_turn_before_its_row(db, monkeypatch):
    """cc.decide locks the account's row. A sign-in writes in the account's turn and then needs that row, so the
    change takes the turn first: taken after the row, the two waited for each other."""
    from app.core import auditor_rights, legal_holds
    monkeypatch.setattr(auditor_rights, "after_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(legal_holds, "after_starter_change", lambda *a, **k: None)
    ada, alice = _user(db, "ada", RoleEnum.ADMIN), _user(db, "alice")
    order, decide = [], cc.decide
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: order.append(("turn", user_id)))
    monkeypatch.setattr(cc, "decide", lambda db_, **kw: order.append(("row", kw["target_id"])) or decide(db_, **kw))
    api._credential_change(db, ada, alice, cc.PASSWORD, summary="a new password",
                           payload={"password_hash": hash_password(NEW)})
    db.commit()
    assert order[:2] == [("turn", alice.id), ("row", alice.id)], order


def test_the_locks_on_an_accounts_row_leave_its_key_free():
    """A row that names the account (a session, a held sign-in, an audit row) is written by a sign-in in its turn.
    It waits for a lock that holds the row's key, and for none that leaves it free."""
    for path, function in (("app/core/credential_changes.py", "_lock_account"),
                           ("app/core/last_admin.py", "removes_last_admin")):
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        (node,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function]
        locks = [n for n in ast.walk(node) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "with_for_update"]
        assert len(locks) == 1, (path, function)
        assert [(k.arg, getattr(k.value, "value", None)) for k in locks[0].keywords] == [("key_share", True)]


def test_the_last_administrator_guard_takes_the_accounts_turn_before_any_row(db, monkeypatch):
    from app.core import last_admin
    ada, bea = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bea", RoleEnum.ADMIN)
    ada_id, order = ada.id, []
    assert bea.id != ada_id
    monkeypatch.setattr(sign_in_lockout, "take_sessions_turn",
                        lambda db_, user_id, busy=False: order.append(("turn", user_id)))

    @sa.event.listens_for(db.get_bind(), "before_cursor_execute")
    def _statement(conn, cursor, statement, parameters, context, executemany):
        if "FROM users" in statement and "users.role" in statement:
            order.append(("the administrators' rows", None))
    try:
        assert last_admin.removes_last_admin(db, ada) is False
    finally:
        sa.event.remove(db.get_bind(), "before_cursor_execute", _statement)
    assert order == [("turn", ada_id), ("the administrators' rows", None)]


def test_every_sign_in_the_application_builds_says_what_its_first_proof_read():
    """A door that builds a sign-in without the count would be compared with the account as it stands when the
    sign-in is built, after its checks: a change that fell in between would pass. Every door says it."""
    missing = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) == "SignInResult":
                said = {k.arg for k in node.keywords}
                if "sessions_ended" not in said and "is_temporary" not in said:
                    missing.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
    assert missing == [], missing
