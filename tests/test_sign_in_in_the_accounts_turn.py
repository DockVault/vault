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


@pytest.mark.parametrize("written", ["a session", "a held sign-in"])
def test_a_sign_in_is_not_written_for_an_account_turned_off_while_it_waited_for_its_turn(db, monkeypatch, written):
    """The account's state is judged again in the turn, on the account as it is committed, whatever the count
    says. An account turned off by something that ended no session of it (it had none to end, so nothing was
    counted) is refused where the sign-in is written, as it would be at the door."""
    alice = _user(db, "alice")
    write = (sign_in.complete_sign_in if written == "a session"
             else lambda db_, result: sign_in.begin_pending(db_, result, sign_in.STAGE_SECOND_FACTOR))
    table = "active_sessions" if written == "a session" else "pending_logins"
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(alice))
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: _elsewhere(
        db, "UPDATE users SET is_active = 0 WHERE id = :id", id=alice.id.hex))
    with pytest.raises(HTTPException) as refused:
        write(db, result)
    assert (refused.value.status_code, refused.value.detail) == (401, "Invalid username or password")
    db.rollback()
    assert _rows(db, table, alice) == 0 and _count(db, alice) == 0


def test_the_end_of_an_accounts_sessions_is_counted_in_the_accounts_turn(db, monkeypatch):
    """The count is added to under the turn, so the count a sign-in compares with in its own turn is one nobody
    is changing: the turn first, then the count."""
    alice = _user(db, "alice")
    alice_id, order = alice.id, []
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: order.append(("turn", user_id)))

    @sa.event.listens_for(db.get_bind(), "before_cursor_execute")
    def _statement(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE USERS") and "sessions_ended" in statement:
            order.append(("counted", None))
    try:
        api._revoke_sessions(db, user_id=alice_id)
        db.commit()
    finally:
        sa.event.remove(db.get_bind(), "before_cursor_execute", _statement)
    assert order == [("turn", alice_id), ("counted", None)], order


@pytest.mark.parametrize("written", ["a session", "a held sign-in"])
def test_a_turn_held_too_long_refuses_the_sign_in_as_busy_and_leaves_no_session(db, monkeypatch, written):
    """Something holds the account's turn for longer than the connection waits (a change that settles many
    accounts in one transaction). The sign-in is refused as busy, with a time to come back, and writes nothing;
    the session the password door made for it, in a commit of its own, is deleted with it."""
    from sqlalchemy.exc import OperationalError
    from app.services.auth_service import AuthService
    alice = _user(db, "alice")
    write = (sign_in.complete_sign_in if written == "a session"
             else lambda db_, result: sign_in.begin_pending(db_, result, sign_in.STAGE_SECOND_FACTOR))
    made = AuthService(db)._create_session(alice, None, IP, channel="web")
    assert _rows(db, "active_sessions", alice) == 1

    class _Held(Exception):
        pgcode = "55P03"

    class _Other(Exception):
        pgcode = "40001"

    def held(error):
        def turn(db_, user_id):
            raise OperationalError("SELECT pg_advisory_xact_lock", {}, error)
        return turn
    monkeypatch.setattr(api, "_sessions_turn", held(_Held()))
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, session_token=made,
                                  sessions_ended=sign_in.as_read(alice))
    with pytest.raises(HTTPException) as busy:
        write(db, result)
    assert (busy.value.status_code, busy.value.detail) == (503, sign_in.BUSY)
    assert busy.value.headers == {"Retry-After": str(sign_in_lockout.BUSY_RETRY_SECONDS)}
    assert result.session_token is None
    assert _rows(db, "active_sessions", alice) == 0 and _rows(db, "pending_logins", alice) == 0
    # Another failure of the database is its own: not a busy turn.
    monkeypatch.setattr(api, "_sessions_turn", held(_Other()))
    with pytest.raises(OperationalError):
        write(db, sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(alice)))


def test_a_sign_in_from_before_a_change_leaves_no_session_of_its_proof(db, monkeypatch):
    """The password door writes its session in its own turn and commits it. Where the sign-in then finds, in the
    turn it writes in, that the account's sessions were ended since, that session is deleted with the sign-in."""
    from app.services.auth_service import AuthService
    alice = _user(db, "alice")
    made = AuthService(db)._create_session(alice, None, IP, channel="web")
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, session_token=made,
                                  sessions_ended=sign_in.as_read(alice))
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: _elsewhere(
        db, "UPDATE users SET sessions_ended = sessions_ended + 1 WHERE id = :id", id=alice.id.hex))
    with pytest.raises(HTTPException) as refused:
        sign_in.begin_pending(db, result, sign_in.STAGE_SECOND_FACTOR)
    assert (refused.value.status_code, refused.value.detail) == (401, sign_in.EXPIRED)
    assert result.session_token is None
    assert _rows(db, "active_sessions", alice) == 0 and _rows(db, "pending_logins", alice) == 0


def test_a_sign_in_for_an_account_deleted_while_it_waited_is_refused_and_not_an_error(db, monkeypatch):
    alice = _user(db, "alice")
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(alice))
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: _elsewhere(
        db, "DELETE FROM users WHERE id = :id", id=alice.id.hex))
    with pytest.raises(HTTPException) as refused:
        sign_in.complete_sign_in(db, result)
    assert (refused.value.status_code, refused.value.detail) == (401, sign_in.EXPIRED)


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


def test_an_approval_takes_the_accounts_turn_then_its_row_then_the_request(db, monkeypatch):
    """A held request is decided under the same order as a change made at once: the account's turn at its sessions,
    its row, then the request's row. The request names the account, which is read first without a lock."""
    from app.core.models import CredentialChange
    ada, alice = _user(db, "ada", RoleEnum.ADMIN), _user(db, "alice")
    held = CredentialChange(target_user_id=alice.id, requested_by_id=ada.id, requested_by_name=ada.username,
                            kind=cc.PASSWORD, status=cc.HELD, requested_at=cc.utcnow(),
                            expires_at=cc.utcnow() + timedelta(days=7))
    db.add(held)
    db.commit()
    held_id, alice_id = held.id, alice.id          # read now: a read after the commit is a statement of its own
    order, lock_account = [], cc._lock_account
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: order.append(("turn", user_id)))
    monkeypatch.setattr(cc, "_lock_account", lambda db_, user_id: order.append(("row", user_id)) or lock_account(db_, user_id))

    @sa.event.listens_for(db.get_bind(), "before_cursor_execute")
    def _statement(conn, cursor, statement, parameters, context, executemany):
        if "FROM credential_changes" in statement and "credential_changes.status" in statement:
            order.append(("the request", None))
    try:
        change, target = api._open_credential_request(db, held_id)
    finally:
        sa.event.remove(db.get_bind(), "before_cursor_execute", _statement)
    assert order == [("turn", alice_id), ("row", alice_id), ("the request", None)], order
    assert change.id == held_id and target.id == alice_id
    # A request that is not there names no account: no turn, and the answer it always had.
    del order[:]
    with pytest.raises(HTTPException) as gone:
        api._open_credential_request(db, uuid.uuid4())
    assert gone.value.status_code == 404 and order == []


def test_a_reset_link_takes_the_accounts_turn_before_the_rows_it_locks():
    """The reset ends the account's sessions, in the account's turn, and judges the link under a lock on the
    account's row and its maker's. The turn comes first, as everywhere: read from the route as it is written,
    since the route's limiter and its token are the server's."""
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    (route,) = [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "do_reset"]
    calls = [(n.lineno, ast.unparse(n)) for n in ast.walk(route) if isinstance(n, ast.Call)]
    turns = [line for line, text in calls if text == "_sessions_turn(db, user.id)"]
    locked = [line for line, text in calls if text == "_reset_link_refusal(db, r, user, lock=True)"]
    ends = [line for line, text in calls if text.startswith("_revoke_sessions(")]
    assert len(turns) == 1 and len(locked) == 1 and ends, (turns, locked, ends)
    assert turns[0] < locked[0] < min(ends)
    # Nothing between the turn and the commit locks a row before the turn: the only locking read is the link's.
    before = [text for line, text in calls if line < turns[0] and "with_for_update" in text]
    assert before == [], before


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


def test_a_deletion_takes_the_accounts_turn_after_the_vault_rows_and_before_the_account_goes():
    """The order inside the deletion: the vault rows it locks, the account's turn at its sessions, the
    administrators' rows, the withdrawal of the account's requests, the row itself. (The meeting with a sign-in
    that is being written is forced on PostgreSQL in tests/test_sign_in_lock_order_live.py.)"""
    import inspect
    from app.api import api_server as api
    source = inspect.getsource(api.delete_user)
    steps = ("record_rotations_owed_by(db, user.id)", "_sessions_turn(db, user.id)", "removes_last_admin(db, user)",
             "_account_lost_standing(db, user", "db.delete(user)")
    assert all(source.count(step) == 1 for step in steps), [(step, source.count(step)) for step in steps]
    order = [source.index(step) for step in steps]
    assert order == sorted(order), order


def test_a_promotion_takes_the_accounts_turn_before_it_reads_or_writes_the_account(monkeypatch):
    """Recording the grant flushes what the caller changed on the account, which locks its row, and the take-back
    that follows takes the account's turn: the turn comes first, also for a promotion that is then refused.
    (The meeting with a sign-in is forced on PostgreSQL in tests/test_sign_in_lock_order_live.py.)"""
    import types
    import uuid
    from fastapi import HTTPException
    from app.api import api_server as api
    from app.core import admin_grants, auditor_rights
    order, answer = [], [None]
    monkeypatch.setattr(api, "_sessions_turn", lambda db, user_id: order.append(("the turn", user_id)))
    monkeypatch.setattr(auditor_rights, "promotion_refusal", lambda db, user: order.append("asked") or answer[0])
    monkeypatch.setattr(admin_grants, "record", lambda db, user_id, **kw: order.append("recorded"))
    monkeypatch.setattr(api, "_revoke_reset_links_outranked_by", lambda db, user, actor: order.append("links"))
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice")
    api._record_admin_grant(types.SimpleNamespace(), alice, by=None)
    assert order == [("the turn", alice.id), "asked", "recorded", "links"]
    del order[:]
    answer[0] = "the account holds the auditor right"
    with pytest.raises(HTTPException) as refused:
        api._record_admin_grant(types.SimpleNamespace(), alice, by=None)
    assert refused.value.status_code == 409 and order == [("the turn", alice.id), "asked"]


def test_a_change_of_somebody_elses_account_takes_that_accounts_turn_before_it_touches_the_row():
    """Inside the request that changes an account: the vault rows a deactivation locks come first, then the
    account's turn (for somebody else's account), then the administrators' rows, then every field. A request
    that changes the caller's own account takes none here."""
    import inspect
    from app.api import api_server as api
    source = inspect.getsource(api.update_user)
    steps = ("n_bl = _blacklist_user_vault_keys(db, user.id, current_user.id)",
             "    if not is_self:\n        _sessions_turn(db, user.id)",
             "if removes_last_admin(db, user):", "outcome = _credential_change(",
             "user.sftp_enabled = user_update.sftp_enabled", "_record_admin_grant(db, user, by=current_user)",
             "user.is_active = user_update.is_active")
    assert all(step in source for step in steps), [step for step in steps if step not in source]
    order = [source.index(step) for step in steps]
    assert order == sorted(order), order
    assert source.count("_sessions_turn(db, user.id)") == 1


def test_a_sign_in_waits_a_short_time_for_its_turn_and_the_transaction_gets_its_own_wait_back(monkeypatch):
    """Where a sign-in is written it runs on the server's one loop: the wait for the account's turn is bounded
    for that one statement, and the transaction's own wait is put back for what follows: the one it had (read
    before), whatever it was, not the connection's usual one. Elsewhere than on PostgreSQL nothing is set (there
    is no such wait there)."""
    import types
    import uuid
    from app.api import api_server as api
    from app.core import database
    from app.services import sign_in

    class Session:
        def __init__(self, dialect):
            self.said, self.dialect = [], dialect

        def get_bind(self):
            return types.SimpleNamespace(dialect=types.SimpleNamespace(name=self.dialect))

        def execute(self, statement, params=None):
            self.said.append(str(statement) if params is None else (str(statement), dict(params)))
            return types.SimpleNamespace(scalar=lambda: self.own)

    assert sign_in.WRITE_WAIT_MS == 500 < database._LOCK_TIMEOUT_MS
    alice = uuid.uuid4()
    monkeypatch.setattr(api, "_sessions_turn", lambda db, user_id: db.said.append(("the turn", user_id)))
    for own in ("5s", "7s", "0"):                    # the connection's usual wait, a longer one, none at all
        pg = Session("postgresql")
        pg.own = own
        assert sign_in.with_a_short_wait(pg, lambda: api._sessions_turn(pg, alice) or "taken") == "taken"
        assert pg.said == ["SELECT current_setting('lock_timeout')",
                           ("SELECT set_config('lock_timeout', :wait, true)", {"wait": "500ms"}),
                           ("the turn", alice),
                           ("SELECT set_config('lock_timeout', :own, true)", {"own": own})], own
    other = Session("sqlite")
    sign_in.with_a_short_wait(other, lambda: api._sessions_turn(other, alice))
    assert other.said == [("the turn", alice)]
    # The writer takes its turn through it, and nothing else.
    import inspect
    source = inspect.getsource(sign_in.in_the_accounts_turn)
    assert "with_a_short_wait(db, lambda: api._sessions_turn(db, user.id))" in source
    assert source.count("_sessions_turn(") == 1


@pytest.mark.parametrize("route, first", [
    ("update_user", "_blacklist_user_vault_keys(db, user.id, current_user.id)"),
    ("toggle_user_active", "_blacklist_user_vault_keys(db, user.id, current_user.id)"),
    ("toggle_user_locked", 'raise HTTPException(status_code=400, detail="Cannot lock your own account")')])
def test_the_other_routes_that_lock_or_turn_off_an_account_take_its_turn_before_its_rows(route, first):
    """PUT /api/user-management/users/{id} and the two switches: the vault rows a deactivation locks come first,
    then the account's turn, then the administrators' rows, then the rows that go with the account's standing (its
    auditor right, its open requests), then the ending of its sessions. Taken where the sessions are ended, the
    turn came after those rows, and a request from the Users page, which takes the turn first, waited for them."""
    import inspect
    from app.api import user_management_api as um
    source = inspect.getsource(getattr(um, route))
    steps = (first, "_sessions_turn(db, user.id)", "removes_last_admin(db, user)",
             "_account_lost_standing(db, user, actor=current_user, because=", "_revoke_sessions(db, user_id=user.id")
    assert all(step in source for step in steps), [step for step in steps if step not in source]
    order = [source.index(step) for step in steps]
    assert order == sorted(order), order
    assert source.count("_sessions_turn(db, user.id)") == 1
    # Not for the caller's own account in the route that may be called for it (it changes nothing of its standing).
    if route == "update_user":
        assert "    if current_user.id != user_id:\n        from app.api.api_server import _sessions_turn\n" \
               "        _sessions_turn(db, user.id)" in source


def test_the_order_of_the_locks_names_the_rows_of_an_auditor_right_after_the_turn():
    from pathlib import Path
    from app.services import sign_in
    text = Path(sign_in.__file__).read_text(encoding="utf-8")
    table = text[text.index("# The order of the locks."):text.index("# Any of them may be skipped")]
    assert table.index("3. the account's turn at its sessions") < table.index("4. the account's row") \
        < table.index("5. a row of credential_changes or of auditor_grants")


def test_an_account_that_loses_its_standing_has_its_row_locked_before_the_rows_of_its_standing():
    """The order of the locks puts the account's row before a row of its requests or of its auditor right. Where
    an account is locked, turned off, demoted or deleted, those rows are locked first by what withdraws and
    suspends them, and the account's row was written only after: the row is taken first now, with its key free."""
    import inspect
    from app.api import api_server as api
    source = inspect.getsource(api._account_lost_standing)
    steps = ("db.query(User.id).filter(User.id == user.id).with_for_update(key_share=True).first()",
             "_withdraw_requests_of(db, user, actor=actor, because=because)",
             "auditor_rights.after_lost_standing(db, user, actor=actor, because=because)")
    assert all(step in source for step in steps), [step for step in steps if step not in source]
    order = [source.index(step) for step in steps]
    assert order == sorted(order), order
    # As the recorder of the order reads it: the turn, the row, a row of the auditor right, the row again.
    from _lock_order_recorder import ACCOUNT_ROW, CHANGE_ROW, SESSIONS_TURN, Held
    held = Held()
    for kind, key in ((SESSIONS_TURN, "a"), (ACCOUNT_ROW, "a"), (CHANGE_ROW, "*"), (ACCOUNT_ROW, "a")):
        assert held.take(kind, key) == [], (kind, key)
    late = Held()
    for kind, key in ((SESSIONS_TURN, "a"), (CHANGE_ROW, "*")):
        assert late.take(kind, key) == []
    assert late.take(ACCOUNT_ROW, "a") != [], "the row taken only after a row of the auditor right is out of order"


@pytest.mark.parametrize("refused", ["turned off while it waited", "locked before it was judged",
                                     "its held sign-in already spent", "a later step"])
def test_a_refused_sign_in_leaves_no_session_of_its_proof_whatever_refused_it(db, monkeypatch, refused):
    """The password door commits its session before the pipeline judges the sign-in. Only a sign-in from before a
    change, and one that found its turn busy, took that session with them: refused for anything else, the
    sign-in got no token and its session stayed among the account's, of no use to anyone. Every refusal drops
    it, and what the refused sign-in had written and not committed goes with it."""
    import types
    from app.services.auth_service import AuthService
    alice = _user(db, "alice")
    made = AuthService(db)._create_session(alice, None, IP, channel="web")
    assert _rows(db, "active_sessions", alice) == 1
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, session_token=made,
                                  sessions_ended=sign_in.as_read(alice))
    monkeypatch.setattr(api, "_login_second_factor_in_effect", lambda db_, user: False)
    monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: None)
    expected = 401
    if refused == "turned off while it waited":
        monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: _elsewhere(
            db, "UPDATE users SET is_active = 0 WHERE id = :id", id=alice.id.hex))
    elif refused == "locked before it was judged":
        alice.is_locked = True                         # an administrator's lock, committed after the door's check
        db.commit()
        expected = 403
    elif refused == "its held sign-in already spent":
        result.pending = types.SimpleNamespace(id=uuid.uuid4())
    else:
        def a_step_that_writes_and_then_refuses(db_, pending, commit=True):
            db_.execute(sa.text("UPDATE users SET sessions_ended = sessions_ended + 5 WHERE id = :id"),
                        {"id": alice.id.hex})
            raise HTTPException(status_code=403, detail="refused by a later step")
        result.pending = types.SimpleNamespace(id=uuid.uuid4())
        monkeypatch.setattr(sign_in, "consume_pending", a_step_that_writes_and_then_refuses)
        expected = 403
    with pytest.raises(HTTPException) as answer:
        sign_in.finish(db, result)
    assert answer.value.status_code == expected, answer.value.detail
    assert result.session_token is None
    db.rollback()
    assert _rows(db, "active_sessions", alice) == 0 and _rows(db, "pending_logins", alice) == 0
    # What the refused sign-in wrote and did not commit was not kept by the drop's commit.
    assert _count(db, alice) == 0


def test_a_refusal_with_no_session_of_a_proof_touches_nothing(db, monkeypatch):
    """A sign-in whose proof made no session (a code after a held sign-in, a passkey) is refused as it was: the
    transaction is left to the caller, nothing is rolled back and nothing committed here."""
    alice = _user(db, "alice")
    alice.is_locked = True
    db.commit()
    ended = []
    monkeypatch.setattr(db, "rollback", lambda: ended.append("rollback"))
    monkeypatch.setattr(db, "commit", lambda: ended.append("commit"))
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(alice))
    for step in (sign_in.finish, sign_in.in_the_accounts_turn):
        monkeypatch.setattr(api, "_sessions_turn", lambda db_, user_id: None)
        with pytest.raises(HTTPException) as answer:
            step(db, result)
        assert answer.value.status_code == 403 and ended == [], step
    # Both steps are guarded, and each is still read as itself (its name, its words, its source).
    for step in (sign_in.finish, sign_in.in_the_accounts_turn):
        assert step.__wrapped__.__name__ == step.__name__ and step.__doc__
    import inspect
    assert inspect.getsource(sign_in.finish).startswith("@a_refusal_leaves_no_session\ndef finish(")
    assert inspect.getsource(sign_in.in_the_accounts_turn).startswith(
        "@a_refusal_leaves_no_session\ndef in_the_accounts_turn(")


def test_what_is_not_a_refusal_is_not_taken_for_one(db, monkeypatch):
    """An error that is no refusal (the database's, a bug's) passes as it is: the guard drops a session only for
    an answer the pipeline gave."""
    from app.services.auth_service import AuthService
    alice = _user(db, "alice")
    made = AuthService(db)._create_session(alice, None, IP, channel="web")
    result = sign_in.SignInResult(alice, [sign_in.PASSWORD], IP, session_token=made,
                                  sessions_ended=sign_in.as_read(alice))

    def broken(db_, user, client_ip):
        raise RuntimeError("not a refusal")
    monkeypatch.setattr(sign_in, "refuse_unless_the_account_may_sign_in", broken)
    with pytest.raises(RuntimeError):
        sign_in.finish(db, result)
    assert result.session_token == made and _rows(db, "active_sessions", alice) == 1
