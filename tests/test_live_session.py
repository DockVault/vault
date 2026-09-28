"""The larger request bodies go only to a session that is signed in right now.

app.core.live_session decides it, before the route runs, for the request-body limit. A token's
signature and expiry were all that was checked, so a logged-out or revoked session, a deactivated or
administrator-locked account and a switched-off or expired temporary credential could all send a
48 MiB multipart body (spooled to /tmp, which is memory in the shipped compose files) or an 8 MiB JSON
one before the route refused them. These hold the check to get_current_user's, case by case, against
the real tables in a throwaway SQLite database, and cover the cache that keeps an upload burst to one
lookup. tests/test_body_limit.py covers how the limit uses the answer; tests/test_request_body_limit_live.py
the deployed stack.
"""
import secrets
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import live_session as ls  # noqa: E402
from app.core.models import ActiveSession, RoleEnum, TemporaryCredential, User  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
from app.core.session_hash_utils import hash_session_token  # noqa: E402

pytestmark = pytest.mark.unit


def _naive(dt):
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


NOW = datetime.now(timezone.utc)


@pytest.fixture
def db(monkeypatch):
    denylisted = set()
    monkeypatch.setattr("app.services.auth_service.is_token_denylisted", lambda t: t in denylisted)
    monkeypatch.setattr("app.core.temp_scope.attach_scope", lambda db, user, cred: None)
    with tempfile.TemporaryDirectory() as tmp:
        # The check runs in a worker thread when the application asks it (see the last test).
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'sessions.db'}",
                                  connect_args={"check_same_thread": False})
        for table in (User.__table__, TemporaryCredential.__table__, ActiveSession.__table__):
            table.create(engine)
        s = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        s.denylisted = denylisted
        yield s
        s.close()
        engine.dispose()


# --------------------------------------------------------------------------- building each case

def _account(db, **fields):
    fields = {"is_active": True, **fields}
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=RoleEnum.USER,
             **fields)
    db.add(u)
    db.commit()
    return u


def _regular(db, user, **session):
    token = secrets.token_urlsafe(32)
    db.add(ActiveSession(session_token=hash_session_token(token), user_id=user.id, ip_address="198.51.100.7",
                         is_active=True, revoked=session.pop("revoked", False), **session))
    db.commit()
    return {"sub": str(user.id), "username": user.username, "session_token": token, "is_temporary": False}


def _temporary(db, user, session=None, **cred):
    token = secrets.token_urlsafe(32)
    fields = {"expires_at": _naive(NOW + timedelta(hours=1)), "deactivate_at": _naive(NOW + timedelta(hours=1)),
              "is_active": True}
    fields.update(cred)
    c = TemporaryCredential(id=uuid.uuid4(), user_id=user.id, temp_username=f"t_{uuid.uuid4().hex[:8]}",
                            credential_hash="x", **fields)
    db.add(c)
    db.commit()
    row = {"is_active": True, "last_activity": _naive(NOW)}
    row.update(session or {})
    db.add(ActiveSession(session_token=hash_session_token(token), user_id=user.id, temp_credential_id=c.id,
                         ip_address="198.51.100.7", revoked=False, **row))
    db.commit()
    return {"sub": str(user.id), "username": c.temp_username, "session_token": token, "is_temporary": True}, c


def _web_door_admits(db, claims):
    """What get_current_user says about the same token: True when it returns a user."""
    token = create_access_token(claims)
    try:
        run_coroutine(S.get_current_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), db))
        return True
    except HTTPException as exc:
        assert exc.status_code in (401, 403), exc.status_code
        return False


CASES = {}


def case(name):
    def register(build):
        CASES[name] = build
        return build
    return register


@case("regular session, signed in")
def _(db):
    return _regular(db, _account(db)), True


@case("regular session, row revoked (logged out, locked or deactivated earlier)")
def _(db):
    return _regular(db, _account(db), revoked=True), False


@case("regular session, row gone")
def _(db):
    user = _account(db)
    return {"sub": str(user.id), "username": user.username, "session_token": secrets.token_urlsafe(32),
            "is_temporary": False}, False


@case("regular session, token denylisted at logout")
def _(db):
    claims = _regular(db, _account(db))
    db.denylisted.add(claims["session_token"])
    return claims, False


@case("regular session, idle but not revoked")
def _(db):
    claims = _regular(db, _account(db))
    db.query(ActiveSession).update({ActiveSession.is_active: False})
    db.commit()
    return claims, True


@case("account deactivated")
def _(db):
    return _regular(db, _account(db, is_active=False)), False


@case("account locked by an administrator")
def _(db):
    return _regular(db, _account(db, is_locked=True, locked_until=None)), False


@case("account locked automatically after wrong passwords")
def _(db):
    return _regular(db, _account(db, is_locked=True, locked_until=_naive(NOW + timedelta(minutes=15)))), True


@case("account deleted")
def _(db):
    user = _account(db)
    claims = _regular(db, user)
    db.query(User).filter(User.id == user.id).delete()
    db.commit()
    return claims, False


@case("temporary credential, signed in")
def _(db):
    return _temporary(db, _account(db))[0], True


@case("temporary credential, session row inactive")
def _(db):
    return _temporary(db, _account(db), session={"is_active": False})[0], False


@case("temporary credential, idle past the grace")
def _(db):
    return _temporary(db, _account(db), session={"last_activity": _naive(NOW - timedelta(minutes=66))})[0], False


@case("temporary credential, switched off")
def _(db):
    return _temporary(db, _account(db), is_active=False)[0], False


@case("temporary credential, finished (its connection closed)")
def _(db):
    return _temporary(db, _account(db), slot_released_at=_naive(NOW - timedelta(minutes=1)))[0], False


@case("temporary credential, past deactivate_at")
def _(db):
    return _temporary(db, _account(db), deactivate_at=_naive(NOW - timedelta(minutes=1)))[0], False


@case("temporary credential, past expires_at")
def _(db):
    return _temporary(db, _account(db), expires_at=_naive(NOW - timedelta(minutes=1)))[0], False


@case("temporary credential, row gone")
def _(db):
    claims, cred = _temporary(db, _account(db))
    db.execute(sa.text("DELETE FROM temporary_credentials"))   # SQLite does not cascade here
    db.commit()
    return claims, False


@case("temporary credential, token denylisted")
def _(db):
    claims = _temporary(db, _account(db))[0]
    db.denylisted.add(claims["session_token"])
    return claims, False


@case("temporary credential of a deactivated account")
def _(db):
    return _temporary(db, _account(db, is_active=False))[0], False


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_check_agrees_with_get_current_user(db, name):
    claims, expected = CASES[name](db)
    assert ls.session_is_live(db, claims) is expected, name
    assert _web_door_admits(db, claims) is expected, f"the case no longer says what get_current_user does: {name}"


def test_the_cases_cover_every_refusal_get_current_user_makes():
    """Each 401 and 403 get_current_user raises has a case above (a new refusal there needs one here)."""
    import inspect
    source = inspect.getsource(S.get_current_user)
    raised = source.count("raise HTTPException(")
    # Refusals: invalid token, no sub, no session_token (session_claims), denylisted, regular row
    # revoked or gone, temp row gone, temp idle, temp cred gone, temp cred off, temp cred finished,
    # temp cred past a limit, user gone, user inactive, admin lock.
    assert raised == 14, f"get_current_user now raises {raised} times; add the new case here and in live_session"


# --------------------------------------------------------------------------- the token itself

def test_only_a_signed_unexpired_session_token_has_claims():
    ok = create_access_token({"sub": "u1", "session_token": "s"})
    assert ls.session_claims(b"Bearer " + ok.encode())["session_token"] == "s"
    assert ls.session_claims(b"bearer  " + ok.encode() + b" ")
    pending = create_access_token({"sub": "u1", "stage": "second_factor", "pre_auth": "p"})
    assert ls.session_claims(b"Bearer " + pending.encode()) is None, "a second-factor token is no session"
    assert ls.session_claims(b"Bearer " + create_access_token({"sub": "u1"}).encode()) is None
    expired = create_access_token({"sub": "u1", "session_token": "s"}, expires_delta=timedelta(minutes=-5))
    assert ls.session_claims(b"Bearer " + expired.encode()) is None
    head, payload, sig = ok.split(".")
    assert ls.session_claims(f"Bearer {head}.{payload}.{sig[::-1]}".encode()) is None
    for bad in (None, b"", b"Bearer", b"Basic " + ok.encode(), b"\xff\xfe"):
        assert ls.session_claims(bad) is None


# --------------------------------------------------------------------------- caller_state and its cache

class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def fresh_answers(monkeypatch):
    clock = _Clock()
    answers = ls._Answers(seconds=5.0, max_entries=8, clock=clock)
    monkeypatch.setattr(ls, "answers", answers)
    return clock, answers


def _bearer(claims):
    return b"Bearer " + create_access_token(claims).encode()


def _state(header, ask):
    return run_coroutine(ls.caller_state(header, ask=ask))


def test_no_bearer_token_is_no_credential_and_asks_nothing(fresh_answers):
    ask = lambda claims: pytest.fail("asked the database")   # noqa: E731
    for header in (None, b"", b"Basic dXNlcjpwYXNz", b"Bearer "):
        assert _state(header, ask) == ls.NO_CREDENTIAL


def test_a_token_this_server_did_not_sign_has_ended_without_asking(fresh_answers):
    ask = lambda claims: pytest.fail("asked the database")   # noqa: E731
    assert _state(b"Bearer not-a-token", ask) == ls.ENDED
    assert _state(_bearer({"sub": "u1"}), ask) == ls.ENDED, "a token without a session"


def test_an_answer_is_cached_for_a_few_seconds_then_asked_again(fresh_answers):
    # The shipped cache: a few seconds, so an ended session keeps a larger limit no longer than that.
    assert 0 < ls.CACHE_SECONDS <= 5 and ls._Answers().seconds == ls.CACHE_SECONDS
    clock, answers = fresh_answers
    asked = []
    live = {"value": True}

    def ask(claims):
        asked.append(claims["session_token"])
        return live["value"]

    header = _bearer({"sub": "u1", "session_token": "s1"})
    assert [_state(header, ask) for _ in range(20)] == [ls.LIVE] * 20
    assert asked == ["s1"], "an upload burst asked the database more than once"
    live["value"] = False
    clock.now += 4.9
    assert _state(header, ask) == ls.LIVE and len(asked) == 1
    clock.now += 0.2
    assert _state(header, ask) == ls.ENDED and len(asked) == 2, "an ended session kept the larger limit"
    assert _state(header, ask) == ls.ENDED and len(asked) == 2, "an ended session was asked again at once"


def test_each_session_has_its_own_answer(fresh_answers):
    asked = []

    def ask(claims):
        asked.append(claims["session_token"])
        return claims["session_token"] == "live" and not claims.get("is_temporary")

    assert _state(_bearer({"sub": "u1", "session_token": "live"}), ask) == ls.LIVE
    assert _state(_bearer({"sub": "u1", "session_token": "gone"}), ask) == ls.ENDED
    assert _state(_bearer({"sub": "u1", "session_token": "live", "is_temporary": True}), ask) == ls.ENDED
    assert asked == ["live", "gone", "live"]


def test_a_database_error_is_unknown_and_never_cached(fresh_answers):
    calls = []

    def ask(claims):
        calls.append(1)
        raise RuntimeError("database unavailable")

    header = _bearer({"sub": "u1", "session_token": "s1"})
    assert _state(header, ask) == ls.UNKNOWN
    assert _state(header, ask) == ls.UNKNOWN
    assert len(calls) == 2


def test_the_cache_is_bounded_and_drops_the_oldest(fresh_answers):
    clock, answers = fresh_answers
    for i in range(20):
        answers.put(("u", str(i), False), ls.LIVE)
        clock.now += 0.01
    assert len(answers) == 8
    assert answers.get(("u", "0", False)) is None and answers.get(("u", "19", False)) == ls.LIVE
    clock.now += 10
    answers.put(("u", "new", False), ls.LIVE)
    assert len(answers) == 1, "expired answers were kept once the cache was full"


def test_the_default_asks_the_database_in_a_worker_thread(monkeypatch, fresh_answers):
    import threading
    seen = []
    loop_thread = []

    def ask_database(claims):
        seen.append(threading.current_thread().name)
        return True

    async def run(header):
        loop_thread.append(threading.current_thread().name)
        return await ls.caller_state(header)

    monkeypatch.setattr(ls, "_ask_database", ask_database)
    assert run_coroutine(run(_bearer({"sub": "u1", "session_token": "s1"}))) == ls.LIVE
    assert seen and seen[0] != loop_thread[0], "the database was asked on the event loop"


# --------------------------------------------------------------------------- through the real application

def _post_through_app(path, pieces, headers):
    """Drive the real application with a chunked POST; return (status, detail, bytes it read)."""
    queue = list(pieces)
    read = {"bytes": 0}
    out = []

    async def run():
        import asyncio

        async def receive():
            if queue:
                piece = queue.pop(0)
                read["bytes"] += len(piece)
                return {"type": "http.request", "body": piece, "more_body": bool(queue)}
            await asyncio.sleep(3600)

        async def send(message):
            out.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
                 "scheme": "http", "server": ("localhost", 80), "client": ("198.51.100.78", 1234),
                 "headers": [(b"host", b"localhost"), (b"transfer-encoding", b"chunked")] + headers}
        await S.app(scope, receive, send)

    run_coroutine(run())
    status = next(m["status"] for m in out if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in out if m["type"] == "http.response.body")
    import json
    return status, json.loads(body)["detail"], read["bytes"]


def test_the_application_refuses_an_ended_sessions_upload_before_reading_any_of_it(db, monkeypatch):
    """The measured case: 48 MiB of multipart with a token signed for a session that does not exist
    was read whole, spooled to /tmp, before the route said 401. Now nothing of it is read."""
    monkeypatch.setattr(ls, "_ask_database", lambda claims: ls.session_is_live(db, claims))
    monkeypatch.setattr(ls, "answers", ls._Answers())
    user = _account(db)
    ghost = create_access_token({"sub": str(user.id), "username": user.username,
                                 "session_token": "no-such-session", "is_temporary": False})
    head = (b'--b\r\nContent-Disposition: form-data; name="files"; filename="a.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n")
    pieces = [head] + [b"A" * (1024 * 1024)] * 48 + [b"\r\n--b--\r\n"]
    status, detail, read = _post_through_app(
        f"/vaults/{uuid.uuid4()}/files", pieces,
        [(b"content-type", b"multipart/form-data; boundary=b"), (b"authorization", b"Bearer " + ghost.encode())])
    assert (status, read) == (401, 0), (status, detail, read)
    assert "sign in" in detail
