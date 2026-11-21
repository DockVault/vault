"""A factor written in the account's turn at its sessions and what ends the account's sessions, made to meet on a
running stack's Postgres (a throwaway database of its own, tests/_throwaway_db.py): two connections, the
application's own functions, the meeting forced with events.

- A passkey stored at a held sign-in, and an authenticator made active at one, while an administrator's change is
  made at once. The change locks the account's row; taken before the turn, that lock and the turn waited for each
  other and the database ended the change. Both finish now, and the change finds what was written: a reset retires
  the key and takes the authenticator away.
- A passkey stored from a session while a second-factor reset is made: the store holds the turn, the reset waits,
  then retires the key; a store whose session the reset has ended is refused, and stores nothing.

test_passkey_written_in_the_turn.py holds the same rules offline, where the turn is stood in for.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def db_name():
    yield from throwaway_database()


SCENARIO = PREAMBLE + r'''
import threading, time, types
from app.api import api_server as api
from app.core import auditor_rights, credential_changes as cc, legal_holds, sign_in_lockout
from app.core.models import (ActiveSession, PendingLogin, RoleEnum, SecondFactorEnrollment, User,
                             WebAuthnCredential)
from app.core.security import create_access_token, hash_password
from app.services import sign_in
from app.services.auth_service import AuthService

IP = "192.0.2.44"
api._force_close_after_commit = lambda *a, **k: None
api._notify_credential_change = lambda *a, **k: None
auditor_rights.after_credential_change = lambda *a, **k: None
legal_holds.after_starter_change = lambda *a, **k: None
sign_in._record = lambda *a, **k: None


def account(name, role=RoleEnum.USER):
    with SessionLocal() as s:
        u = User(username=name + "-" + uuid.uuid4().hex[:6], email=None, password_hash=hash_password("Old-Password-8x!"),
                 role=role, is_active=True, is_locked=False)
        s.add(u)
        s.commit()
        return u.id


def key_for(s, uid):
    return WebAuthnCredential(id=uuid.uuid4(), user_id=uid, credential_id=uuid.uuid4().bytes, public_key_cose=b"k",
                              cose_alg=-7, created_at=datetime.utcnow())


def keys(uid):
    with SessionLocal() as s:
        return sorted(row.retired_at is not None for row in s.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == uid))


def state(uid):
    with SessionLocal() as s:
        user = s.get(User, uid)
        return {"keys retired": keys(uid), "to set up again": user.second_factor_reset_at is not None,
                "authenticator": [e.status for e in s.query(SecondFactorEnrollment).filter(
                    SecondFactorEnrollment.user_id == uid)],
                "held open": s.query(PendingLogin).filter(PendingLogin.user_id == uid,
                                                          PendingLogin.consumed_at.is_(None)).count(),
                "sessions": sorted([bool(r.is_active), bool(r.revoked)] for r in s.query(ActiveSession).filter(
                    ActiveSession.user_id == uid))}


def together(**targets):
    out = {}

    def wrap(name, fn):
        started = time.monotonic()
        try:
            out[name] = ["ok", fn()]
        except Exception as exc:  # noqa: BLE001
            code = getattr(getattr(exc, "orig", None), "pgcode", None) or getattr(exc, "status_code", "")
            out[name] = ["error", type(exc).__name__, str(code), str(getattr(exc, "detail", exc)).splitlines()[0][:120]]
        out[name + " seconds"] = round(time.monotonic() - started, 2)
    threads = [threading.Thread(target=wrap, args=item) for item in targets.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(40)
    return out


# The account's turn, with a pause inside it for the thread that asks for one: longer than the database waits
# before it looks for a ring of waiters (deadlock_timeout, one second).
_take, here, in_turn = sign_in_lockout.take_sessions_turn, threading.local(), threading.Event()


def take_and_hold(db, user_id, busy=False):
    _take(db, user_id, busy=busy)
    pause = getattr(here, "stay", 0)
    if pause:
        here.stay = 0
        in_turn.set()
        time.sleep(pause)
sign_in_lockout.take_sessions_turn = take_and_hold


def held_sign_in(uid):
    with SessionLocal() as s:
        row = PendingLogin(user_id=uid, client_ip=IP, enrollment_required=True,
                           expires_at=datetime.utcnow() + timedelta(minutes=5))
        s.add(row)
        s.commit()
        return row.id


def a_session(uid):
    """A session of the account and a request that carries its token."""
    with SessionLocal() as s:
        token = AuthService(s)._create_session(s.get(User, uid), None, IP, channel="web")
    bearer = create_access_token({"sub": str(uid), "session_token": token})
    return types.SimpleNamespace(headers={"Authorization": "Bearer " + bearer}, client=types.SimpleNamespace(host=IP))


def after_the_turn_is_held(fn):
    def run():
        in_turn.wait(15)
        return fn()
    return run


def a_change(admin_id, uid, kind):
    def run():
        with SessionLocal() as s:
            payload = {"password_hash": hash_password("New-Password-9y!")} if kind == cc.PASSWORD else {}
            api._credential_change(s, s.get(User, admin_id), s.get(User, uid), kind, summary="a change",
                                   payload=payload)
            s.commit()
            return "changed"
    return run


pair, out = os.environ["PAIR"], {}
ada, alice = account("ada", RoleEnum.ADMIN), account("alice")

if pair == "a passkey at a held sign-in":
    hold = held_sign_in(alice)

    def store():
        with SessionLocal() as s:
            user, pending = s.get(User, alice), s.get(PendingLogin, hold)
            here.stay = 1.6
            sign_in.refuse_a_factor_the_sign_in_could_not_finish(s, user, pending, IP)
            s.add(key_for(s, alice))
            user.second_factor_reset_at = None
            s.commit()
            return "stored"
    out = together(writer=store, ender=after_the_turn_is_held(a_change(ada, alice, cc.SECOND_FACTOR)))
elif pair == "an authenticator at a held sign-in":
    hold = held_sign_in(alice)
    with SessionLocal() as s:
        s.add(SecondFactorEnrollment(user_id=alice, method="totp", secret_enc="sealed", status="unconfirmed",
                                     confirmed_at=datetime.utcnow()))
        s.get(User, alice).second_factor_reset_at = datetime.utcnow()
        s.commit()

    def activate():
        with SessionLocal() as s:
            user, pending = s.get(User, alice), s.get(PendingLogin, hold)
            here.stay = 1.6
            sign_in.refuse_a_factor_the_sign_in_could_not_finish(s, user, pending, IP)
            s.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == alice).one().status = "active"
            user.second_factor_reset_at = None
            s.commit()
            return "active"
    out = together(writer=activate, ender=after_the_turn_is_held(a_change(ada, alice, cc.PASSWORD)))
elif pair in ("a passkey from a session", "a passkey from a session the reset ended"):
    request = a_session(alice)

    def store():
        with SessionLocal() as s:
            user = s.get(User, alice)
            if pair == "a passkey from a session":
                here.stay = 1.6
            api._session_still_stands_in_the_turn(s, user, request)
            s.add(key_for(s, alice))
            s.commit()
            return "stored"
    if pair == "a passkey from a session":
        out = together(writer=store, ender=after_the_turn_is_held(a_change(ada, alice, cc.SECOND_FACTOR)))
    else:
        a_change(ada, alice, cc.SECOND_FACTOR)()
        out = together(writer=store)
out["after"], out["the turn was held"] = state(alice), in_turn.is_set()
print(json.dumps(out))
'''


def test_a_passkey_stored_at_a_held_sign_in_and_a_reset_both_finish_and_the_reset_retires_it(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a passkey at a held sign-in"})
    assert out["writer"] == ["ok", "stored"] and out["ender"] == ["ok", "changed"], out
    assert out["the turn was held"] is True, out             # the key was stored in the account's turn
    assert out["ender seconds"] >= 1.0, out                  # the reset waited for the turn the store held
    after = out["after"]
    assert after["keys retired"] == [True] and after["to set up again"] is True and after["held open"] == 0, out


def test_an_authenticator_made_active_at_a_held_sign_in_and_a_new_password_both_finish(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "an authenticator at a held sign-in"})
    assert out["writer"] == ["ok", "active"] and out["ender"] == ["ok", "changed"], out
    assert out["the turn was held"] is True, out
    assert out["ender seconds"] >= 1.0, out
    after = out["after"]
    # A new password takes no factor away: the authenticator set up before it stands, and the held sign-in is spent.
    assert after["authenticator"] == ["active"] and after["held open"] == 0, out


def test_a_passkey_stored_from_a_session_is_retired_by_the_reset_that_waited_for_it(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a passkey from a session"})
    assert out["writer"] == ["ok", "stored"] and out["ender"] == ["ok", "changed"], out
    assert out["the turn was held"] is True, out             # the key was stored in the account's turn
    assert out["ender seconds"] >= 1.0, out
    after = out["after"]
    assert after["keys retired"] == [True] and after["sessions"] == [[False, True]], out


def test_a_session_the_reset_ended_stores_no_passkey(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a passkey from a session the reset ended"})
    assert out["writer"][:3] == ["error", "HTTPException", "401"], out
    assert out["after"]["keys retired"] == [], out
