"""What writes for an account in its turn at its sessions and what ends the account's sessions, made to meet on a
running stack's Postgres (a throwaway database of its own, tests/_throwaway_db.py): two connections, the
application's own functions, the meeting forced with events.

- A sign-in that holds the account's turn while it writes its session, and something that ends the account's
  sessions at that moment: a change an administrator makes at once, the approval of a held change, a reset link
  used, the lock of an administrator. Each of them locks the account's row; taken before the turn, that lock and
  the turn waited for each other and the database ended one of the two. Both finish now, and the session the
  sign-in wrote is ended by what came after it.
- The password door and an administrator's new password: the door's check and its session are one turn, so the
  change waits for the door and then ends its session; an attempt that loaded the account and waited for its turn
  while the password was changed checks the password that stands, and is refused.
- A sign-in, and a sign-in held for a further step, read before the account's sessions were ended and written
  after: refused, with nothing written.

test_sign_in_in_the_accounts_turn.py holds the same rules offline, where the turn is stood in for.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def db_name():
    yield from throwaway_database()


SCENARIO = PREAMBLE + r'''
import asyncio, threading, time, types
from app.api import api_server as api
from app.core import auditor_rights, credential_changes as cc, endpoint_permissions as ep, legal_holds
from app.core import password_reset, sign_in_lockout
from app.core.models import ActiveSession, PasswordResetToken, PendingLogin, RoleEnum, User
from app.core.security import hash_password, verify_password
from app.services import auth_service as auth_mod, sign_in

OLD, NEW, IP = "Old-Password-8x!", "New-Password-9y!", "192.0.2.44"
# What is not the database stands still: no live-monitor signal, no notice, no throttle, no step-up.
api._force_close_after_commit = lambda *a, **k: None
api._enforce_step_up = lambda *a, **k: None
api._notify_account_change = lambda *a, **k: None
api._notify_credential_change = lambda *a, **k: None
api._fire_action_email = lambda *a, **k: None
ep.check_endpoint_permission = lambda *a, **k: None
auditor_rights.after_credential_change = lambda *a, **k: None
legal_holds.after_starter_change = lambda *a, **k: None
sign_in._record = lambda *a, **k: None
auth_mod.AuthService._check_rate_limit = lambda self, *a, **k: None
auth_mod.AuthService._give_back = lambda self, *a, **k: None
REQUEST = types.SimpleNamespace(headers={}, client=types.SimpleNamespace(host=IP), state=types.SimpleNamespace(),
                                base_url="https://vault.example.com/", url=types.SimpleNamespace(path="/"))


def account(name, role=RoleEnum.USER):
    with SessionLocal() as s:
        u = User(username=name + "-" + uuid.uuid4().hex[:6], email=None, password_hash=hash_password(OLD), role=role,
                 is_active=True, is_locked=False)
        s.add(u)
        s.commit()
        return u.id, u.username


def sessions(uid):
    with SessionLocal() as s:
        return sorted([bool(r.is_active), bool(r.revoked)] for r in s.query(ActiveSession).filter(
            ActiveSession.user_id == uid))


def held_open(uid):
    with SessionLocal() as s:
        return s.query(PendingLogin).filter(PendingLogin.user_id == uid, PendingLogin.consumed_at.is_(None)).count()


def password_is(uid, password):
    with SessionLocal() as s:
        return verify_password(password, s.get(User, uid).password_hash)


def together(**targets):
    """Run each target on a thread of its own; what each returned, or the error it ended with, and how long it
    took."""
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


# The account's turn at its sessions, with a pause inside it for the thread that asks for one: the turn is held
# for longer than the database waits before it looks for a ring of waiters (deadlock_timeout, one second).
_take, here, in_turn = sign_in_lockout.take_sessions_turn, threading.local(), threading.Event()


def take_and_hold(db, user_id, busy=False):
    _take(db, user_id, busy=busy)
    pause = getattr(here, "stay", 0)
    if pause:
        here.stay = 0
        in_turn.set()
        time.sleep(pause)
sign_in_lockout.take_sessions_turn = take_and_hold


def writer(uid):
    """A sign-in that completes: its session written in the account's turn, which it holds for a while."""
    def run():
        s = SessionLocal()
        try:
            user = s.get(User, uid)
            result = sign_in.SignInResult(user, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(user))
            here.stay = 1.6
            sign_in.complete_sign_in(s, result)
            return "signed in"
        finally:
            s.close()
    return run


def after_the_turn_is_held(fn):
    def run():
        in_turn.wait(15)
        return fn()
    return run


def a_change_made_at_once(admin_id, uid):
    def run():
        with SessionLocal() as s:
            api._credential_change(s, s.get(User, admin_id), s.get(User, uid), cc.PASSWORD, summary="a new password",
                                   payload={"password_hash": hash_password(NEW)})
            s.commit()
            return "changed"
    return run


def an_approval(admin_id, other_admin_id, uid):
    """A second change inside the window is held; the server's operator approves it."""
    with SessionLocal() as s:
        api._credential_change(s, s.get(User, admin_id), s.get(User, uid), cc.RESET_LINK, summary="a link",
                               payload={})
        s.commit()
    with SessionLocal() as s:
        outcome = api._credential_change(s, s.get(User, other_admin_id), s.get(User, uid), cc.PASSWORD,
                                         summary="a new password", payload={"password_hash": hash_password(NEW)})
        s.commit()
        assert outcome.held, "the second change was not held"
        change_id = outcome.change.id

    def run():
        with SessionLocal() as s:
            change, target = api._open_credential_request(s, change_id)
            api._approve_credential_change(s, change, target, approver=None)
            s.commit()
            return "approved"
    return run


def a_reset_link_used(uid):
    token, prefix = password_reset.mint_reset_token()
    with SessionLocal() as s:
        s.add(PasswordResetToken(user_id=uid, token_prefix=prefix,
                                 token_hash=password_reset.hash_reset_token(token, api._reset_pepper()),
                                 expires_at=datetime.utcnow() + timedelta(minutes=5), created_by=None,
                                 made_by_other=False))
        s.commit()

    def run():
        with SessionLocal() as s:
            asyncio.run(api.do_reset(token=token, body=api.ResetPasswordRequest(new_password=NEW), request=REQUEST,
                                     db=s))
            return "reset"
    return run


def a_lock(admin_id, uid):
    def run():
        with SessionLocal() as s:
            asyncio.run(api.update_user(user_id=uid, user_update=api.UserUpdate(is_locked=True),
                                        current_user=s.get(User, admin_id), db=s, request=REQUEST))
            return "locked"
    return run


pair, out = os.environ["PAIR"], {}
ada, _ = account("ada", RoleEnum.ADMIN)
bea, _ = account("bea", RoleEnum.ADMIN)
alice, alice_name = account("alice")

if pair in ("a change made at once", "an approval", "a reset link used", "the lock of an administrator"):
    target = alice
    if pair == "a change made at once":
        ender = a_change_made_at_once(ada, alice)
    elif pair == "an approval":
        ender = an_approval(ada, bea, alice)
    elif pair == "a reset link used":
        ender = a_reset_link_used(alice)
    else:
        target, _ = account("cora", RoleEnum.ADMIN)
        ender = a_lock(ada, target)
    out = together(writer=writer(target), ender=after_the_turn_is_held(ender))
    out["sessions"] = sessions(target)
elif pair == "the password door":
    checked, changed, check = threading.Event(), threading.Event(), auth_mod.verify_password

    def slow_check(password, hashed):
        ok = check(password, hashed)
        checked.set()
        changed.wait(2.5)
        return ok
    auth_mod.verify_password = slow_check

    def door():
        with SessionLocal() as s:
            auth_mod.AuthService(s).authenticate_user(alice_name, OLD, IP, channel=os.environ.get("CHANNEL", "web"))
            return "signed in"

    def change():
        checked.wait(15)
        try:
            return a_change_made_at_once(ada, alice)()
        finally:
            changed.set()
    out = together(door=door, ender=change)
    out["sessions"], out["password is the new one"] = sessions(alice), password_is(alice, NEW)
elif pair == "an attempt that waited for its turn":
    loaded, changed, take = threading.Event(), threading.Event(), sign_in_lockout.take_turn

    def wait_for_the_change(db, user_id):
        loaded.set()
        changed.wait(15)
        take(db, user_id)
    sign_in_lockout.take_turn = wait_for_the_change

    def attempt():
        with SessionLocal() as s:
            auth_mod.AuthService(s).authenticate_user(alice_name, OLD, IP, channel=os.environ.get("CHANNEL", "web"))
            return "signed in"

    def change():
        loaded.wait(15)
        try:
            return a_change_made_at_once(ada, alice)()
        finally:
            changed.set()
    out = together(door=attempt, ender=change)
    out["sessions"] = sessions(alice)
elif pair in ("a session read before", "a held sign-in read before"):
    with SessionLocal() as s:
        user = s.get(User, alice)
        result = sign_in.SignInResult(user, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(user))
        a_change_made_at_once(ada, alice)()
        try:
            if pair == "a session read before":
                sign_in.complete_sign_in(s, result)
            else:
                sign_in.begin_pending(s, result, sign_in.STAGE_SECOND_FACTOR)
            out["writer"] = ["ok", "written"]
        except Exception as exc:  # noqa: BLE001
            out["writer"] = ["error", type(exc).__name__, str(getattr(exc, "status_code", "")),
                             str(getattr(exc, "detail", exc))[:120]]
    out["sessions"], out["held"] = sessions(alice), held_open(alice)
print(json.dumps(out))
'''


@pytest.mark.parametrize("ender", ["a change made at once", "an approval", "a reset link used",
                                   "the lock of an administrator"])
def test_a_sign_in_writing_in_its_turn_and_what_ends_the_sessions_both_finish(db_name, ender):
    out = run_in(db_name, SCENARIO, env={"PAIR": ender})
    assert out["writer"] == ["ok", "signed in"], out
    assert out["ender"][0] == "ok", out                      # not ended by the database as one of a ring of waiters
    assert out["ender seconds"] >= 1.0, out                  # it waited for the turn the sign-in held
    assert out["sessions"] == [[False, True]], out           # and then ended the session that sign-in wrote


@pytest.mark.parametrize("channel", ["web", "sftp"])
def test_the_password_doors_session_is_written_before_a_new_password_or_not_at_all(db_name, channel):
    out = run_in(db_name, SCENARIO, env={"PAIR": "the password door", "CHANNEL": channel})
    assert out["door"] == ["ok", "signed in"] and out["ender"] == ["ok", "changed"], out
    assert out["ender seconds"] >= 2.0, out                  # the change waited for the door's turn
    assert out["password is the new one"] is True
    assert all(revoked for _active, revoked in out["sessions"]) and out["sessions"], out


@pytest.mark.parametrize("channel", ["web", "sftp"])
def test_an_attempt_that_waited_while_the_password_was_changed_checks_the_new_one(db_name, channel):
    out = run_in(db_name, SCENARIO, env={"PAIR": "an attempt that waited for its turn", "CHANNEL": channel})
    assert out["ender"] == ["ok", "changed"], out
    assert out["door"][:2] == ["error", "InvalidCredentialsError"], out
    assert out["sessions"] == [], out


@pytest.mark.parametrize("written", ["a session", "a held sign-in"])
def test_a_sign_in_read_before_the_sessions_were_ended_is_not_written_after(db_name, written):
    out = run_in(db_name, SCENARIO, env={"PAIR": f"{written} read before"})
    assert out["writer"][:3] == ["error", "HTTPException", "401"], out
    assert out["sessions"] == [] and out["held"] == 0, out
