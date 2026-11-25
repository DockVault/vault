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
- A promotion sent with a switch of the account's SFTP access, of an account whose password somebody else set:
  recording the grant writes the account's row, and the take-back of the password then asks for the turn the
  sign-in holds, while the sign-in goes on to write that row. The promotion takes the turn first now.
- A sign-in that finds the account's turn held for longer than it waits where it is written: answered as busy
  after a short wait, with nothing written, and not after the connection's own, longer wait (the routes that
  finish a sign-in are answered on the server's one loop).
- Two administrators who lock, or turn off, one account that holds the auditor right, one from the Users page
  and one by another route (the switch that locks, the switch that turns off, PUT /api/user-management/users/{id}).
  The Users page's request takes the account's turn first and then locks the account's auditor right; the other
  routes locked that row first and asked for the turn where they end the sessions, and the database ended one of
  the two. They take the turn first now: both finish.
- A held sign-in that goes on (to a session, or to a further hold) and an administrator's deletion of the account
  at that moment: the sign-in has spent its held row and holds the account's turn; the deletion's removal of the
  account's held sign-ins and the sign-in's next write waited for each other, and the database ended one of the
  two. The deletion takes the turn now: both finish, and the account is gone with what the sign-in wrote.

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


def a_reset_link_used(uid, maker_id):
    """A link an administrator made for the account: used, it is judged again under a lock on the maker's row and
    the account's, which is what the account's turn must come before (a link the account made itself locks none)."""
    token, prefix = password_reset.mint_reset_token()
    with SessionLocal() as s:
        s.add(PasswordResetToken(user_id=uid, token_prefix=prefix,
                                 token_hash=password_reset.hash_reset_token(token, api._reset_pepper()),
                                 expires_at=datetime.utcnow() + timedelta(minutes=5), created_by=maker_id,
                                 made_by_other=True))
        s.commit()

    def run():
        with SessionLocal() as s:
            asyncio.run(api.do_reset(token=token, body=api.ResetPasswordRequest(new_password=NEW), request=REQUEST,
                                     db=s))
            return "reset"
    return run


def a_promotion_with_an_sftp_switch(admin_id, uid):
    """The account is made an administrator and its SFTP password sign-in is switched off in one request; its
    password was set by somebody else, so the promotion takes it back and ends the account's sessions."""
    from app.core import password_origin
    with SessionLocal() as s:
        password_origin.set_by_other(s.get(User, uid), admin_id)
        s.commit()

    def run():
        with SessionLocal() as s:
            asyncio.run(api.update_user(user_id=uid,
                                        user_update=api.UserUpdate(role=RoleEnum.ADMIN, sftp_password_auth=False),
                                        current_user=s.get(User, admin_id), db=s, request=REQUEST))
            return "promoted"
    return run


def a_lock(admin_id, uid):
    def run():
        with SessionLocal() as s:
            asyncio.run(api.update_user(user_id=uid, user_update=api.UserUpdate(is_locked=True),
                                        current_user=s.get(User, admin_id), db=s, request=REQUEST))
            return "locked"
    return run


# A held sign-in that goes on: the writer spends it and then stays for a while, with the account's turn and the
# spent row held, before it writes what the held sign-in becomes.
_spend, spent = sign_in.consume_pending, threading.Event()


def spend_and_stay(db, pending, *, commit=True):
    _spend(db, pending, commit=commit)
    pause = getattr(here, "stay_spent", 0)
    if pause:
        here.stay_spent = 0
        spent.set()
        time.sleep(pause)
sign_in.consume_pending = spend_and_stay


def a_held_sign_in(uid):
    with SessionLocal() as s:
        held = PendingLogin(user_id=uid, client_ip=IP, expires_at=datetime.utcnow() + timedelta(minutes=5))
        s.add(held)
        s.commit()
        return held.id


def held_writer(uid, held_id, becomes):
    def run():
        s = SessionLocal()
        try:
            user = s.get(User, uid)
            result = sign_in.SignInResult(user, [sign_in.PASSWORD], IP, pending=s.get(PendingLogin, held_id),
                                          sessions_ended=sign_in.as_read(user))
            here.stay_spent = 1.6
            if becomes == "a session":
                sign_in.complete_sign_in(s, result)
            else:
                sign_in.begin_pending(s, result, sign_in.STAGE_SECOND_FACTOR)
            return "written"
        finally:
            s.close()
    return run


def a_deletion(admin_id, uid):
    def run():
        spent.wait(15)
        with SessionLocal() as s:
            asyncio.run(api.delete_user(user_id=uid, current_user=s.get(User, admin_id), db=s, request=REQUEST))
            return "deleted"
    return run


def a_turn_held(uid, seconds):
    """Something that holds the account's turn for a while, as a change that settles many accounts does."""
    def run():
        with SessionLocal() as s:
            _take(s, uid)
            in_turn.set()
            time.sleep(seconds)
            s.rollback()
            return "let go"
    return run


def a_sign_in_that_comes_meanwhile(uid):
    def run():
        in_turn.wait(15)
        s = SessionLocal()
        try:
            user = s.get(User, uid)
            result = sign_in.SignInResult(user, [sign_in.PASSWORD], IP, sessions_ended=sign_in.as_read(user))
            started = time.monotonic()
            try:
                sign_in.complete_sign_in(s, result)
            finally:
                waited.append(round(time.monotonic() - started, 2))
            return "signed in"
        finally:
            s.close()
    return run


waited = []
pair, out = os.environ["PAIR"], {}
ada, _ = account("ada", RoleEnum.ADMIN)
bea, _ = account("bea", RoleEnum.ADMIN)
alice, alice_name = account("alice")

if pair in ("a change made at once", "an approval", "a reset link used", "the lock of an administrator",
            "a promotion with an SFTP switch"):
    target = alice
    if pair == "a change made at once":
        ender = a_change_made_at_once(ada, alice)
    elif pair == "an approval":
        # A third administrator, who could approve: with none, the second change is refused, not held. The
        # database is the module's, so one from an earlier meeting would do, but this one stands by itself.
        account("cora", RoleEnum.ADMIN)
        ender = an_approval(ada, bea, alice)
    elif pair == "a reset link used":
        ender = a_reset_link_used(alice, ada)
    elif pair == "a promotion with an SFTP switch":
        ender = a_promotion_with_an_sftp_switch(ada, alice)
    else:
        target, _ = account("cora", RoleEnum.ADMIN)
        ender = a_lock(ada, target)
    out = together(writer=writer(target), ender=after_the_turn_is_held(ender))
    out["sessions"], out["the turn was held"] = sessions(target), in_turn.is_set()
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
elif pair in ("a deletion and a held sign-in that becomes a session", "a deletion and a held sign-in held again"):
    held = a_held_sign_in(alice)
    becomes = "a session" if pair.endswith("a session") else "held again"
    out = together(writer=held_writer(alice, held, becomes), ender=a_deletion(ada, alice))
    with SessionLocal() as s:
        out["the account is there"] = s.get(User, alice) is not None
    out["sessions"], out["held"], out["the sign-in stayed"] = sessions(alice), held_open(alice), spent.is_set()
elif pair.startswith("the Users page and "):
    from datetime import datetime
    from app.api import user_management_api as um
    from app.core.models import AuditorGrant
    api._notify_account_status_changes = lambda *a, **k: None
    api._announce_lost_standing = lambda *a, **k: None
    api._notify_users = lambda *a, **k: []

    async def no_detail(**kw):
        return {}
    um.get_user_detail = no_detail
    # The account holds the auditor right: where it loses its standing, that row is locked.
    with SessionLocal() as s:
        s.add(AuditorGrant(user_id=alice, username_at_grant=alice_name, status="active", proposed_by=ada,
                           proposed_by_username="ada", approved_by=bea, approved_by_username="bea",
                           approved_at=datetime.utcnow(), credential_changers=[]))
        s.commit()
    # The other route stays, once the account has lost its standing there (its auditor right locked), until the
    # Users page's request holds the account's turn, or for a while when it never does.
    lost, standing_lost = api._account_lost_standing, threading.Event()

    def lost_and_stay(db, user, *, actor, because):
        told = lost(db, user, actor=actor, because=because)
        pause = getattr(here, "stay_after_standing", 0)
        if pause:
            here.stay_after_standing = 0
            standing_lost.set()
            if in_turn.wait(pause):
                time.sleep(0.5)                    # the Users page's request is at the row held here by now
        return told
    api._account_lost_standing = lost_and_stay
    locks = pair.endswith("locks")

    def the_other_route():
        here.stay_after_standing = 2.5
        with SessionLocal() as s:
            admin = s.get(User, bea)
            if pair.endswith("the switch that locks"):
                asyncio.run(um.toggle_user_locked(user_id=alice, current_user=admin, db=s, request=REQUEST))
            elif pair.endswith("the switch that turns off"):
                asyncio.run(um.toggle_user_active(user_id=alice, current_user=admin, db=s, request=REQUEST))
            else:
                asyncio.run(um.update_user(user_id=alice, update_data=um.UserUpdateRequest(is_active=False),
                                           request=REQUEST, current_user=admin, db=s))
            return "done"

    def the_users_page():
        standing_lost.wait(15)
        here.stay = 0.05
        change = api.UserUpdate(is_locked=True) if locks else api.UserUpdate(is_active=False)
        with SessionLocal() as s:
            asyncio.run(api.update_user(user_id=alice, user_update=change, current_user=s.get(User, ada), db=s,
                                        request=REQUEST))
            return "done"
    out = together(other=the_other_route, page=the_users_page)
    with SessionLocal() as s:
        user = s.get(User, alice)
        out["locked"], out["active"] = bool(user.is_locked), bool(user.is_active)
        out["right"] = [g.status for g in s.query(AuditorGrant).filter(AuditorGrant.user_id == alice)]
elif pair == "a turn held for longer than a sign-in waits":
    out = together(holder=a_turn_held(alice, 2.5), writer=a_sign_in_that_comes_meanwhile(alice))
    out["sessions"], out["the sign-in waited"] = sessions(alice), waited
elif pair == "the wait a transaction had":
    from sqlalchemy import text
    with SessionLocal() as s:
        usual = s.execute(text("SELECT current_setting('lock_timeout')")).scalar()
        s.execute(text("SET LOCAL lock_timeout = '7s'"))
        inside = []
        sign_in.with_a_short_wait(s, lambda: inside.append(s.execute(text("SELECT current_setting('lock_timeout')")).scalar()))
        after = s.execute(text("SELECT current_setting('lock_timeout')")).scalar()
        s.rollback()
        out = {"usual": usual, "inside": inside, "after": after,
               "next transaction": s.execute(text("SELECT current_setting('lock_timeout')")).scalar()}
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
                                   "the lock of an administrator", "a promotion with an SFTP switch"])
def test_a_sign_in_writing_in_its_turn_and_what_ends_the_sessions_both_finish(db_name, ender):
    out = run_in(db_name, SCENARIO, env={"PAIR": ender})
    assert out["writer"] == ["ok", "signed in"], out
    assert out["the turn was held"] is True, out             # the sign-in wrote in the account's turn
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


@pytest.mark.parametrize("becomes", ["a held sign-in that becomes a session", "a held sign-in held again"])
def test_a_deletion_and_a_held_sign_in_that_goes_on_both_finish(db_name, becomes):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a deletion and " + becomes})
    assert out["the sign-in stayed"] is True, out            # with its held row spent and the account's turn held
    assert out["writer"] == ["ok", "written"], out
    assert out["ender"] == ["ok", "deleted"], out            # not ended by the database as one of a ring of waiters
    assert out["ender seconds"] >= 1.0, out                  # it waited for the turn the sign-in held
    assert out["the account is there"] is False and out["sessions"] == [] and out["held"] == 0, out


def test_a_sign_in_waits_a_short_time_for_a_turn_that_is_held_and_is_answered_as_busy(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a turn held for longer than a sign-in waits"})
    assert out["holder"] == ["ok", "let go"], out
    assert out["writer"][:3] == ["error", "HTTPException", "503"], out
    (waited,) = out["the sign-in waited"]
    assert 0.3 <= waited < 1.5, out                          # its own short wait: not the 2.5 s, nor the connection's 5
    assert out["sessions"] == [], out


def test_the_short_wait_gives_a_transaction_the_wait_it_had_back(db_name):
    """A transaction that had set a wait of its own gets that wait back after the short one, not the
    connection's usual one; and nothing of it outlives the transaction."""
    out = run_in(db_name, SCENARIO, env={"PAIR": "the wait a transaction had"})
    assert out["usual"] == "5s" and out["inside"] == ["500ms"], out
    assert out["after"] == "7s" and out["next transaction"] == "5s", out


@pytest.mark.parametrize("other", ["the switch that locks", "the switch that turns off",
                                   "PUT /users/{id} that turns off"])
def test_two_administrators_who_lock_or_turn_off_an_auditors_account_by_two_routes_both_finish(db_name, other):
    out = run_in(db_name, SCENARIO, env={"PAIR": "the Users page and " + other})
    assert out["other"] == ["ok", "done"], out               # not ended by the database as one of a ring of waiters
    assert out["page"] == ["ok", "done"], out
    assert out["page seconds"] >= 2.0, out                   # the Users page waited for the turn the other one held
    assert out["right"] == ["suspended"], out                # the right was suspended once, and stands so
    assert (out["locked"], out["active"]) == ((True, True) if other.endswith("locks") else (False, False)), out
