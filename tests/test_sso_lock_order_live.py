"""A sign-in through a provider written in the account's turn, and what changes the provider or ends its sessions,
made to meet on a running stack's Postgres (a throwaway database of its own, tests/_throwaway_db.py): two
connections, the application's own functions, the meeting forced with events.

The provider's row stands before an account's turn in the order of the locks. A sign-in through the provider holds
the row shared from before its turn until it commits; a turn-off, a save and a provider's logout take the row for
themselves. So each of those comes wholly after a sign-in that is being written, and ends what it wrote, or wholly
before it, and the sign-in is refused:

- the provider turned off while a sign-in through it is written, and a sign-in written after the turn-off;
- a provider's logout (the back-channel route itself, with a token that names the provider's session and not
  the person) while a sign-in that carries the same provider session is written, and such a sign-in written
  after a logout;
- a provider saved, which settles its accounts in their turns, while a held sign-in sets a factor up and goes on to
  its session. The set-up took the turn before the provider's row once, the save the row before the turn: the two
  waited for each other.

- a provider saved, with its password rule changed, while "Stay signed in" moves the record of the provider's
  session to the new session in the account's turn. The record refers to the provider; the save took the
  provider's row with its key, and then the account's turn.

- a provider's row held for longer than a sign-in waits where it is written (a save that settles many accounts):
  the sign-in is answered as busy after its own short wait, with nothing written. The routes that finish a
  sign-in are answered on the server's one loop, where the connection's five seconds would be everybody's.

test_sso_sessions.py holds the same rules offline, where the row and the turn are stood in for.
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
from app.api import sso_providers_router as R
from app.api import sso_router
from app.core import sign_in_lockout, sso_only
from app.core.models import (ActiveSession, ExternalIdentity, PendingLogin, RoleEnum, SsoProvider, SsoSession, User)
from app.core.rate_limiter import rate_limiter
from app.core.security import hash_password
from app.services import oidc_client as oc
from app.services import sign_in, sso_sign_in
from app.services.auth_service import AuthService

IP, SUBJECT = "192.0.2.44", "subject-1"
api._force_close_after_commit = lambda *a, **k: None
sign_in._record = lambda *a, **k: None
sso_router._audit = lambda *a, **k: None
# The provider's logout: its token is taken as verified, with the claims the scenario gives it.
rate_limiter.check_rate_limit = lambda **kw: (True, 0, 0)
sso_sign_in.provider_config = lambda row: object()
oc.discover = lambda provider, fetch=None: {}
logout_claims = {}
oc.verify_logout_token = lambda provider, discovery, token, fetch=None, seen_jti=None: dict(logout_claims)


def account(name):
    with SessionLocal() as s:
        u = User(username=name + "-" + uuid.uuid4().hex[:6], email=None, password_hash=hash_password("Old-Password-8x!"),
                 role=RoleEnum.USER, is_active=True, is_locked=False)
        s.add(u)
        s.commit()
        return u.id


def provider_with(uid):
    with SessionLocal() as s:
        row = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name="contoso-" + uuid.uuid4().hex[:6],
                          label="Contoso", issuer="https://idp.example/", client_id="c", client_secret_enc="e",
                          policy={"sso_backchannel_logout": True})
        s.add(row)
        s.flush()
        s.add(ExternalIdentity(user_id=uid, provider_id=row.id, issuer="https://idp.example/", subject=SUBJECT,
                               subject_source="oidc:sub", linked_by="self"))
        s.commit()
        return row.id


def state(uid, pid):
    with SessionLocal() as s:
        return {"provider": s.get(SsoProvider, pid).state,
                "sessions": sorted([bool(r.is_active), bool(r.revoked)] for r in s.query(ActiveSession).filter(
                    ActiveSession.user_id == uid)),
                "provider sessions": s.query(SsoSession).filter(SsoSession.provider_id == pid).count(),
                "sso only": bool(s.get(User, uid).sso_only),
                "held open": s.query(PendingLogin).filter(PendingLogin.user_id == uid,
                                                          PendingLogin.consumed_at.is_(None)).count()}


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


def after_the_turn_is_held(fn):
    def run():
        in_turn.wait(15)
        return fn()
    return run


def through_the_provider(uid, pid, sid, pause=0.0, answered=None):
    """A sign-in that came through the provider and completes: its session written in the account's turn. The
    provider answered it at ``answered`` (now, when the meeting starts, if not given)."""
    answered = time.time() if answered is None else answered

    def run():
        with SessionLocal() as s:
            user = s.get(User, uid)
            result = sign_in.SignInResult(user, [], IP, provider_id=str(pid), provider_sub=SUBJECT, provider_sid=sid,
                                          provider_answered_at=answered, sessions_ended=sign_in.as_read(user))
            here.stay = pause
            sign_in.complete_sign_in(s, result)
            return "signed in"
    return run


def turn_off(pid):
    """What the state route does to turn a provider off: the row for itself, the state, then its sessions ended."""
    def run():
        with SessionLocal() as s:
            row = R._row_or_404(s, pid, lock=True)
            row.state = "disabled"
            s.commit()
            return R._end_sessions_of(s, pid)
    return run


def logout(pid, sid, sub=SUBJECT):
    """The provider's back-channel logout, through the route. With ``sub`` None the token names the provider's
    session only, so nothing but the provider's row makes the logout wait for a sign-in that is being written
    (with the person named, their turn would too)."""
    class Request:
        headers = {}
        client = types.SimpleNamespace(host=IP)

        async def form(self):
            return {"logout_token": "a-token"}

    def run():
        logout_claims.clear()
        logout_claims.update({"sid": sid, "jti": uuid.uuid4().hex})
        if sub is not None:
            logout_claims["sub"] = sub
        with SessionLocal() as s:
            return asyncio.run(sso_router.backchannel_logout(str(pid), Request(), s)).status_code
    return run


def held_sign_in(uid):
    with SessionLocal() as s:
        row = PendingLogin(user_id=uid, client_ip=IP, enrollment_required=True,
                           expires_at=datetime.utcnow() + timedelta(minutes=5))
        s.add(row)
        s.commit()
        return row.id


pair, out = os.environ["PAIR"], {}
alice = account("alice")
contoso = provider_with(alice)

if pair == "turned off while a sign-in is written":
    out = together(writer=through_the_provider(alice, contoso, "s-1", pause=1.6),
                   ender=after_the_turn_is_held(turn_off(contoso)))
elif pair == "a sign-in after the turn-off":
    out = {"ender": ["ok", turn_off(contoso)()]}
    out.update(together(writer=through_the_provider(alice, contoso, "s-1")))
elif pair == "logged out while a sign-in is written":
    out = together(writer=through_the_provider(alice, contoso, "s-held", pause=1.6),
                   ender=after_the_turn_is_held(logout(contoso, "s-held", sub=None)))
elif pair == "a sign-in after the logout":
    before = time.time()
    time.sleep(0.05)
    out = {"ender": ["ok", logout(contoso, "s-held")()]}
    time.sleep(0.05)
    # The provider answered the first before its logout. The second came through another session of the
    # provider's; the third is the person signing in again, answered after the logout with the session id kept.
    out.update(together(writer=through_the_provider(alice, contoso, "s-held", answered=before)))
    out.update(together(other=through_the_provider(alice, contoso, "s-other", answered=before)))
    out.update(together(again=through_the_provider(alice, contoso, "s-held")))
elif pair == "saved while a held sign-in sets a factor up":
    hold = held_sign_in(alice)

    def set_up():
        with SessionLocal() as s:
            user, pending = s.get(User, alice), s.get(PendingLogin, hold)
            pending._provider_id, pending._provider_sub = str(contoso), SUBJECT
            pending._sessions_ended, pending._methods_so_far = sign_in.as_read(user), ()
            here.stay = 1.6
            sign_in.refuse_a_factor_the_sign_in_could_not_finish(s, user, pending, IP)
            # (the factor is written here, in the turn) and the sign-in goes on to its session, in the same turn
            result = sign_in.SignInResult(user, [], IP, pending=pending, provider_id=str(contoso),
                                          provider_sub=SUBJECT, sessions_ended=sign_in.ended_of(pending))
            sign_in.complete_sign_in(s, result)
            return "signed in"

    def save():
        with SessionLocal() as s:
            row = R._row_or_404(s, contoso, lock=True)
            row.label = "Contoso (renamed)"
            sso_only.settle(s, s.get(User, alice))
            s.commit()
            return "saved"
    out = together(writer=set_up, ender=after_the_turn_is_held(save))
elif pair == "saved while a renewal moves the provider's session":
    through_the_provider(alice, contoso, "s-old")()

    def renewal():
        """What "Stay signed in" does in the account's turn: the old session read under a lock, a new one
        made, and the record of the provider's session moved to it (the rules it asks before are left out)."""
        with SessionLocal() as s:
            user = s.get(User, alice)
            here.stay = 1.6
            api._sessions_turn(s, alice)
            old_row = (s.query(ActiveSession).filter(ActiveSession.user_id == alice)
                       .populate_existing().with_for_update().first())
            auth = AuthService(s)
            new_session = auth._create_session(user, None, IP, expires_at=datetime.utcnow() + timedelta(hours=1),
                                               channel=auth.WEB, commit=False)
            sign_in.carry_renewed_provider_session(s, old_row, new_session)
            s.commit()
            return "renewed"

    def save():
        with SessionLocal() as s:
            row = R._row_or_404(s, contoso, lock=True)
            row.policy = {"sso_backchannel_logout": True, "sso_password_login": "disabled"}
            changed = sso_only.apply_password_login(s, row)
            s.commit()
            return len(changed["made_sso_only"])
    out = together(writer=renewal, ender=after_the_turn_is_held(save))
elif pair == "a row held for longer than a sign-in waits":
    def hold_the_row():
        with SessionLocal() as s:
            R._row_or_404(s, contoso, lock=True)
            in_turn.set()
            time.sleep(2.5)
            s.rollback()
            return "let go"
    out = together(holder=hold_the_row, writer=after_the_turn_is_held(through_the_provider(alice, contoso, "s-1")))
out["after"], out["the turn was held"] = state(alice, contoso), in_turn.is_set()
print(json.dumps(out))
'''

REFUSED = ["error", "HTTPException", "401", "This sign-in cannot be completed; start again."]


def test_a_provider_turned_off_while_a_sign_in_is_written_waits_for_it_and_ends_its_session(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "turned off while a sign-in is written"})
    assert out["writer"] == ["ok", "signed in"] and out["ender"] == ["ok", 1], out
    assert out["the turn was held"] is True, out
    assert out["ender seconds"] >= 1.0, out                  # the turn-off waited for the row the sign-in held
    after = out["after"]
    assert after["provider"] == "disabled" and after["sessions"] == [[False, True]], out


def test_a_sign_in_written_after_its_provider_was_turned_off_is_refused_and_writes_nothing(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a sign-in after the turn-off"})
    assert out["ender"] == ["ok", 0] and out["writer"] == REFUSED, out
    assert out["after"]["sessions"] == [] and out["after"]["provider sessions"] == 0, out


def test_a_providers_logout_while_a_sign_in_through_its_session_is_written_ends_what_was_written(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "logged out while a sign-in is written"})
    assert out["writer"] == ["ok", "signed in"] and out["ender"] == ["ok", 200], out
    assert out["the turn was held"] is True, out
    assert out["ender seconds"] >= 1.0, out                  # the logout waited for the row the sign-in held
    assert out["after"]["sessions"] == [[False, True]] and out["after"]["provider"] == "enabled", out


def test_a_sign_in_through_a_provider_session_that_was_logged_out_is_refused_and_another_is_not(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a sign-in after the logout"})
    assert out["ender"] == ["ok", 200] and out["writer"] == REFUSED, out
    assert out["other"] == ["ok", "signed in"], out          # another session of the provider's is its own sign-in
    assert out["again"] == ["ok", "signed in"], out          # answered after the logout: a new sign-in
    assert out["after"]["sessions"] == [[True, False], [True, False]] and out["after"]["provider sessions"] == 2, out


def test_a_provider_saved_while_a_held_sign_in_sets_a_factor_up_waits_and_both_finish(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "saved while a held sign-in sets a factor up"})
    assert out["writer"] == ["ok", "signed in"] and out["ender"] == ["ok", "saved"], out
    assert out["the turn was held"] is True, out
    assert out["ender seconds"] >= 1.0, out                  # the save waited for the row; nothing waited in a ring
    after = out["after"]
    assert after["sessions"] == [[True, False]] and after["held open"] == 0 and after["sso only"] is False, out


def test_a_provider_saved_while_a_renewal_moves_the_providers_session_waits_and_both_finish(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "saved while a renewal moves the provider's session"})
    assert out["writer"] == ["ok", "renewed"] and out["ender"] == ["ok", 1], out
    assert out["the turn was held"] is True, out
    assert out["ender seconds"] >= 1.0, out                  # the save waited for the turn; nothing waited in a ring
    assert out["after"]["sso only"] is True and out["after"]["provider sessions"] == 2, out


def test_a_sign_in_waits_a_short_time_for_a_providers_row_that_is_held_and_is_answered_as_busy(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a row held for longer than a sign-in waits"})
    assert out["holder"] == ["ok", "let go"], out
    assert out["writer"][:3] == ["error", "HTTPException", "503"] and "busy" in out["writer"][3], out
    assert 0.3 <= out["writer seconds"] < 1.5, out           # its own short wait: not the 2.5 s, nor the connection's 5
    assert out["after"]["sessions"] == [] and out["after"]["provider sessions"] == 0, out
