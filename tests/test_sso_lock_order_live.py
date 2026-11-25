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

- a link of the account to a second provider whose people hold no password, and a save that lets the people of
  the first hold a password again. Both are decided in the account's turn: the link that comes while the save
  holds it waits, reads the flag the save left and holds the account to the provider it links; the save that
  comes while the link holds it waits and finds the link. Decided outside the turn, the link changed nothing on a
  flag the save was changing, and left the account linked to such a provider with a password it could set again.
  A turn held for longer than a link waits refuses the link as busy, with nothing linked.

- a reset link the person asked for, used while a save holds the accounts the provider made to the provider
  (the account was made at a first sign-in and its password is still the one nobody knows). Both take the
  account's turn. The save first: the reset reads the flag again in its turn and is refused as an unknown
  link; decided on the flag read before, it wrote the chosen password onto an account that holds none. The
  reset first: the save finds an account with a password of its own and leaves it.

- an identity unlinked, by an administrator or by its owner, while a sign-in through it is written. The unlink
  ends the sessions that came through the identity, and it reads them before it removes it: read while the
  sign-in's session was not committed yet, there was none to end, and the session then stood through an identity
  that was gone. Both take the account's turn: the unlink waits for the sign-in and ends its session, and a
  sign-in that comes after the unlink finds no identity and writes nothing.

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
from app.core import password_origin, password_reset, sign_in_lockout, sso_only
from app.core.models import (ActiveSession, ExternalIdentity, PasswordResetToken, PendingLogin, RoleEnum,
                             SsoProvider, SsoSession, User)
from app.core.rate_limiter import rate_limiter
from app.core.security import hash_password, verify_password
from app.services import oidc_client as oc
from app.services import sign_in, sso_sign_in
from app.services.auth_service import AuthService

IP, SUBJECT, CHOSEN = "192.0.2.44", "subject-1", "Chosen-With-A-Link-1!"
REQUEST = types.SimpleNamespace(headers={}, client=types.SimpleNamespace(host=IP), state=types.SimpleNamespace(),
                                base_url="https://vault.example.com/", url=types.SimpleNamespace(path="/"))
api._notify_account_change = lambda *a, **k: None
api._fire_action_email = lambda *a, **k: None
api._force_close_after_commit = lambda *a, **k: None
sign_in._record = lambda *a, **k: None
sso_router._audit = lambda *a, **k: None
# The store's memory of the providers' logouts is whole from before the sign-ins of this scenario: they begin
# nowhere but here, and a sign-in that begins at the vault marks the memory at its own start
# (app/core/sso_state.logout_memory_reaches). On a store nothing has touched yet, the first sign-in written here
# would otherwise count as begun before the memory.
from app.core import sso_state as _memory
_memory.logout_memory_reaches()
# The provider's logout: its token is taken as verified, with the claims the scenario gives it.
rate_limiter.check_rate_limit = lambda **kw: (True, 0, 0)
sso_sign_in.provider_config = lambda row: object()
oc.discover = lambda provider, fetch=None: {}
logout_claims = {}
oc.verify_logout_token = lambda provider, discovery, token, fetch=None, seen_jti=None: dict(logout_claims)


def account(name, role=RoleEnum.USER):
    with SessionLocal() as s:
        u = User(username=name + "-" + uuid.uuid4().hex[:6], email=None, password_hash=hash_password("Old-Password-8x!"),
                 role=role, is_active=True, is_locked=False)
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
                "links": s.query(ExternalIdentity).filter(ExternalIdentity.user_id == uid).count(),
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


def second_provider():
    """Another provider that is on, whose people hold no password."""
    with SessionLocal() as s:
        row = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name="fabrikam-" + uuid.uuid4().hex[:6],
                          label="Fabrikam", issuer="https://idp2.example/", client_id="c", client_secret_enc="e",
                          policy={"sso_password_login": "disabled"})
        s.add(row)
        s.commit()
        return row.id


def held_to(uid, pid):
    """The account as a provider whose people hold no password leaves it: linked, and flagged."""
    with SessionLocal() as s:
        s.get(SsoProvider, pid).policy = {"sso_password_login": "disabled"}
        s.get(User, uid).sso_only = True
        s.commit()


def allow_passwords_again(pid, pause=0.0):
    """The save of the provider's password rule, as its route makes it: the one unknown password hashed first,
    the row taken, the linked accounts settled in their turns."""
    def run():
        ready = sso_only.a_password_nobody_knows()
        with SessionLocal() as s:
            row = R._row_or_404(s, pid, lock=True)
            row.policy = {"sso_password_login": "allowed"}
            here.stay = pause
            changed = sso_only.apply_password_login(s, row, unknown_hash=ready)
            s.commit()
            return "restored" if changed["restored"] else "left as it was"
    return run


def link_to(uid, pid, pause=0.0):
    """The link from Your account, as its route makes it: the provider's row read and held, then the link."""
    def run():
        with SessionLocal() as s:
            row = sso_router._provider_as_it_stands(s, pid)
            user = s.get(User, uid)
            answer = types.SimpleNamespace(issuer="https://idp2.example/", subject="subject-q", tenant_id=None,
                                           email=None, display_name=None)
            here.stay = pause
            sso_sign_in.link_identity(s, row, user, answer, linked_by="self")
            s.commit()
            return "linked"
    return run


def made_at_a_first_sign_in():
    """An account a provider made at a first sign-in while it let such accounts set a password: not flagged, its
    password still the one nobody knows."""
    with SessionLocal() as s:
        row = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name="made-" + uuid.uuid4().hex[:6],
                          label="Made", issuer="https://idp3.example/", client_id="c", client_secret_enc="e",
                          policy={"sso_jit_password": True})
        s.add(row)
        u = User(username="jay-" + uuid.uuid4().hex[:6], email=None, password_hash=sso_only.a_password_nobody_knows(),
                 role=RoleEnum.USER, is_active=True, is_locked=False)
        s.add(u)
        s.flush()
        password_origin.mark_nobody_knows(u)
        s.add(ExternalIdentity(user_id=u.id, provider_id=row.id, issuer="https://idp3.example/", subject="subject-j",
                               subject_source="oidc:sub", linked_by="jit"))
        s.commit()
        return u.id, row.id


def the_made_here_rule_saved(pid, pause=0.0):
    """The provider stops letting the accounts it made set a password: saved as the route saves it."""
    def run():
        ready = sso_only.a_password_nobody_knows()
        with SessionLocal() as s:
            row = R._row_or_404(s, pid, lock=True)
            row.policy = {"sso_jit_password": False}
            here.stay = pause
            changed = sso_only.apply_password_login(s, row, unknown_hash=ready)
            s.commit()
            return "held" if changed["made_sso_only"] else "left as it was"
    return run


def a_reset_link_of_its_own(uid, pause=0.0):
    """A reset link the person asked for, used."""
    token, prefix = password_reset.mint_reset_token()
    with SessionLocal() as s:
        s.add(PasswordResetToken(user_id=uid, token_prefix=prefix,
                                 token_hash=password_reset.hash_reset_token(token, api._reset_pepper()),
                                 expires_at=datetime.utcnow() + timedelta(minutes=5), created_by=None,
                                 made_by_other=False))
        s.commit()

    def run():
        with SessionLocal() as s:
            here.stay = pause
            asyncio.run(api.do_reset(token=token, body=api.ResetPasswordRequest(new_password=CHOSEN), request=REQUEST,
                                     db=s))
            return "reset"
    return run


def identity_of(uid, pid):
    with SessionLocal() as s:
        return s.query(ExternalIdentity).filter(ExternalIdentity.user_id == uid,
                                                ExternalIdentity.provider_id == pid).first().id


def an_unlink(identity_id, by, as_administrator):
    """The route itself: DELETE /admin/sso/identities/{id} as an administrator, DELETE /users/me/identities/{id}
    as the identity's owner. What is not the database stands still."""
    from app.api import sso_admin_router as A
    A._step_up = lambda *a, **k: None
    A._audit = lambda *a, **k: None
    R._tell_administrators = lambda *a, **k: None
    sso_router._tell_owner = lambda *a, **k: None
    api._enforce_step_up = lambda *a, **k: None
    api._notify_users = lambda *a, **k: []
    # The provider's confirmation of an owner's unlink is kept beside the session, not in the database: it
    # stands still here too. test_sso_unlink_asks_the_provider.py holds it.
    sso_sign_in.unlink_asks_the_provider = lambda *a, **k: False

    def run():
        with SessionLocal() as s:
            who = s.get(User, by)
            if as_administrator:
                return A.unlink_identity(identity_id=str(identity_id), request=REQUEST, current_user=who,
                                         db=s)["sessions_ended"]
            return asyncio.run(sso_router.unlink_my_identity(identity_id=identity_id, request=REQUEST,
                                                             current_user=who, db=s))["sessions_ended"]
    return run


def password_of(uid):
    with SessionLocal() as s:
        u = s.get(User, uid)
        return {"sso only": bool(u.sso_only), "nobody knows": password_origin.nobody_knows(u),
                "the chosen one": bool(verify_password(CHOSEN, u.password_hash)),
                "links left": s.query(PasswordResetToken).filter(PasswordResetToken.user_id == uid).count()}


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
elif pair == "a reset link used while a save holds the account to its provider":
    jay, made = made_at_a_first_sign_in()
    # The save holds the turn for less than the connection waits, and longer than a ring of waiters takes to
    # be found: the reset is to wait for it, and to decide on what it left.
    out = together(ender=the_made_here_rule_saved(made, pause=1.6),
                   writer=after_the_turn_is_held(a_reset_link_of_its_own(jay)))
    out["the account"] = password_of(jay)
elif pair == "the rule saved while a reset link is used":
    jay, made = made_at_a_first_sign_in()
    out = together(writer=a_reset_link_of_its_own(jay, pause=1.6),
                   ender=after_the_turn_is_held(the_made_here_rule_saved(made)))
    out["the account"] = password_of(jay)
elif pair == "linked while a save lets the account hold a password again":
    fabrikam = second_provider()
    held_to(alice, contoso)
    # The save holds the turn for less than a link waits: the link is to wait for it, not to be sent away.
    out = together(ender=allow_passwords_again(contoso, pause=0.2),
                   writer=after_the_turn_is_held(link_to(alice, fabrikam)))
elif pair == "saved while a link is decided":
    fabrikam = second_provider()
    held_to(alice, contoso)
    out = together(writer=link_to(alice, fabrikam, pause=1.6),
                   ender=after_the_turn_is_held(allow_passwords_again(contoso)))
elif pair == "a link while the account's turn is held":
    fabrikam = second_provider()

    def hold_the_turn():
        with SessionLocal() as s:
            _take(s, alice)
            in_turn.set()
            time.sleep(2.5)
            s.rollback()
            return "let go"
    out = together(holder=hold_the_turn, writer=after_the_turn_is_held(link_to(alice, fabrikam)))
elif pair.startswith("unlinked by "):
    by_an_administrator = "an administrator" in pair
    unlink = an_unlink(identity_of(alice, contoso), account("root", RoleEnum.ADMIN) if by_an_administrator else alice,
                       by_an_administrator)
    if pair.endswith("while a sign-in is written"):
        out = together(writer=through_the_provider(alice, contoso, "s-1", pause=1.6),
                       ender=after_the_turn_is_held(unlink))
        if not by_an_administrator:
            # The owner's route waits a short time only: it is tried again once the sign-in is written.
            try:
                out["again"] = ["ok", unlink()]
            except Exception as exc:  # noqa: BLE001
                out["again"] = ["error", type(exc).__name__, str(getattr(exc, "status_code", ""))]
    else:
        out = {"ender": ["ok", unlink()]}
        out.update(together(writer=through_the_provider(alice, contoso, "s-1")))
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


def test_a_link_that_comes_while_a_save_restores_the_account_waits_and_decides_on_what_the_save_left(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "linked while a save lets the account hold a password again"})
    assert out["ender"] == ["ok", "restored"] and out["writer"] == ["ok", "linked"], out
    assert out["the turn was held"] is True, out
    assert out["writer seconds"] >= 0.15, out                # the link waited for the turn the save held
    assert out["after"]["links"] == 2 and out["after"]["sso only"] is True, out      # held by the one it linked


def test_a_save_that_comes_while_a_link_is_decided_waits_and_finds_the_link(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "saved while a link is decided"})
    assert out["writer"] == ["ok", "linked"] and out["ender"] == ["ok", "left as it was"], out
    assert out["the turn was held"] is True, out
    assert out["ender seconds"] >= 1.0, out                  # the save waited for the turn; nothing waited in a ring
    assert out["after"]["links"] == 2 and out["after"]["sso only"] is True, out


def test_a_link_waits_a_short_time_for_a_turn_that_is_held_and_is_refused_as_busy(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a link while the account's turn is held"})
    assert out["holder"] == ["ok", "let go"], out
    assert out["writer"] == ["error", "Refusal", "", "account_busy"], out
    assert 0.3 <= out["writer seconds"] < 1.5, out           # its own short wait: not the 2.5 s, nor the connection's 5
    assert out["after"]["links"] == 1 and out["after"]["sso only"] is False, out


def test_a_reset_link_used_while_a_save_holds_the_account_to_its_provider_waits_and_sets_no_password(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "a reset link used while a save holds the account to its provider"})
    assert out["ender"] == ["ok", "held"], out
    assert out["writer"][:3] == ["error", "HTTPException", "404"], out
    assert out["the turn was held"] is True and out["writer seconds"] >= 1.0, out    # it waited for the turn
    assert out["the account"] == {"sso only": True, "nobody knows": True, "the chosen one": False,
                                  "links left": 0}, out


def test_a_save_that_comes_while_a_reset_link_is_used_waits_and_leaves_the_password_the_person_chose(db_name):
    out = run_in(db_name, SCENARIO, env={"PAIR": "the rule saved while a reset link is used"})
    assert out["writer"] == ["ok", "reset"] and out["ender"] == ["ok", "left as it was"], out
    assert out["the turn was held"] is True and out["ender seconds"] >= 1.0, out     # the save waited for the turn
    assert out["the account"] == {"sso only": False, "nobody knows": False, "the chosen one": True,
                                  "links left": 1}, out


@pytest.mark.parametrize("by", ["an administrator", "its owner"])
def test_an_identity_unlinked_while_a_sign_in_through_it_is_written_waits_and_ends_its_session(db_name, by):
    """Both unlinks take the account's turn before they read its identities. The administrator's waits for the
    sign-in that holds it and then ends the session it wrote. The owner's runs on the server's one loop and waits
    a short time only: it is answered as busy with nothing unlinked, and tried again it ends the session."""
    out = run_in(db_name, SCENARIO, env={"PAIR": f"unlinked by {by} while a sign-in is written"})
    assert out["writer"] == ["ok", "signed in"], out
    assert out["the turn was held"] is True, out
    if by == "an administrator":
        assert out["ender"] == ["ok", 1], out                # the session the sign-in wrote, ended by the unlink
        assert out["ender seconds"] >= 1.0, out              # it waited for the turn
    else:
        assert out["ender"][:3] == ["error", "HTTPException", "503"], out
        assert out["ender seconds"] < 1.5, out               # a link's short wait, not the sign-in's time
        assert out["again"] == ["ok", 1], out                # tried again: the session the sign-in wrote, ended
    after = out["after"]
    assert after["links"] == 0 and after["sessions"] == [[False, True]], out


@pytest.mark.parametrize("by", ["an administrator", "its owner"])
def test_a_sign_in_through_an_identity_that_was_unlinked_is_refused_and_writes_nothing(db_name, by):
    out = run_in(db_name, SCENARIO, env={"PAIR": f"unlinked by {by} before a sign-in"})
    assert out["ender"] == ["ok", 0] and out["writer"][:3] == ["error", "HTTPException", "401"], out
    after = out["after"]
    assert after["links"] == 0 and after["sessions"] == [] and after["provider sessions"] == 0, out
