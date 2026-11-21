"""Every way an address reaches an account, and whose word it then is (app/core/email_confirmation.py). Offline.

Only an address the vault itself confirmed links an account to a single sign-on provider by email. So each path
that writes an address is held here to what it may say of it: the invitation form confirms the address the
invitation carried and never one the person typed; an administrator's change confirms; a person's own change with
the password does not; the code sent to a new address does; and the statement that confirms, once, the accounts
made from an invitation before the mark existed confirms those and nobody else.
"""
import hashlib
import sqlite3
import uuid
from types import SimpleNamespace

import pytest

from _async_run import run_coroutine
from test_admin_invitations import _accepting, _invite, _user, api, db  # noqa: F401  (the fixture is used by name)

from app.core import credential_changes as cc  # noqa: E402
from app.core import email_confirmation  # noqa: E402
from app.core.models import RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit

REQUEST = SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.9"), cookies={}, url=SimpleNamespace(path="/"))


def _account(db, name, email, *, confirmed=False):
    user = User(username=name, email=email, password_hash="x", role=RoleEnum.USER, is_active=True, is_locked=False)
    if confirmed:
        email_confirmation.confirm(user)
    db.add(user)
    db.commit()
    return user


# --------------------------------------------------------------------------- the invitation form

@pytest.mark.parametrize("carried, typed, holds, confirmed", [
    ("invited@example.test", None, "invited@example.test", True),
    ("invited@example.test", "typed@example.com", "invited@example.test", True),   # the form's own is not read
    (None, "typed@example.com", "typed@example.com", False),
    (None, None, None, False),
])
def test_the_form_confirms_the_address_an_invitation_carried_and_never_one_the_person_typed(
        db, monkeypatch, carried, typed, holds, confirmed):
    root = _user(db, "root")
    _accepting(monkeypatch)
    inv, token = _invite(db, root, "newbie", role="user")
    inv.email = carried
    db.commit()
    run_coroutine(api.accept_invite(token=token, payload=api.InviteAccept(password="Accept-Passw0rd!123", email=typed),
                                    request=REQUEST, db=db))
    user = db.query(User).filter(User.username == "newbie").one()
    assert user.email == holds
    assert email_confirmation.confirmed(user) is confirmed and (user.email_confirmed_at is not None) is confirmed


# --------------------------------------------------------------------------- an administrator's change, a person's own

def test_an_administrators_change_confirms_the_address_and_the_persons_own_change_does_not(db, monkeypatch):
    """The administrator's change goes through the one function every credential change does; the person's own
    goes through the account route with the current password. The code sent to a new address confirms it."""
    from app.core import otp_service, rate_limiter, security
    root = _user(db, "root")
    carol = _account(db, "carol", "typed@example.com")
    assert email_confirmation.confirmed(carol) is False
    out = api._make_credential_change(db, cc.EMAIL, carol, {"email": "set@example.test"}, actor_id=root.id,
                                      actor_name="root")
    db.commit()
    assert out == {"old_email": "typed@example.com", "new_email": "set@example.test"}
    assert carol.email == "set@example.test" and email_confirmation.confirmed(carol) is True
    # The person changes it with the current password: their own claim, whatever it says.
    monkeypatch.setattr(security, "verify_password", lambda given, stored: given == "the-password")
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(api, "_email_change_requires_verification", lambda db: False)
    monkeypatch.setattr(api, "get_client_ip", lambda request: "192.0.2.9")
    monkeypatch.setattr(api.UserResponse, "model_validate", classmethod(lambda cls, user: {"email": user.email}))
    run_coroutine(api.update_own_account(
        body=api.SelfUpdate(current_password="the-password", email="mine@example.com"), request=REQUEST,
        current_user=carol, db=db))
    db.refresh(carol)
    assert carol.email == "mine@example.com" and email_confirmation.confirmed(carol) is False
    assert carol.email_confirmed_at is None and carol.email_confirmed_for is None
    # The code the vault sent to a new address: typed back, the address is the account's and confirmed.
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(otp_service, "verify", lambda db, **kw: SimpleNamespace(
        ok=kw["code"] == "123456" and kw["purpose"] == "email_change", destination="proved@example.test"))
    with pytest.raises(api.HTTPException):
        run_coroutine(api.confirm_email_change(body=api.EmailChangeConfirm(code="000000"), request=REQUEST,
                                               current_user=carol, db=db))
    assert carol.email == "mine@example.com" and email_confirmation.confirmed(carol) is False
    run_coroutine(api.confirm_email_change(body=api.EmailChangeConfirm(code="123456"), request=REQUEST,
                                           current_user=carol, db=db))
    assert carol.email == "proved@example.test" and email_confirmation.confirmed(carol) is True


# --------------------------------------------------------------------------- the one-time statement

def _backfill_database():
    """The two tables the statement reads, in SQLite, with the database functions it names standing in for
    PostgreSQL's (what they compute against a real PostgreSQL is held by the live test of the same statement)."""
    assert sqlite3.sqlite_version_info >= (3, 33), "UPDATE ... FROM needs SQLite 3.33"
    con = sqlite3.connect(":memory:")
    con.create_function("btrim", 1, lambda s: s.strip(" ") if s is not None else None)
    con.create_function("convert_to", 2, lambda s, _enc: s.encode("utf-8") if s is not None else None)
    con.create_function("sha256", 1, lambda b: hashlib.sha256(b).digest() if b is not None else None)
    con.create_function("encode", 2, lambda b, _how: b.hex() if b is not None else None)
    con.execute("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, email_confirmed_at TEXT, email_confirmed_for TEXT)")
    con.execute("CREATE TABLE account_invitations (id TEXT PRIMARY KEY, accepted_user_id TEXT, accepted_at TEXT, email TEXT)")
    return con


def test_the_one_time_statement_confirms_the_accounts_an_invitation_vouched_for_and_nobody_else():
    """Run as it is written. An account is confirmed when the invitation it was made from carried the address it
    still holds; not when the invitation carried none (the person typed it), not when the account holds another
    address since, not while the invitation is not accepted, and never an account without an address. The mark
    is for the address as the vault compares addresses, so letter case on either side changes nothing, and a
    mark that is already whole is left as it is."""
    con = _backfill_database()
    accepted = "2026-03-01 10:00:00"
    cases = {
        # name: (the account's address, its marks, the invitation's address, accepted at, confirmed afterwards)
        "carried and still held": ("ann@example.test", (None, None), "ann@example.test", accepted, True),
        "carried in other letters": ("Bea@Example.Test", (None, None), "bea@example.test", accepted, True),
        "held with spaces around": (" cy@example.test ", (None, None), " cy@example.test ", accepted, True),
        "half a mark": ("dee@example.test", ("2026-01-01 00:00:00", None), "dee@example.test", accepted, True),
        "the invitation carried none": ("eve@example.test", (None, None), None, accepted, False),
        "another address since": ("fay@other.test", (None, None), "fay@example.test", accepted, False),
        "not accepted": ("gil@example.test", (None, None), "gil@example.test", None, False),
        "no address": (None, (None, None), "hal@example.test", accepted, False),
        "no invitation": ("ida@example.test", (None, None), ..., None, False),
        "confirmed already": ("jo@example.test", ("2026-02-02 02:02:02", email_confirmation.mark_for("jo@example.test")),
                              "jo@example.test", accepted, True),
    }
    for name, (email, marks, carried, when, _expected) in cases.items():
        con.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (name, email, *marks))
        if carried is not ...:
            con.execute("INSERT INTO account_invitations VALUES (?, ?, ?, ?)", (str(uuid.uuid4()), name, when, carried))
    # An invitation another account accepted, carrying this account's address, vouches for nothing here.
    con.execute("INSERT INTO account_invitations VALUES (?, ?, ?, ?)", (str(uuid.uuid4()), "somebody else", accepted, "ida@example.test"))
    changed = con.execute(email_confirmation.BACKFILL).rowcount
    rows = {r[0]: r[1:] for r in con.execute("SELECT id, email, email_confirmed_at, email_confirmed_for FROM users")}
    for name, (email, marks, _carried, _when, expected) in cases.items():
        _email, at, mark = rows[name]
        user = SimpleNamespace(email=email, email_confirmed_at=at, email_confirmed_for=mark)
        assert email_confirmation.confirmed(user) is expected, name
        if name == "confirmed already":
            assert (at, mark) == marks, "a whole mark is left as it is"
        elif expected:
            assert at == accepted and mark == email_confirmation.mark_for(email), name       # as of the acceptance
        else:
            assert (at, mark) == marks, name
    assert changed == 4
    # Run again it finds nothing left to confirm (the vault runs it once all the same: backfill_once).
    assert con.execute(email_confirmation.BACKFILL).rowcount == 0


def test_the_statement_runs_once_and_never_again(db):
    """Run at every start, it would confirm again an address the account lost and its owner then typed back with
    the password alone. The note that it ran is what stops it."""
    from sqlalchemy import text
    ran = []

    class _Once:
        def query(self, model):
            return db.query(model)

        def execute(self, statement):
            ran.append(str(statement))
            return SimpleNamespace(rowcount=3)

        def add(self, row):
            db.add(row)

        def commit(self):
            db.commit()

    assert email_confirmation.backfill_once(_Once()) == 3 and ran == [str(text(email_confirmation.BACKFILL))]
    assert email_confirmation.backfill_once(_Once()) == 0 and len(ran) == 1
