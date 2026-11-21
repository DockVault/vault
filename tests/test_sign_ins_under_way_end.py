"""What ends an account's sessions ends its sign-ins under way too, on each route that does it, on a real database.

A sign-in held for a further step (the second factor, the password, the set-up of a factor) lives five minutes
and was proved by what the account had when it began. Where the account's sessions are ended because how it
signs in changed, or because it is locked, turned off or taken back at a promotion, that held sign-in is spent
with them, and so is an authenticator app the account had begun to set up and not finished: whoever began it
knows its secret. Another account's held sign-in and set-up are left alone. The routes an administrator's
password, second-factor reset, sign-out everywhere and removal of a last passkey go through are driven in
test_passkey_settings_hardening.py; here are the others, each driven as the route itself.
"""
from datetime import datetime, timedelta

import pytest

from _async_run import run_coroutine
from test_password_origin import (OLD, PROMOTE, _link, _request, _use, _user, api, po, um,  # noqa: F401
                                  world)                      # (world is a fixture, used by name)

from app.core import credential_changes as cc  # noqa: E402
from app.core.models import (PendingLogin, RoleEnum, SecondFactorEnrollment,  # noqa: E402
                             SecondFactorRecoveryCode)

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    """A database with every table of the model, as the vault's own has."""
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


@pytest.fixture
def under_way(db):
    """Gives each account it is called with a held sign-in and an authenticator begun and not finished (its
    secret shown, a code confirmed, two recovery codes made)."""
    def begin(*users):
        for user in users:
            db.add(PendingLogin(user_id=user.id, client_ip="192.0.2.44", enrollment_required=True,
                                expires_at=datetime.utcnow() + timedelta(minutes=5)))
            db.add(SecondFactorEnrollment(user_id=user.id, method="totp", secret_enc="sealed", status="unconfirmed",
                                          confirmed_at=datetime.utcnow()))
            for prefix in ("aaaaaaaa", "bbbbbbbb"):
                db.add(SecondFactorRecoveryCode(user_id=user.id, code_prefix=prefix, code_hash="h"))
        db.commit()
    return begin


def _left(db, user):
    """(held sign-ins still open, held sign-ins spent, set-ups begun, recovery codes) of ``user``, as another
    connection finds them: what the route committed, not what it left in its own transaction."""
    from sqlalchemy.orm import sessionmaker
    other = sessionmaker(bind=db.get_bind())()
    try:
        held = other.query(PendingLogin).filter(PendingLogin.user_id == user.id)
        return (held.filter(PendingLogin.consumed_at.is_(None)).count(),
                held.filter(PendingLogin.consumed_at.isnot(None)).count(),
                other.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == user.id).count(),
                other.query(SecondFactorRecoveryCode).filter(SecondFactorRecoveryCode.user_id == user.id).count())
    finally:
        other.close()


def _a_reset_link_used(db, ada, alice, monkeypatch):
    monkeypatch.setattr(api, "_reset_link_refusal", lambda *a, **k: None)
    assert _use(db, _link(db, alice, created_by=None, made_by_other=False)) == {"ok": True}


def _its_own_change(db, ada, alice, monkeypatch):
    run_coroutine(api.update_own_account(body=api.SelfUpdate(current_password=OLD, new_password="Mine-Now-8x!"),
                                         request=_request(), current_user=alice, db=db))


def _an_administrators_password(db, ada, alice, monkeypatch):
    api._apply_credential_change(db, cc.PASSWORD, alice, {"password_hash": "h"}, actor_id=ada.id, actor_name="ada")
    db.commit()


def _promoted(route):
    def promote(db, ada, alice, monkeypatch):
        po.set_by_other(alice, ada.id)             # a password somebody else set: taken back at the promotion
        db.commit()
        PROMOTE[route](db, ada, alice)
    return promote


def _patched(**change):
    def patch(db, ada, alice, monkeypatch):
        run_coroutine(api.update_user(user_id=alice.id, user_update=api.UserUpdate(**change), current_user=ada,
                                      db=db, request=_request()))
    return patch


def _turned_off_in_user_management(db, ada, alice, monkeypatch):
    run_coroutine(um.update_user(user_id=alice.id, update_data=um.UserUpdateRequest(is_active=False),
                                 request=_request(), current_user=ada, db=db))


def _toggled(route):
    def toggle(db, ada, alice, monkeypatch):
        run_coroutine(getattr(um, route)(user_id=alice.id, current_user=ada, db=db, request=_request()))
    return toggle


ENDS = {
    "a reset link used": _a_reset_link_used,
    "the account's own change of its password": _its_own_change,
    "an administrator's new password": _an_administrators_password,
    "a lock, PATCH /users/{id}": _patched(is_locked=True),
    "a deactivation, PATCH /users/{id}": _patched(is_active=False),
    "a deactivation, PUT /api/user-management/users/{id}": _turned_off_in_user_management,
    "a deactivation, the user-management switch": _toggled("toggle_user_active"),
    "a lock, the user-management switch": _toggled("toggle_user_locked"),
    **{f"a password taken back at a promotion, {route}": _promoted(route) for route in sorted(PROMOTE)},
}


@pytest.mark.parametrize("what", sorted(ENDS))
def test_what_ends_an_accounts_sessions_ends_its_sign_ins_under_way_and_a_set_up_left_half_way(
        db, world, under_way, monkeypatch, what):
    """Mallory knows Alice's password and holds a sign-in of hers at the set-up of a factor; she has begun an
    authenticator there and knows its secret. Whatever then ends Alice's sessions spends that sign-in and removes
    the set-up, so its last step, sent later from a session of Alice's own, makes nothing of Mallory's the
    account's second factor. Bob's are his own and stay."""
    ada, alice, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "alice"), _user(db, "bob")
    under_way(alice, bob)
    assert _left(db, alice) == _left(db, bob) == (1, 0, 1, 2)
    ENDS[what](db, ada, alice, monkeypatch)
    assert world.revoked.count(alice.id) >= 1 and bob.id not in world.revoked, "the sessions it ended are Alice's"
    assert _left(db, alice) == (0, 1, 0, 0)
    assert _left(db, bob) == (1, 0, 1, 2)


def test_a_reset_link_spends_them_in_the_transaction_that_writes_the_password(db, world, under_way, monkeypatch):
    """The reset writes the password, ends the sessions and spends the sign-ins under way in one transaction: both
    commit, or neither does. Spent only after the password was committed, a failure in between would leave the new
    password with the old one's held sign-in alive."""
    from sqlalchemy.orm import Session
    from app.core.models import User
    from app.services import sign_in
    alice = _user(db, "alice")
    under_way(alice)
    before, seen, spend = alice.password_hash, [], sign_in.spend_sign_ins_under_way

    def spent_when(db_, user_id):
        with Session(bind=db.get_bind()) as other:          # what has been committed by now
            seen.append((user_id, other.get(User, alice.id).password_hash == before))
        return spend(db_, user_id)
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", spent_when)
    _a_reset_link_used(db, None, alice, monkeypatch)
    assert seen == [(alice.id, True)], "the new password was committed before the sign-ins under way were spent"
    assert _left(db, alice) == (0, 1, 0, 0)


def test_an_authenticator_in_use_and_its_codes_stay(db, world, under_way):
    """Only a set-up that was not finished goes: an authenticator the account uses, and its recovery codes, are
    the account's own and are not touched by what ends its sessions."""
    from app.services import sign_in
    ada, alice = _user(db, "ada", RoleEnum.ADMIN), _user(db, "alice")
    under_way(alice)
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == alice.id).update({"status": "active"})
    db.commit()
    assert sign_in.spend_sign_ins_under_way(db, alice.id) == 1
    db.commit()
    assert _left(db, alice) == (0, 1, 1, 2)
