"""A password set on an account, and a provider's save that holds the account to no password, made to meet
(app/api/api_server.py do_reset, _make_credential_change; app/core/sso_only.py settle).

Both take the account's turn. The save first: what sets a password reads the flag again once it has the turn and
refuses, as it refuses an account it finds flagged. Decided on the flag read before the turn, a reset link wrote
the person's chosen password onto an account that signs in only through its provider; the account's next
settling took that for a password of its own and let the account go, for good. Offline, on a database with every
table; the turn itself is PostgreSQL's and is stood in for by what runs when it is asked for.
tests/test_sso_lock_order_live.py makes the two meet on PostgreSQL, in both orders."""
import pytest
from fastapi import HTTPException

from test_password_origin import _link, _use, _user, api, cc, world  # noqa: F401
from test_sso_unlink_meets_the_password_rule import _another, db  # noqa: F401

pytestmark = pytest.mark.unit

RANDOM = "argon2:of-random-bytes"


def _held_meanwhile(db, account_id, turns):
    """What the account's turn gives way to once: a provider's save that made the account sign in only through
    it, committed."""
    from app.core import password_origin
    from app.core.models import User

    def turn(session, owner):
        turns.append(str(owner))
        if len(turns) > 1:
            return
        other = _another(db)
        account = other.get(User, account_id)
        account.sso_only, account.password_hash = True, RANDOM
        password_origin.mark_nobody_knows(account)
        other.commit()
        other.close()
    return turn


def _as_it_stands(db, account_id):
    from app.core import password_origin
    from app.core.models import User
    after = _another(db)
    try:
        account = after.get(User, account_id)
        return bool(account.sso_only), account.password_hash, password_origin.nobody_knows(account)
    finally:
        after.close()


def test_a_reset_link_used_while_the_account_is_held_to_its_provider_sets_no_password(db, world, monkeypatch):
    from app.core.models import AuditLog, PasswordResetToken
    jay = _user(db, "jay")
    token = _link(db, jay, created_by=None, made_by_other=False)        # the person asked for it
    turns = []
    monkeypatch.setattr(api, "_sessions_turn", _held_meanwhile(db, jay.id, turns))
    with pytest.raises(HTTPException) as refused:
        _use(db, token)
    assert refused.value.status_code == 404 and refused.value.detail == "This reset link is invalid or has expired."
    assert turns == [str(jay.id)]
    assert _as_it_stands(db, jay.id) == (True, RANDOM, True)             # as the save left it: no password of its own
    after = _another(db)
    assert after.query(PasswordResetToken).count() == 0                  # the link is gone, as for any refused link
    row = after.query(AuditLog).filter(AuditLog.action == "password_reset_link_refused").one()
    assert row.details["reason"] == "sso_only"
    after.close()
    assert world.revoked == []


def test_a_reset_link_used_before_the_account_is_held_sets_the_password(db, world, monkeypatch):
    """The control: nothing committed meanwhile, the link works and the flag is read (and found clear)."""
    from app.core import password_origin
    from app.core.models import User
    jay = _user(db, "jay")
    token = _link(db, jay, created_by=None, made_by_other=False)
    turns = []
    monkeypatch.setattr(api, "_sessions_turn", lambda session, owner: turns.append(str(owner)))
    assert _use(db, token) == {"ok": True}
    assert turns and turns[0] == str(jay.id)
    after = _another(db)
    account = after.get(User, jay.id)
    assert not account.sso_only and not password_origin.nobody_knows(account)
    from app.core.security import verify_password
    assert verify_password("Chosen-With-A-Link-1!", account.password_hash)
    after.close()


@pytest.mark.parametrize("for_someone_else", [True, False])
def test_a_password_set_for_an_account_held_meanwhile_is_refused(db, world, monkeypatch, for_someone_else):
    """An administrator's password for the account, made at once or approved later: the account as the route
    loaded it was not held; it is in the turn."""
    from app.core.models import RoleEnum, User
    root, jay = _user(db, "root", RoleEnum.ADMIN), _user(db, "jay")
    target = db.query(User).filter(User.id == jay.id).first()
    assert not target.sso_only
    turns = []
    monkeypatch.setattr(api, "_sessions_turn", _held_meanwhile(db, jay.id, turns))
    with pytest.raises(HTTPException) as refused:
        api._make_credential_change(db, cc.PASSWORD, target, {"password_hash": "argon2:chosen-by-root"},
                                    actor_id=root.id, actor_name="root", for_someone_else=for_someone_else)
    assert refused.value.status_code == 409 and "signs in only through its organisation's provider" in refused.value.detail
    assert turns == [str(jay.id)]
    db.rollback()
    assert _as_it_stands(db, jay.id) == (True, RANDOM, True)
    assert world.revoked == []


def test_the_flag_is_read_again_and_nothing_else_of_the_account(db, world):
    """What the caller set on the account before the turn stays as it set it."""
    from app.core.models import User
    jay = _user(db, "jay")
    target = db.query(User).filter(User.id == jay.id).first()
    other = _another(db)
    other.get(User, jay.id).sso_only = True
    other.commit()
    other.close()
    target.email = "pending@example.com"                                  # not written yet
    assert api._signs_in_only_through_its_provider_now(db, target) is True
    assert target.email == "pending@example.com"
    # A stand-in without a session's state is taken as it is.
    from types import SimpleNamespace
    assert api._signs_in_only_through_its_provider_now(SimpleNamespace(), SimpleNamespace(sso_only=False)) is False
    assert api._signs_in_only_through_its_provider_now(SimpleNamespace(), SimpleNamespace(sso_only=True)) is True
