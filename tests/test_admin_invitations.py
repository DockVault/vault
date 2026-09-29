"""An invitation that makes an administrator stands only while its maker is an administrator who can act,
offline on a real database.

Demoting, deactivating, locking or deleting an administrator left their pending administrator invitations
open, and acceptance never looked at who had made one: the accepted account became an administrator on
the word of someone who no longer was one. Now every route that takes an administrator away revokes
those invitations (through _withdraw_requests_of, which each such route calls: see
test_credential_change_independence.py), recorded, and acceptance refuses one whose maker is not an
administrator who can act. An administrator's invitation also keeps the inviter's lineage when it is made.
test_invite_accept.py drives the routes on a running stack.
"""
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import admin_grants, invitations  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core.models import (AccountInvitation, AdminGrant, AuditLog, CredentialChange,  # noqa: E402
                             PasswordResetToken, RoleEnum, SystemSetting, User)

pytestmark = pytest.mark.unit

PEPPER = "p" * 48


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'invitations.db'}")
        # PasswordResetToken: making an administrator revokes the open reset links a non-administrator made.
        for model in (User, AdminGrant, CredentialChange, AuditLog, AccountInvitation, SystemSetting,
                      PasswordResetToken):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role=RoleEnum.ADMIN):
    u = User(username=name, email=None, password_hash="x", role=role, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def _invite(db, by, username, role="admin", **kw):
    """A pending invitation made by ``by`` (None: its maker is gone), and its token."""
    token, prefix = invitations.mint_invite()
    inv = AccountInvitation(username=username, email=None, role=role, token_prefix=prefix,
                            token_hash=invitations.hash_invite_token(token, PEPPER),
                            expires_at=kw.pop("expires_at", datetime.utcnow() + timedelta(days=1)),
                            created_by=by.id if by is not None else None, **kw)
    db.add(inv)
    db.commit()
    return inv, token


# --------------------------------------------------------------------------- revoked when the maker leaves

@pytest.mark.parametrize("because", ["demoted", "deactivated", "locked", "deleted"])
def test_an_administrator_who_leaves_has_their_pending_administrator_invitations_revoked(db, because):
    alice, bob = _user(db, "alice"), _user(db, "bob")
    now = datetime.utcnow()
    pending, _ = _invite(db, bob, "new-admin")
    user_invite, _ = _invite(db, bob, "new-user", role="user")
    others, _ = _invite(db, alice, "alices-admin")
    accepted, _ = _invite(db, bob, "took-it", accepted_at=now)
    expired, _ = _invite(db, bob, "too-late", expires_at=now - timedelta(minutes=1))
    ids = {n: i.id for n, i in (("pending", pending), ("user", user_invite), ("others", others),
                                ("accepted", accepted), ("expired", expired))}

    assert api._withdraw_requests_of(db, bob, actor=alice, because=because) == [], "no requests were open"
    db.commit()

    revoked = {n for n, i in ids.items() if db.get(AccountInvitation, i).revoked_at is not None}
    assert revoked == {"pending"}, revoked
    (row,) = db.query(AuditLog).filter(AuditLog.action == "account_invitation_revoked").all()
    assert (row.user_id, row.resource_type, row.resource_id) == (alice.id, "account_invitation", str(ids["pending"]))
    assert row.details["revoked_because"] == because and row.details["invited_by"] == "bob"
    assert row.details["username"] == "new-admin" and row.details["role"] == "admin"


def test_an_invitation_revoked_with_its_maker_cannot_be_accepted_after_a_promotion_back(db, monkeypatch):
    # Revoked is revoked: making bob an administrator again does not bring it back.
    _accepting(monkeypatch)
    alice, bob = _user(db, "alice"), _user(db, "bob")
    _inv, token = _invite(db, bob, "new-admin")
    api._withdraw_requests_of(db, bob, actor=alice, because="demoted")
    db.commit()
    with pytest.raises(HTTPException) as refused:
        _accept(db, token)
    assert refused.value.status_code == 404


# --------------------------------------------------------------------------- refused at acceptance

def _accepting(monkeypatch):
    """What acceptance needs that is not the database: invitations on, a pepper, no rate limit, no
    plan cap, and the notices after the commit recorded instead of sent."""
    from app.core import endpoint_permissions
    from app.core import rate_limiter
    told = []
    monkeypatch.setattr(api, "_invite_pepper", lambda: PEPPER)
    monkeypatch.setattr(api, "_account_policy", lambda db: {"invite_enabled": True, "email_requirement": "optional"})
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_enforce_user_cap", lambda db: None)
    monkeypatch.setattr(endpoint_permissions, "grant_default_permissions_for_role", lambda *a, **k: [])
    monkeypatch.setattr(api, "_announce_admin_granted", lambda db, user, **k: told.append(user.username))
    monkeypatch.setattr(api, "_fire_action_email", lambda *a, **k: None)
    return told


def _accept(db, token):
    return run_coroutine(api.accept_invite(
        token=token, payload=api.InviteAccept(password="Accept-Passw0rd!123"),
        request=SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.9")), db=db))


def _refusals(db):
    return [r.details.get("reason") for r in db.query(AuditLog)
            .filter(AuditLog.action == "account_invitation_accept_failed").all()]


@pytest.mark.parametrize("fate", ["demoted", "deactivated", "locked", "deleted"])
def test_an_administrators_invitation_whose_maker_left_is_refused(db, monkeypatch, fate):
    # One left pending when its maker left (made before invitations were revoked with their maker, or by a
    # change made outside the routes): refused, like a revoked one, and recorded; no account is made.
    told = _accepting(monkeypatch)
    _alice, bob = _user(db, "alice"), _user(db, "bob")
    inv, token = _invite(db, bob, "new-admin")
    if fate == "demoted":
        bob.role = RoleEnum.USER
    elif fate == "deactivated":
        bob.is_active = False
    elif fate == "locked":
        bob.is_locked, bob.locked_until = True, None
    else:
        inv.created_by = None                      # what deleting bob does to it
    db.commit()
    with pytest.raises(HTTPException) as refused:
        _accept(db, token)
    assert (refused.value.status_code, refused.value.detail) == (404, "Invitation not found.")
    assert _refusals(db) == ["inviter_not_admin"]
    assert db.query(User).filter(User.username == "new-admin").count() == 0
    assert db.get(AccountInvitation, inv.id).accepted_at is None and told == []
    with pytest.raises(HTTPException) as looked_up:
        run_coroutine(api.get_invite(token=token, request=SimpleNamespace(headers={}, client=None), db=db))
    assert looked_up.value.status_code == 404, "the form is not offered either"


def test_an_administrators_invitation_from_an_administrator_who_can_act_is_accepted(db, monkeypatch):
    # The control for the refusals above, and a lock that wrong passwords armed runs out by itself: the
    # maker is still an administrator who can act.
    told = _accepting(monkeypatch)
    _alice, bob = _user(db, "alice"), _user(db, "bob")
    bob.is_locked, bob.locked_until = True, datetime.utcnow() + timedelta(minutes=10)
    db.commit()
    _inv, token = _invite(db, bob, "new-admin")
    assert _accept(db, token) == {"ok": True, "username": "new-admin"}
    made = db.query(User).filter(User.username == "new-admin").one()
    assert made.role == RoleEnum.ADMIN and told == ["new-admin"]
    assert admin_grants.of(db, [made.id])[made.id].granted_by_id == bob.id


def test_a_users_invitation_does_not_depend_on_its_maker(db, monkeypatch):
    _accepting(monkeypatch)
    bob = _user(db, "bob")
    _inv, token = _invite(db, bob, "new-user", role="user")
    bob.role = RoleEnum.USER
    db.commit()
    assert _accept(db, token)["username"] == "new-user"
    assert db.query(User).filter(User.username == "new-user").one().role == RoleEnum.USER


# --------------------------------------------------------------------------- the lineage kept when made

def _create(db, monkeypatch, who, role):
    from app.core import email_actions
    monkeypatch.setattr(api, "_invite_pepper", lambda: PEPPER)
    monkeypatch.setattr(api, "_account_policy", lambda db: {"invite_enabled": True, "email_requirement": "optional",
                                                           "invite_ttl_hours": 24})
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(email_actions, "send_action_email", lambda *a, **k: False)
    answer = run_coroutine(api.create_invite(payload=api.InviteCreate(username=f"inv-{role}", role=role),
                                             current_user=who, db=db, request=None))
    return db.query(AccountInvitation).filter(AccountInvitation.token_prefix == answer["token_prefix"]).one()


def test_an_administrators_invitation_keeps_the_inviters_lineage_when_it_is_made(db, monkeypatch):
    alice, bob = _user(db, "alice"), _user(db, "bob")
    admin_grants.record(db, bob.id, granted_by_id=alice.id, granted_by_name="alice")
    db.commit()
    inv = _create(db, monkeypatch, bob, "admin")
    assert inv.inviter_lineage == [str(bob.id), str(alice.id)] == admin_grants.lineage_through(db, bob.id)
    assert inv.created_by == bob.id


def test_a_users_invitation_keeps_no_lineage(db, monkeypatch):
    alice, bob = _user(db, "alice"), _user(db, "bob")
    admin_grants.record(db, bob.id, granted_by_id=alice.id, granted_by_name="alice")
    db.commit()
    inv = _create(db, monkeypatch, bob, "user")
    assert db.execute(sa.text("SELECT inviter_lineage IS NULL FROM account_invitations "
                              "WHERE id = :i"), {"i": inv.id.hex}).scalar() == 1
