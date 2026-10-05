"""Whether an account's current password is its own or one someone else set, offline on a real database.

Someone who set another person's password knows it. The account records when its current password was set
by someone else and by whom (app/core/password_origin.py): set when an administrator, a user who manages
users or the host operator sets it, when a reset link another account made is used, and when an
administrator creates the account with a password; cleared when the person changes it themselves (to a
different one), uses a link they asked for, or joins by invitation or sign-up. When such an account is
made an administrator, on each route that does it, the password is made unusable, its sessions end, and a
reset link goes to the person's own inbox (or, when no email can go, to the promoting administrator to
hand over). An administrator whose current password someone else set may not approve a held change.
Existing accounts are filled from the audit log once. test_password_origin_live.py drives the routes on a
running stack.
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
from app.api import user_management_api as um  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import endpoint_permissions as ep  # noqa: E402
from app.core import password_origin as po  # noqa: E402
from app.core import password_reset  # noqa: E402
from app.core.models import (AccountInvitation, AdminGrant, AuditLog, CredentialChange, Group,  # noqa: E402
                             PasswordResetToken, RoleEnum, SystemSetting, User, UserEndpointPermission,
                             UserSSHKey, user_groups)
from app.core.security import hash_password, verify_password  # noqa: E402

pytestmark = pytest.mark.unit

PEPPER = "r" * 48 + ":password_reset"
OLD = "Old-Password-8x!"


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'origin.db'}")
        for model in (User, UserEndpointPermission, AuditLog, AdminGrant, CredentialChange, AccountInvitation,
                      PasswordResetToken, SystemSetting, Group, UserSSHKey):
            model.__table__.create(engine)
        user_groups.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def world(monkeypatch):
    """Stand-ins for what the routes need that is not the database; records what they would tell and
    send, and whose sessions they would end."""
    from app.core import rate_limiter
    out = SimpleNamespace(notices=[], revoked=[], sent=[], smtp=False)
    monkeypatch.setattr(api, "_notify_account_change",
                        lambda db, user, **kw: out.notices.append((user.username, kw["title"], kw["change"])))
    monkeypatch.setattr(api, "_notify_users", lambda *a, **k: None)
    monkeypatch.setattr(api, "_notify_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(api, "_announce_admin_granted", lambda *a, **k: None)
    monkeypatch.setattr(api, "_announce_decided_change", lambda *a, **k: None)
    monkeypatch.setattr(api, "_fire_action_email", lambda *a, **k: None)
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(api, "_enforce_user_cap", lambda db: None)
    monkeypatch.setattr(api, "removes_last_admin", lambda db, target: False)
    monkeypatch.setattr(um, "removes_last_admin", lambda db, target: False)

    async def detail(**kw):
        return {}
    monkeypatch.setattr(um, "get_user_detail", detail)
    monkeypatch.setattr(api, "_reset_pepper", lambda: PEPPER)
    monkeypatch.setattr(password_reset, "pepper_ok", lambda pepper: True)
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_validate_password_policy", lambda db, pw: None)
    monkeypatch.setattr(api, "_revoke_sessions", lambda db, **kw: out.revoked.append(kw["user_id"]) or 0)
    monkeypatch.setattr(api, "_smtp_configured", lambda db: out.smtp)

    def send(db, user, base_url, *, created_by_id, to=None, note_html="", made_by_other=False):
        out.sent.append((user.username, created_by_id, to, note_html, made_by_other))
        return True
    monkeypatch.setattr(api, "_mint_and_send_reset", send)
    return out


def _user(db, name, role=RoleEnum.USER):
    """An account holding the password OLD, as its own."""
    u = User(username=name, email=f"{name}@example.com", password_hash=hash_password(OLD), role=role,
             is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    ep.grant_default_permissions_for_role(str(u.id), role, db)
    return u


def _request():
    return SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.44"),
                           base_url="https://vault.example.com/")


def _marked(db, user):
    db.expire_all()
    u = db.get(User, user.id)
    return (u.password_set_by, u.password_set_by_other_at is not None)


def _audit(db, action):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == action).all()


# --------------------------------------------------------------------------- where it is set and cleared

def test_a_password_someone_else_sets_is_marked_with_who_set_it(db, world):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    api._apply_credential_change(db, cc.PASSWORD, bob, {"password_hash": "h"}, actor_id=ada.id, actor_name="ada")
    db.commit()
    assert _marked(db, bob) == (ada.id, True)
    # The host operator: marked, with nobody named.
    api._apply_credential_change(db, cc.PASSWORD, bob, {"password_hash": "h"}, actor_id=None,
                                 actor_name=cc.HOST_OPERATOR)
    db.commit()
    assert _marked(db, bob) == (None, True)


def test_an_administrators_own_password_through_their_route_is_their_own(db, world):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN)
    po.set_by_other(ada, bob.id)
    db.commit()
    api._apply_credential_change(db, cc.PASSWORD, ada, {"password_hash": "h"}, actor_id=ada.id, actor_name="ada",
                                 for_someone_else=False)
    db.commit()
    assert _marked(db, ada) == (None, False)


def test_the_edit_route_marks_a_password_an_administrator_set(db, world):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    run_coroutine(api.update_user(user_id=bob.id, user_update=api.UserUpdate(password="Admin-Chosen-8x!"),
                                  current_user=ada, db=db, request=_request()))
    assert _marked(db, bob) == (ada.id, True)


def test_an_approved_request_marks_the_password_as_the_askers(db, world):
    alice, bob, carol = _user(db, "alice", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN), _user(db, "carol")
    change = cc.hold(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"password_hash": hash_password("Chosen-By-Alice-1!")})
    db.commit()
    api._approve_credential_change(db, change, carol, approver=bob)
    assert _marked(db, carol) == (alice.id, True)


def _link(db, target, *, created_by, made_by_other):
    token, prefix = password_reset.mint_reset_token()
    db.add(PasswordResetToken(user_id=target.id, token_prefix=prefix,
                              token_hash=password_reset.hash_reset_token(token, PEPPER),
                              expires_at=datetime.utcnow() + timedelta(minutes=5), created_by=created_by,
                              made_by_other=made_by_other))
    db.commit()
    return token


def _use(db, token):
    body = api.ResetPasswordRequest(new_password="Chosen-With-A-Link-1!")
    return run_coroutine(api.do_reset(token=token, body=body, request=_request(), db=db))


@pytest.mark.parametrize("made,expected", [
    ("by another account", "maker"),
    ("by another account, before the column", "maker"),
    ("by another account since deleted", "nobody named"),
    ("by the person", None),
    ("by the person, before the column", None),
    ("by the person, named, before the column", None),
    ("on the host", None),
])
def test_a_reset_link_used_marks_the_password_as_its_makers_or_the_persons(db, world, made, expected):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, ada.id)      # an earlier password someone else set: a link of their own clears it
    db.commit()
    created_by, made_by_other = {"by another account": (ada.id, True),
                                 "by another account, before the column": (ada.id, None),
                                 "by another account since deleted": (None, True),
                                 "by the person": (None, False), "by the person, before the column": (None, None),
                                 "by the person, named, before the column": (bob.id, None),
                                 "on the host": (None, False)}[made]
    monkey = pytest.MonkeyPatch()
    monkey.setattr(api, "_reset_link_refusal", lambda *a, **k: None)
    try:
        assert _use(db, _link(db, bob, created_by=created_by, made_by_other=made_by_other)) == {"ok": True}
    finally:
        monkey.undo()
    assert _marked(db, bob) == {"maker": (ada.id, True), "nobody named": (None, True), None: (None, False)}[expected]
    (row,) = _audit(db, "password_reset_completed")
    assert row.details == {"link_made_by_other": expected is not None}


def test_an_account_an_administrator_creates_holds_a_password_the_administrator_set(db, world):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    for name, role in (("bob", RoleEnum.USER), ("root2", RoleEnum.ADMIN)):
        made = run_coroutine(api.create_user(user_create=api.UserCreate(username=name, password="Admin-Chosen-8x!",
                                                                        role=role),
                                             current_user=ada, db=db, request=_request()))
        assert _marked(db, made) == (ada.id, True)
        # Created as an administrator: nothing is taken back (only a promotion does that).
        assert verify_password("Admin-Chosen-8x!", db.get(User, made.id).password_hash)


def test_the_persons_own_change_clears_it_but_the_same_password_again_does_not(db, world):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, ada.id)
    db.commit()
    run_coroutine(api.update_own_account(body=api.SelfUpdate(current_password=OLD, new_password=OLD),
                                         request=_request(), current_user=bob, db=db))
    assert _marked(db, bob) == (ada.id, True), "the same password again: whoever set it still knows it"
    run_coroutine(api.update_own_account(body=api.SelfUpdate(current_password=OLD, new_password="Mine-Now-8x!"),
                                         request=_request(), current_user=bob, db=db))
    assert _marked(db, bob) == (None, False)


# --------------------------------------------------------------------------- at promotion

def _patch_users(db, actor, target):
    return run_coroutine(api.update_user(user_id=target.id, user_update=api.UserUpdate(role=RoleEnum.ADMIN),
                                         current_user=actor, db=db, request=_request()))


def _put_user_management(db, actor, target):
    return run_coroutine(um.update_user(user_id=target.id, update_data=um.UserUpdateRequest(role=RoleEnum.ADMIN),
                                        request=_request(), current_user=actor, db=db))


def _patch_role(db, actor, target):
    return run_coroutine(um.change_user_role(user_id=target.id, request=um.ChangeRoleRequest(new_role=RoleEnum.ADMIN),
                                             current_user=actor, db=db, http_request=_request()))


PROMOTE = {"PATCH /users/{id}": _patch_users, "PUT /api/user-management/users/{id}": _put_user_management,
           "PATCH /api/user-management/users/{id}/role": _patch_role}


def _answer(r):
    if isinstance(r, dict):
        return r.get("promotion_password_reset")
    if hasattr(r, "body"):
        import json
        return json.loads(r.body).get("promotion_password_reset")
    return r.promotion_password_reset


@pytest.mark.parametrize("route", sorted(PROMOTE))
def test_a_promotion_takes_back_a_password_someone_else_set_and_emails_a_link(db, world, route):
    ada, carol, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "carol", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, ada.id)
    db.commit()
    world.smtp = True
    answer = _answer(PROMOTE[route](db, carol, bob))
    db.expire_all()
    after = db.get(User, bob.id)
    assert after.role == RoleEnum.ADMIN
    assert not verify_password(OLD, after.password_hash), "the password someone else set no longer works"
    assert world.revoked.count(bob.id) >= 1, "their sessions end"
    assert _marked(db, bob) == (ada.id, True), "marked until they set their own"
    (row,) = _audit(db, "password_reset_at_promotion")
    assert (row.user_id, row.resource_id, row.status) == (carol.id, str(bob.id), "success")
    assert row.details["target_username"] == "bob" and row.details["password_set_by"] == "ada"
    # A link of the self-service kind to their own address: only their inbox chooses the new password.
    ((who, created_by, to, note, made_by_other),) = world.sent
    assert (who, created_by, to, made_by_other) == ("bob", None, "bob@example.com", False)
    assert "You were made an administrator" in note
    assert answer == {"emailed": True, "reset_link": None, "expires_in_minutes": None}
    (change,) = [n[2] for n in world.notices if n[:2] == ("bob", "Your password was reset")]
    assert "A link to choose a new one was sent to your email address." in change


@pytest.mark.parametrize("route", sorted(PROMOTE))
def test_without_email_the_promoting_administrator_gets_a_link_to_hand_over(db, world, route):
    ada, carol, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "carol", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, ada.id)
    db.commit()
    answer = _answer(PROMOTE[route](db, carol, bob))
    assert world.sent == []
    assert answer["emailed"] is False and answer["reset_link"].startswith("https://vault.example.com/?reset=")
    assert answer["expires_in_minutes"]
    (link,) = db.query(PasswordResetToken).filter(PasswordResetToken.user_id == bob.id).all()
    assert (link.created_by, link.made_by_other) == (carol.id, True), "judged again when used"
    (minted,) = _audit(db, "password_reset_link_minted")
    assert minted.user_id == carol.id and minted.details["at_promotion"] is True
    (change,) = [n[2] for n in world.notices if n[:2] == ("bob", "Your password was reset")]
    assert "The administrator who made you one has a link for you to choose a new one." in change


@pytest.mark.parametrize("route", sorted(PROMOTE))
def test_a_promotion_link_goes_to_the_address_before_an_administrators_recent_change(db, world, route):
    ada, carol, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "carol", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, ada.id)
    # Within 14 days an administrator moved the address: the link goes to the one before, as a self-service
    # one would, so whoever controls the new address cannot choose the new administrator's password.
    row = cc.record_made(db, kind=cc.EMAIL, target_id=bob.id, requester_id=ada.id, requester_name="ada",
                         now=cc.utcnow() - timedelta(days=3))
    row.payload = cc.applied_email_payload({"old_email": "bob@example.com", "new_email": "bob@new.example.org"})
    bob.email = "bob@new.example.org"
    db.commit()
    world.smtp = True
    answer = _answer(PROMOTE[route](db, carol, bob))
    ((who, created_by, to, note, made_by_other),) = world.sent
    assert (who, created_by, to, made_by_other) == ("bob", None, "bob@example.com", False)
    assert "You were made an administrator" in note
    assert "An administrator changed this account's email address" in note
    assert answer == {"emailed": True, "reset_link": None, "expires_in_minutes": None}


def test_a_link_goes_to_the_promoting_administrator_when_the_address_was_just_changed(db, world, monkeypatch):
    ada, carol, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "carol", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, ada.id)
    db.commit()
    world.smtp = True
    # An administrator moved the address within 14 days and there was none before: nothing may be sent.
    monkeypatch.setattr(api, "_self_service_reset_destination", lambda db, user: None)
    answer = _answer(_patch_role(db, carol, bob))
    assert world.sent == [] and answer["reset_link"]


@pytest.mark.parametrize("route", sorted(PROMOTE))
def test_a_promotion_leaves_a_password_of_the_persons_own(db, world, route):
    carol, bob = _user(db, "carol", RoleEnum.ADMIN), _user(db, "bob")
    answer = _answer(PROMOTE[route](db, carol, bob))
    assert answer is None
    assert verify_password(OLD, db.get(User, bob.id).password_hash)
    assert _audit(db, "password_reset_at_promotion") == [] and world.sent == []


def test_the_users_list_says_whose_password_it_is(db, world, monkeypatch):
    from app.core import sign_in_lockout
    # What else the list reads: who has a second factor (none here), and the sign-in locks (none).
    db.execute(sa.text("CREATE TABLE second_factor_enrollments (id CHAR(32), user_id CHAR(32), status VARCHAR(16))"))
    db.commit()
    monkeypatch.setattr(sign_in_lockout, "blocks_by_user", lambda db, ids: {})
    ada, bob, carol = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob"), _user(db, "carol")
    po.set_by_other(bob, ada.id)
    po.set_by_other(carol, None)
    db.commit()
    listed = {u.username: u.password_set_by_other for u in run_coroutine(api.list_users(current_user=ada, db=db))}
    assert listed["ada"] is None
    assert listed["bob"]["by"] == "ada" and listed["bob"]["at"].endswith("Z")
    assert listed["carol"]["by"] is None


# --------------------------------------------------------------------------- at approval

def test_a_password_set_with_nobody_named_still_counts(db, world):
    # The host operator set it, or whoever set it has since been deleted: nobody is named, and it is still
    # someone else's.
    carol, bob = _user(db, "carol", RoleEnum.ADMIN), _user(db, "bob")
    po.set_by_other(bob, None)
    db.commit()
    assert po.is_set_by_other(bob)
    assert _answer(_patch_role(db, carol, bob)) is not None
    assert not verify_password(OLD, db.get(User, bob.id).password_hash)
    (row,) = _audit(db, "password_reset_at_promotion")
    assert row.details["password_set_by"] is None


def _independent(db, *names):
    """Administrators of long standing, none made by another (as the host tool would have made them)."""
    out = []
    for name in names:
        u = _user(db, name, RoleEnum.ADMIN)
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR)
        db.query(AdminGrant).filter(AdminGrant.user_id == u.id).update(
            {AdminGrant.granted_at: datetime.utcnow() - timedelta(days=30)})
        db.commit()
        out.append(u)
    return out


def test_the_rule_refuses_an_approver_whose_password_someone_else_set():
    kw = dict(requester_id="r", approver_grant=None, requester_grant=None, changed=set(),
              requested_at=datetime.utcnow(), target_id="t")
    assert cc.refusal_reason("a", **kw) is None
    assert cc.refusal_reason("a", approver_password_set_by_other=True, **kw) == cc.PASSWORD_NOT_OWN
    # The rules before it keep their precedence.
    assert cc.refusal_reason("r", approver_password_set_by_other=True, **kw) == cc.ASKED


def test_an_administrator_holding_a_password_someone_else_set_may_not_approve(db, world):
    alice, bob = _independent(db, "alice", "bob")
    carol = _user(db, "carol")
    cc.record_made(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id, requester_name="alice")
    db.commit()
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"delivery": "copy"})
    db.commit()
    assert cc.approval_refusal(db, change, bob.id) is None
    po.set_by_other(bob, alice.id)
    db.commit()
    assert cc.approval_refusal(db, change, bob.id) == cc.PASSWORD_NOT_OWN
    assert [a.username for a in cc.approvers(db, alice.id, change)] == []
    # The approve route refuses it, saying why.
    with pytest.raises(HTTPException) as refused:
        run_coroutine(api.approve_credential_request(change_id=change.id, request=_request(), current_user=bob,
                                                     db=db))
    assert refused.value.status_code == 403
    assert "Your current password was set by someone else" in refused.value.detail
    # A second change nobody else may approve is refused, naming the rule.
    with pytest.raises(cc.NoApprover) as none:
        cc.decide(db, requester_id=alice.id, target_id=carol.id)
    assert none.value.refusals == [("bob", cc.PASSWORD_NOT_OWN)]
    assert api._no_approver_text(none.value.refusals, "carol") == "bob holds a password someone else set"
    assert api._approval_refusal_text(cc.PASSWORD_NOT_OWN, "alice", short=True) == \
        "You cannot approve this: your password was set by someone else."


# --------------------------------------------------------------------------- existing accounts, from the log

def _row(db, action, when, *, by=None, username=None, resource=None, details=None, status="success"):
    db.add(AuditLog(action=action, status=status, user_id=by.id if by is not None else None,
                    username=username if username is not None else (by.username if by is not None else None),
                    resource_type="user" if resource is not None else None,
                    resource_id=str(resource.id) if resource is not None else None, details=details or {},
                    timestamp=when))


def test_existing_accounts_are_filled_from_the_audit_log(db):
    t = datetime(2026, 1, 1)
    ada, gone = User(username="ada", password_hash="x", role=RoleEnum.ADMIN), User(username="gone", password_hash="x")
    bea = User(username="bea", password_hash="x", role=RoleEnum.ADMIN)
    names = ("created", "set", "set_then_own", "host_set", "linked", "self_link", "approved", "invited", "nothing",
             "host_link", "failed_set", "set_by_gone", "approved_named", "approved_link", "linked_then_own",
             "own_route")
    people = {n: User(username=n, password_hash="x") for n in names}
    db.add_all([ada, bea, gone, *people.values()])
    db.commit()
    p = people
    _row(db, "user_created", t, by=ada, resource=p["created"], details={"created_username": "created"})
    _row(db, "user_updated", t, by=ada, resource=p["set"], details={"changes": {"password": "changed"}})
    _row(db, "user_updated", t, by=ada, resource=p["set_then_own"], details={"changes": {"password": "changed"}})
    _row(db, "self_account_update", t + timedelta(days=1), by=p["set_then_own"], details={"fields": ["password"]})
    _row(db, "user_updated", t, username=cc.HOST_OPERATOR, resource=p["host_set"],
         details={"changes": {"password": "changed"}, "by": "host operator"})
    _row(db, "password_reset_link_minted", t, by=ada, details={"target_user_id": str(p["linked"].id)})
    _row(db, "password_reset_completed", t + timedelta(hours=1), by=p["linked"])
    _row(db, "user_updated", t, by=ada, resource=p["self_link"], details={"changes": {"password": "changed"}})
    _row(db, "password_reset_completed", t + timedelta(hours=1), by=p["self_link"])   # asked for by the person
    _row(db, "credential_change_approved", t, by=ada, resource=p["approved"],
         details={"kind": "password", "requested_by": "gone"})
    _row(db, "credential_change_approved", t, by=ada, resource=p["approved_named"],
         details={"kind": "password", "requested_by": "bea"})
    # A link an administrator approved is handed to that administrator: its maker.
    _row(db, "credential_change_approved", t, by=ada, resource=p["approved_link"],
         details={"kind": "reset_link", "requested_by": "bea"})
    _row(db, "password_reset_completed", t + timedelta(hours=1), by=p["approved_link"])
    # Another account's link used, then later one the person asked for (which leaves no row of its own).
    _row(db, "password_reset_link_minted", t, by=ada, details={"target_user_id": str(p["linked_then_own"].id)})
    _row(db, "password_reset_completed", t + timedelta(hours=1), by=p["linked_then_own"])
    _row(db, "password_reset_completed", t + timedelta(days=2), by=p["linked_then_own"])
    # Their own, through an administrator's route.
    _row(db, "user_updated", t, by=p["own_route"], resource=p["own_route"], details={"changes": {"password": "changed"}})
    _row(db, "account_invitation_accepted", t, by=p["invited"])
    _row(db, "password_reset_link_minted", t, username=cc.HOST_OPERATOR, details={"target_user_id": str(p["host_link"].id)})
    _row(db, "password_reset_completed", t + timedelta(hours=1), by=p["host_link"])
    _row(db, "user_updated", t, by=ada, resource=p["failed_set"], details={"changes": {"password": "changed"}},
         status="failure")
    _row(db, "user_updated", t, by=gone, resource=p["set_by_gone"], details={"changes": {"password": "changed"}})
    # A row that changed something else says nothing about the password.
    _row(db, "user_updated", t + timedelta(days=2), by=ada, resource=p["nothing"], details={"changes": {"email": "x"}})
    db.commit()
    gone_id = gone.id
    db.execute(User.__table__.delete().where(User.__table__.c.id == gone_id))
    db.commit()
    assert po.backfill_from_audit(db) == 8
    db.expire_all()
    got = {n: (db.get(User, u.id).password_set_by, db.get(User, u.id).password_set_by_other_at) for n, u in p.items()}
    assert got == {
        "created": (ada.id, t), "set": (ada.id, t), "set_then_own": (None, None), "host_set": (None, t),
        "linked": (ada.id, t + timedelta(hours=1)), "self_link": (None, None),
        # Set as the one who asked chose it; whose account is gone, so nobody is named.
        "approved": (None, t), "invited": (None, None), "nothing": (None, None), "host_link": (None, None),
        "failed_set": (None, None), "set_by_gone": (None, t), "approved_named": (bea.id, t),
        "approved_link": (ada.id, t + timedelta(hours=1)), "linked_then_own": (None, None), "own_route": (None, None)}
    assert gone_id not in {v[0] for v in got.values()}


def test_the_boot_adds_the_columns_and_fills_them_once():
    source = (Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = source[source.index("def _run_lightweight_migrations():"):source.index("def _verify_retired_object_id_triggers")]
    assert body.count("password_origin.add_columns_once(db)") == 1
    assert "ADD COLUMN IF NOT EXISTS password_set_by UUID REFERENCES users(id) ON DELETE SET NULL" in po.COLUMNS_DDL
    assert "ADD COLUMN IF NOT EXISTS password_set_by_other_at TIMESTAMP" in po.COLUMNS_DDL


def test_the_columns_are_filled_only_when_they_are_added(monkeypatch):
    ran = []
    fake = SimpleNamespace(execute=lambda stmt, *a: ran.append(str(stmt)))
    monkeypatch.setattr(po, "backfill_from_audit", lambda db: ran.append("backfill") or 3)
    monkeypatch.setattr(po, "columns_exist", lambda db: True)
    assert po.add_columns_once(fake) is None and ran == []
    monkeypatch.setattr(po, "columns_exist", lambda db: False)
    assert po.add_columns_once(fake) == 3
    assert ran[-2:] == [po.COLUMNS_DDL, "backfill"]
