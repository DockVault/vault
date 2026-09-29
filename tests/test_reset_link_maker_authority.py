"""A password reset link someone made for another account is judged again when it is used, offline on a
real database.

A user given the permission to manage users may make a reset link for an ordinary user. Authority was
checked when the link was made, and never when it was used: an administrator then made that user an
administrator, the link still set the new administrator's password, and its maker signed in as an
administrator. Now a link another account made is judged again when it is looked up (GET /reset/{token})
and when it is used (POST), by the rule the routes that make one apply (app/core/account_authority.py,
link_refusal), as its maker and the account stand then. A refused link answers exactly as an unknown one,
is revoked, and is recorded with why. Making an account an administrator also revokes the open links for
it that someone who may not make one for an administrator made.
test_reset_link_maker_authority_live.py reproduces the sequence on a running stack.
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
from app.core import account_authority as aa  # noqa: E402
from app.core import password_reset  # noqa: E402
from app.core.models import (AdminGrant, AuditLog, PasswordResetToken, RoleEnum, User,  # noqa: E402
                             UserEndpointPermission)

pytestmark = pytest.mark.unit

PEPPER = "r" * 48 + ":password_reset"
UNKNOWN = "This reset link is invalid or has expired."
NEW_PASSWORD = "Delegate-Owns-Pw0rd!7"


# --------------------------------------------------------------------------- the rule


def _who(role, **kw):
    return SimpleNamespace(id=kw.pop("id", object()), role=role, is_active=kw.pop("is_active", True),
                           is_locked=kw.pop("is_locked", False), locked_until=kw.pop("locked_until", None))


@pytest.mark.parametrize("maker,target,may_manage,why", [
    (None, RoleEnum.USER, False, aa.MAKER_DELETED),
    (dict(role=RoleEnum.ADMIN, is_active=False), RoleEnum.USER, True, aa.MAKER_INACTIVE),
    (dict(role=RoleEnum.ADMIN, is_locked=True), RoleEnum.USER, True, aa.MAKER_LOCKED),
    (dict(role=RoleEnum.USER), RoleEnum.USER, False, aa.MAKER_WITHOUT_PERMISSION),
    (dict(role=RoleEnum.USER), RoleEnum.ADMIN, True, aa.ADMINISTRATOR),
    (dict(role=RoleEnum.EXTERNAL), RoleEnum.USER, True, aa.HIGHER_ROLE),
    (dict(role=RoleEnum.USER), RoleEnum.USER, True, None),
    (dict(role=RoleEnum.ADMIN), RoleEnum.ADMIN, True, None),
    # A lock that wrong passwords armed pauses new sign-ins only: the maker still stands.
    (dict(role=RoleEnum.ADMIN, is_locked=True, locked_until=datetime(2099, 1, 1)), RoleEnum.ADMIN, True, None),
])
def test_a_link_stands_only_while_its_maker_could_make_it_for_the_account_as_it_is_now(maker, target,
                                                                                        may_manage, why):
    maker = _who(**maker) if maker is not None else None
    assert aa.link_refusal(maker, _who(target), maker_may_manage_users=may_manage) == why


# --------------------------------------------------------------------------- the routes


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'reset_links.db'}")
        for model in (User, AuditLog, UserEndpointPermission, PasswordResetToken, AdminGrant):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def resetting(monkeypatch):
    """What the reset routes need that is not the database: a pepper, no rate limit, the password policy
    and the session revocation (tested elsewhere) left out, and a link lifetime."""
    from app.core import rate_limiter
    monkeypatch.setattr(api, "_reset_pepper", lambda: PEPPER)
    monkeypatch.setattr(password_reset, "pepper_ok", lambda pepper: True)
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_validate_password_policy", lambda db, pw: None)
    monkeypatch.setattr(api, "_revoke_sessions", lambda db, **kw: 0)
    monkeypatch.setattr(api, "_password_reset_policy", lambda db: (False, 15))


def _user(db, name, role=RoleEnum.USER, manages_users=False):
    u = User(username=name, email=f"{name}@example.com", password_hash="old-hash", role=role,
             is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    if manages_users:
        for group in ("USER_VIEW", "USER_MANAGE"):
            db.add(UserEndpointPermission(user_id=u.id, endpoint_group=group))
        db.commit()
    return u


def _mint(db, target, maker):
    """A link for ``target`` made the way the routes make one: by ``maker`` (None: the server's operator)."""
    link = api._mint_reset_link(db, target, "https://vault.example.com", created_by_id=getattr(maker, "id", None),
                                made_by_other=maker is not None and maker.id != target.id)
    return link.split("?reset=")[1]


def _legacy(db, target, created_by):
    """A link from before made_by_other existed: the column is NULL."""
    token, prefix = password_reset.mint_reset_token()
    db.add(PasswordResetToken(user_id=target.id, token_prefix=prefix,
                              token_hash=password_reset.hash_reset_token(token, PEPPER),
                              expires_at=datetime.utcnow() + timedelta(minutes=10), created_by=created_by,
                              made_by_other=None))
    db.commit()
    return token


def _request():
    return SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.44"))


def _look_up(db, token):
    return run_coroutine(api.get_reset(token=token, request=_request(), db=db))


def _use(db, token, password=None):
    body = api.ResetPasswordRequest(new_password=password or NEW_PASSWORD)
    return run_coroutine(api.do_reset(token=token, body=body, request=_request(), db=db))


def _refused(call):
    with pytest.raises(HTTPException) as refused:
        call()
    return refused.value.status_code, refused.value.detail


def _open_links(db, user):
    db.expire_all()
    return db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id,
                                               PasswordResetToken.consumed_at.is_(None)).count()


def _audit(db, action):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == action).all()


def _password_of(db, user):
    db.expire_all()
    return db.get(User, user.id).password_hash


def test_a_delegates_link_made_before_a_promotion_is_refused_after_it(db):
    # The sequence that took an administrator's account on a running stack: a user who manages users makes
    # a link for an ordinary user, an administrator then promotes that user, and the link is used. The promotion here is
    # made behind the routes (the routes also revoke the link: see the promotion test below), so what
    # refuses it is the check at use.
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    assert db.query(PasswordResetToken).one().made_by_other is True
    carol.role = RoleEnum.ADMIN
    db.commit()

    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)
    assert _password_of(db, carol) == "old-hash", "the new administrator's password was set"
    assert _open_links(db, carol) == 0, "the refused link was left open"
    (row,) = _audit(db, "password_reset_link_refused")
    assert (row.status, row.user_id, row.resource_type, row.resource_id) == ("failure", None, "user", str(carol.id))
    assert row.details["reason"] == aa.ADMINISTRATOR
    assert (row.details["target_username"], row.details["made_by"]) == ("carol", "dana")
    assert _audit(db, "password_reset_completed") == []


def test_the_lookup_that_shows_the_form_refuses_it_too(db):
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    assert _look_up(db, token) == {"username": "carol"}, "the form is shown while the link stands"
    carol.role = RoleEnum.ADMIN
    db.commit()
    assert _refused(lambda: _look_up(db, token)) == (404, UNKNOWN)
    assert _open_links(db, carol) == 0
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [aa.ADMINISTRATOR]
    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN), "revoked at the lookup"


def test_setting_the_password_reads_the_maker_and_the_account_under_a_share_lock(db, monkeypatch):
    # POST judges the link with both accounts' rows read FOR SHARE until the password is set: a promotion
    # or a demotion in progress finishes before they are read, and one that starts later waits until the
    # link has been used. Without the lock, a promotion committed between the check and the new password
    # would let a link its maker may no longer use set an administrator's password.
    from sqlalchemy.orm import Query
    locks = []
    real = Query.with_for_update

    def recording(self, *args, **kwargs):
        locks.append(({d.get("entity") for d in self.column_descriptions}, args, kwargs))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Query, "with_for_update", recording)
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    assert _look_up(db, token) == {"username": "carol"}
    assert [lock for lock in locks if User in lock[0]] == [], "the lookup that shows the form changes nothing"
    assert _use(db, token) == {"ok": True}
    user_locks = [(args, kwargs) for entities, args, kwargs in locks if User in entities]
    assert user_locks == [((), {"read": True})], locks


def test_a_refused_link_answers_exactly_as_an_unknown_one_whatever_password_comes_with_it(db, monkeypatch):
    # The weak-password answer (400) comes before the token is used; a refused link must not reach it, or the
    # 400 would tell its holder that the link itself is good.
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    carol.role = RoleEnum.ADMIN
    db.commit()

    def weak(db, password):
        raise HTTPException(status_code=400, detail="Password is too weak.")

    monkeypatch.setattr(api, "_validate_password_policy", weak)
    unknown = _refused(lambda: _use(db, "no-such-token-" + "x" * 30, password="weakweakweak"))
    assert _refused(lambda: _use(db, token, password="weakweakweak")) == unknown == (404, UNKNOWN)


@pytest.mark.parametrize("fate,why", [
    ("demoted", aa.MAKER_WITHOUT_PERMISSION),
    ("deactivated", aa.MAKER_INACTIVE),
    ("locked", aa.MAKER_LOCKED),
    ("deleted", aa.MAKER_DELETED),
])
def test_an_administrators_link_is_refused_once_the_administrator_is_gone(db, fate, why):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    token = _mint(db, carol, ada)
    if fate == "demoted":
        ada.role = RoleEnum.USER
    elif fate == "deactivated":
        ada.is_active = False
    elif fate == "locked":
        ada.is_locked, ada.locked_until = True, None
    else:
        db.query(User).filter(User.id == ada.id).delete(synchronize_session=False)
    db.commit()
    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)
    assert _password_of(db, carol) == "old-hash"
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [why]


def test_a_delegates_link_is_refused_once_the_permission_is_taken_away(db):
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    db.query(UserEndpointPermission).filter(UserEndpointPermission.user_id == dana.id,
                                            UserEndpointPermission.endpoint_group == "USER_MANAGE").delete()
    db.commit()
    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [aa.MAKER_WITHOUT_PERMISSION]


def test_a_deleted_makers_link_does_not_pass_for_one_the_person_asked_for(db):
    # Deleting the maker sets created_by to NULL, as on a self-service link: made_by_other keeps them apart.
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    db.query(PasswordResetToken).update({"created_by": None})   # what ON DELETE SET NULL leaves
    db.commit()
    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [aa.MAKER_DELETED]


@pytest.mark.parametrize("maker_kind", ["delegate", "administrator", "operator", "self"])
def test_a_link_that_still_stands_is_used_as_before(db, maker_kind):
    dana = _user(db, "dana", manages_users=True)
    ada = _user(db, "ada", RoleEnum.ADMIN)
    bob = _user(db, "bob", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    maker, target = {"delegate": (dana, carol), "administrator": (ada, bob), "operator": (None, bob),
                     "self": (carol, carol)}[maker_kind]
    token = _mint(db, target, maker)
    assert db.query(PasswordResetToken).one().made_by_other is (maker_kind in ("delegate", "administrator"))
    assert _look_up(db, token) == {"username": target.username}
    assert _use(db, token) == {"ok": True}
    assert _password_of(db, target) != "old-hash"
    assert _audit(db, "password_reset_link_refused") == []


def test_a_self_service_link_stands_even_for_an_administrator(db):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    token = _legacy(db, ada, created_by=None)
    db.query(PasswordResetToken).update({"made_by_other": False})
    db.commit()
    assert _use(db, token) == {"ok": True}


@pytest.mark.parametrize("created_by,stands", [("dana", False), (None, True), ("carol", True)])
def test_a_link_from_before_the_column_is_read_from_who_made_it(db, created_by, stands):
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol", RoleEnum.ADMIN)          # promoted after the link was made
    maker_id = {"dana": dana.id, "carol": carol.id, None: None}[created_by]
    token = _legacy(db, carol, created_by=maker_id)
    if stands:
        assert _use(db, token) == {"ok": True}
    else:
        assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)


def test_an_automatic_lock_on_the_maker_does_not_refuse_the_link(db):
    # Wrong passwords pause new sign-ins only; an administrator's lock is what takes authority away.
    ada = _user(db, "ada", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    token = _mint(db, carol, ada)
    ada.is_locked, ada.locked_until = True, datetime.utcnow() + timedelta(minutes=15)
    db.commit()
    assert _use(db, token) == {"ok": True}


# --------------------------------------------------------------------------- made with a credential change


def test_a_credential_change_records_whether_another_account_made_the_link(db, monkeypatch):
    from app.core import email_actions
    monkeypatch.setattr(email_actions, "public_base_url", lambda request: "https://vault.example.com")
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")

    def made_by_other(actor_id):
        api._apply_credential_change(db, "reset_link", carol, {"delivery": "copy"}, actor_id=actor_id,
                                     actor_name="x", request=None)
        db.expire_all()
        return db.query(PasswordResetToken).filter(PasswordResetToken.consumed_at.is_(None)).one().made_by_other

    assert made_by_other(dana.id) is True, "a user who manages users"
    assert made_by_other(carol.id) is False, "the person's own account"
    assert made_by_other(None) is False, "the server's operator on the host"


# --------------------------------------------------------------------------- a promotion revokes them


def test_making_the_account_an_administrator_revokes_a_delegates_open_link(db):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    dana = _user(db, "dana", manages_users=True)
    carol = _user(db, "carol")
    token = _mint(db, carol, dana)
    api._record_admin_grant(db, carol, by=ada)
    carol.role = RoleEnum.ADMIN
    db.commit()

    assert _open_links(db, carol) == 0
    (row,) = _audit(db, "password_reset_link_revoked")
    assert (row.status, row.user_id, row.resource_id) == ("success", ada.id, str(carol.id))
    assert row.details["revoked_because"] == "made_an_administrator"
    assert (row.details["made_by"], row.details["reason"]) == ("dana", aa.ADMINISTRATOR)
    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)
    assert _password_of(db, carol) == "old-hash"


@pytest.mark.parametrize("maker_kind", ["administrator", "self", "operator"])
def test_a_promotion_keeps_a_link_an_administrator_or_the_person_made(db, maker_kind):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    _mint(db, carol, {"administrator": ada, "self": carol, "operator": None}[maker_kind])
    api._record_admin_grant(db, carol, by=ada)
    carol.role = RoleEnum.ADMIN
    db.commit()
    assert _open_links(db, carol) == 1
    assert _audit(db, "password_reset_link_revoked") == []


def test_both_are_catalogued():
    from app.core import audit_catalog
    refused = audit_catalog.lookup("password_reset_link_refused")
    revoked = audit_catalog.lookup("password_reset_link_revoked")
    assert (refused.category, refused.severity) == ("security", "warning")
    assert (revoked.category, revoked.severity) == ("accounts", "notice")


def test_every_route_that_uses_a_reset_link_judges_its_maker():
    # A route that resolves a reset token uses a link, and must judge its maker too: today the lookup that
    # shows the form and the one that sets the password. A new one without the check fails here.
    import ast
    import inspect
    import textwrap
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(routes, prefix):
        for r in routes:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    def called(fn):
        tree = ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(fn))))
        return {getattr(n.func, "id", getattr(n.func, "attr", None)) for n in ast.walk(tree)
                if isinstance(n, ast.Call)}

    uses = {(m, p): called(r.endpoint) for p, r in walk(api.app.router.routes, "")
            for m in r.methods - {"HEAD", "OPTIONS"} if "_resolve_valid_reset_token" in called(r.endpoint)}
    assert set(uses) == {("GET", "/reset/{token}"), ("POST", "/reset/{token}")}, sorted(uses)
    for route, names in uses.items():
        assert {"_reset_link_refusal", "_refuse_reset_link"} <= names, f"{route} does not judge the link's maker"


# --------------------------------------------------------------------------- an approved request's link


@pytest.fixture
def held_link(db, monkeypatch):
    """A second reset link for carol asked for by alice and held, as the rule on credential changes holds
    it; approving it mints the link and hands it to the approver."""
    from app.core import credential_changes as cc
    from app.core import email_actions
    from app.core.models import CredentialChange
    CredentialChange.__table__.create(db.get_bind())
    monkeypatch.setattr(email_actions, "public_base_url", lambda request: "https://vault.example.com")
    monkeypatch.setattr(api, "_announce_decided_change", lambda *a, **k: None)
    alice, bob = _user(db, "alice", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"delivery": "copy"})
    db.commit()

    def approve(approver):
        result = api._approve_credential_change(db, change, carol, approver=approver)
        return result["reset_link"].split("?reset=")[1]
    return SimpleNamespace(alice=alice, bob=bob, carol=carol, approve=approve)


def test_an_approved_link_is_made_by_the_administrator_who_approved_it(db, held_link):
    # The approver receives the link to pass on; the one who asked never sees it. So the link stands on
    # the approver: the asker leaving takes nothing away, and the approver leaving does.
    token = held_link.approve(held_link.bob)
    row = db.query(PasswordResetToken).one()
    assert (row.created_by, row.made_by_other) == (held_link.bob.id, True)
    held_link.alice.is_active = False
    db.commit()
    assert _look_up(db, token) == {"username": "carol"}, "the asker's leaving refused the approver's link"
    held_link.bob.is_active = False
    db.commit()
    assert _refused(lambda: _use(db, token)) == (404, UNKNOWN)
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [aa.MAKER_INACTIVE]


def test_a_link_approved_on_the_host_stands_on_its_own(db, held_link):
    token = held_link.approve(None)
    row = db.query(PasswordResetToken).one()
    assert (row.created_by, row.made_by_other) == (None, False)
    held_link.alice.is_active = False
    db.commit()
    assert _use(db, token) == {"ok": True}
