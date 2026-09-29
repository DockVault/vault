"""A change of role resets an account's stored permissions to the new role's defaults, offline on a real
database.

An account created as an administrator (POST /users, an administrator's invitation) holds the
administrator's defaults as stored permission rows, among them the permission to manage users. No route
that demoted an administrator removed them, so a former administrator kept that permission as a user:
they could make password reset links for other people's accounts, and while no check stood on whose
account a link was for, one for an administrator's, and so become an administrator again. Now every
route that changes a role resets the account's permissions to the new role's defaults in the same
transaction, keeps what another administrator granted it, records what was removed, and says so in the
notice of the role change. test_role_change_permissions_live.py drives the routes on a running stack.
"""
import ast
import tempfile
import uuid
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
from app.core import account_authority as aa  # noqa: E402
from app.core import endpoint_permissions as ep  # noqa: E402
from app.core import password_reset  # noqa: E402
from app.core.models import (AccountInvitation, AdminGrant, AuditLog, CredentialChange, Group,  # noqa: E402
                             PasswordResetToken, RoleEnum, SystemSetting, User, UserEndpointPermission,
                             user_groups)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
PEPPER = "r" * 48 + ":password_reset"
UNKNOWN = "This reset link is invalid or has expired."
ADMIN_ONLY = ["USER_MANAGE", "USER_VIEW"]


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'roles.db'}")
        for model in (User, UserEndpointPermission, AuditLog, AdminGrant, CredentialChange, AccountInvitation,
                      PasswordResetToken, SystemSetting, Group):
            model.__table__.create(engine)
        user_groups.create(engine)          # PATCH /users/{id} answers with the account and its departments
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def told(monkeypatch):
    """The notices the routes send (the user's, and the other administrators'), and the stand-ins for what
    the routes need that is not the database."""
    from app.core import rate_limiter
    notices = []
    monkeypatch.setattr(api, "_notify_account_change",
                        lambda db, user, **kw: notices.append((user.username, kw["title"], kw["change"])))
    monkeypatch.setattr(api, "_announce_admin_granted", lambda *a, **k: None)
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(api, "removes_last_admin", lambda db, target: False)
    monkeypatch.setattr(um, "removes_last_admin", lambda db, target: False)

    async def detail(**kw):
        return {}
    monkeypatch.setattr(um, "get_user_detail", detail)
    # The reset routes: a pepper, no rate limit, no password policy, no session revocation.
    monkeypatch.setattr(api, "_reset_pepper", lambda: PEPPER)
    monkeypatch.setattr(password_reset, "pepper_ok", lambda pepper: True)
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_validate_password_policy", lambda db, pw: None)
    monkeypatch.setattr(api, "_revoke_sessions", lambda db, **kw: 0)
    return notices


def _user(db, name, role=RoleEnum.USER):
    """An account as POST /users makes one: the role's defaults stored as rows, with no granter."""
    u = User(username=name, email=f"{name}@example.com", password_hash="old-hash", role=role,
             is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    ep.grant_default_permissions_for_role(str(u.id), role, db)
    return u


def _groups(db, user):
    db.expire_all()
    return sorted(g for (g,) in db.query(UserEndpointPermission.endpoint_group).filter(
        UserEndpointPermission.user_id == user.id))


def _grant(db, user, group, by):
    ep.grant_endpoint_permission(str(user.id), group, db, granted_by=str(by.id))


def _audit(db, action):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == action).all()


USER_DEFAULTS = sorted(ep.role_default_groups(RoleEnum.USER))
ADMIN_DEFAULTS = sorted(ep.role_default_groups(RoleEnum.ADMIN))


def test_the_administrators_own_defaults_are_the_permissions_to_view_and_manage_users():
    # What an administrator created as one holds and a user does not: the permissions this is about.
    assert sorted(set(ADMIN_DEFAULTS) - set(USER_DEFAULTS)) == ADMIN_ONLY
    assert ep.role_default_groups(RoleEnum.EXTERNAL) == []


# --------------------------------------------------------------------------- the rule


def test_an_administrator_made_a_user_keeps_only_the_users_defaults(db):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    assert _groups(db, ada) == ADMIN_DEFAULTS, "created as an administrator: the defaults are stored rows"
    change = ep.reset_to_role_defaults(ada.id, RoleEnum.USER, db)
    db.commit()
    assert change == {"removed": ADMIN_ONLY, "added": [], "kept": []}
    assert _groups(db, ada) == USER_DEFAULTS


def test_a_permission_another_administrator_granted_stays(db):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    dana = _user(db, "dana")
    _grant(db, dana, "USER_MANAGE", by=ada)
    dana.role = RoleEnum.ADMIN
    ep.reset_to_role_defaults(dana.id, RoleEnum.ADMIN, db)
    dana.role = RoleEnum.USER
    change = ep.reset_to_role_defaults(dana.id, RoleEnum.USER, db)
    db.commit()
    assert change["removed"] == [] and change["kept"] == ADMIN_ONLY
    assert _groups(db, dana) == sorted(USER_DEFAULTS + ADMIN_ONLY)


def test_a_permission_the_account_granted_itself_goes(db):
    # An administrator may grant their own account a permission: it changes nothing while they are one,
    # and must not outlast their own demotion.
    bob = _user(db, "bob", RoleEnum.ADMIN)
    ep.revoke_endpoint_permission(str(bob.id), "USER_VIEW", db)     # takes USER_MANAGE with it
    _grant(db, bob, "USER_MANAGE", by=bob)
    assert {r.granted_by for r in db.query(UserEndpointPermission).filter(
        UserEndpointPermission.endpoint_group.in_(ADMIN_ONLY))} == {bob.id}
    change = ep.reset_to_role_defaults(bob.id, RoleEnum.USER, db)
    db.commit()
    assert change["removed"] == ADMIN_ONLY and change["kept"] == []
    assert _groups(db, bob) == USER_DEFAULTS


def test_a_grant_whose_granter_was_deleted_cannot_be_told_from_a_default_and_goes(db):
    dana = _user(db, "dana")
    db.add(UserEndpointPermission(user_id=dana.id, endpoint_group="USER_VIEW", granted_by=None))
    db.add(UserEndpointPermission(user_id=dana.id, endpoint_group="USER_MANAGE", granted_by=None))
    db.commit()
    assert ep.reset_to_role_defaults(dana.id, RoleEnum.EXTERNAL, db)["removed"] == sorted(ADMIN_ONLY + USER_DEFAULTS)


def test_what_a_kept_grant_depends_on_stays_with_it(db):
    # Granted again by an administrator, FILE_UPLOAD is a grant; what it needs (FILE_VIEW, VAULT_VIEW) is
    # still held as the user's defaults, and stays so that the grant keeps working.
    ada = _user(db, "ada", RoleEnum.ADMIN)
    eve = _user(db, "eve")
    ep.revoke_endpoint_permission(str(eve.id), "FILE_UPLOAD", db)
    _grant(db, eve, "FILE_UPLOAD", by=ada)
    change = ep.reset_to_role_defaults(eve.id, RoleEnum.EXTERNAL, db)
    db.commit()
    assert _groups(db, eve) == ["FILE_UPLOAD", "FILE_VIEW", "VAULT_VIEW"]
    assert change["kept"] == ["FILE_UPLOAD", "FILE_VIEW", "VAULT_VIEW"]
    eve.role = RoleEnum.EXTERNAL
    assert ep.endpoint_permission_denial(db, eve, "FILE_UPLOAD") is None, "the kept grant still works"


def test_a_promotion_adds_the_administrators_defaults_and_a_demotion_takes_them_back(db):
    carol = _user(db, "carol")
    assert ep.reset_to_role_defaults(carol.id, RoleEnum.ADMIN, db) == {"removed": [], "added": ADMIN_ONLY,
                                                                     "kept": []}
    db.commit()
    assert _groups(db, carol) == ADMIN_DEFAULTS
    ep.reset_to_role_defaults(carol.id, RoleEnum.USER, db)
    db.commit()
    assert _groups(db, carol) == USER_DEFAULTS


def test_a_row_outside_the_catalogue_is_left_alone(db):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    db.add(UserEndpointPermission(user_id=ada.id, endpoint_group="users.list", granted_by=None))
    db.commit()
    ep.reset_to_role_defaults(ada.id, RoleEnum.USER, db)
    db.commit()
    assert "users.list" in _groups(db, ada)


def test_nothing_is_committed_by_the_reset(db):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    ep.reset_to_role_defaults(ada.id, RoleEnum.USER, db)
    db.rollback()
    assert _groups(db, ada) == ADMIN_DEFAULTS


# --------------------------------------------------------------------------- the routes


def _request():
    return SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.44"))


def _patch_users(db, actor, target, role):
    return run_coroutine(api.update_user(user_id=target.id, user_update=api.UserUpdate(role=role),
                                         current_user=actor, db=db, request=_request()))


def _put_user_management(db, actor, target, role):
    return run_coroutine(um.update_user(user_id=target.id, update_data=um.UserUpdateRequest(role=role),
                                        request=None, current_user=actor, db=db))


def _patch_role(db, actor, target, role):
    return run_coroutine(um.change_user_role(user_id=target.id, request=um.ChangeRoleRequest(new_role=role),
                                             current_user=actor, db=db, http_request=None))


ROUTES = {
    "PATCH /users/{id}": _patch_users,
    "PUT /api/user-management/users/{id}": _put_user_management,
    "PATCH /api/user-management/users/{id}/role": _patch_role,
}


def _mint(db, target, maker):
    link = api._mint_reset_link(db, target, "https://vault.example.com", created_by_id=maker.id,
                                made_by_other=maker.id != target.id)
    return link.split("?reset=")[1]


def _use(db, token):
    body = api.ResetPasswordRequest(new_password="Former-Admin-Pw0rd!7")
    return run_coroutine(api.do_reset(token=token, body=body, request=_request(), db=db))


def _mint_through_the_route(db, maker, target):
    return run_coroutine(api.admin_mint_reset_link(user_id=target.id, request=_request(), current_user=maker,
                                                   db=db))


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_each_route_that_demotes_an_administrator_resets_their_permissions(db, told, route):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    bob = _user(db, "bob", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    token = _mint(db, carol, bob)          # made while bob was an administrator

    ROUTES[route](db, ada, bob, RoleEnum.USER)

    db.expire_all()
    assert db.get(User, bob.id).role == RoleEnum.USER
    assert _groups(db, bob) == USER_DEFAULTS, "the administrator's defaults outlived the demotion"
    (row,) = _audit(db, "permissions_reset_for_role")
    assert (row.status, row.user_id, row.resource_type, row.resource_id) == ("success", ada.id, "user", str(bob.id))
    assert (row.details["old_role"], row.details["new_role"], row.details["removed"]) == ("admin", "user", ADMIN_ONLY)
    assert row.details["target_username"] == "bob"
    notice = [n for n in told if n[0] == "bob" and n[1] == "Your role was changed"]
    assert len(notice) == 1 and "Manage Users" in notice[0][2] and "View Users" in notice[0][2], told

    # The former administrator can make no reset link now...
    with pytest.raises(HTTPException) as refused:
        _mint_through_the_route(db, db.get(User, bob.id), carol)
    assert refused.value.status_code == 403
    assert db.query(PasswordResetToken).filter(PasswordResetToken.created_by == bob.id).count() == 1
    # ...and the one made before the demotion is refused when used, exactly as an unknown one.
    with pytest.raises(HTTPException) as used:
        _use(db, token)
    assert (used.value.status_code, used.value.detail) == (404, UNKNOWN)
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [aa.MAKER_WITHOUT_PERMISSION]
    db.expire_all()
    assert db.get(User, carol.id).password_hash == "old-hash"


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_each_route_that_makes_an_administrator_an_external_user_resets_their_permissions(db, told, route):
    # The external role has no permissions of its own, so an administrator made an external user keeps
    # none. Kept, the permission to manage users would reach every other external account, whose role is
    # not above theirs: the check on whose account a link is for does not stop that on its own.
    ada = _user(db, "ada", RoleEnum.ADMIN)
    bob = _user(db, "bob", RoleEnum.ADMIN)
    xena = _user(db, "xena", RoleEnum.EXTERNAL)
    token = _mint(db, xena, bob)           # made while bob was an administrator

    ROUTES[route](db, ada, bob, RoleEnum.EXTERNAL)

    db.expire_all()
    assert db.get(User, bob.id).role == RoleEnum.EXTERNAL
    assert _groups(db, bob) == [], "an external user holds no permission nobody granted them"
    (row,) = _audit(db, "permissions_reset_for_role")
    assert (row.details["old_role"], row.details["new_role"]) == ("admin", "external")
    assert (row.details["removed"], row.details["added"], row.details["kept"]) == (ADMIN_DEFAULTS, [], [])
    notice = [n for n in told if n[0] == "bob" and n[1] == "Your role was changed"]
    assert len(notice) == 1 and "Manage Users" in notice[0][2], told

    # No reset link for another external account now...
    with pytest.raises(HTTPException) as refused:
        _mint_through_the_route(db, db.get(User, bob.id), xena)
    assert refused.value.status_code == 403
    assert db.query(PasswordResetToken).filter(PasswordResetToken.created_by == bob.id).count() == 1
    # ...and the one made before is refused when used, because its maker may no longer manage users.
    with pytest.raises(HTTPException) as used:
        _use(db, token)
    assert (used.value.status_code, used.value.detail) == (404, UNKNOWN)
    assert [r.details["reason"] for r in _audit(db, "password_reset_link_refused")] == [aa.MAKER_WITHOUT_PERMISSION]
    db.expire_all()
    assert db.get(User, xena.id).password_hash == "old-hash"


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_promotion_and_a_demotion_through_the_route_come_back_to_the_users_defaults(db, told, route):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    ROUTES[route](db, ada, carol, RoleEnum.ADMIN)
    assert _groups(db, carol) == ADMIN_DEFAULTS
    db.expire_all()
    ROUTES[route](db, ada, db.get(User, carol.id), RoleEnum.USER)
    assert _groups(db, carol) == USER_DEFAULTS
    assert [r.details["removed"] for r in _audit(db, "permissions_reset_for_role")] == [[], ADMIN_ONLY]
    notices = [n[2] for n in told if n[0] == "carol" and n[1] == "Your role was changed"]
    assert len(notices) == 2 and "reset" not in notices[0] and "Manage Users" in notices[1], notices


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_grant_made_again_after_the_demotion_works(db, told, route):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    bob = _user(db, "bob", RoleEnum.ADMIN)
    carol = _user(db, "carol")
    ROUTES[route](db, ada, bob, RoleEnum.USER)
    db.expire_all()
    bob = db.get(User, bob.id)
    assert ep.endpoint_permission_denial(db, bob, "USER_MANAGE") == "missing_required_group"
    run_coroutine(api.grant_user_permission(user_id=bob.id, request=api.GrantPermissionRequest(
        endpoint_group="USER_MANAGE"), current_user=ada, db=db))
    assert ep.endpoint_permission_denial(db, bob, "USER_MANAGE") is None
    token = _mint(db, carol, bob)
    assert _use(db, token) == {"ok": True}, "a delegate's link for an ordinary user works as before"
    # And a later change of role keeps what was granted deliberately.
    ROUTES[route](db, ada, bob, RoleEnum.ADMIN)
    db.expire_all()
    ROUTES[route](db, ada, db.get(User, bob.id), RoleEnum.USER)
    assert "USER_MANAGE" in _groups(db, bob)


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_resaving_the_same_role_resets_nothing(db, told, route):
    if route == "PATCH /api/user-management/users/{id}/role":
        pytest.skip("that route refuses a role the account already has")
    ada = _user(db, "ada", RoleEnum.ADMIN)
    dana = _user(db, "dana")
    db.add(UserEndpointPermission(user_id=dana.id, endpoint_group="USER_MANAGE", granted_by=None))
    db.add(UserEndpointPermission(user_id=dana.id, endpoint_group="USER_VIEW", granted_by=None))
    db.commit()
    ROUTES[route](db, ada, dana, RoleEnum.USER)
    assert "USER_MANAGE" in _groups(db, dana)
    assert _audit(db, "permissions_reset_for_role") == []


def test_a_route_that_fails_after_the_role_is_set_keeps_the_permissions(db, told, monkeypatch):
    # The reset is in the role change's transaction: a refusal after it undoes both.
    ada = _user(db, "ada", RoleEnum.ADMIN)
    bob = _user(db, "bob", RoleEnum.ADMIN)

    def cap(db):
        raise HTTPException(status_code=403, detail="The plan's user limit is reached.")
    monkeypatch.setattr(api, "_enforce_user_cap", cap)
    bob.is_active = False
    db.commit()
    with pytest.raises(HTTPException):
        run_coroutine(api.update_user(user_id=bob.id, user_update=api.UserUpdate(role=RoleEnum.USER, is_active=True),
                                      current_user=ada, db=db, request=_request()))
    db.rollback()
    assert _groups(db, bob) == ADMIN_DEFAULTS
    assert db.get(User, bob.id).role == RoleEnum.ADMIN


def test_the_action_is_catalogued():
    from app.core import audit_catalog
    action = audit_catalog.lookup("permissions_reset_for_role")
    assert (action.category, action.severity) == ("accounts", "notice")


# --------------------------------------------------------------------------- every role change


def _role_assignments():
    """(file, enclosing function) of every assignment to an account's ``role`` in app/."""
    out = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                targets = node.targets if isinstance(node, ast.Assign) else (
                    [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for t in targets:
                    if isinstance(t, ast.Attribute) and t.attr == "role":
                        out.append((path.relative_to(ROOT).as_posix(), fn.name))
    return out


def test_every_change_of_role_goes_through_the_one_place_that_resets_permissions():
    # A role set anywhere else would leave the old role's permissions to the account. A new place that
    # changes a role fails here until it calls _set_role instead.
    assert _role_assignments() == [("app/api/api_server.py", "_set_role")]


def test_every_route_that_changes_a_role_calls_it():
    import inspect
    callers = set()
    for module in (api, um):
        tree = ast.parse(inspect.getsource(module))
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name != "_set_role":
                if any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_set_role" for n in ast.walk(fn)):
                    callers.add((module.__name__.rsplit(".", 1)[-1], fn.name))
    assert callers == {("api_server", "update_user"), ("user_management_api", "update_user"),
                       ("user_management_api", "change_user_role")}, callers
