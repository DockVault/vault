"""Nobody who is not an administrator changes an administrator's account, offline.

An administrator can give a user the permission to manage users. The two reset-link routes let such a
user make a password reset link for any account, an administrator's included: copied, the link is the
administrator's account. Now a caller who is not an interactive administrator may change only an account
whose role is not above theirs (app/core/account_authority.py), and a refusal is recorded.

This drives the rule, the two routes as a user who holds the permission (against an administrator and
against an ordinary user, on a real database), and sweeps every route that changes someone else's
account: each one either requires an interactive administrator outright or asks the rule.
test_account_authority_live.py drives every such route on a running stack.
"""
import ast
import inspect
import tempfile
import textwrap
import uuid
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
from app.core.models import AuditLog, RoleEnum, User, UserEndpointPermission  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _who(role, temp=False, uid=None):
    person = SimpleNamespace(id=uid or uuid.uuid4(), role=role)
    if temp:
        person._is_temp_session = True
    return person


# --------------------------------------------------------------------------- the rule

@pytest.mark.parametrize("caller,target,why", [
    (RoleEnum.ADMIN, RoleEnum.ADMIN, None),
    (RoleEnum.ADMIN, RoleEnum.USER, None),
    (RoleEnum.USER, RoleEnum.ADMIN, aa.ADMINISTRATOR),
    (RoleEnum.USER, RoleEnum.USER, None),
    (RoleEnum.USER, RoleEnum.EXTERNAL, None),
    (RoleEnum.EXTERNAL, RoleEnum.ADMIN, aa.ADMINISTRATOR),
    (RoleEnum.EXTERNAL, RoleEnum.USER, aa.HIGHER_ROLE),
    (RoleEnum.EXTERNAL, RoleEnum.EXTERNAL, None),
    ("admin", "admin", None),                  # a role as the database stores it
    ("user", "admin", aa.ADMINISTRATOR),
])
def test_a_caller_may_change_only_an_account_not_above_their_role(caller, target, why):
    assert aa.refusal(_who(caller), _who(target)) == why


def test_a_temporary_credential_never_acts_as_an_administrator():
    temp_admin = _who(RoleEnum.ADMIN, temp=True)
    assert not aa.acts_as_administrator(temp_admin)
    assert aa.refusal(temp_admin, _who(RoleEnum.ADMIN)) == aa.ADMINISTRATOR
    assert aa.refusal(temp_admin, _who(RoleEnum.USER)) is None
    assert aa.refusal(_who(RoleEnum.EXTERNAL, temp=True), _who(RoleEnum.USER)) == aa.HIGHER_ROLE


def test_your_own_account_and_the_host_operator_are_not_refused():
    me = uuid.uuid4()
    assert aa.refusal(_who(RoleEnum.USER, uid=me), _who(RoleEnum.ADMIN, uid=me)) is None
    assert aa.refusal(None, _who(RoleEnum.ADMIN)) is None


def test_each_refusal_says_why_in_plain_words():
    assert aa.DETAILS[aa.ADMINISTRATOR] == "Only an administrator can change an administrator's account."
    assert "above yours" in aa.DETAILS[aa.HIGHER_ROLE]


# --------------------------------------------------------------------------- the reset-link routes

@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'authority.db'}")
        for model in (User, AuditLog, UserEndpointPermission):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role):
    u = User(username=name, email=f"{name}@example.com", password_hash="x", role=role, is_active=True,
             is_locked=False)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def delegate(db):
    """dana, a user given the permission to manage users (and the one it depends on), as a grant stores it."""
    dana = _user(db, "dana", RoleEnum.USER)
    for group in ("USER_VIEW", "USER_MANAGE"):
        db.add(UserEndpointPermission(user_id=dana.id, endpoint_group=group))
    db.commit()
    return dana


@pytest.fixture
def made(monkeypatch):
    """The credential changes the routes went on to make, stubbed: the rule on them is tested elsewhere."""
    calls = []
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    monkeypatch.setattr(api, "_notify_credential_change", lambda *a, **k: None)
    from app.core import password_reset
    monkeypatch.setattr(password_reset, "pepper_ok", lambda pepper: True)

    def credential_change(db, actor, target, kind, *, summary, payload, request=None):
        calls.append((actor.username, target.username, kind, payload.get("delivery")))
        result = {"reset_link": "https://vault.example.com/?reset=x", "expires_in_minutes": 60,
                  "email_sent": True}
        return SimpleNamespace(held=False, change=None, result=result, last=None)

    monkeypatch.setattr(api, "_credential_change", credential_change)
    return calls


_ROUTES = {
    "copy": lambda uid, who, db: api.admin_mint_reset_link(
        user_id=uid, request=SimpleNamespace(headers={}, client=None), current_user=who, db=db),
    "email": lambda uid, who, db: api.admin_send_reset_link(
        user_id=uid, request=SimpleNamespace(headers={}, client=None), current_user=who, db=db),
}


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_a_user_who_manages_users_cannot_make_a_reset_link_for_an_administrator(db, delegate, made, route):
    ada = _user(db, "ada", RoleEnum.ADMIN)
    ada_id = ada.id
    with pytest.raises(HTTPException) as refused:
        run_coroutine(_ROUTES[route](ada_id, delegate, db))
    assert refused.value.status_code == 403
    assert refused.value.detail == "Only an administrator can change an administrator's account."
    assert made == [], "a reset link was made for the administrator"
    (row,) = db.query(AuditLog).filter(AuditLog.action == "account_change_refused_role").all()
    assert (row.status, row.user_id, row.resource_id) == ("failure", delegate.id, str(ada_id))
    assert row.details == {"change": "reset_link", "target_username": "ada", "target_role": "admin",
                           "reason": aa.ADMINISTRATOR}


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_a_user_who_manages_users_still_makes_one_for_an_ordinary_user(db, delegate, made, route):
    carol = _user(db, "carol", RoleEnum.USER)
    answer = run_coroutine(_ROUTES[route](carol.id, delegate, db))
    assert made == [("dana", "carol", "reset_link", route)]
    assert ("reset_link" in answer) if route == "copy" else answer == {"email_sent": True}
    assert db.query(AuditLog).filter(AuditLog.action == "account_change_refused_role").count() == 0


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_an_administrator_still_makes_one_for_another_administrator(db, made, route):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN)
    run_coroutine(_ROUTES[route](bob.id, ada, db))
    assert made == [("ada", "bob", "reset_link", route)]


def test_an_external_user_who_manages_users_cannot_reach_a_user(db, made):
    # The same rule one rank down: an external account's role is below a user's.
    eve = _user(db, "eve", RoleEnum.EXTERNAL)
    for group in ("USER_VIEW", "USER_MANAGE"):
        db.add(UserEndpointPermission(user_id=eve.id, endpoint_group=group))
    db.commit()
    carol = _user(db, "carol", RoleEnum.USER)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(_ROUTES["copy"](carol.id, eve, db))
    assert refused.value.status_code == 403 and "above yours" in refused.value.detail
    assert made == []


# --------------------------------------------------------------------------- every route that can

def _routes():
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(routes, prefix):
        for r in routes:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    return list(walk(api.app.router.routes, ""))


def _dependency_names(route):
    names, stack = set(), [route.dependant]
    while stack:
        d = stack.pop()
        for sub in d.dependencies:
            if sub.call is not None:
                names.add(getattr(sub.call, "__name__", ""))
            stack.append(sub)
    return names


def _asks_the_rule(fn, depth=2):
    """Whether ``fn`` calls _refuse_change_above_caller, itself or through a function of its module."""
    fn = inspect.unwrap(fn)
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    called = {getattr(n.func, "id", getattr(n.func, "attr", None)) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    if "_refuse_change_above_caller" in called:
        return True
    if depth == 0:
        return False
    module = inspect.getmodule(fn)
    return any(_asks_the_rule(getattr(module, name), depth - 1) for name in called
               if name and name.startswith("_") and inspect.isfunction(getattr(module, name, None)))


# Every route that changes someone else's account: credentials, identity, role, active or locked,
# sessions, and deleting it.
CHANGES_AN_ACCOUNT = {
    ("POST", "/users/{user_id}/reset-link"),
    ("POST", "/users/{user_id}/send-reset-link"),
    ("PATCH", "/users/{user_id}"),
    ("POST", "/users/{user_id}/ssh-keys"),
    ("DELETE", "/users/{user_id}/ssh-keys/{key_id}"),
    ("POST", "/users/{user_id}/second-factor/reset"),
    ("POST", "/users/{user_id}/delete"),
    ("POST", "/users/{user_id}/terminate-sessions"),
    ("PUT", "/api/user-management/users/{user_id}"),
    ("POST", "/api/user-management/users/{user_id}/toggle-active"),
    ("POST", "/api/user-management/users/{user_id}/toggle-locked"),
    ("PATCH", "/api/user-management/users/{user_id}/role"),
    ("POST", "/api/user-management/users/{user_id}/temp-credentials"),
    ("POST", "/permissions/users/{user_id}/grant"),
    ("DELETE", "/permissions/users/{user_id}/revoke/{group_name}"),
    ("POST", "/admin/credential-requests/{change_id}/approve"),
    ("POST", "/users"),
    ("POST", "/invites"),
}

# Routes that name an account but change something else about it, with the reason.
NOT_THE_ACCOUNT = {
    ("POST", "/shares/{share_id}/claims/{user_id}/revoke"): "a share's claim, not the account",
    ("DELETE", "/groups/{group_id}/members/{user_id}"): "a department's membership, not the account",
    ("DELETE", "/vaults/{vault_id}/permissions/{user_id}"): "a vault's access, not the account",
    ("DELETE", "/ecc/vaults/{vault_id}/members/{user_id}"): "a zero-knowledge vault's key, not the account",
}

_ADMIN_ONLY = {"require_admin", "require_interactive_admin"}


def test_every_route_that_changes_someone_elses_account_is_listed():
    found = {(m, p) for p, r in _routes() for m in r.methods - {"HEAD", "OPTIONS", "GET"}
             if "{user_id}" in p}
    unlisted = found - {k for k in CHANGES_AN_ACCOUNT if "{user_id}" in k[1]} - set(NOT_THE_ACCOUNT)
    assert not unlisted, f"a route names an account and is in neither list: {sorted(unlisted)}"


@pytest.mark.parametrize("method,path", sorted(CHANGES_AN_ACCOUNT))
def test_every_such_route_requires_an_administrator_or_asks_the_rule(method, path):
    routes = [r for p, r in _routes() if p == path and method in r.methods]
    assert len(routes) == 1, f"{method} {path} is not one route"
    route = routes[0]
    admin_only = bool(_dependency_names(route) & _ADMIN_ONLY)
    assert admin_only or _asks_the_rule(route.endpoint), (
        f"{method} {path} lets someone who is not an administrator change another account without the rule")


def test_the_reset_link_routes_ask_the_rule_because_nothing_else_stops_a_delegate():
    # They are the routes a user who manages users reaches: no administrator dependency stands in front.
    for path in ("/users/{user_id}/reset-link", "/users/{user_id}/send-reset-link"):
        (route,) = [r for p, r in _routes() if p == path]
        assert not _dependency_names(route) & _ADMIN_ONLY, path
        assert _asks_the_rule(route.endpoint), path


def test_the_refusal_is_catalogued():
    from app.core import audit_catalog
    entry = audit_catalog.lookup("account_change_refused_role")
    assert entry is not None and entry.category == "security" and entry.severity == "warning"
