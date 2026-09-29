"""Nobody who is not an administrator changes an administrator's account, offline.

An administrator can give a user the permission to manage users. The two reset-link routes let such a
user make a password reset link for any account, an administrator's included: copied, the link is the
administrator's account. Now a caller who is not an interactive administrator may change only an account
whose role is not above theirs (app/core/account_authority.py), and a refusal is recorded.

This drives the rule, the two routes as a user who holds the permission (against an administrator and
against an ordinary user, on a real database), and sweeps every route that changes someone else's
account: each one either requires an interactive administrator outright or asks the rule. The sweep finds
such a route by what its code does (a credential change, a write to an account's fields, its credential
rows made or deleted, an account looked up by a path parameter), whatever its parameters are called, and
every route it finds must be in one of the lists below.
test_account_authority_live.py drives every such route on a running stack.
"""
import ast
import inspect
import re
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

# Routes that name an account, or look as if they change one, but change something else, with the reason.
NOT_THE_ACCOUNT = {
    ("POST", "/shares/{share_id}/claims/{user_id}/revoke"): "a share's claim, not the account",
    ("DELETE", "/groups/{group_id}/members/{user_id}"): "a department's membership, not the account",
    ("DELETE", "/vaults/{vault_id}/permissions/{user_id}"): "a vault's access, not the account",
    ("DELETE", "/ecc/vaults/{vault_id}/members/{user_id}"): "a zero-knowledge vault's key, not the account",
    ("PUT", "/vaults/{vault_id}/password"): "a vault's password, not an account's",
    ("DELETE", "/invites/{invite_id}"): "an invitation not yet accepted: there is no account yet",
}

# Routes that change the caller's own account and no one else's, with the reason.
OWN_ACCOUNT = {
    ("PATCH", "/users/me"): "the caller's own settings, password and email",
    ("POST", "/users/me/confirm-email-change"): "the caller's own email change",
    ("DELETE", "/users/me/second-factor"): "the caller's own second factor",
    ("POST", "/users/me/second-factor/recovery/acknowledge"): "the caller's own recovery codes",
    ("POST", "/users/me/second-factor/recovery/regenerate"): "the caller's own recovery codes",
    ("POST", "/users/me/second-factor/totp/confirm"): "the caller's own second factor",
    ("POST", "/users/me/second-factor/totp/enroll"): "the caller's own second factor",
    ("POST", "/auth/temp-credentials"): "a temporary credential for the caller's own account",
}

# Routes that remove a device or a temporary credential: the caller's own, and another account's only
# when the caller is an administrator. Each compares the owner with the caller (checked below).
OWN_UNLESS_ADMINISTRATOR = {
    ("POST", "/devices/{device_id}/revoke"),
    ("DELETE", "/devices/{device_id}"),
    ("POST", "/devices/{device_id}/grants/{vault_id}/revoke"),
    ("POST", "/temp-creds/{temp_username}/deactivate"),
    ("POST", "/temp-creds/{temp_username}/delete"),
    ("POST", "/api/user-management/temp-credentials/{temp_cred_id}/deactivate"),
    ("DELETE", "/api/user-management/temp-credentials/{temp_cred_id}"),
}

# Public routes that act on the account a link was made for, or send a link to the account's own
# address: whoever holds the link acts, with no session, so none of the lists above fits them.
LINK_USE = {
    ("POST", "/reset/{token}"): "sets the password of the account a reset link was made for",
    ("POST", "/invites/{token}/accept"): "makes the account an invitation was made for",
    ("POST", "/auth/forgot-password"): "emails a reset link to the account's own address",
}

_ADMIN_ONLY = {"require_admin", "require_interactive_admin"}


# What changes an account, as the code says it: a helper that makes a credential change, mints a reset
# link, or gives or takes a role, a standing, a permission or sessions; a write to one of an account's
# own fields; or making or deleting one of the rows that are its credentials.
_ACCOUNT_CHANGERS = {
    "_credential_change", "_apply_credential_change", "_approve_credential_change", "_mint_reset_link",
    "_mint_and_send_reset", "_record_admin_grant", "_withdraw_requests_of", "grant_endpoint_permission",
    "revoke_endpoint_permission", "create_temporary_credential", "_revoke_sessions",
}
_ACCOUNT_FIELDS = {
    "password_hash", "email", "role", "is_locked", "locked_until", "failed_login_attempts",
    "second_factor_reset_at", "sftp_enabled", "sftp_password_auth", "storage_quota_bytes",
}
_ACCOUNT_ROWS = {
    "UserSSHKey", "AccountInvitation", "PasswordResetToken", "SecondFactorEnrollment",
    "SecondFactorRecoveryCode", "UserEndpointPermission", "TemporaryCredential",
}


def _source_tree(fn):
    return ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(fn))))


def _queried_models(node):
    """The model names a query chain reads (``db.query(Model).filter(...)``), for the call it ends in."""
    models = set()
    while isinstance(node, (ast.Call, ast.Attribute)):
        if isinstance(node, ast.Call):
            if getattr(node.func, "attr", None) == "query":
                models |= {a.id for a in node.args if isinstance(a, ast.Name)}
            node = node.func.value if isinstance(node.func, ast.Attribute) else None
        else:
            node = node.value
    return models


def _account_changes(fn, depth=2, seen=None):
    """What in ``fn``, or in a function of its module it calls (to ``depth``), changes an account."""
    seen = set() if seen is None else seen
    fn = inspect.unwrap(fn)
    if fn in seen:
        return set()
    seen.add(fn)
    try:
        tree = _source_tree(fn)
    except (OSError, TypeError):
        return set()
    found, called, queried, deletes = set(), set(), set(), False
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                if isinstance(t, ast.Attribute) and t.attr in _ACCOUNT_FIELDS:
                    found.add(f"sets .{t.attr}")
        elif isinstance(n, ast.Attribute) and n.attr in _ACCOUNT_CHANGERS:
            found.add(n.attr)            # also when handed on, as run_offloaded(service.method, ...) does
        elif isinstance(n, ast.Call):
            name = getattr(n.func, "id", getattr(n.func, "attr", None))
            called.add(name)
            if name in _ACCOUNT_CHANGERS:
                found.add(name)
            if isinstance(n.func, ast.Name) and name in _ACCOUNT_ROWS:
                found.add(f"makes {name}")
            if isinstance(n.func, ast.Attribute):
                queried |= _queried_models(n.func.value) & _ACCOUNT_ROWS
                deletes = deletes or name == "delete"
                if name in ("delete", "update"):
                    found |= {f"{name}s {m}" for m in _queried_models(n.func.value) & _ACCOUNT_ROWS}
    if deletes and queried:
        found |= {f"deletes {m}" for m in queried}    # read first, then db.delete(row)
    if depth:
        module = inspect.getmodule(fn)
        for name in called:
            helper = getattr(module, name, None) if name else None
            if inspect.isfunction(helper):
                found |= _account_changes(helper, depth - 1, seen)
    return found


def _names_an_account_in_its_path(path, fn):
    """Whether the route looks an account up by one of its path parameters, whatever it is called."""
    params = set(re.findall(r"{(\w+)}", path))
    for n in ast.walk(_source_tree(fn)):
        if (isinstance(n, ast.Compare) and isinstance(n.left, ast.Attribute)
                and isinstance(n.left.value, ast.Name) and n.left.value.id == "User"):
            if params & {x.id for c in n.comparators for x in ast.walk(c) if isinstance(x, ast.Name)}:
                return True
    return False


def _changes_or_names_an_account(path, route):
    return ("{user_id}" in path or bool(_account_changes(route.endpoint))
            or _names_an_account_in_its_path(path, route.endpoint))


_LISTED = (CHANGES_AN_ACCOUNT | set(NOT_THE_ACCOUNT) | set(OWN_ACCOUNT) | OWN_UNLESS_ADMINISTRATOR
           | set(LINK_USE))


def test_every_route_that_changes_an_account_is_listed():
    # Found by what the route does, not by what its parameter is called: a new route that sets an
    # account's password under /accounts/{account} is found as surely as one under /users/{user_id},
    # and so is one that takes the account in its body.
    found = {(m, p) for p, r in _routes() for m in r.methods - {"HEAD", "OPTIONS", "GET"}
             if _changes_or_names_an_account(p, r)}
    unlisted = found - _LISTED
    assert not unlisted, f"a route changes or names an account and is in no list: {sorted(unlisted)}"


def test_every_listed_route_exists():
    routes = {(m, p) for p, r in _routes() for m in r.methods}
    assert not _LISTED - routes, f"listed, but there is no such route: {sorted(_LISTED - routes)}"


def _set_a_password(account_ref, db, body):
    target = db.query(User).filter(User.id == account_ref).first()
    target.password_hash = body.password_hash


def _drop_a_key(ref, key_ref, db):
    from app.core.models import UserSSHKey
    key = db.query(UserSSHKey).filter(UserSSHKey.id == key_ref).first()
    db.delete(key)


def _lock_through_a_helper(db, who):
    _lock(who)


def _lock(who):
    who.is_locked = True


def _read_only(db, account_ref):
    return db.query(User).filter(User.is_active.is_(True)).count()


def test_the_sweep_finds_an_account_change_whatever_the_parameter_is_called():
    assert _names_an_account_in_its_path("/accounts/{account_ref}/password", _set_a_password)
    assert "sets .password_hash" in _account_changes(_set_a_password)
    assert "deletes UserSSHKey" in _account_changes(_drop_a_key)
    assert "sets .is_locked" in _account_changes(_lock_through_a_helper), "through a helper of the module"
    assert not _account_changes(_read_only)
    assert not _names_an_account_in_its_path("/accounts/{account_ref}", _read_only)


def _only_own_unless_administrator(fn, depth=1):
    """Whether ``fn`` (or a function of its module it calls) refuses a caller who is not an administrator
    another account's row: ``current_user.role != RoleEnum.ADMIN and <row>.user_id != current_user.id``."""
    tree = _source_tree(fn)
    for n in ast.walk(tree):
        if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.And):
            parts = {ast.unparse(v).replace(" ", "") for v in n.values}
            if ("current_user.role!=RoleEnum.ADMIN" in parts
                    and any(x.endswith(".user_id!=current_user.id") for x in parts)):
                return True
    if depth == 0:
        return False
    module = inspect.getmodule(inspect.unwrap(fn))
    called = {getattr(n.func, "id", None) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    return any(_only_own_unless_administrator(getattr(module, name), depth - 1) for name in called
               if name and inspect.isfunction(getattr(module, name, None)))


@pytest.mark.parametrize("method,path", sorted(OWN_UNLESS_ADMINISTRATOR))
def test_a_device_or_temporary_credential_is_removed_only_by_its_owner_or_an_administrator(method, path):
    (route,) = [r for p, r in _routes() if p == path and method in r.methods]
    assert _only_own_unless_administrator(route.endpoint), f"{method} {path} does not compare owner and caller"


@pytest.mark.parametrize("method,path", sorted(OWN_ACCOUNT))
def test_a_route_for_the_callers_own_account_names_no_account(method, path):
    (route,) = [r for p, r in _routes() if p == path and method in r.methods]
    assert not re.findall(r"{(\w+)}", path), f"{method} {path} takes a parameter"


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
