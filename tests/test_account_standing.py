"""Every route that takes an account's standing away calls _account_lost_standing, offline.

An account loses its standing when it is demoted from administrator, deactivated, locked by an
administrator, or deleted. Whatever must follow from that (an administrator's open requests withdrawn
and their invitations revoked, today) is done in one place, api_server._account_lost_standing, which
every such route calls before it makes the change; nothing else calls _withdraw_requests_of. This sweeps
every route by what its code does: a route that sets an account's is_active, is_locked or role, deletes
an account, or calls the withdrawal, itself or through a function it calls, with the account passed on,
must reach _account_lost_standing, or be listed below with the reason it takes nothing away. A throwaway
route of each shape shows the sweep finds it.
"""
import ast
import inspect
import re
from pathlib import Path

import pytest

import test_account_authority as authority

pytestmark = pytest.mark.unit

api = authority.api
APP = Path(__file__).resolve().parent.parent / "app"
HELPER = "_account_lost_standing"
STANDING_FIELDS = {"is_active", "is_locked", "role"}

# Routes whose code sets one of those fields on an account, or deletes one, without taking anyone's
# standing away, with the reason: (method, path) -> why. None today; making an account sets its role and
# its flags in the constructor, which is no change to an account that had standing.
TAKES_NOTHING_AWAY: dict = {}


def _user_param_names(fn, args, keywords, users):
    """The parameters of ``fn`` that the call passes an account to, by position or by name."""
    try:
        params = list(inspect.signature(inspect.unwrap(fn)).parameters)
    except (TypeError, ValueError):
        return set()
    names = set()
    for i, arg in enumerate(args):
        if isinstance(arg, ast.Name) and arg.id in users and i < len(params):
            names.add(params[i])
    for kw in keywords:
        if kw.arg and isinstance(kw.value, ast.Name) and kw.value.id in users and kw.arg in params:
            names.add(kw.arg)
    return names


def standing_changes(fn, user_params=frozenset(), depth=2, seen=None):
    """What in ``fn``, or in a function it calls with an account (to ``depth``), takes an account's standing:
    ``sets .<field>`` on an account, ``deletes User``, ``updates User``, a field named at run time, or a
    direct call to the withdrawal. A function it calls is followed when it is of its own module or of the
    app's, as test_account_authority follows them."""
    seen = set() if seen is None else seen
    fn = inspect.unwrap(fn)
    key = (fn, frozenset(user_params))
    if key in seen:
        return set()
    seen.add(key)
    try:
        tree = authority._source_tree(fn)
    except (OSError, TypeError):
        return set()
    module = inspect.getmodule(fn)
    local = authority._local_imports(tree)

    def scope(name):
        return local[name] if name in local else getattr(module, name, None)

    users = authority._user_names(tree) | set(user_params)
    found = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = list(n.targets if isinstance(n, ast.Assign) else [n.target])
            while any(isinstance(t, (ast.Tuple, ast.List)) for t in targets):
                targets = [e for t in targets for e in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t])]
            for t in targets:
                if (isinstance(t, ast.Attribute) and t.attr in STANDING_FIELDS and isinstance(t.value, ast.Name)
                        and t.value.id in users):
                    found.add(f"sets .{t.attr}")
        elif isinstance(n, ast.Call):
            name = getattr(n.func, "id", getattr(n.func, "attr", None))
            if name == "_withdraw_requests_of":
                found.add("_withdraw_requests_of")
            if (name == "setattr" and len(n.args) >= 2 and isinstance(n.args[0], ast.Name)
                    and n.args[0].id in users):
                field = n.args[1]
                if not isinstance(field, ast.Constant):
                    found.add("sets a field of an account named at run time")
                elif field.value in STANDING_FIELDS:
                    found.add(f"sets .{field.value}")
            if isinstance(n.func, ast.Attribute) and name in ("delete", "update"):
                if "User" in authority._queried_models(n.func.value):
                    found.add(f"{name}s User")
                if (name == "delete" and n.args and isinstance(n.args[0], ast.Name)
                        and n.args[0].id in users):
                    found.add("deletes User")
            if depth:
                target = authority._resolve(n.func, scope)
                if (inspect.isfunction(target) and target.__name__ != HELPER
                        and (authority._in_app(target) or inspect.getmodule(target) is module)):
                    passed = _user_param_names(target, n.args, n.keywords, users)
                    if passed:
                        found |= standing_changes(target, passed, depth - 1, seen)
    return found


def reaches_the_helper(fn, depth=2, seen=None):
    """Whether ``fn`` calls _account_lost_standing, itself or through a function it calls, of its own module
    or of the app's."""
    seen = set() if seen is None else seen
    fn = inspect.unwrap(fn)
    if fn in seen:
        return False
    seen.add(fn)
    try:
        tree = authority._source_tree(fn)
    except (OSError, TypeError):
        return False
    module = inspect.getmodule(fn)
    local = authority._local_imports(tree)

    def scope(name):
        return local[name] if name in local else getattr(module, name, None)

    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            if getattr(n.func, "id", getattr(n.func, "attr", None)) == HELPER:
                return True
            if depth:
                target = authority._resolve(n.func, scope)
                if (inspect.isfunction(target) and (authority._in_app(target) or inspect.getmodule(target) is module)
                        and reaches_the_helper(target, depth - 1, seen)):
                    return True
    return False


def problems(method, path, route):
    """Why ``route`` breaks the rule, or an empty list."""
    changes = standing_changes(route.endpoint)
    if not changes or (method, path) in TAKES_NOTHING_AWAY:
        return []
    out = []
    if not reaches_the_helper(route.endpoint):
        out.append(f"{method} {path} {sorted(changes)} without {HELPER}")
    if "_withdraw_requests_of" in changes:
        out.append(f"{method} {path} calls _withdraw_requests_of itself")
    return out


def _mutating_routes():
    return [(m, p, r) for p, r in authority._routes() for m in sorted(r.methods - {"HEAD", "OPTIONS", "GET"})]


# --------------------------------------------------------------------------- the rule

def test_every_route_that_takes_standing_away_calls_the_helper():
    found = [x for m, p, r in _mutating_routes() for x in problems(m, p, r)]
    assert not found, found


def test_the_sweep_finds_the_routes_it_should():
    # Not vacuous: the routes that demote, deactivate, lock and delete are found, and reach the helper.
    taking = {(m, p) for m, p, r in _mutating_routes() if standing_changes(r.endpoint)}
    expected = {
        ("PATCH", "/users/{user_id}"),
        ("POST", "/users/{user_id}/delete"),
        ("PUT", "/api/user-management/users/{user_id}"),
        ("POST", "/api/user-management/users/{user_id}/toggle-active"),
        ("POST", "/api/user-management/users/{user_id}/toggle-locked"),
        ("PATCH", "/api/user-management/users/{user_id}/role"),
    }
    assert expected <= taking, sorted(expected - taking)
    assert taking - expected <= set(TAKES_NOTHING_AWAY), sorted(taking - expected - set(TAKES_NOTHING_AWAY))
    for method, path, route in _mutating_routes():
        if (method, path) in expected:
            assert reaches_the_helper(route.endpoint), (method, path)


def test_every_route_listed_as_taking_nothing_away_exists_and_changes_what_it_says():
    routes = {(m, p): r for m, p, r in _mutating_routes()}
    for key, why in TAKES_NOTHING_AWAY.items():
        assert key in routes, f"listed, but there is no such route: {key}"
        assert standing_changes(routes[key].endpoint), f"{key} changes no standing field: drop it from the list"
        assert why


def test_nothing_but_the_helper_calls_the_withdrawal():
    callers = set()
    for path in APP.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    if (isinstance(node, ast.Call)
                            and getattr(node.func, "id", getattr(node.func, "attr", None)) == "_withdraw_requests_of"):
                        callers.add((path.relative_to(APP).as_posix(), fn.name))
    assert callers == {("api/api_server.py", HELPER)}, sorted(callers)


def test_the_helper_withdraws_reports_keys_and_returns_what_is_announced(monkeypatch):
    calls = []

    def withdraw(db, user, *, actor, because):
        calls.append(("withdraw", db, user, actor, because))
        return ["told"]

    def report(db, user, *, actor, because):
        calls.append(("keys", db, user, actor, because))
        return {"maker": "bob"}

    monkeypatch.setattr(api, "_withdraw_requests_of", withdraw)
    monkeypatch.setattr(api, "_report_keys_added_by", report)
    lost = api._account_lost_standing("db", "bob", actor="ada", because="locked")
    assert (lost.withdrawn, lost.keys) == (["told"], {"maker": "bob"})
    assert calls == [("withdraw", "db", "bob", "ada", "locked"), ("keys", "db", "bob", "ada", "locked")]
    # And the announcement after the commit tells both.
    announced = []
    monkeypatch.setattr(api, "_announce_withdrawn_requests", lambda db, w: announced.append(("withdrawn", w)))
    monkeypatch.setattr(api, "_announce_keys_reported", lambda db, r, request=None: announced.append(("keys", r)))
    api._announce_lost_standing("db", lost)
    assert announced == [("withdrawn", ["told"]), ("keys", {"maker": "bob"})]


# --------------------------------------------------------------------------- throwaway routes

def _withdraw_requests_of(db, user, *, actor, because):   # noqa: ARG001 -- a stand-in, found by name
    return []


def _account_lost_standing(db, user, *, actor, because):   # noqa: ARG001 -- a stand-in, found by name
    return []


def _deactivate_through_the_withdrawal(db, ref):
    from app.core.models import User
    account = db.query(User).filter(User.id == ref).first()
    _withdraw_requests_of(db, account, actor=None, because="deactivated")
    account.is_active = False


def _deactivate_through_the_helper(db, ref):
    from app.core.models import User
    account = db.query(User).filter(User.id == ref).first()
    _account_lost_standing(db, account, actor=None, because="deactivated")
    account.is_active = False


def _lock_quietly(db, ref):
    from app.core.models import User
    account = db.get(User, ref)
    account.is_locked, account.locked_until = True, None


def _demote_through_set_role(db, ref):
    from app.core.models import RoleEnum, User
    target = db.query(User).filter(User.id == ref).first()
    api._set_role(db, target, RoleEnum.USER, actor=None)


def _delete_quietly(db, ref):
    from app.core.models import User
    doomed = db.query(User).filter(User.id == ref).first()
    db.delete(doomed)


def _bulk_deactivate(db, ref):
    from app.core.models import User
    db.query(User).filter(User.id == ref).update({"is_active": False})


def _flip_a_session(db, ref):
    from app.core.models import ActiveSession
    session = db.query(ActiveSession).filter(ActiveSession.id == ref).first()
    session.is_active = False          # a session's flag, not an account's


@pytest.mark.parametrize("fn,why", [
    (_deactivate_through_the_withdrawal, "calls _withdraw_requests_of itself"),
    (_deactivate_through_the_withdrawal, "without _account_lost_standing"),
    (_lock_quietly, "without _account_lost_standing"),
    (_demote_through_set_role, "without _account_lost_standing"),
    (_delete_quietly, "without _account_lost_standing"),
    (_bulk_deactivate, "without _account_lost_standing"),
])
def test_a_throwaway_route_of_each_shape_is_refused(fn, why):
    route = authority._throwaway_route(fn)
    found = problems("POST", route.path, route)
    assert any(why in p for p in found), found


def test_a_throwaway_route_that_calls_the_helper_passes():
    route = authority._throwaway_route(_deactivate_through_the_helper)
    assert standing_changes(route.endpoint) == {"sets .is_active"}
    assert problems("POST", route.path, route) == []


def test_a_flag_on_something_that_is_not_an_account_is_not_standing():
    route = authority._throwaway_route(_flip_a_session)
    assert standing_changes(route.endpoint) == set()


def test_a_helper_given_the_account_is_followed_and_one_given_something_else_is_not():
    assert standing_changes(_demote_through_set_role) == {"sets .role"}
    source = inspect.getsource(api._set_role)
    assert re.search(r"\buser\.role = new_role\b", source)


def _leave(db, who):
    _account_lost_standing(db, who, actor=None, because="deactivated")


def _lock_through_a_helper(db, who):
    who.is_locked = True


def _deactivate_through_a_helper_that_calls_the_helper(db, ref):
    from app.core.models import User
    account = db.query(User).filter(User.id == ref).first()
    _leave(db, account)
    account.is_active = False


def _lock_through_a_helper_given_the_account(db, ref):
    from app.core.models import User
    account = db.query(User).filter(User.id == ref).first()
    _lock_through_a_helper(db, account)


def test_the_helper_may_be_called_through_a_function_of_the_routes_module():
    route = authority._throwaway_route(_deactivate_through_a_helper_that_calls_the_helper)
    assert reaches_the_helper(route.endpoint)
    assert problems("POST", route.path, route) == []


def test_a_change_made_by_a_function_of_the_routes_module_is_found():
    route = authority._throwaway_route(_lock_through_a_helper_given_the_account)
    assert standing_changes(route.endpoint) == {"sets .is_locked"}
    assert any("without _account_lost_standing" in p for p in problems("POST", route.path, route))
