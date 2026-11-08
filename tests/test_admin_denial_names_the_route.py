"""A refused administrator action names the route it was refused on.

The web app writes an admin_access_denied row for every non-administrator turned away at an administrator
dependency. The row's endpoint is the route template of the request, filled in from the request context once
routing has matched it: an investigator can tell a stray read of one page from a probe of another. It is the
template, never the path or the query, so no identifier or token in a URL reaches the record.
"""
import sys
import types

import pytest

import _bare_api_env

_bare_api_env.set_bare_api_env()

from app.api import api_server  # noqa: E402
from app.core import request_context as rc  # noqa: E402

pytestmark = pytest.mark.unit


class _FakeDB:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        pass

    def rollback(self):
        pass


class _Route:
    path = "/users/{user_id}"


def _denial(scope):
    db = _FakeDB()
    user = types.SimpleNamespace(id="00000000-0000-0000-0000-000000000007", username="someone", role="user")
    token = rc.set_request_context(rc.RequestContext("GET", "/users/7f3a9c", "Mozilla/5.0", "web", scope))
    try:
        api_server._audit_admin_denial(db, user, "admin role required")
    finally:
        rc.reset_request_context(token)
    assert len(db.added) == 1, "one denial row"
    return db.added[0]


def test_the_denial_row_names_the_route_template():
    row = _denial({"route": _Route()})
    assert row.action == "admin_access_denied"
    assert row.endpoint == "/users/{user_id}"
    assert row.method == "GET"
    assert row.details == {"reason": "admin role required"}


def test_before_routing_the_row_holds_the_path_without_a_query_and_the_template_once_routed():
    """The context is built from the request's path alone (a query never enters it), and the same scope is
    filled by routing: a row written after that names the template."""
    scope = {}
    row = _denial(scope)
    assert row.endpoint == "/users/7f3a9c"
    assert "?" not in row.endpoint
    scope["route"] = _Route()
    assert _denial(scope).endpoint == "/users/{user_id}"


def test_the_module_is_the_one_the_app_runs():
    assert sys.modules["app.api.api_server"] is api_server
