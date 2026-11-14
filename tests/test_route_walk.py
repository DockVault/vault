"""The walk the route sweeps share (tests/_route_walk.py) reaches every route the app serves, offline.

It follows a router included inside another under both prefixes, and an application mounted under a path, so a
sweep built on it misses no route wherever the route is declared. On the vault's own app it reaches the routes of
every included router, and each path it names is one the app itself builds an address for.
"""
import pytest

from _bare_api_env import set_bare_api_env
from _route_walk import served_routes

pytestmark = pytest.mark.unit


def _paths(routes):
    return {path for path, _route in served_routes(routes)}


def test_the_walk_follows_a_router_included_inside_another():
    from fastapi import APIRouter, FastAPI

    inner, outer, app = APIRouter(prefix="/inner"), APIRouter(), FastAPI()
    inner.add_api_route("/{token}/open", lambda token: None)
    outer.include_router(inner, prefix="/outer")
    app.include_router(outer, prefix="/top")
    assert "/top/outer/inner/{token}/open" in _paths(app.routes)


def test_the_walk_follows_an_application_mounted_under_a_path():
    from fastapi import APIRouter, FastAPI

    sub, router, app = FastAPI(), APIRouter(prefix="/links"), FastAPI()
    router.add_api_route("/{token}", lambda token: None)
    sub.include_router(router)
    app.mount("/mounted", sub)
    assert "/mounted/links/{token}" in _paths(app.routes)
    # The mount itself is no route: what it serves is.
    assert "/mounted" not in _paths(app.routes)


def test_on_the_vaults_app_the_walk_reaches_the_included_routers_as_the_app_addresses_them():
    set_bare_api_env()
    from app.api import api_server as api

    served = _paths(api.app.routes)
    flat = {getattr(r, "path", None) for r in api.app.routes}
    assert len(served - flat) > 100
    # A route of a router included with a prefix of its own, and of one included without one.
    assert api.app.url_path_for("test_action", key="x1") == "/email/actions/x1/test"
    assert "/email/actions/{key}/test" in served
    assert api.app.url_path_for("put_managed_setting", key="x1") == "/settings/managed/x1"
    assert "/settings/managed/{key}" in served
