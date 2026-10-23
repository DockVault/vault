"""No route an anonymous link uses answers HEAD, offline.

A HEAD is what a link checker, a crawler or a chat app's preview sends to learn about a URL without
fetching it, so it must never reach a link's page, its redeem or its download: a HEAD that ran the
download would use up the grant the person's own click is about to need. FastAPI answers HEAD on a
route declared for GET alone with 405 (Starlette's own Route would add HEAD to it), so this holds as
long as no link route is declared with HEAD, or through a route class that adds it. Pinned here for
every route under the anonymous link families, found from the app's own route table, and the live
half (each route, with a real token and grant, answering 405 and spending nothing) is in
tests/test_api_link_routes_refuse_head.py.
"""
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core.log_redaction import SECRET_PATH_ROUTES  # noqa: E402

pytestmark = pytest.mark.unit

LINK_FAMILIES = ("/l/", "/p/", "/u/", "/public-links/", "/note-links/", "/receivers/")


def _link_routes():
    """The routes that take an anonymous link's token: a family's prefix followed by {token}."""
    out = []
    for route in S.app.routes:
        path = getattr(route, "path", "")
        if any(path.startswith(prefix + "{token}") for prefix in LINK_FAMILIES):
            out.append(route)
    return out


def test_the_link_families_are_the_ones_the_access_log_masks():
    assert set(LINK_FAMILIES) == {prefix for prefix, _follow in SECRET_PATH_ROUTES} - {"/invites/", "/reset/", "/shares/"}


def test_every_link_route_is_found():
    paths = {route.path for route in _link_routes()}
    for expected in ("/l/{token}", "/p/{token}", "/u/{token}", "/public-links/{token}/redeem",
                     "/public-links/{token}/download/{file_id}", "/note-links/{token}/redeem"):
        assert expected in paths, expected
    assert any(p.startswith("/receivers/{token}/") for p in paths), paths


def test_no_link_route_answers_head():
    answering = sorted((route.path, sorted(route.methods)) for route in _link_routes()
                       if "HEAD" in (getattr(route, "methods", None) or ()))
    assert answering == [], f"a HEAD would reach these: {answering}"


def test_the_route_class_adds_no_head_to_a_get_route():
    # The behaviour the rule above rests on: a route declared for GET alone keeps exactly GET.
    from fastapi import FastAPI

    probe = FastAPI()

    @probe.get("/p/{token}")
    def page(token: str):
        return {}

    [route] = [r for r in probe.routes if getattr(r, "path", "") == "/p/{token}"]
    assert route.methods == {"GET"}
    for route in _link_routes():
        if "GET" in route.methods:
            assert route.methods == {"GET"}, (route.path, route.methods)
