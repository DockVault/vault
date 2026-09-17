"""Every device-principal route meets the same auth posture and rate-limit class, and nothing else
depends on the device resolver.

The device secret is an opaque, non-JWT bearer: it must reach ONLY the routes that explicitly depend
on get_current_device_principal, and those routes must NOT also accept an account JWT (get_current_user),
so an unknown/foreign secret meets the one shared 401 and an account token never reaches a device
route. The device routes are also ordinary API routes, counted in the same general-API rate-limit
bucket class as the mint -- none is a cheaper probe, none is on the exclude list.

The resolver's own docstring says a route-sweep pins this boundary both ways; this is that sweep. It
reads the declared dependency graph from app.routes under the bare env -- no socket, no live stack --
the same way test_auth_offload_slot_ordering.py reads declared dependency order.
"""
import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

_DEVICE_PREFIX = "/device/"  # singular: the device-PRINCIPAL routes (plural /devices/* are account-admin)


def _app():
    # The bootstrap connects lazily; this never opens a socket, it only reads declared dependencies.
    set_bare_api_env()
    import app.api.api_server as S
    return S.app


def _dep_names(route):
    """Flatten a route's dependency tree to the set of dependency-callable names."""
    names = set()
    root = getattr(route, "dependant", None)
    stack = [root] if root is not None else []
    while stack:
        d = stack.pop()
        for sub in getattr(d, "dependencies", []):
            if sub.call is not None:
                names.add(getattr(sub.call, "__name__", ""))
            stack.append(sub)
    return names


def _device_routes(app):
    return [r for r in app.routes if getattr(r, "path", "").startswith(_DEVICE_PREFIX)]


def _real_methods(route):
    return {m for m in (getattr(route, "methods", set()) or set()) if m not in ("HEAD", "OPTIONS")}


def test_there_are_device_principal_routes_to_sweep():
    routes = _device_routes(_app())
    assert routes, "no /device/* routes found -- the sweep would be vacuous"


def test_every_device_route_requires_the_device_resolver_and_not_the_user_resolver():
    for r in _device_routes(_app()):
        names = _dep_names(r)
        assert "get_current_device_principal" in names, (
            f"{r.path} does not depend on get_current_device_principal -- it would not meet the "
            f"shared device 401 posture")
        assert "get_current_user" not in names, (
            f"{r.path} also depends on get_current_user -- an account JWT could reach a device route")


def test_no_non_device_route_depends_on_the_device_resolver():
    app = _app()
    for r in app.routes:
        if getattr(r, "path", "").startswith(_DEVICE_PREFIX):
            continue
        assert "get_current_device_principal" not in _dep_names(r), (
            f"{getattr(r, 'path', '')} depends on the device resolver -- the boundary leaks the other way")


def test_every_device_route_shares_the_mints_rate_limit_class_and_is_not_excluded():
    from app.core.rate_limiter import classify_api_rate_limit
    mint_class = classify_api_rate_limit("POST", "/device/sync-credential")
    from app.core.rate_limiter import RATE_LIMIT_EXCLUDE_PATHS as excluded  # the middleware's own list, not a copy
    for r in _device_routes(_app()):
        assert not any(r.path.startswith(e) for e in excluded), f"{r.path} is on the rate-limit exclude list"
        for method in _real_methods(r) or {"GET"}:
            assert classify_api_rate_limit(method, r.path) == mint_class, (
                f"{method} {r.path} is not in the mint's rate-limit class ({mint_class}) -- a cheaper probe")
