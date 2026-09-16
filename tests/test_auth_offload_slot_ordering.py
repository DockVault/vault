"""Every offloaded auth route acquires the concurrency slot BEFORE any database connection source.

The slot bounds these routes below the database pool only if it is held for the WHOLE request —
before any dependency that checks a connection out. FastAPI resolves a path operation's dependencies
in the order they are declared, one after another, so the invariant is exactly this: on each
offloaded route ``auth_offload_slot`` must appear before ``get_db`` AND before any principal/user
resolver (which queries the session or device row as it resolves). A slot declared after them — or
acquired inside the handler body, as the first cut did — lets the request hold a connection while it
queues on the semaphore, and the pool bound is falsified (the regular-login branch even runs a real
SELECT, ``_login_identifier(db)``, as an argument to the offloaded call).

This pins the resolution order for all three offloaded routes. Moving the slot after ``get_db`` (or
dropping it) turns this red. The slot's cap is pinned by test_auth_offload.py; that a request past the
slot runs its blocking work off the loop is pinned by the outage tests. The live proof that
``engine.pool.checkedout()`` stays at or below the slot count under a burst larger than the pool is
measured on a running stack.
"""
import os

import pytest

pytestmark = pytest.mark.unit


def _load_app():
    # Dummy connection strings so the import is side-effect-free (engines/clients connect lazily);
    # this test never opens a socket, it only reads the declared dependency order.
    for k, v in {
        "DATABASE_URL": "postgresql://x:x@localhost:5432/x",
        "REDIS_URL": "redis://localhost:6379/0",
        "SECRET_KEY": "t" * 32,
        "JWT_SECRET_KEY": "t" * 32,
    }.items():
        os.environ.setdefault(k, v)
    import app.api.api_server as server
    return server.app


def _dep_names(app, path, method="POST"):
    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return [d.call.__name__ if d.call else d.name for d in route.dependant.dependencies]
    raise AssertionError(f"route {method} {path} not found")


# (path, the connection-checking resolvers that MUST come after the slot on that route)
_OFFLOADED_ROUTES = [
    ("/auth/login", ["get_db"]),
    ("/device/sync-credential", ["get_current_device_principal", "get_db"]),
    ("/auth/temp-credentials", ["get_current_user", "get_db"]),
]


@pytest.mark.parametrize("path,after", _OFFLOADED_ROUTES)
def test_offload_slot_is_resolved_before_any_connection_source(path, after):
    app = _load_app()
    names = _dep_names(app, path)
    assert "auth_offload_slot" in names, (
        f"{path} does not declare the auth_offload_slot dependency — it is not bounded below the pool")
    slot_at = names.index("auth_offload_slot")
    for dep in after:
        assert dep in names, f"{path} unexpectedly does not depend on {dep}: {names}"
        assert slot_at < names.index(dep), (
            f"{path} resolves {dep} before auth_offload_slot ({names}) — a connection can be checked "
            f"out before the slot is held, so the slot does not bound the pool for this route")
