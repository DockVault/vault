"""Every route the app serves, with its full path, for the tests that sweep the app's routes.

A router added with include_router may sit in the app's route list as one entry that holds the router's own routes
(original_router) and the prefix it was included with (include_context.prefix), and an application mounted under a
path (Mount) holds the routes of its own; a walk of the app's list alone never sees either. This walk follows each
under its prefix, nested ones too. tests/test_route_walk.py checks the walk itself.
"""


def served_routes(routes, prefix=""):
    """(full path, route) for every route with a path, the routes of included routers and of mounted applications
    among them. A mount is not itself a route: what it serves is (a mounted static directory serves no route)."""
    from starlette.routing import Mount

    for route in routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            context = getattr(route, "include_context", None)
            yield from served_routes(included.routes, prefix + (getattr(context, "prefix", "") or ""))
        elif isinstance(route, Mount):
            yield from served_routes(route.routes or [], prefix + route.path)
        elif getattr(route, "path", None) is not None:
            yield prefix + route.path, route
