"""Every route the app serves, with its full path, for the tests that sweep the app's routes.

A router added with include_router may sit in the app's route list as one entry that holds the router's own routes
(original_router) and the prefix it was included with (include_context.prefix), so a walk of that list alone never
sees those routes. This walk follows each such entry under its prefix, nested ones too.
"""


def served_routes(routes, prefix=""):
    """(full path, route) for every route with a path, the routes of included routers among them."""
    for route in routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            context = getattr(route, "include_context", None)
            yield from served_routes(included.routes, prefix + (getattr(context, "prefix", "") or ""))
        elif getattr(route, "path", None) is not None:
            yield prefix + route.path, route
