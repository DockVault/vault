"""What an identity provider sends back in the address never reaches a log line.

The provider returns the person to the callback with the authorization code and the state in the query
(``/auth/sso/<provider>/callback?code=...&state=...``), and some send a session state or their issuer beside
them; a refused sign-in comes back with an error and its description. A code is spent once and a state names one
login, but neither belongs in a log. An access line prints a query's parameter names and never a value
(app/core/log_redaction.py), which this pins for the callback's own parameters: through the functions that reduce
an address, through the filter the web server's access log runs every line through, and on a line read back. (What
the callback itself logs of a refusal is pinned with the callback, in tests/test_sso_sign_in.py.) No single
sign-on route carries a secret in its path: its path parameters are row ids.
"""
import re
import uuid

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.log_redaction import access_target, redact_access_path, redact_secret_urls_in_text  # noqa: E402

pytestmark = pytest.mark.unit

PROVIDER = str(uuid.uuid4())
CALLBACK = f"/auth/sso/{PROVIDER}/callback"
CODE, STATE, SESSION_STATE = "SplxlOBeZQQYbYS6WxSbIA", "af0ifjsldkj-9c1e", "b4c7e0d1.session"
ANSWERS = {
    "a sign-in": (f"code={CODE}&state={STATE}", "code&state"),
    "with the provider's session state and issuer": (
        f"code={CODE}&state={STATE}&session_state={SESSION_STATE}&iss=https%3A%2F%2Fidp.example%2Frealms%2Fdv",
        "code&state&session_state&iss"),
    "a refusal by the provider": (
        f"error=access_denied&error_description=The+user+{SESSION_STATE}+was+denied&state={STATE}",
        "error&error_description&state"),
}


@pytest.mark.parametrize("case", sorted(ANSWERS))
def test_the_callbacks_query_reaches_a_line_as_names_only(case):
    query, names = ANSWERS[case]
    for line in (redact_access_path(CALLBACK + "?" + query), access_target(CALLBACK, query)):
        assert line == CALLBACK + "?" + names
    # A line already written, read back (the log pull, the in-app sink): the same.
    written = f'203.0.113.9:51234 - "GET {CALLBACK}?{query} HTTP/1.1" 302'
    read_back = redact_secret_urls_in_text(written)
    for secret in (CODE, STATE, SESSION_STATE, "idp.example"):
        assert secret not in read_back, read_back
    assert f"GET {CALLBACK}?{names} HTTP/1.1" in read_back


@pytest.mark.parametrize("case", sorted(ANSWERS))
def test_the_access_logs_own_filter_reduces_the_callbacks_line(case):
    """The web server's access record carries the address as its third argument; the filter installed on that log
    (app/api/api_server.py) rewrites it before the line is formatted."""
    import logging
    from app.core.log_redaction import AccessLogRedactFilter
    query, names = ANSWERS[case]
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                               ("203.0.113.9:51234", "GET", CALLBACK + "?" + query, "1.1", 302), None)
    assert AccessLogRedactFilter().filter(record) is True
    line = record.getMessage()
    assert line == f'203.0.113.9:51234 - "GET {CALLBACK}?{names} HTTP/1.1" 302'
    for secret in (CODE, STATE, SESSION_STATE, "idp.example"):
        assert secret not in line


def test_the_filter_is_put_on_the_access_log_when_the_app_starts():
    """The app's start-up installs it on the logger the web server's access lines go through."""
    import inspect
    import logging
    from app.core.log_redaction import AccessLogRedactFilter
    source = inspect.getsource(api)
    calls = [line for line in source.splitlines() if line.strip() == "_install_access_log_redaction()"]
    assert len(calls) == 1
    api._install_access_log_redaction()
    api._install_access_log_redaction()                    # once, however often it is asked
    installed = [f for f in logging.getLogger("uvicorn.access").filters if isinstance(f, AccessLogRedactFilter)]
    assert len(installed) == 1


def _served(routes, prefix=""):
    """Every path the app serves. A router added with include_router keeps its routes to itself (the app lists the
    router, not its routes), so those are walked too, under the prefix they were included with."""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            included_under = getattr(getattr(route, "include_context", None), "prefix", "") or ""
            yield from _served(inner.routes, prefix + included_under)
        elif getattr(route, "path", None):
            yield prefix + route.path


def test_no_single_sign_on_route_carries_a_secret_in_its_path():
    """The path parameters of these routes are row ids (a provider, an identity, a request); what is secret travels
    in a body, in the callback's query (above) or in the page's fragment, which is never sent to the server."""
    routes = [path for path in _served(api.app.routes) if "/sso/" in path or "/identities" in path]
    assert len(routes) >= 10, routes
    assert CALLBACK.replace(PROVIDER, "{provider_id}") in routes
    assert "/auth/sso/{provider_id}/backchannel-logout" in routes
    for path in routes:
        for name in re.findall(r"\{([^}:]+)", path):
            assert name.endswith("_id"), (path, name)
