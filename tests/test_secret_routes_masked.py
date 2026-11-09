"""Every route that carries a secret in its path is masked wherever its address is written down.

A route whose path holds a secret must be in the masked list (app/core/log_redaction.py SECRET_PATH_ROUTES):
the access log, the in-app log sink and the log pull then never hold it, and the answer's Referrer-Policy keeps
it out of every Referer. A path parameter is taken to hold a secret when it is named token, code, secret, claim
or key, or ends in one of those words after an underscore (reset_token, claim_code); a name ending in _id is an
identifier. The few named so that hold no secret are listed in NOT_SECRET with the reason. This walks the
routes the app really serves, so a new route with a secret in its path fails here until it is masked or listed.
An anonymous link route is also recorded under its link's channel, not the web app's.
"""
import re

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.log_redaction import redact_access_path, redact_log_path, redact_secret_urls_in_text  # noqa: E402
from app.core.request_context import channel_for_path  # noqa: E402

pytestmark = pytest.mark.unit

TOKEN = "Sk7Qe2LmN9xVb4Rt"
SECRET_WORDS = ("token", "code", "secret", "claim", "key")
NOT_SECRET = {
    ("/second-factor/actions/{key}", "key"): "the catalog name of a step-up action, such as admin.settings.write",
}


def _holds_a_secret(name: str) -> bool:
    return name in SECRET_WORDS or any(name.endswith("_" + w) for w in SECRET_WORDS)


def _secret_params(path):
    return [n for n in re.findall(r"\{([^}:]+)", path) if _holds_a_secret(n) and (path, n) not in NOT_SECRET]


def _token_routes():
    out = []
    for route in api.app.routes:
        path = getattr(route, "path", "")
        names = _secret_params(path)
        if not names:
            continue
        sample = path
        for n in names:
            sample = re.sub(r"\{" + n + r"(:[^}]*)?\}", TOKEN, sample)
        sample = re.sub(r"\{[^}]+\}", "x1", sample)
        out.append((path, sample))
    return out


@pytest.mark.parametrize("name,secret", [("token", True), ("code", True), ("secret", True), ("claim", True),
                                         ("key", True), ("reset_token", True), ("claim_code", True),
                                         ("token_id", False), ("key_id", False), ("user_id", False),
                                         ("keyword", False), ("tokens", False)])
def test_which_names_are_taken_to_hold_a_secret(name, secret):
    assert _holds_a_secret(name) is secret


def test_every_name_listed_as_no_secret_is_a_route_the_app_serves():
    served = {getattr(r, "path", "") for r in api.app.routes}
    assert all(path in served and "{" + name + "}" in path for path, name in NOT_SECRET)


def test_there_are_token_routes_to_check():
    paths = {p for p, _ in _token_routes()}
    assert "/receivers/{token}/page" in paths and "/u/{token}" in paths and len(paths) >= 10


@pytest.mark.parametrize("path,sample", _token_routes())
def test_every_route_with_a_token_in_its_path_is_masked(path, sample):
    assert TOKEN not in redact_log_path(sample), path
    assert TOKEN not in redact_access_path(sample), path
    assert TOKEN not in redact_secret_urls_in_text(f'"GET {sample} HTTP/1.1" 200'), path
    assert api._referrer_policy(sample, "") == "strict-origin", path


def test_the_upload_pages_own_request_is_an_upload_link_request():
    assert channel_for_path(f"/receivers/{TOKEN}/page") == "upload_link"
    assert channel_for_path("/receivers/7d1e2a/token-copy") == "web"


@pytest.mark.parametrize("name", ["token", "code", "secret", "claim", "key", "claim_code"])
def test_a_new_route_with_a_secret_in_its_path_is_found_and_would_fail_until_masked(monkeypatch, name):
    from starlette.routing import Route
    path = "/made-up-route/{" + name + "}/open"
    monkeypatch.setattr(api.app.router, "routes", list(api.app.router.routes) + [Route(path, lambda r: None)])
    found = dict(_token_routes())
    assert path in found and TOKEN in found[path]
    assert TOKEN in redact_access_path(found[path])     # not masked yet: the walk above fails on it
