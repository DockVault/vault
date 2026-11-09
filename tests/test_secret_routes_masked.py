"""Every route that carries a secret in its path is masked wherever its address is written down.

A route whose path holds a link's, an invitation's or a reset's token (a `{token}` path parameter) must be in
the masked list (app/core/log_redaction.py SECRET_PATH_ROUTES): the access log, the in-app log sink and the log
pull then never hold the token, and the answer's Referrer-Policy keeps it out of every Referer. This walks the
routes the app really serves, so a new route with a token in its path fails here until it is listed. An
anonymous link route is also recorded under its link's channel, not the web app's.
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


def _token_routes():
    out = []
    for route in api.app.routes:
        path = getattr(route, "path", "")
        if "{token}" not in path:
            continue
        sample = re.sub(r"\{[^}]+\}", "x1", path.replace("{token}", TOKEN))
        out.append((path, sample))
    return out


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
