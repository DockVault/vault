"""No address the sign-in features give out is taken from a request.

A passkey's relying party, the redirect address a provider is handed, the place a sign-in sends the browser back to
and every emailed link are built on the vault's configured address (app/core/public_url.py, on
app/core/allowed_hosts.link_base). A request's Host header is the caller's to write, so none of the sign-in modules
reads it, in any of the ways a request names its host. tests/test_email_default_templates.py holds the API's main
module to the same rule; this holds the modules of the sign-in pipeline, passkeys and single sign-on, whichever of
them this tree has. Offline, from the source."""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ("app/services/sign_in.py", "app/core/sign_in_codes.py", "app/core/public_url.py")
PASSKEYS = ("app/services/webauthn_service.py", "app/core/webauthn_settings.py", "app/core/webauthn_challenges.py",
            "app/api/sign_in_settings_router.py")
SINGLE_SIGN_ON = ("app/api/sso_router.py", "app/api/sso_admin_router.py", "app/services/sso_sign_in.py",
                  "app/services/sso_freshness.py", "app/services/sso_groups.py", "app/services/oidc_client.py",
                  "app/core/sso_only.py", "app/core/sso_policy.py", "app/core/sso_state.py")
MODULES = [m for m in PIPELINE + PASSKEYS + SINGLE_SIGN_ON if (ROOT / m).is_file()]


def request_addresses(tree) -> list:
    """Every place ``tree`` reads the host a request names: its base URL, its Host or X-Forwarded-Host header, the
    host, port or network location of its URL, its whole URL as text, or an address made with url_for."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "base_url":
            found.append(ast.unparse(node))
        read = (node.args[0] if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get" and node.args else
                node.slice if isinstance(node, ast.Subscript) else None)
        holder = node.func.value if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else (
            node.value if isinstance(node, ast.Subscript) else None)
        if (isinstance(holder, ast.Attribute) and holder.attr == "headers" and isinstance(read, ast.Constant)
                and str(read.value).lower() in ("host", "x-forwarded-host")):
            found.append(ast.unparse(node))
        if (isinstance(node, ast.Attribute) and node.attr in ("netloc", "hostname", "port")
                and isinstance(node.value, ast.Attribute) and node.value.attr == "url"):
            found.append(ast.unparse(node))
        if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "str" and node.args
                and isinstance(node.args[0], ast.Attribute) and node.args[0].attr == "url"):
            found.append(ast.unparse(node))
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "url_for":
            found.append(ast.unparse(node))
    return found


def test_the_pipelines_own_modules_are_among_those_read():
    assert set(PIPELINE) <= set(MODULES)


@pytest.mark.parametrize("module", MODULES)
def test_no_sign_in_module_reads_the_host_a_request_names(module):
    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    assert request_addresses(tree) == [], module


@pytest.mark.parametrize("source", [
    "base = str(request.base_url)",
    "host = request.headers.get('host')",
    "host = request.headers.get('X-Forwarded-Host', '')",
    "host = request.headers['Host']",
    "where = request.url.netloc",
    "name = request.url.hostname",
    "port = request.url.port",
    "whole = str(request.url)",
    "back = request.url_for('callback')",
])
def test_the_check_finds_each_way_a_request_names_its_host(source):
    assert len(request_addresses(ast.parse(source))) >= 1, source


@pytest.mark.parametrize("source", [
    "host = urlsplit(provider.issuer).hostname",          # a provider's address, not the request's
    "query = request.url.query",
    "agent = request.headers.get('user-agent')",
    "base = public_base_url()",
    "link = mint(db, user, base_url=base)",
])
def test_the_check_leaves_what_names_no_request_host(source):
    assert request_addresses(ast.parse(source)) == [], source
