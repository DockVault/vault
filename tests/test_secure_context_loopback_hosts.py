"""The secure-context answer for loopback hosts matches the browsers' own rule, not a shorter list.

The download-sink resolver asks whether the browser is in a secure context, because only there can
it register the streaming worker. Over plain HTTP that is true for the hosts a browser calls
"potentially trustworthy": ``localhost``, any host ending in ``.localhost``, and any loopback
ADDRESS in any spelling. The server used to answer from an exact-match list of three strings, so a
``vault.localhost`` deployment -- where the browser has WebCrypto and the worker -- was told
``buffered`` for a reason that was not true. One predicate, driven through the real resolver.
"""
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S

pytestmark = pytest.mark.unit


class _EmptyDB:
    """No organisation policy row and no user preference row: the shipped default decides."""

    def query(self, *a):
        return self

    def filter(self, *a):
        return self

    def first(self):
        return None


def _request(host: str, scheme: str = "http"):
    from starlette.requests import Request
    scope = {
        "type": "http", "method": "GET", "path": "/zk-enabled", "query_string": b"",
        "scheme": scheme, "server": ("127.0.0.1", 8271), "client": ("10.0.0.5", 40000),
        "headers": [(b"host", host.encode("ascii"))],
    }
    return Request(scope)


def _sink_for(host, scheme="http"):
    return S._resolved_download_sink(_request(host, scheme), _EmptyDB(), SimpleNamespace(id="u1"))


TRUSTWORTHY = [
    "localhost", "LOCALHOST", "localhost.", "vault.localhost", "a.b.vault.localhost",
    "vault.localhost.", "127.0.0.1", "127.5.6.7", "[::1]", "[0:0:0:0:0:0:0:1]", "[::0001]",
    "[::ffff:127.0.0.1]",
]
NOT_TRUSTWORTHY = [
    "vault.example.com", "localhost.example.com", "notlocalhost", "mylocalhost", "10.0.0.1",
    "[::2]", "[::]", "0.0.0.0", "[fe80::1]", "127.0.0.1.example.com", "localhost-vault",
]


@pytest.mark.parametrize("host", TRUSTWORTHY)
def test_a_loopback_host_over_plain_http_is_a_secure_context(host):
    got = _sink_for(host + ":8271")
    assert got["reason"] != "insecure_context", (host, got)
    assert got["sink"] == "streaming", (host, got)


@pytest.mark.parametrize("host", NOT_TRUSTWORTHY)
def test_any_other_host_over_plain_http_is_not(host):
    got = _sink_for(host + ":8271")
    assert got["sink"] == "buffered" and got["reason"] == "insecure_context", (host, got)


def test_https_is_secure_whatever_the_host():
    got = _sink_for("vault.example.com", scheme="https")
    assert got["sink"] == "streaming" and got["reason"] != "insecure_context"


def test_the_predicate_is_the_browsers_rule_and_the_site_asks_it():
    # The rule itself, on the bare predicate, so a future site can reuse it; and the one site that
    # answers the secure-context question asks the predicate rather than keeping a list of its own.
    assert all(S._is_loopback_host(h.strip("[]")) for h in TRUSTWORTHY)
    assert not any(S._is_loopback_host(h.strip("[]")) for h in NOT_TRUSTWORTHY)
    assert S._is_loopback_host("") is False and S._is_loopback_host(None) is False
    import inspect
    site = inspect.getsource(S._resolved_download_sink)
    assert "_is_loopback_host(host)" in site
    assert '"127.0.0.1"' not in site and '"::1"' not in site
