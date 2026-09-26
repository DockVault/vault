"""How the vault decides a request's client address, run against real Starlette requests.

Every per-IP throttle and every audit row takes its address from app.core.net_utils.client_ip, so
these cases pin the parts a forged header could otherwise reach: several X-Forwarded-For lines, IPv6
zone ids, over-long tokens, a chain made only of trusted hops, and a loopback peer when no proxy is
trusted.
"""
import pathlib
import re

import pytest
from starlette.requests import Request

from app.core import net_utils

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parent.parent

TRUSTED = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"


def _request(peer, *xff_lines):
    headers = [(b"x-forwarded-for", line.encode()) for line in xff_lines]
    return Request({
        "type": "http", "method": "GET", "path": "/", "raw_path": b"/", "query_string": b"",
        "headers": headers, "client": (peer, 40000), "server": ("vault", 443), "scheme": "https",
    })


@pytest.fixture
def trust(monkeypatch):
    def _set(spec):
        monkeypatch.setattr(net_utils.settings, "trusted_proxies", spec, raising=False)
        monkeypatch.setattr(net_utils.settings, "trust_all_proxies", False, raising=False)
        net_utils._trusted_networks.cache_clear()
    yield _set
    net_utils._trusted_networks.cache_clear()


def test_a_second_forwarded_for_line_is_read(trust):
    # A proxy that adds its own header line (HAProxy's `option forwardfor`) leaves the client's line
    # first. Reading only that line would believe whatever the client wrote.
    trust(TRUSTED)
    req = _request("172.18.0.5", "198.51.100.9", "203.0.113.50")
    assert net_utils.forwarded_for_chain(req) == "198.51.100.9, 203.0.113.50"
    assert net_utils.client_ip(req) == "203.0.113.50"


def test_a_forged_trusted_address_on_its_own_line_is_not_the_client(trust):
    trust(TRUSTED)
    req = _request("172.18.0.5", "10.0.0.7", "203.0.113.50")
    assert net_utils.client_ip(req) == "203.0.113.50"


@pytest.mark.parametrize("token", [
    "fe80::1%eth0",
    "fe80::1%" + "a" * 300,
    "[fe80::1%25eth0]:443",
])
def test_an_ipv6_zone_id_is_not_an_address(token):
    assert net_utils._parse_ip(token) is None


def test_a_zone_id_hop_is_skipped_not_believed(trust):
    trust(TRUSTED)
    zoned = "fe80::1%" + "x" * 300
    assert net_utils.client_ip(_request("172.18.0.5", "203.0.113.50, " + zoned)) == "203.0.113.50"
    # Nothing else usable in the chain: the peer, never the forged value.
    assert net_utils.client_ip(_request("172.18.0.5", zoned)) == "172.18.0.5"


def test_an_over_long_token_is_not_an_address():
    assert net_utils._parse_ip("1" * 57) is None
    # The longest real form still parses: a bracketed full IPv6 address with a port.
    longest = "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535"
    assert net_utils._parse_ip(longest) is not None


def test_every_resolved_address_fits_the_stored_column(trust):
    trust(TRUSTED)
    chains = ["fe80::1%" + "z" * 500, "1" * 400, "garbage, " + "f" * 90, "::ffff:203.0.113.50"]
    for chain in chains:
        assert len(net_utils.client_ip(_request("172.18.0.5", chain))) <= 45


def test_an_all_trusted_chain_resolves_to_the_nearest_hop(trust):
    # The left-most entry is client-written, so it could name any address inside the trusted range.
    trust(TRUSTED)
    assert net_utils.client_ip(_request("127.0.0.1", "10.0.0.7, 192.168.1.2")) == "192.168.1.2"


def test_a_loopback_peer_is_not_trusted_by_default(trust):
    trust("")
    assert net_utils.client_ip(_request("127.0.0.1", "203.0.113.50")) == "127.0.0.1"


def test_uvicorn_does_not_rewrite_the_peer():
    # uvicorn's own proxy-header handling believes X-Forwarded-For from 127.0.0.1 and rewrites the
    # peer before the app sees it; the vault's launch turns it off so TRUSTED_PROXIES alone decides.
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    launch = src[src.index("    uvicorn.run(\n"):]
    launch = launch[:launch.index("\n    )\n")]
    assert re.search(r"^\s*proxy_headers=False,$", launch, re.M), "uvicorn.run must pass proxy_headers=False"


class _CountingLimiter:
    """An in-memory stand-in for the Redis limiter: counts hits per key, refuses past the limit."""

    def __init__(self):
        self.hits = {}

    def check_rate_limit(self, key, limit, window, prefix="rate_limit", fail_open=False):
        full = f"{prefix}:{key}"
        self.hits[full] = self.hits.get(full, 0) + 1
        return self.hits[full] <= limit, max(0, limit - self.hits[full]), 0


def test_a_username_that_looks_like_an_ip_has_its_own_bucket():
    # Failing logins AS the name "203.0.113.50" must not spend the budget of the address
    # 203.0.113.50: the two kinds of subject live in separate buckets.
    from app.services.auth_service import AuthService, RateLimitExceededError

    svc = AuthService.__new__(AuthService)
    limiter = _CountingLimiter()
    for _ in range(4):
        svc._redis_rate_limit(limiter, "203.0.113.50", "198.51.100.9", 5, 10, 60)
    with pytest.raises(RateLimitExceededError):  # the name's own bucket still trips
        for _ in range(2):
            svc._redis_rate_limit(limiter, "203.0.113.50", "198.51.100.9", 5, 10, 60)
    # The address itself, logging in as someone else, is untouched.
    svc._redis_rate_limit(limiter, "alice", "203.0.113.50", 5, 1, 60)
    assert limiter.hits["rate_limit:login_ip:203.0.113.50"] == 1
    assert set(limiter.hits) == {
        "rate_limit:login_user:203.0.113.50", "rate_limit:login_ip:198.51.100.9",
        "rate_limit:login_user:alice", "rate_limit:login_ip:203.0.113.50",
    }
