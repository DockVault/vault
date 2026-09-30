"""The deployed API refuses a bearer token of about a megabyte quickly, as it refuses any bad token.

tests/test_access_token_length.py holds verify_access_token to it offline: a token longer than any
the server signs is refused on its length, without being decoded. The server in front accepts an
Authorization header of this size, so this sends one through it: to signed-in routes, sign-out, the
second-factor step, and a body large enough that the upload size check asks who is calling. Each
must answer exactly what a short invalid token gets, and the token must cost the server no more than
any other header of that size.
"""
import statistics
import time
import uuid

import pytest
import requests

from conftest import BASE_URL

TIMEOUT = 30

# About a megabyte, shaped like a token: three base64url segments.
BIG = f"{'e' * 600_000}.{'e' * 400_000}.{'e' * 43}"
SHORT = "e.e.e"
# The same megabyte in a header the vault does not read: what carrying it costs, token or not.
PADDING = {"X-Padding": BIG}

# A body over what anyone may send to this route without a live session, so the size check has to
# look at the token before it reads the body.
_NOTE = {"title": "t", "content": "x" * (80 * 1024)}

# (method, path, JSON body)
_ROUTES = [
    ("GET", "/users/me", None),
    ("GET", "/vaults", None),
    ("POST", "/api/logout", None),
    ("POST", "/auth/second-factor/verify", {"code": "123456"}),
    ("POST", "/notes", _NOTE),
]

# Decoding a megabyte token took the server about a hundred milliseconds more than carrying the
# megabyte in another header (twice per request: the rate limiter and the route); refused on its
# length it takes nothing more.
MEDIAN_ALLOWANCE_SECONDS = 0.05
ROUNDS = 15

# One connection for the module: opening one per request costs more than what is measured here.
_session = requests.Session()


def _send(method, path, token, body=None, extra_headers=None):
    headers = {
        "Authorization": f"Bearer {token}",
        # Its own rate-limit bucket, as the other live modules do.
        "X-Forwarded-For": f"198.51.100.{uuid.uuid4().int % 250 + 1}",
    }
    headers.update(extra_headers or {})
    started = time.perf_counter()
    r = _session.request(method, f"{BASE_URL}{path}", headers=headers, json=body, timeout=TIMEOUT)
    return r, time.perf_counter() - started


@pytest.mark.parametrize("method, path, body", _ROUTES, ids=[f"{m} {p}" for m, p, _ in _ROUTES])
def test_a_megabyte_token_gets_what_any_invalid_token_gets(method, path, body):
    big, _ = _send(method, path, BIG, body)
    short, _ = _send(method, path, SHORT, body)
    # A 401 from the vault itself, not a refusal of the header's size by the server in front of it
    # (which would prove nothing about the vault), and the same answer as a short invalid token.
    assert big.status_code == 401, (big.status_code, big.text[:300])
    assert (big.status_code, big.json()) == (short.status_code, short.json())


def test_it_costs_no_more_than_any_other_header_of_its_size():
    big, carried = [], []
    for _ in range(ROUNDS):
        # Taken in turn, so a slow moment on the host weighs on both.
        r, took = _send("GET", "/users/me", BIG)
        assert r.status_code == 401, r.status_code
        big.append(took)
        r, took = _send("GET", "/users/me", SHORT, extra_headers=PADDING)
        assert r.status_code == 401, r.status_code
        carried.append(took)
    extra = statistics.median(big) - statistics.median(carried)
    assert extra < MEDIAN_ALLOWANCE_SECONDS, (
        f"a megabyte token took {extra * 1000:.0f} ms longer (median of {ROUNDS}) than a short token "
        f"with a megabyte in another header: token {sorted(round(t * 1000) for t in big)} ms, "
        f"other header {sorted(round(t * 1000) for t in carried)} ms")


def test_the_service_is_still_up_after_them():
    assert _send("GET", "/users/me", BIG)[0].status_code == 401
    health = _session.get(f"{BASE_URL}/health", timeout=TIMEOUT)
    assert health.status_code == 200, health.text[:300]
