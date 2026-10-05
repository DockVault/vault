"""The deployed API answers a bearer token nested past the stack with 401, like any bad token.

tests/test_access_token_nesting.py holds the entry points to it offline. This sends the token
through the real server, to the routes that answered it with a 500 while the JWT library let a
RecursionError out of decoding the header: signed-in reads, sign-out, the second-factor step and
its enrollment. None of them may treat it as anything but invalid credentials, and the service must
still be up afterwards.
"""
import base64
import uuid

import pytest
import requests

from conftest import BASE_URL

# Tokens of about 267 KB (the array) and 800 KB (the object). The shipped image turned such a token
# into a 500 from about 6,300 levels; this depth is past an 8 MiB main thread as well. The server now
# refuses a token this long on its length before decoding it (tests/test_access_token_length_live.py),
# and the answer asked for here is the same either way.
DEPTH = 100_000
TIMEOUT = 30


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _nested(opening: bytes, closing: bytes, middle: bytes = b"") -> str:
    header = opening * DEPTH + middle + closing * DEPTH
    return f"{_b64u(header)}.{_b64u(b'{}')}.{_b64u(b'x')}"


_TOKENS = {
    "array": _nested(b"[", b"]"),
    "object": _nested(b'{"a":', b"}", b"1"),
}

# (method, path, JSON body, the dependency's own refusal)
_SESSION_REFUSAL = "Invalid authentication credentials"
_PRE_AUTH_REFUSAL = "A valid pre-authentication token is required."
_ROUTES = [
    ("GET", "/users/me", None, _SESSION_REFUSAL),
    ("GET", "/vaults", None, _SESSION_REFUSAL),
    ("GET", "/auth/session", None, _SESSION_REFUSAL),
    ("POST", "/api/logout", None, _SESSION_REFUSAL),
    ("GET", "/users/me/second-factor", None, _SESSION_REFUSAL),
    ("POST", "/users/me/second-factor/totp/enroll", None, _SESSION_REFUSAL),
    ("POST", "/auth/second-factor/verify", {"code": "123456"}, _PRE_AUTH_REFUSAL),
]


def _send(method, path, token, body):
    return requests.request(
        method,
        f"{BASE_URL}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            # Its own rate-limit bucket, as the other live modules do.
            "X-Forwarded-For": f"198.51.100.{uuid.uuid4().int % 250 + 1}",
        },
        json=body,
        timeout=TIMEOUT,
    )


@pytest.mark.parametrize("kind", sorted(_TOKENS))
@pytest.mark.parametrize("method, path, body, refusal", _ROUTES,
                         ids=[f"{m} {p}" for m, p, _, _ in _ROUTES])
def test_a_token_nested_past_the_stack_is_refused_as_invalid(kind, method, path, body, refusal):
    r = _send(method, path, _TOKENS[kind], body)
    # A 401 from the route's own dependency, not a 500, and not a refusal of the header's size by
    # the server in front of it (which would prove nothing about the decode).
    assert r.status_code == 401, (r.status_code, r.text[:300])
    assert r.json().get("detail") == refusal, r.text[:300]


def test_the_service_is_still_up_after_them():
    for kind, token in _TOKENS.items():
        assert _send("GET", "/users/me", token, None).status_code == 401, kind
    health = requests.get(f"{BASE_URL}/health", timeout=TIMEOUT)
    assert health.status_code == 200, health.text[:300]
