"""A bearer token longer than any this server signs is refused on its length, before it is decoded.

jwt.decode base64-checks and parses the whole token before it can check the signature, so the cost
of refusing a bad token grows with its length, and uvicorn accepts an Authorization header of
megabytes. verify_access_token, which every bearer token the web API reads goes through, refuses a
token longer than MAX_ACCESS_TOKEN_LENGTH without calling jwt.decode, and answers it as it answers
any other invalid token. The server's own tokens are a few hundred characters; the longest it can
sign stays well under the limit (test below). tests/test_access_token_length_live.py sends such a
token to the deployed stack.
"""
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
import app.core.security as security  # noqa: E402
from app.core import live_session  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.rate_limiter import RateLimitMiddleware  # noqa: E402
from app.core.security import (  # noqa: E402
    MAX_ACCESS_TOKEN_LENGTH, create_access_token, verify_access_token,
)

pytestmark = pytest.mark.unit

# About a megabyte, as an attacker would send: far over the limit, and nothing like a token.
FLAT = "a" * 1_000_000


def _signed_over_the_limit() -> str:
    """A token this server signed, valid in every way except its length."""
    token = create_access_token({"sub": "u1", "session_token": "s", "pad": "x" * MAX_ACCESS_TOKEN_LENGTH})
    assert len(token) > MAX_ACCESS_TOKEN_LENGTH
    return token


@pytest.fixture
def decodes(monkeypatch):
    """The tokens jwt.decode is asked to decode, in order; it still decodes them."""
    seen = []
    real = security.jwt.decode

    def spy(token, *args, **kwargs):
        seen.append(token)
        return real(token, *args, **kwargs)

    monkeypatch.setattr(security.jwt, "decode", spy)
    return seen


class _NoDatabase:
    """A token refused on its face is refused before any lookup."""

    def __getattr__(self, name):
        pytest.fail(f"the database was asked ({name}) for a token refused on its length")


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _refusal(dependency, token: str) -> tuple:
    """The status, detail and headers a request dependency refuses the token with."""
    with pytest.raises(HTTPException) as refused:
        run_coroutine(dependency(_credentials(token), db=_NoDatabase()))
    return refused.value.status_code, refused.value.detail, refused.value.headers


def _request(token: str) -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/users/me",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "client": ("192.0.2.10", 1234),
        "scheme": "https",
        "server": ("vault.example", 443),
    })


def test_the_longest_token_this_server_can_sign_is_well_under_the_limit(monkeypatch):
    # A username may be up to 255 characters, and JSON writes each character outside the Basic
    # Multilingual Plane as a 12-byte surrogate pair; HS512 gives the longest signature. Every claim
    # a session token can carry is present.
    monkeypatch.setattr(settings, "jwt_algorithm", "HS512")
    monkeypatch.setattr(settings, "jwt_secret_key", "k" * 64)
    claims = {"sub": "0" * 36, "username": "\U0001F600" * 255, "session_token": "s" * 43,
              "is_temporary": False, "amr": ["pwd", "recovery"], "mfa_at": 2_000_000_000}
    token = create_access_token(claims)
    assert len(token) * 3 // 2 < MAX_ACCESS_TOKEN_LENGTH, len(token)
    assert verify_access_token(token)["username"] == claims["username"]


def test_a_token_over_the_limit_is_refused_without_being_decoded(decodes):
    assert verify_access_token(_signed_over_the_limit()) is None
    assert verify_access_token(FLAT) is None
    assert verify_access_token(FLAT.encode()) is None
    assert decodes == []


def test_the_limit_is_on_the_length_alone(decodes):
    # One character more than the limit is not decoded; a token at the limit is.
    assert verify_access_token("a" * (MAX_ACCESS_TOKEN_LENGTH + 1)) is None
    assert decodes == []
    assert verify_access_token("a" * MAX_ACCESS_TOKEN_LENGTH) is None
    assert len(decodes) == 1


def test_a_token_the_server_signed_still_verifies(decodes):
    token = create_access_token({"sub": "u1", "session_token": "s"})
    claims = verify_access_token(token)
    assert claims["sub"] == "u1" and claims["session_token"] == "s"
    assert decodes == [token]


@pytest.mark.parametrize("make", [_signed_over_the_limit, lambda: FLAT], ids=["signed", "flat"])
def test_a_signed_in_route_answers_it_as_any_invalid_token(decodes, make):
    over = _refusal(S.get_current_user, make())
    assert over[0] == 401
    assert over == _refusal(S.get_current_user, "not-a-token")
    assert decodes == ["not-a-token"]


@pytest.mark.parametrize("make", [_signed_over_the_limit, lambda: FLAT], ids=["signed", "flat"])
def test_the_second_factor_step_answers_it_as_any_invalid_token(decodes, make):
    over = _refusal(S.get_pre_auth_principal, make())
    assert over[0] == 401
    assert over == _refusal(S.get_pre_auth_principal, "not-a-token")
    assert decodes == ["not-a-token"]


def test_the_rate_limiter_buckets_it_by_address_without_decoding_it(decodes, monkeypatch):
    monkeypatch.setattr("app.core.net_utils.client_ip", lambda _request: "198.51.100.9")
    middleware = object.__new__(RateLimitMiddleware)
    assert middleware._get_client_identifier(_request(_signed_over_the_limit())) == "ip:198.51.100.9"
    assert middleware._get_client_identifier(_request(FLAT)) == "ip:198.51.100.9"
    assert decodes == []
    # A token of normal length still buckets by its user.
    assert middleware._get_client_identifier(_request(create_access_token({"sub": "u1"}))) == "user:u1"
    assert len(decodes) == 1


def test_the_upload_size_check_sees_no_session_in_it(decodes):
    header = f"Bearer {_signed_over_the_limit()}".encode()
    assert live_session.bearer_token(header) is not None  # a bearer token, just not a valid one
    assert live_session.session_claims(header) is None
    assert decodes == []


def test_a_recursion_error_from_the_library_is_an_invalid_token(monkeypatch):
    # PyJWT before 2.14.0 raised RecursionError out of jwt.decode for a header nested deeper than
    # the stack. Whatever the library raises it for, the token is invalid, not a 500.
    def overflow(*_args, **_kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    token = create_access_token({"sub": "u1", "session_token": "s"})
    monkeypatch.setattr(security.jwt, "decode", overflow)
    assert verify_access_token(token) is None
    status, detail, _headers = _refusal(S.get_current_user, token)
    assert (status, detail) == (401, "Invalid authentication credentials")
