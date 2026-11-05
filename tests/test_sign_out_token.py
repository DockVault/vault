"""How POST /auth/sign-out reads the token it is sent, offline (app/core/security.py:
verify_access_token_for_sign_out).

The web app signs out after its session has run out as well, and that session's row stays listed as signed in
until it is ended, so the sign-out reads a token this server signed whether or not it has expired. Nothing else
is let go: a token signed with another key, with another algorithm or none, or altered after it was signed, is
not read, and one longer than any this server signs is refused on its length without being decoded, as every
other bearer token is (tests/test_access_token_length.py). It reads tokens for that one route only; every other
reader still refuses an expired token. tests/test_api_sign_out.py holds the route on a running stack.
"""
from datetime import timedelta

import jwt
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.core.security as security  # noqa: E402
from app.core.rate_limiter import classify_api_rate_limit  # noqa: E402
from app.core.security import (  # noqa: E402
    MAX_ACCESS_TOKEN_LENGTH, create_access_token, verify_access_token, verify_access_token_for_sign_out,
)

pytestmark = pytest.mark.unit

CLAIMS = {"sub": "u1", "username": "ana", "session_token": "s" * 43, "is_temporary": False}


def _key():
    return security._runtime_settings().jwt_secret_key


def _alg():
    return security._runtime_settings().jwt_algorithm


def test_an_expired_token_this_server_signed_is_read_for_a_sign_out_and_by_nothing_else():
    expired = create_access_token(dict(CLAIMS), timedelta(minutes=-5))
    assert verify_access_token(expired) is None
    claims = verify_access_token_for_sign_out(expired)
    assert claims["session_token"] == CLAIMS["session_token"] and claims["sub"] == "u1"


def test_a_token_still_in_its_time_is_read_as_well():
    token = create_access_token(dict(CLAIMS), timedelta(minutes=5))
    assert verify_access_token_for_sign_out(token)["session_token"] == CLAIMS["session_token"]


def test_a_token_this_server_did_not_sign_is_not_read():
    other_key = jwt.encode(dict(CLAIMS), "another-key-" + "x" * 32, algorithm=_alg())
    unsigned = jwt.encode(dict(CLAIMS), None, algorithm="none")
    head, body, sig = create_access_token(dict(CLAIMS), timedelta(minutes=-5)).split(".")
    altered_claims = jwt.encode(dict(CLAIMS, sub="u2"), _key(), algorithm=_alg()).split(".")[1]
    altered = ".".join((head, altered_claims, sig))
    for token in (other_key, unsigned, altered, "not-a-token", ""):
        assert verify_access_token_for_sign_out(token) is None, token


def test_a_token_over_the_length_limit_is_refused_without_being_decoded(monkeypatch):
    seen = []
    real = security.jwt.decode
    monkeypatch.setattr(security.jwt, "decode", lambda token, *a, **k: seen.append(token) or real(token, *a, **k))
    long_one = create_access_token(dict(CLAIMS, pad="x" * MAX_ACCESS_TOKEN_LENGTH), timedelta(minutes=-5))
    assert len(long_one) > MAX_ACCESS_TOKEN_LENGTH
    assert verify_access_token_for_sign_out(long_one) is None
    assert verify_access_token_for_sign_out("a" * (MAX_ACCESS_TOKEN_LENGTH + 1)) is None
    assert seen == []


def test_the_sign_out_counts_against_the_sign_in_rate_limit_as_logout_does():
    assert classify_api_rate_limit("POST", "/auth/sign-out") == classify_api_rate_limit("POST", "/api/logout") \
        == "auth"
