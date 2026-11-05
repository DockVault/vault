"""How POST /auth/sign-out reads the token it is sent, offline (app/core/security.py:
verify_access_token_for_sign_out).

The web app signs out after its session has run out as well, and that session's row stays listed as signed in
until it is ended, so the sign-out reads a token this server signed whether or not it has expired. Nothing else
is let go: a token signed with another key, with another algorithm or none, or altered after it was signed, is
not read, and one longer than any this server signs is refused on its length without being decoded, as every
other bearer token is (tests/test_access_token_length.py). It reads tokens for that one route only; every other
reader still refuses an expired token. tests/test_api_sign_out.py holds the route on a running stack.

The rate limiter reads the sign-out's token the same way (app/core/rate_limiter.py: SIGN_OUT_BUCKET,
sign_out_session_of): the sign-out is in the auth class, at its limit and window, but counted in a bucket of its own,
by the session its token names, expired or not, and by address for a token that names no session. Never by the
account: every other token the server signed for it (another session's, one that has run out, a temporary
credential's, whose account is its owner's) is counted apart, so none of them can use up a session's sign-out. The
sign-ins (by address) and the account's other auth requests are counted apart from it, as before.
"""
import hashlib
import time
from datetime import timedelta

import jwt
import pytest
from starlette.requests import Request
from starlette.responses import Response

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.core.security as security  # noqa: E402
from app.core.rate_limiter import (  # noqa: E402
    SIGN_OUT_BUCKET, RateLimitMiddleware, classify_api_rate_limit, is_sign_out_request,
)
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


def test_the_sign_out_is_in_the_auth_class_as_logout_is():
    assert classify_api_rate_limit("POST", "/auth/sign-out") == classify_api_rate_limit("POST", "/api/logout") \
        == "auth"


def test_only_the_sign_out_itself_is_read_as_one():
    assert is_sign_out_request("POST", "/auth/sign-out") and is_sign_out_request("post", "/auth/sign-out/")
    for method, path in (("GET", "/auth/sign-out"), ("PUT", "/auth/sign-out"), ("POST", "/api/logout"),
                         ("POST", "/auth/login"), ("POST", "/auth/sign-out/more"), ("POST", "/auth/sign-outs"),
                         ("POST", "/x/auth/sign-out"), ("POST", ""), (None, None)):
        assert not is_sign_out_request(method, path), (method, path)


ADDRESS = "198.51.100.9"


class _CountingLimiter:
    """Stands in for the Redis limiter: notes each count (bucket, who, limit, window) and lets it through."""

    def __init__(self):
        self.counted = []

    def check_rate_limit(self, identifier, limit, window, prefix="rate_limit", **_):
        self.counted.append((prefix, identifier, limit, window))
        return True, limit - 1, int(time.time()) + window

    def get_rate_limit_headers(self, limit, remaining, reset_time):
        return {}


def _counted(monkeypatch, method, path, authorization=None, state=None):
    """Where the middleware counts one request: (bucket prefix, who, limit, window). `state`: what an earlier layer
    put on the request (request.state)."""
    monkeypatch.setattr("app.core.net_utils.client_ip", lambda _request: ADDRESS)
    limiter = _CountingLimiter()
    middleware = RateLimitMiddleware(None, limiter, default_limit=100, default_window=60, auth_limit=10,
                                     auth_window=60)
    headers = [(b"authorization", authorization.encode())] if authorization is not None else []
    scope = {"type": "http", "method": method, "path": path, "headers": headers, "client": (ADDRESS, 1234),
             "scheme": "https", "server": ("vault.example", 443), "query_string": b""}
    if state is not None:
        scope["state"] = dict(state)
    request = Request(scope)

    async def call_next(_request):
        return Response("ok")

    assert run_coroutine(middleware.dispatch(request, call_next)).status_code == 200
    assert len(limiter.counted) == 1, limiter.counted
    return limiter.counted[0]


SIGN_OUTS = f"rate_limit:api:{SIGN_OUT_BUCKET}"


def _session(session_token):
    """Who a sign-out of the session `session_token` is counted against: the hash the server keeps of it."""
    return "session:" + hashlib.sha256(session_token.encode()).hexdigest()


def test_a_sign_out_is_counted_by_the_session_its_token_names_expired_or_not_in_a_bucket_of_its_own(monkeypatch):
    assert SIGN_OUTS != "rate_limit:api:auth"
    expired = create_access_token(dict(CLAIMS), timedelta(minutes=-5))
    live = create_access_token(dict(CLAIMS), timedelta(minutes=5))
    for token in (expired, live):
        assert _counted(monkeypatch, "POST", "/auth/sign-out", f"Bearer {token}") == \
            (SIGN_OUTS, _session(CLAIMS["session_token"]), 10, 60)


def test_no_other_token_of_the_account_is_counted_against_a_sessions_sign_out(monkeypatch):
    """Another session of the account, one that has run out, and a temporary credential's (its account is its
    owner's, its session its own): each is counted against its own session, none against the account."""
    mine = create_access_token(dict(CLAIMS), timedelta(minutes=5))
    old = create_access_token(dict(CLAIMS, session_token="o" * 43), timedelta(minutes=-60))
    lent = create_access_token(dict(CLAIMS, session_token="t" * 43, is_temporary=True), timedelta(minutes=5))
    counted = [_counted(monkeypatch, "POST", "/auth/sign-out", f"Bearer {token}")[1] for token in (mine, old, lent)]
    assert counted == [_session("s" * 43), _session("o" * 43), _session("t" * 43)], counted


def test_a_sign_out_is_counted_by_session_whatever_an_earlier_layer_says_of_the_account(monkeypatch):
    """An earlier layer naming the account on the request (request.state.user_id, by which the other requests are
    counted) does not make a sign-out the account's; with a token that names no session, it is counted by address."""
    live = create_access_token(dict(CLAIMS), timedelta(minutes=5))
    by_layer = {"user_id": "u1"}
    assert _counted(monkeypatch, "POST", "/auth/sign-out", f"Bearer {live}", state=by_layer) == \
        (SIGN_OUTS, _session(CLAIMS["session_token"]), 10, 60)
    assert _counted(monkeypatch, "POST", "/auth/sign-out", None, state=by_layer) == (SIGN_OUTS, f"ip:{ADDRESS}", 10, 60)
    # Every other request is counted by the account that layer names, as before.
    assert _counted(monkeypatch, "GET", "/auth/session", None, state=by_layer) == \
        ("rate_limit:api:auth", "user:u1", 10, 60)


def test_a_sign_out_with_a_token_that_names_no_session_is_counted_by_address_in_its_own_bucket(monkeypatch):
    other_key = jwt.encode(dict(CLAIMS), "another-key-" + "x" * 32, algorithm=_alg())
    over = create_access_token(dict(CLAIMS, pad="x" * MAX_ACCESS_TOKEN_LENGTH), timedelta(minutes=-5))
    # Signed by the server, for the account, but naming no session: a second-factor pending token, and tokens whose
    # session claim is missing, empty or not a string.
    pending = create_access_token({"sub": "u1", "username": "ana", "stage": "second_factor", "pre_auth": "p1"},
                                  timedelta(minutes=5))
    no_session = [create_access_token(dict(CLAIMS, session_token=value), timedelta(minutes=5))
                  for value in (None, "", 7, ["s" * 43])]
    for authorization in (None, "Bearer", "Bearer ", "Bearer not-a-token", f"Bearer {other_key}", f"Bearer {over}",
                          f"Basic {create_access_token(dict(CLAIMS), timedelta(minutes=5))}", f"Bearer {pending}",
                          *(f"Bearer {token}" for token in no_session)):
        assert _counted(monkeypatch, "POST", "/auth/sign-out", authorization) == (SIGN_OUTS, f"ip:{ADDRESS}", 10, 60), \
            authorization


def test_the_sign_ins_and_the_other_auth_requests_are_counted_as_before(monkeypatch):
    expired = create_access_token(dict(CLAIMS), timedelta(minutes=-5))
    live = create_access_token(dict(CLAIMS), timedelta(minutes=5))
    auth = "rate_limit:api:auth"
    assert _counted(monkeypatch, "POST", "/auth/login") == (auth, f"ip:{ADDRESS}", 10, 60)
    assert _counted(monkeypatch, "GET", "/auth/policy") == (auth, f"ip:{ADDRESS}", 10, 60)
    assert _counted(monkeypatch, "GET", "/auth/session", f"Bearer {live}") == (auth, "user:u1", 10, 60)
    # An expired token names no one anywhere else: by address, as before.
    assert _counted(monkeypatch, "GET", "/auth/session", f"Bearer {expired}") == (auth, f"ip:{ADDRESS}", 10, 60)
    assert _counted(monkeypatch, "POST", "/api/logout", f"Bearer {expired}") == (auth, f"ip:{ADDRESS}", 10, 60)
    assert _counted(monkeypatch, "GET", "/auth/sign-out", f"Bearer {expired}") == (auth, f"ip:{ADDRESS}", 10, 60)
    assert _counted(monkeypatch, "GET", "/users/me", f"Bearer {expired}") == \
        ("rate_limit:api:default", f"ip:{ADDRESS}", 100, 60)
