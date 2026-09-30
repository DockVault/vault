"""A bearer token nested deeper than the stack is an invalid token, answered 401 like any other.

jwt.decode parses a token's header as JSON before it checks anything else. PyJWT before 2.14.0 let
the RecursionError from a header nested deeper than the interpreter's stack escape (GHSA-8wjv-2p76-3863),
and verify_access_token catches only PyJWTError. So anyone, without signing in, could make every
route behind get_current_user or the second-factor principal answer 500 instead of 401 (in the
shipped image an Authorization header of about 8 KB was enough) and write a traceback to the log for
each request. Nothing was exposed and no check was skipped; the answer was simply wrong.

These hold the vault's own entry points to a 401 for such a token, whatever the library does.
tests/test_access_token_nesting_live.py sends the same token to the deployed stack.
"""
import base64
import functools
import json

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core.security import create_access_token, verify_access_token  # noqa: E402

pytestmark = pytest.mark.unit

# Far past any stack a test or a server runs on: a level of JSON nesting takes on the order of a
# hundred bytes of C stack, so this would need tens of megabytes. An 8 MiB main thread overflows
# before a hundred thousand levels, a small worker thread much sooner.
DEPTH = 1_000_000

# Arrays are the cheapest to build and parse; objects are what a header is meant to be.
_OPENINGS = {"array": (b"[", b"]"), "object": (b'{"a":', b"}")}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@functools.cache
def _nested_token(kind: str) -> str:
    opening, closing = _OPENINGS[kind]
    header = opening * DEPTH + (b"1" if kind == "object" else b"") + closing * DEPTH
    return f"{_b64u(header)}.{_b64u(json.dumps({'sub': 'x'}).encode())}.{_b64u(b'x')}"


class _NoDatabase:
    """A token refused on its face is refused before any lookup."""

    def __getattr__(self, name):
        pytest.fail(f"the database was asked ({name}) for a token that does not parse")


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_the_token_is_nested_deeper_than_this_interpreter_can_parse():
    # Without this the rest could pass by never reaching the stack at all.
    for kind in _OPENINGS:
        header = _nested_token(kind).split(".", 1)[0]
        raw = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        with pytest.raises(RecursionError):
            json.loads(raw)


@pytest.mark.parametrize("kind", sorted(_OPENINGS))
def test_verify_access_token_refuses_a_header_nested_past_the_stack(kind):
    assert verify_access_token(_nested_token(kind)) is None


@pytest.mark.parametrize("kind", sorted(_OPENINGS))
def test_a_signed_in_route_answers_401_to_it(kind):
    with pytest.raises(HTTPException) as refused:
        run_coroutine(S.get_current_user(_credentials(_nested_token(kind)), db=_NoDatabase()))
    assert refused.value.status_code == 401
    assert refused.value.detail == "Invalid authentication credentials"


@pytest.mark.parametrize("kind", sorted(_OPENINGS))
def test_the_second_factor_step_answers_401_to_it(kind):
    with pytest.raises(HTTPException) as refused:
        run_coroutine(S.get_pre_auth_principal(_credentials(_nested_token(kind)), db=_NoDatabase()))
    assert refused.value.status_code == 401


def test_a_token_the_server_signed_still_verifies():
    # The same entry point, so a refusal above is about the nesting and not a broken decode.
    claims = verify_access_token(create_access_token({"sub": "u1", "session_token": "s"}))
    assert claims["sub"] == "u1" and claims["session_token"] == "s"
