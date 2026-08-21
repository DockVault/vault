"""Unit tests for app/core/response_hash_utils.check_if_none_match — the conditional-GET matcher.

The ETag/If-None-Match parsing (RFC 7232 3.2: "*", weak W/ validators, comma-lists) was exercised
only through one live endpoint, and those tests could bail into a pass. These drive the matcher
directly, offline, so every branch (no header / "*" / exact / weak / comma-list / no-match) is pinned.
"""
import pytest

from app.core.response_hash_utils import check_if_none_match, compute_response_hash

pytestmark = pytest.mark.unit

HASH = "42907b2ce9fa42c3474d9f956cff0da0a8c26a92410dac8d95fb3e80038f9e68"


class _Req:
    """Minimal stand-in: check_if_none_match only reads request.headers.get('If-None-Match')."""
    def __init__(self, if_none_match=None):
        self.headers = {"If-None-Match": if_none_match} if if_none_match is not None else {}


def test_no_header_returns_false():
    assert check_if_none_match(_Req(), HASH) is False


def test_star_matches_any():
    assert check_if_none_match(_Req("*"), HASH) is True


def test_exact_quoted_match():
    assert check_if_none_match(_Req(f'"{HASH}"'), HASH) is True


def test_weak_validator_matches():
    assert check_if_none_match(_Req(f'W/"{HASH}"'), HASH) is True


def test_comma_list_one_of_many_matches():
    assert check_if_none_match(_Req(f'"deadbeef", W/"{HASH}"'), HASH) is True


def test_non_matching_tag_is_false():
    assert check_if_none_match(_Req('"deadbeef"'), HASH) is False


def test_different_content_hash_is_false():
    assert check_if_none_match(_Req(f'"{HASH}"'), "a-different-hash") is False


def test_hash_is_stable_and_order_independent():
    # compute_response_hash underpins the ETag; equal content -> equal tag, and dict key order
    # must not change it (else a client's cached ETag would spuriously miss).
    a = compute_response_hash({"x": 1, "y": [2, 3]})
    b = compute_response_hash({"y": [2, 3], "x": 1})
    assert a == b and len(a) == 64
    assert compute_response_hash({"x": 1}) != compute_response_hash({"x": 2})
