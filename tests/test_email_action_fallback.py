"""Offline unit tests for the system-action body fail-safe.

A SYSTEM security email (email_change / password_reset / account_invite) must never send without its
required token — the verification code or the reset/invite link. If an admin binds or customizes a
template whose body drops that token, the send helper falls back to the built-in body so the security
payload is never silently lost.
"""
import pytest

from app.core.email_actions import (
    SYSTEM, OPTIONAL, SPEC_BY_KEY, _fallback_body_if_missing_required_token as fb,
)

pytestmark = pytest.mark.unit


def test_code_action_body_missing_token_falls_back_to_builtin():
    spec = SPEC_BY_KEY["email_change"]
    assert "action.code" in spec["default_body_html"]
    out = fb(SYSTEM, "<p>Hi, please confirm.</p>", spec)   # custom body, NO code token
    assert out == spec["default_body_html"]                # fell back to the built-in (has the code)


def test_body_that_keeps_the_token_is_left_unchanged():
    spec = SPEC_BY_KEY["email_change"]
    custom = "<p>Your code is {{action.code}} — welcome.</p>"
    assert fb(SYSTEM, custom, spec) == custom              # token present -> keep the admin's template


def test_whitespace_token_variant_still_counts():
    spec = SPEC_BY_KEY["email_change"]
    custom = "<p>Code: {{ action.code }}</p>"               # spaced variant
    assert fb(SYSTEM, custom, spec) == custom              # still recognized -> not overridden


@pytest.mark.parametrize("key", ["password_reset", "account_invite"])
def test_link_actions_missing_link_fall_back(key):
    spec = SPEC_BY_KEY[key]
    assert "action.link" in spec["default_body_html"]
    assert fb(SYSTEM, "<p>No link here.</p>", spec) == spec["default_body_html"]


def test_optional_action_is_never_overridden():
    # A non-system action carries no mandatory security token; a custom body is always respected.
    spec = SPEC_BY_KEY["email_change"]
    custom = "<p>anything</p>"
    assert fb(OPTIONAL, custom, spec) == custom


def test_empty_body_is_passed_through():
    spec = SPEC_BY_KEY["email_change"]
    assert fb(SYSTEM, "", spec) == ""
    assert fb(SYSTEM, None, spec) is None
