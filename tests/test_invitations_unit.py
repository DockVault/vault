"""Unit coverage for the account-invitation token helpers (offline, no DB).

The at-rest discipline mirrors the log-pull token: a 256-bit urlsafe plaintext, a short public prefix,
a peppered HMAC-SHA256 hash, and a constant-time compare — with a DEDICATED pepper so a leak of the
log-pull pepper cannot forge invitation hashes.
"""
import pytest

from app.core import invitations
from app.services import log_pull

pytestmark = pytest.mark.unit


def test_mint_returns_plaintext_and_matching_prefix():
    plaintext, prefix = invitations.mint_invite()
    assert isinstance(plaintext, str) and len(plaintext) >= 40   # token_urlsafe(32) ~ 43 chars
    assert prefix == plaintext[:invitations.PREFIX_LEN]
    assert len(prefix) == invitations.PREFIX_LEN
    # two mints differ (fresh entropy)
    assert invitations.mint_invite()[0] != plaintext


@pytest.mark.parametrize("blank", ["", None])
def test_token_prefix_handles_blank(blank):
    assert invitations.token_prefix(blank) == ""


def test_hash_is_deterministic_and_pepper_sensitive():
    tok = "example-token-value"
    p = "x" * 40
    assert invitations.hash_invite_token(tok, p) == invitations.hash_invite_token(tok, p)
    assert invitations.hash_invite_token(tok, p) != invitations.hash_invite_token(tok, "y" * 40)


def test_hash_is_independent_of_the_log_pull_pepper_hash():
    # Same token, same pepper string, but the invite hash must not equal the log-pull hash unless the
    # HMAC construction is identical — they ARE identical HMAC-SHA256 here, so this documents that the
    # SEPARATION comes from using a DIFFERENT pepper in practice, not a different algorithm.
    tok, pepper = "shared-token", "z" * 40
    assert invitations.hash_invite_token(tok, pepper) == log_pull.hash_log_token(tok, pepper)
    # With the real deployment using distinct peppers, the stored hashes diverge:
    assert invitations.hash_invite_token(tok, "invite-" + "a" * 33) != log_pull.hash_log_token(tok, "logpull-" + "a" * 33)


def test_tokens_match_true_only_for_the_right_token_and_pepper():
    tok, pepper = "the-real-token", "p" * 40
    stored = invitations.hash_invite_token(tok, pepper)
    assert invitations.invite_tokens_match(tok, pepper, stored) is True
    assert invitations.invite_tokens_match("wrong-token", pepper, stored) is False
    assert invitations.invite_tokens_match(tok, "q" * 40, stored) is False
    assert invitations.invite_tokens_match(tok, pepper, "") is False


@pytest.mark.parametrize("pepper,ok", [
    ("", False), ("   ", False), ("short", False), (None, False), (12345, False),
    ("x" * 32, True), ("y" * 64, True),
])
def test_pepper_ok(pepper, ok):
    assert invitations.pepper_ok(pepper) is ok
