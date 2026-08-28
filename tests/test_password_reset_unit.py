"""Offline unit tests for the password-reset token crypto (domain separation + reuse of the audited
invitation helpers)."""
import pytest

from app.core import password_reset as pr
from app.core import invitations as inv

pytestmark = pytest.mark.unit


def test_reset_pepper_is_domain_separated_and_strong():
    secret = "x" * 40
    rp = pr.reset_pepper(secret)
    assert rp.endswith(":password_reset") and pr.pepper_ok(rp)
    # a reset-token hash is never equal to an invite hash of the SAME token+secret (domain separation),
    # so a leak of one hash space can't forge the other.
    tok, _ = pr.mint_reset_token()
    assert pr.hash_reset_token(tok, rp) != inv.hash_invite_token(tok, secret)


def test_reset_token_roundtrip_and_prefix():
    tok, prefix = pr.mint_reset_token()
    assert prefix == pr.token_prefix(tok) and len(prefix) == pr.PREFIX_LEN
    rp = pr.reset_pepper("y" * 40)
    h = pr.hash_reset_token(tok, rp)
    assert pr.reset_tokens_match(tok, rp, h)
    assert not pr.reset_tokens_match("wrong-token", rp, h)
    assert not pr.reset_tokens_match(tok, rp, "")           # a blank stored hash never matches
