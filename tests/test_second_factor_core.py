"""Pure second-factor crypto: TOTP (RFC 6238), recovery codes, receipt helpers (app/core/second_factor.py).

No running vault and no DB — pins the risky crypto (RFC 6238 vectors, the drift window, the recovery-code
shape + the non-secret lookup prefix) independent of any instance. The DB-backed verify dispatch / replay
claim / receipt consumption are exercised end-to-end by the route integration tests in later phases.
"""
import base64
import os
import sys

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor as sf          # noqa: E402
from app.core.security import verify_password, hash_password   # noqa: E402


def test_password_is_never_accepted_as_a_second_factor():
    """The account password is the FIRST factor; check_second_factor must never accept it as the
    SECOND (else a stolen password defeats MFA). method='password' — even with the correct password —
    and any unknown method short-circuit to False without touching the DB."""
    class _U:
        id = "u"
        password_hash = hash_password("correct horse battery staple")
    u = _U()
    assert sf.check_second_factor(None, user=u, action="login", method="password",
                                  code="correct horse battery staple") is False
    assert sf.check_second_factor(None, user=u, action="login", method="banana", code="x") is False


def test_totp_rfc6238_sha1_vectors():
    # RFC 6238 Appendix B test key, SHA-1, truncated to 6 digits (the last 6 of the 8-digit reference).
    seed = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert sf._totp_at_step(seed, 59 // sf.TOTP_STEP_SECONDS) == "287082"           # T=59  -> 94287082
    assert sf._totp_at_step(seed, 1111111109 // sf.TOTP_STEP_SECONDS) == "081804"    # -> 07081804
    assert sf._totp_at_step(seed, 1234567890 // sf.TOTP_STEP_SECONDS) == "005924"    # -> 89005924
    assert sf._totp_at_step(seed, 2000000000 // sf.TOTP_STEP_SECONDS) == "279037"    # -> 69279037


def test_matching_step_accepts_current_and_drift_rejects_far_and_malformed():
    seed = sf.generate_totp_secret()
    now = 1_000_000_000.0
    step = sf.current_totp_step(now)
    assert sf.matching_totp_step(seed, sf._totp_at_step(seed, step), at_time=now) == step
    assert sf.matching_totp_step(seed, sf._totp_at_step(seed, step - 1), at_time=now) == step - 1
    assert sf.matching_totp_step(seed, sf._totp_at_step(seed, step + 1), at_time=now) == step + 1
    # two steps away is outside the +/-1 drift window
    assert sf.matching_totp_step(seed, sf._totp_at_step(seed, step + 2), at_time=now) is None
    assert sf.matching_totp_step(seed, sf._totp_at_step(seed, step - 2), at_time=now) is None
    # malformed inputs never match
    for bad in ("12345", "1234567", "abcdef", "", "12 34 56", None):
        assert sf.matching_totp_step(seed, bad, at_time=now) is None


def test_generated_seed_is_valid_base32():
    seed = sf.generate_totp_secret()
    # decodes (padded) without error and produces a real 6-digit code
    base64.b32decode(sf._pad_b32(seed).upper())
    assert sf._totp_at_step(seed, 42).isdigit() and len(sf._totp_at_step(seed, 42)) == 6


def test_recovery_codes_distinct_80bit_with_nonsecret_prefix():
    codes = sf.generate_recovery_codes(10)
    assert len(codes) == 10
    plains = [c[0] for c in codes]
    assert len(set(plains)) == 10                                   # distinct
    for plain, prefix, h in codes:
        assert len(plain) == 20 and all(ch in "0123456789abcdef" for ch in plain)   # 80 bits, hex
        assert prefix == plain[:sf.RECOVERY_PREFIX_LEN] and len(prefix) == 8
        assert h and h != plain                                     # an argon2 hash, not the plaintext
        assert verify_password(plain, h)                            # the hash covers the FULL code
        assert not verify_password(prefix, h)                       # the stored prefix does NOT verify


def test_recovery_format_and_normalize_are_case_and_dash_insensitive():
    plain = "0123456789abcdef0123"
    shown = sf.format_recovery_code(plain)
    assert "-" in shown and sf._normalize_recovery(shown) == plain
    assert sf._normalize_recovery(shown.upper()) == plain
    assert sf._normalize_recovery("  " + shown + "  ") == plain


def test_otpauth_uri_shape():
    uri = sf.otpauth_uri("ABCDEF234567", account="alice@example.com", issuer="DockVault")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCDEF234567" in uri
    assert "algorithm=SHA1" in uri and "digits=6" in uri and "period=30" in uri
