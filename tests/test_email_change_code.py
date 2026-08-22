"""Unit tests for app/core/email_change — the one-time email-change code helpers (offline)."""
import pytest

from app.core.email_change import CODE_TTL_MINUTES, code_matches, generate_code, hash_code

pytestmark = pytest.mark.unit

PEP = "a-server-pepper-value"


def test_generate_code_is_hex_fixed_length_and_unique():
    a, b = generate_code(), generate_code()
    assert a != b                                  # fresh entropy each call
    assert len(a) == 12 and all(c in "0123456789abcdef" for c in a)


def test_hash_is_deterministic_and_pepper_dependent():
    code = generate_code()
    assert hash_code(code, PEP) == hash_code(code, PEP)          # deterministic
    assert hash_code(code, PEP) != hash_code(code, "other")      # keyed by the pepper
    assert len(hash_code(code, PEP)) == 64                       # sha256 hex


def test_code_matches_only_the_exact_code_and_pepper():
    code = generate_code()
    h = hash_code(code, PEP)
    assert code_matches(code, PEP, h) is True
    assert code_matches(code + "0", PEP, h) is False             # wrong code
    assert code_matches(code, "wrong-pepper", h) is False        # wrong pepper
    assert code_matches(code, PEP, h[:-1] + ("0" if h[-1] != "0" else "1")) is False  # tampered hash


def test_empty_inputs_never_match_a_real_hash():
    h = hash_code(generate_code(), PEP)
    assert code_matches("", PEP, h) is False
    assert code_matches("anything", PEP, "") is False


def test_ttl_is_a_sane_short_window():
    assert 1 <= CODE_TTL_MINUTES <= 60
