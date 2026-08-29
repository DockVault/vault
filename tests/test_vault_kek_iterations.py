"""Unit tests for the password KEK PBKDF2 work factor.

New password-KEK wraps derive at 600,000 iterations (the OWASP 2025 recommendation, matching the ZK
identity envelope); the count is stamped into each record's metadata so raising it is forward-only.
Records written before the raise -- both those that stored iterations=100000 and older ones with no
stored count at all -- must still open, which is why the READ fallbacks stay 100000.
"""
import base64

import pytest
from cryptography.fernet import Fernet

from app.core.vault_key_utils import (
    PBKDF2_KEK_ITERATIONS,
    decrypt_vault_key,
    derive_key_encryption_key,
    encrypt_vault_key,
    generate_salt,
    generate_vault_key,
)

pytestmark = pytest.mark.unit

_PW = "correct horse battery staple"


def test_new_wrap_uses_600k_and_round_trips():
    vault_key = generate_vault_key()
    wrap = encrypt_vault_key(vault_key, password=_PW)
    assert wrap["method"] == "password"
    assert wrap["iterations"] == 600000 == PBKDF2_KEK_ITERATIONS
    assert decrypt_vault_key(wrap, password=_PW) == vault_key


def test_wrong_password_does_not_decrypt():
    vault_key = generate_vault_key()
    wrap = encrypt_vault_key(vault_key, password=_PW)
    with pytest.raises(Exception):
        decrypt_vault_key(wrap, password="not the password")


def _legacy_wrap(vault_key, *, stored_iterations):
    """A wrap as an older build would have written it: derived at 100000, and either stamping that
    count in metadata or (the oldest form) omitting the field entirely."""
    salt = generate_salt()
    kek = derive_key_encryption_key(_PW, salt, iterations=100000)
    wrap = {
        "encrypted_key": base64.urlsafe_b64encode(Fernet(kek).encrypt(vault_key)).decode(),
        "salt": salt,
        "method": "password",
        "version": 1,
    }
    if stored_iterations is not None:
        wrap["iterations"] = stored_iterations
    return wrap


def test_old_100k_wrap_still_opens():
    vault_key = generate_vault_key()
    wrap = _legacy_wrap(vault_key, stored_iterations=100000)
    assert decrypt_vault_key(wrap, password=_PW) == vault_key


def test_legacy_wrap_without_stored_count_falls_back_to_100k():
    vault_key = generate_vault_key()
    wrap = _legacy_wrap(vault_key, stored_iterations=None)
    assert decrypt_vault_key(wrap, password=_PW) == vault_key
