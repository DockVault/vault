"""Unit tests for app/core/vault_key_utils — the vault-key wrap/unwrap crypto.

This module wraps each vault's random content key under either a password-derived KEK (password
vaults) or the deployment master key (non-password vaults), and is exercised live at vault creation
and password change. Its REJECTION paths (wrong password, wrong master key, tampered ciphertext,
malformed metadata) had no coverage; a silent regression there would let a wrong credential decrypt,
or turn a clean rejection into a 500. Pure crypto, offline (cryptography only, no DB) -> `unit` lane.
"""
import base64

import pytest
from cryptography.fernet import Fernet

from app.core.vault_key_utils import (
    generate_vault_key,
    encrypt_vault_key,
    decrypt_vault_key,
    VaultKeyError,
    InvalidVaultKeyError,
)

pytestmark = pytest.mark.unit


def test_password_roundtrip():
    vk = generate_vault_key()
    ed = encrypt_vault_key(vk, password="correct-horse")
    assert ed["method"] == "password" and ed["salt"]
    assert decrypt_vault_key(ed, password="correct-horse") == vk


def test_master_key_roundtrip():
    vk = generate_vault_key()
    mk = Fernet.generate_key()
    ed = encrypt_vault_key(vk, master_key=mk)
    assert ed["method"] == "master_key" and ed["salt"] is None
    assert decrypt_vault_key(ed, master_key=mk) == vk


def test_wrong_password_is_rejected():
    ed = encrypt_vault_key(generate_vault_key(), password="the-real-one")
    with pytest.raises(InvalidVaultKeyError):
        decrypt_vault_key(ed, password="WRONG")


def test_wrong_master_key_is_rejected():
    ed = encrypt_vault_key(generate_vault_key(), master_key=Fernet.generate_key())
    with pytest.raises(InvalidVaultKeyError):
        decrypt_vault_key(ed, master_key=Fernet.generate_key())  # a different valid key


def test_tampered_ciphertext_is_rejected():
    vk = generate_vault_key()
    ed = encrypt_vault_key(vk, password="pw")
    raw = bytearray(base64.urlsafe_b64decode(ed["encrypted_key"].encode()))
    raw[-1] ^= 0x01  # flip a bit in the Fernet token
    ed["encrypted_key"] = base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(InvalidVaultKeyError):
        decrypt_vault_key(ed, password="pw")


def test_missing_credential_raises_valueerror():
    ed_pw = encrypt_vault_key(generate_vault_key(), password="pw")
    with pytest.raises(ValueError):
        decrypt_vault_key(ed_pw)  # password method, no password supplied
    ed_mk = encrypt_vault_key(generate_vault_key(), master_key=Fernet.generate_key())
    with pytest.raises(ValueError):
        decrypt_vault_key(ed_mk)  # master_key method, no master_key supplied


def test_malformed_metadata_is_rejected():
    good = encrypt_vault_key(generate_vault_key(), password="pw")
    with pytest.raises(VaultKeyError):
        decrypt_vault_key({"method": "password"}, password="pw")           # no encrypted_key
    with pytest.raises(VaultKeyError):
        decrypt_vault_key({"encrypted_key": good["encrypted_key"]}, password="pw")  # no method
    with pytest.raises(VaultKeyError):
        decrypt_vault_key(dict(good, method="martian"), password="pw")     # unknown method
    no_salt = dict(good, salt=None)
    with pytest.raises(VaultKeyError):
        decrypt_vault_key(no_salt, password="pw")                          # password method, no salt


def test_encrypt_requires_a_credential():
    with pytest.raises((ValueError, VaultKeyError)):
        encrypt_vault_key(generate_vault_key())  # neither password nor master_key
