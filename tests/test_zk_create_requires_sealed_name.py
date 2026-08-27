"""A zero-knowledge vault must seal its name in the browser at CREATE time.

The server is the enforcement boundary for the ZK guarantee: a ZK vault's real name is sealed in the
browser (enc_name) and the plaintext `name` is only ever a non-secret label the browser sends
alongside it (or null). A ZK create that carries a plaintext `name` with NO enc_name is a naive/buggy
/hostile caller putting the real name in the clear -- the server must refuse it, exactly as the rename
path refuses a plaintext name on a ZK vault. Standard vaults are unaffected (they require a real
plaintext name, sealed server-side at rest).
"""
import contextlib

import pytest

from conftest import ensure_ecc_keypair, unique, ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB, ZK_ENC_NAME_STUB


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _base_zk_payload():
    return {
        "type": "zero_knowledge",
        "wrapped_dek": ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ZK_EPHEMERAL_STUB,
    }


def test_zk_create_with_plaintext_name_and_no_seal_is_refused(admin):
    """A plaintext name with no enc_name would store the real name in the clear -> 400."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        payload = _base_zk_payload()
        payload["name"] = unique("secret-name")     # a real name, sent in the clear, unsealed
        r = admin.post("/vaults", json=payload)
        assert r.status_code == 400, (
            f"a ZK vault name sent in the clear must be refused, not stored (got {r.status_code}: {r.text[:200]})"
        )
        assert "sealed" in r.text.lower()


def test_zk_create_with_sealed_name_is_accepted(admin):
    """A sealed name (enc_name), with an optional non-secret label, is accepted."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        payload = _base_zk_payload()
        payload["name"] = unique("label")           # a non-secret label, alongside the seal
        payload["enc_name"] = ZK_ENC_NAME_STUB
        payload["name_key_version"] = 1
        r = admin.post("/vaults", json=payload)
        assert r.status_code == 200, r.text
        vault = r.json()
        assert vault["type"] == "zero_knowledge"
        admin.delete_vault(vault["id"])


def test_zk_create_with_no_name_and_no_seal_is_allowed(admin):
    """A nameless ZK vault (neither a plaintext name nor a seal) leaks nothing, so it is allowed."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        payload = _base_zk_payload()                 # no name, no enc_name
        r = admin.post("/vaults", json=payload)
        assert r.status_code == 200, r.text
        admin.delete_vault(r.json()["id"])


def test_standard_vault_with_plaintext_name_is_unaffected(admin):
    """A Standard vault still requires and accepts a real plaintext name (sealed at rest server-side)."""
    r = admin.post("/vaults", json={"name": unique("std"), "type": "standard"})
    assert r.status_code == 200, r.text
    admin.delete_vault(r.json()["id"])
