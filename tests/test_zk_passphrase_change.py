"""Zero-knowledge passphrase change: PUT /ecc/keys/private re-wraps the private key.

Changing the passphrase re-encrypts the private key IN THE BROWSER under a new passphrase and
stores the new opaque blob WITHOUT changing the public key — so every vault DEK (ECDH-wrapped to
that public key) stays valid and no per-vault re-wrap is needed. The server only ever stores the
ciphertext it can't read.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import create_zk_vault, ensure_ecc_keypair, ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB, ApiClient


def _register(client, blob: str):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP384R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    client.post("/ecc/keys/register", json={"public_key": pub_pem, "encrypted_private_key": blob}).raise_for_status()
    return pub_pem


def test_passphrase_change_swaps_blob_keeps_public_key(admin, temp_user, temp_user_client):
    """The blob is replaced but the PUBLIC key (fingerprint) is unchanged, and a ZK vault the
    user owns remains accessible (its wrapped DEK is bound to the unchanged public key)."""
    c = temp_user_client
    blob1 = json.dumps({"encrypted": "blob-one", "salt": "s1", "iterations": 600000})
    _register(c, blob1)
    fp1 = c.get("/ecc/keys/public").json()["fingerprint"]
    assert c.get("/ecc/keys/private").json()["encrypted_private_key"] == blob1
    with _ZkOn(admin):
        v = create_zk_vault(c)          # temp_user owns a ZK vault
    vid = v["id"]
    try:
        assert c.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        # Change the passphrase (PUT a re-wrapped blob).
        blob2 = json.dumps({"encrypted": "blob-two", "salt": "s2", "iterations": 600000})
        r = c.put("/ecc/keys/private", json={"encrypted_private_key": blob2})
        assert r.status_code == 200, r.text
        # The new blob is served, and the PUBLIC key (fingerprint) is UNCHANGED — the
        # load-bearing property that keeps every wrapped DEK valid without a re-wrap. (has_access
        # is a membership-row lookup, untouched by this endpoint; it's a sanity check, not an
        # unwrap proof — the re-wrap's crypto soundness is proven by the Node round-trip below.)
        assert c.get("/ecc/keys/private").json()["encrypted_private_key"] == blob2
        assert c.get("/ecc/keys/public").json()["fingerprint"] == fp1
        assert c.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
    finally:
        c.delete_vault(vid)


def test_passphrase_change_blocked_for_temp_credential(admin):
    """A temporary credential authenticates AS the owner, but must NOT be able to overwrite the
    owner's private-key blob — that would irreversibly brick their zero-knowledge vaults."""
    ensure_ecc_keypair(admin)   # the owner has a real key that must not be corruptible via a temp cred
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    tc = admin.clone_anonymous()
    tc.login(body["temp_username"], body["credential"])
    r = tc.put("/ecc/keys/private", json={"encrypted_private_key": "malicious-blob"})
    assert r.status_code == 403, r.text
    # The owner's key is untouched — the guard fired before any write.
    assert admin.get("/ecc/keys/public").json()["has_keypair"] is True


def test_passphrase_change_requires_existing_keypair(admin):
    u = admin.create_user(role="user")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    try:
        r = c.put("/ecc/keys/private", json={"encrypted_private_key": "x"})
        assert r.status_code == 404, r.text
        r2 = c.put("/ecc/keys/private", json={"encrypted_private_key": ""})
        assert r2.status_code in (400, 422), r2.text   # empty blob rejected
    finally:
        admin.delete_user(u["id"])


class _ZkOn:
    def __init__(self, admin): self.admin = admin
    def __enter__(self): self.admin.put("/settings", json={"zero_knowledge_enabled": True})
    def __exit__(self, *a): self.admin.put("/settings", json={"zero_knowledge_enabled": False})


# --- browser crypto: the re-wrap under a NEW passphrase decrypts to the SAME key --------------
_NODE_REWRAP = r'''
const { webcrypto } = require('crypto');
global.window = { crypto: webcrypto };
console.log = () => {};
const ECC = require(process.env.ECC_JS);
(async () => {
  const lib = new ECC();
  const kp = await lib.generateKeypair();
  const pem = await lib.exportPrivateKeyPEM(kp.privateKey);
  const b1 = await lib.encryptPrivateKey(pem, 'pass-one-123');
  const pem1 = await lib.decryptPrivateKey(b1.encrypted, 'pass-one-123', b1.salt, b1.iterations); // unlock w/ old
  const b2 = await lib.encryptPrivateKey(pem1, 'pass-two-456');                                   // re-wrap w/ new
  const pem2 = await lib.decryptPrivateKey(b2.encrypted, 'pass-two-456', b2.salt, b2.iterations); // unlock w/ new
  let oldFails = false;
  try { await lib.decryptPrivateKey(b2.encrypted, 'pass-one-123', b2.salt, b2.iterations); }
  catch (e) { oldFails = true; }
  process.stdout.write(JSON.stringify({ unlockedOld: pem1 === pem, unlockedNew: pem2 === pem, oldFails }));
})().catch(e => { console.error(e); process.exit(1); });
'''


def test_passphrase_rewrap_crypto_roundtrip():
    """Real ecc_crypto.js under Node: re-wrapping the private key under a new passphrase yields a
    blob that decrypts to the SAME key with the new passphrase, and the OLD passphrase fails."""
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("node unavailable")
    ecc_js = str((Path(__file__).resolve().parent.parent / "static" / "js" / "ecc_crypto.js")).replace("\\", "/")
    proc = subprocess.run([node, "-"], input=_NODE_REWRAP, capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "ECC_JS": ecc_js}, timeout=30)
    assert proc.returncode == 0, f"node script failed: {proc.stderr}"
    out = json.loads(proc.stdout)
    assert out["unlockedOld"] is True, "old passphrase did not unlock the original key"
    assert out["unlockedNew"] is True, "new passphrase did not decrypt to the same key"
    assert out["oldFails"] is True, "old passphrase still decrypted the re-wrapped blob"
