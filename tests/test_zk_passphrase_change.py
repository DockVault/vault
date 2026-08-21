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

from conftest import (create_zk_vault, ensure_ecc_keypair, compute_key_update_pop,
                      ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB, ApiClient)


def _register(client, blob: str):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from conftest import compute_registration_pop
    priv = ec.generate_private_key(ec.SECP384R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    client.post("/ecc/keys/register", json={
        "public_key": pub_pem, "encrypted_private_key": blob,
        "pop": compute_registration_pop(client, priv, pub_pem),
    }).raise_for_status()
    return pub_pem, priv


def test_passphrase_change_swaps_blob_keeps_public_key(admin, temp_user, temp_user_client):
    """The blob is replaced but the PUBLIC key (fingerprint) is unchanged, and a ZK vault the
    user owns remains accessible (its wrapped DEK is bound to the unchanged public key)."""
    c = temp_user_client
    blob1 = json.dumps({"encrypted": "blob-one", "salt": "s1", "iterations": 600000})
    pub_pem, priv = _register(c, blob1)
    fp1 = c.get("/ecc/keys/public").json()["fingerprint"]
    assert c.get("/ecc/keys/private").json()["encrypted_private_key"] == blob1
    with _ZkOn(admin):
        v = create_zk_vault(c)          # temp_user owns a ZK vault
    vid = v["id"]
    try:
        assert c.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        # Change the passphrase (PUT a re-wrapped blob).
        blob2 = json.dumps({"encrypted": "blob-two", "salt": "s2", "iterations": 600000})
        # Replacement now requires proof that the caller holds the REGISTERED key, bound to
        # these exact bytes. Without it the account's only copy could be overwritten by any
        # session, which is unrecoverable.
        pop = compute_key_update_pop(c, priv, pub_pem, c.user["id"], blob2)
        r = c.put("/ecc/keys/private", json={"encrypted_private_key": blob2, "pop": pop})
        assert r.status_code == 200, r.text
        # That proof is spent. Replaying it VERBATIM -- same proof, same bytes, so nothing but
        # consumption can reject it -- must not install the same blob a second time.
        assert c.put("/ecc/keys/private",
                     json={"encrypted_private_key": blob2, "pop": pop}).status_code == 400, (
            "a proof was accepted twice, so a successful replacement does not consume its challenge"
        )
        # An unproven replacement is refused.
        blob3 = json.dumps({"encrypted": "blob-three", "salt": "s3", "iterations": 600000})
        assert c.put("/ecc/keys/private",
                     json={"encrypted_private_key": blob3}).status_code == 400

        # The challenge is DURABLY consumed, which is a different property from transcript
        # binding and needs the same bytes to isolate it. Mint a fresh proof, spend it on a
        # WRONG mac, then re-send the genuine proof for the SAME blob: that can only fail if the
        # challenge was really consumed by the failed attempt. Asserting with different bytes
        # would pass on the transcript hash alone, even if a wrong proof rolled the delete back
        # and left the challenge alive for mac grinding.
        blob4 = json.dumps({"encrypted": "blob-four", "salt": "s4", "iterations": 600000})
        pop4 = compute_key_update_pop(c, priv, pub_pem, c.user["id"], blob4)
        bad = dict(pop4, mac="A" * len(pop4["mac"]))
        assert c.put("/ecc/keys/private",
                     json={"encrypted_private_key": blob4, "pop": bad}).status_code == 400
        assert c.put("/ecc/keys/private",
                     json={"encrypted_private_key": blob4, "pop": pop4}).status_code == 400, (
            "a genuine proof still worked after a failed attempt on the same challenge, so the "
            "challenge was not durably consumed and macs can be ground against one issuance"
        )
        assert c.get("/ecc/keys/private").json()["encrypted_private_key"] == blob2
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
    assert node, "Node is required: this crypto round-trip must not be skipped into passing"
    ecc_js = str((Path(__file__).resolve().parent.parent / "static" / "js" / "ecc_crypto.js")).replace("\\", "/")
    proc = subprocess.run([node, "-"], input=_NODE_REWRAP, capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "ECC_JS": ecc_js}, timeout=30)
    assert proc.returncode == 0, f"node script failed: {proc.stderr}"
    out = json.loads(proc.stdout)
    assert out["unlockedOld"] is True, "old passphrase did not unlock the original key"
    assert out["unlockedNew"] is True, "new passphrase did not decrypt to the same key"
    assert out["oldFails"] is True, "old passphrase still decrypted the re-wrapped blob"


def test_the_replacement_path_is_blind_to_the_envelope_shape(admin, temp_user_client):
    """A legacy-shaped and a versioned-shaped replacement each succeed against the same server.

    The design calls this out explicitly, and it is load-bearing rather than incidental: it is
    what keeps enabling the versioned writer a CLIENT-only decision instead of a coordinated
    client-and-server release. The server stores the bytes the proof covers and never parses
    them, so both shapes are just strings to it.

    Without this, a field validator or a `startswith('{"encrypted"')` sanity check could be added
    to the route, satisfy the source-level grep that guards this today, and still break every
    versioned replacement -- surfacing only on the day an operator flips the writer on.
    """
    c = temp_user_client
    legacy_blob = json.dumps({"encrypted": "shape-legacy", "salt": "s1", "iterations": 600000})
    pub_pem, priv = _register(c, legacy_blob)
    # No cleanup: temp_user is function-scoped and the account is deleted on teardown, so whatever
    # shape this leaves behind reaches nothing.
    for label, blob in (
        ("legacy", json.dumps({
            "encrypted": "shape-legacy-2", "salt": "s2", "iterations": 600000})),
        ("versioned", json.dumps({
            "v": 1, "kdf": "PBKDF2-SHA256", "iter": 600000, "cipher": "AES-256-GCM",
            "salt": "c2FsdA==", "iv": "aXY=", "ct": "Y3Q="})),
    ):
        pop = compute_key_update_pop(c, priv, pub_pem, c.user["id"], blob)
        r = c.put("/ecc/keys/private",
                  json={"encrypted_private_key": blob, "pop": pop})
        assert r.status_code == 200, f"{label}: {r.text}"
        # Stored verbatim, byte for byte -- the server neither parsed nor normalised it.
        assert c.get("/ecc/keys/private").json()["encrypted_private_key"] == blob, label
