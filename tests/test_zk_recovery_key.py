"""Zero-knowledge recovery key: export a recovery blob, restore access from it.

A recovery kit re-wraps the private key under a SEPARATE recovery passphrase (in the browser) so a
user who forgets their main passphrase can regain access: decrypt the kit with the recovery
passphrase, re-wrap under a NEW main passphrase, and store it via PUT /ecc/keys/private (no new
server endpoint). This proves the full export -> restore crypto chain with the real ecc_crypto.js.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_NODE_RECOVERY = r'''
const { webcrypto } = require('crypto');
global.window = { crypto: webcrypto };
console.log = () => {};
const ECC = require(process.env.ECC_JS);
(async () => {
  const lib = new ECC();
  const kp = await lib.generateKeypair();
  const pem = await lib.exportPrivateKeyPEM(kp.privateKey);

  // Registered: private key wrapped under the MAIN passphrase.
  const main1 = await lib.encryptPrivateKey(pem, 'main-pass-1');

  // EXPORT a recovery kit: unlock with the main passphrase, re-wrap under a RECOVERY passphrase.
  const unlocked = await lib.decryptPrivateKey(main1.encrypted, 'main-pass-1', main1.salt, main1.iterations);
  const rec = await lib.encryptPrivateKey(unlocked, 'recovery-pass-R');

  // RESTORE: decrypt the recovery kit with the recovery passphrase, re-wrap under a NEW main one.
  const restored = await lib.decryptPrivateKey(rec.encrypted, 'recovery-pass-R', rec.salt, rec.iterations);
  const main2 = await lib.encryptPrivateKey(restored, 'main-pass-2');
  const final = await lib.decryptPrivateKey(main2.encrypted, 'main-pass-2', main2.salt, main2.iterations);

  const sameKey = (final === pem) && (unlocked === pem) && (restored === pem);
  // The recovery blob is protected by the RECOVERY passphrase, not the main passphrase.
  let recNeedsRecoveryPass = false;
  try { await lib.decryptPrivateKey(rec.encrypted, 'main-pass-1', rec.salt, rec.iterations); }
  catch (e) { recNeedsRecoveryPass = true; }
  // The restored/new blob is protected by the NEW main passphrase, not the recovery passphrase.
  let newNeedsNewPass = false;
  try { await lib.decryptPrivateKey(main2.encrypted, 'recovery-pass-R', main2.salt, main2.iterations); }
  catch (e) { newNeedsNewPass = true; }
  process.stdout.write(JSON.stringify({ sameKey, recNeedsRecoveryPass, newNeedsNewPass }));
})().catch(e => { console.error(e); process.exit(1); });
'''


def test_recovery_export_and_restore_crypto_roundtrip():
    """Real ecc_crypto.js under Node: export -> restore preserves the exact private key, the
    recovery blob needs the recovery passphrase, and the restored blob needs the new main one."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node unavailable")
    ecc_js = str((Path(__file__).resolve().parent.parent / "static" / "js" / "ecc_crypto.js")).replace("\\", "/")
    proc = subprocess.run([node, "-"], input=_NODE_RECOVERY, capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "ECC_JS": ecc_js}, timeout=30)
    assert proc.returncode == 0, f"node script failed: {proc.stderr}"
    out = json.loads(proc.stdout)
    assert out["sameKey"] is True, "export -> restore did not preserve the private key"
    assert out["recNeedsRecoveryPass"] is True, "the recovery blob decrypted with the main passphrase"
    assert out["newNeedsNewPass"] is True, "the restored blob decrypted with the recovery passphrase"


_NODE_DERIVE_MATCH = r'''
const { webcrypto } = require('crypto');
global.window = { crypto: webcrypto };
console.log = () => {};
const ECC = require(process.env.ECC_JS);
(async () => {
  const lib = new ECC();
  const a = await lib.generateKeypair();
  const b = await lib.generateKeypair();
  const aPubPem = await lib.exportPublicKeyPEM(a.publicKey);
  const bPubPem = await lib.exportPublicKeyPEM(b.publicKey);
  const aPrivPem = await lib.exportPrivateKeyPEM(a.privateKey);
  // The public key DERIVED from A's private key must equal A's registered public key, and NOT B's.
  const derived = await lib.derivePublicKeyPEMFromPrivatePEM(aPrivPem);
  process.stdout.write(JSON.stringify({
    matchesOwn: derived.trim() === aPubPem.trim(),
    matchesOther: derived.trim() === bPubPem.trim(),
  }));
})().catch(e => { console.error(e); process.exit(1); });
'''


def test_derive_public_key_matches_own_and_not_another():
    """derivePublicKeyPEMFromPrivatePEM (the restore keypair-consistency check) reproduces the
    matching public key and does NOT match a different keypair — so restore can refuse a recovery
    kit whose private key doesn't belong to the account (which would orphan every wrapped DEK)."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node unavailable")
    ecc_js = str((Path(__file__).resolve().parent.parent / "static" / "js" / "ecc_crypto.js")).replace("\\", "/")
    proc = subprocess.run([node, "-"], input=_NODE_DERIVE_MATCH, capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "ECC_JS": ecc_js}, timeout=30)
    assert proc.returncode == 0, f"node script failed: {proc.stderr}"
    out = json.loads(proc.stdout)
    assert out["matchesOwn"] is True, "derived public key did not match its own private key"
    assert out["matchesOther"] is False, "derived public key wrongly matched a different keypair"
