"""An independent reference for the zero-knowledge key proof, version 1.

This module deliberately imports no DockVault code. It is a small, explicit description of the key
proof's wire format and of the material a client stores with it, used for three things:

* generating the frozen vectors in ``tests/fixtures/crypto/zk-key-proof-v1/`` (see ``main``);
* checking that the server module and the browser module both reproduce those vectors;
* computing proofs for the HTTP suite (``tests/zk_proof_harness.py``).

What it defines:

* **The transcript** a proof covers: a SHA-256 over the protocol label and, at fixed widths, the
  operation, the challenge id and nonce, the caller, the vault, the vault's mode and epochs at issuance,
  and the hashes of the caller's identity point, the current verifier's point, the point being
  installed and the exact request body. Fixed widths make the encoding injective; the 0x00 bytes
  between fields are for readability.
* **Three role MACs** over that transcript, each an ECDH key confirmation against the server's one-time
  key: ``identity`` (the caller's identity key), ``current-key`` (the key the vault's verifier names)
  and ``new-key`` (the key the request installs).
* **The proof key's seal**: a direct vault's per-epoch proof private key, sealed under that epoch's DEK
  in the version-2 envelope family with purpose byte 0x07.
* **The key check** (a MAC keyed by the DEK) and **the lineage tag** (a MAC keyed by the previous
  epoch's DEK over what the rotation installed).

The constants are public test material and protocol labels, never deployment secrets.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROOF_LABEL = b"dockvault-zk-key-proof-v1"
PROOF_SALT = b"dv-zk-key-proof-v1"
ROLES = ("identity", "current-key", "new-key")
OPS = {"rekey": 1, "share": 2, "index_key": 3, "bootstrap": 4, "create": 5, "owner_reset": 6}
MODES = {"direct": 1, "hierarchical": 2}
# The operations whose proof names no current key: they install the first verifier (bootstrap,
# create) or replace a damaged one (owner_reset).
OPS_WITHOUT_CURRENT_KEY = ("bootstrap", "create", "owner_reset")
HEADER_VERSION = "v1"

V2_HKDF_SALT = b"dockvault-zk-envelope-v2-salt-01"
V2_MAGIC = b"DVZ2"
V2_VERSION = 0x02
V2_PURPOSE_KEY_PROOF_KEY = 0x07
KEY_PROOF_KEY_HEADER = V2_MAGIC + bytes([V2_VERSION, V2_PURPOSE_KEY_PROOF_KEY, 0, 0])
INFO_KEY_PROOF_KEY = b"dockvault-zk-key-proof-key-v2"
INFO_DEK_CHECK = b"dockvault-zk-dek-check-v1"
INFO_KEY_LINEAGE = b"dockvault-zk-key-lineage-v1"
SEALED_MIN_BYTES = 36
SEALED_MAX_BYTES = 8192

_Z = b"\x00"
_ZERO32 = bytes(32)


# ---------------------------------------------------------------------------------- encodings

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def uuid_bytes(value) -> bytes:
    """A UUID as its 36-byte lowercase hyphenated ASCII form."""
    s = str(value).lower()
    if not _UUID.match(s):
        raise ValueError("not a canonical UUID")
    return s.encode("ascii")


def u32(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("not a 32-bit unsigned integer")
    return struct.pack(">I", value)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def point(public_key_pem: str) -> bytes:
    """The 97-byte uncompressed P-384 point of a public-key PEM."""
    key = serialization.load_pem_public_key(public_key_pem.strip().encode())
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise ValueError("not a P-384 public key")
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def point_hash(public_key_pem: Optional[str]) -> bytes:
    """SHA-256 of a key's point, or 32 zero bytes for no key."""
    return hashlib.sha256(point(public_key_pem)).digest() if public_key_pem else _ZERO32


def private_from_scalar(scalar_hex: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int(scalar_hex, 16), ec.SECP384R1())


def public_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def private_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _hkdf(ikm: bytes, *, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


# --------------------------------------------------------------------------------- transcript

def transcript(*, op: str, challenge_id: str, nonce_b64: str, user_id: str, vault_id: str, mode: str,
               dek_epoch: int, team_epoch: int, identity_pem: str, current_pem: Optional[str],
               new_pem: Optional[str], body: bytes) -> bytes:
    """The 32-byte digest every role MACs."""
    nonce = base64.b64decode(nonce_b64, validate=True)
    if len(nonce) != 32:
        raise ValueError("the nonce is not 32 bytes")
    fields = [
        PROOF_LABEL,
        bytes([OPS[op]]),
        uuid_bytes(challenge_id),
        nonce,
        uuid_bytes(user_id),
        uuid_bytes(vault_id),
        bytes([MODES[mode]]),
        u32(dek_epoch),
        u32(team_epoch),
        point_hash(identity_pem),
        point_hash(current_pem),
        point_hash(new_pem),
        hashlib.sha256(body).digest(),
    ]
    return hashlib.sha256(_Z.join(fields)).digest()


def role_key(role: str, private_key: ec.EllipticCurvePrivateKey, server_public_pem: str) -> bytes:
    """The client side of a role's MAC key: ECDH(role private key, server one-time key) -> HKDF."""
    if role not in ROLES:
        raise ValueError("unknown role")
    server = serialization.load_pem_public_key(server_public_pem.encode())
    shared = private_key.exchange(ec.ECDH(), server)
    return _hkdf(shared, salt=PROOF_SALT, info=role.encode("ascii"))


def role_mac(role: str, private_key: ec.EllipticCurvePrivateKey, server_public_pem: str,
             digest: bytes) -> bytes:
    return hmac.new(role_key(role, private_key, server_public_pem), digest, hashlib.sha256).digest()


def proof_header(challenge_id: str, identity_mac: bytes, current_mac: Optional[bytes],
                 new_mac: Optional[bytes]) -> str:
    """``v1.<challenge id>.<identity>.<current or ->.<new or ->``, MACs in unpadded base64url."""
    return ".".join([
        HEADER_VERSION, str(challenge_id).lower(), b64url(identity_mac),
        b64url(current_mac) if current_mac else "-",
        b64url(new_mac) if new_mac else "-",
    ])


# ---------------------------------------------------------------------------- stored material

def key_proof_key_context(vault_id: str, dek_epoch: int, proof_public_pem: str) -> bytes:
    return _Z.join([uuid_bytes(vault_id), u32(dek_epoch), point_hash(proof_public_pem)])


def seal_key_proof_key(dek: bytes, vault_id: str, dek_epoch: int, proof_public_pem: str,
                       pkcs8_der: bytes, nonce: bytes) -> bytes:
    """S_n: the proof private key sealed under the epoch's DEK. The nonce is a parameter only so a
    vector can be frozen; a writer draws a fresh 12 random bytes."""
    if len(dek) != 32 or len(nonce) != 12:
        raise ValueError("a 32-byte DEK and a 12-byte nonce are required")
    context = key_proof_key_context(vault_id, dek_epoch, proof_public_pem)
    key = _hkdf(dek, salt=V2_HKDF_SALT, info=INFO_KEY_PROOF_KEY + _Z + context)
    ct = AESGCM(key).encrypt(nonce, pkcs8_der, KEY_PROOF_KEY_HEADER + context)
    return KEY_PROOF_KEY_HEADER + nonce + ct


def open_key_proof_key(sealed: bytes, dek: bytes, vault_id: str, dek_epoch: int,
                       proof_public_pem: str) -> ec.EllipticCurvePrivateKey:
    """Open S_n and confirm the key inside is the one P_n names. Raises ValueError on any failure."""
    if not SEALED_MIN_BYTES <= len(sealed) <= SEALED_MAX_BYTES or sealed[:8] != KEY_PROOF_KEY_HEADER:
        raise ValueError("not a sealed key-proof key")
    context = key_proof_key_context(vault_id, dek_epoch, proof_public_pem)
    key = _hkdf(dek, salt=V2_HKDF_SALT, info=INFO_KEY_PROOF_KEY + _Z + context)
    pkcs8 = AESGCM(key).decrypt(sealed[8:20], sealed[20:], KEY_PROOF_KEY_HEADER + context)
    private = serialization.load_der_private_key(pkcs8, password=None)
    if point(public_pem(private)) != point(proof_public_pem):
        raise ValueError("the sealed key does not match its public key")
    return private


def dek_check(dek: bytes, vault_id: str, dek_epoch: int) -> bytes:
    ctx = uuid_bytes(vault_id) + _Z + u32(dek_epoch)
    k = _hkdf(dek, salt=V2_HKDF_SALT, info=INFO_DEK_CHECK + _Z + ctx)
    return hmac.new(k, INFO_DEK_CHECK + _Z + ctx, hashlib.sha256).digest()


def lineage_tag(prev_dek: bytes, *, vault_id: str, prev_epoch: int, mode: str, next_team_epoch: int,
                next_verifier_pem: str, next_dek_check: Optional[bytes],
                next_team_wrap_b64: Optional[str]) -> bytes:
    """The tag a rotation from epoch p to p + 1 carries; only a holder of DEK_p can compute it."""
    vid = uuid_bytes(vault_id)
    k = _hkdf(prev_dek, salt=V2_HKDF_SALT, info=INFO_KEY_LINEAGE + _Z + vid + _Z + u32(prev_epoch))
    if mode == "direct":
        check, wrap_hash = next_dek_check, _ZERO32
    else:
        check = _ZERO32
        wrap = base64.b64decode(next_team_wrap_b64 or "", validate=True)
        if not wrap:
            raise ValueError("a team vault rotation's tag covers the next epoch's team DEK wrap")
        wrap_hash = hashlib.sha256(wrap).digest()
    if check is None or len(check) != 32:
        raise ValueError("a direct rotation's tag covers the next epoch's 32-byte key check")
    msg = hashlib.sha256(_Z.join([
        INFO_KEY_LINEAGE, vid, u32(prev_epoch), u32(prev_epoch + 1), bytes([MODES[mode]]),
        u32(next_team_epoch), point_hash(next_verifier_pem), check, wrap_hash,
    ])).digest()
    return hmac.new(k, msg, hashlib.sha256).digest()


# ------------------------------------------------------------------------------ vector writer

NOTICE = "PUBLIC TEST VECTOR - NOT A SECRET - NEVER USED BY A DEPLOYMENT"
SCHEMA = "dockvault-crypto-vector-v1"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "crypto" / "zk-key-proof-v1"

# Fixed scalars and values. Small scalars are fine for public test material and make the vectors
# easy to rebuild by hand.
_FIXED = {
    "server_scalar_hex": "2a",
    "identity_scalar_hex": "11",
    "current_scalar_hex": "22",
    "new_scalar_hex": "33",
    "challenge_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "user_id": "9b2c1d5e-7a34-4c81-9f2b-1a2b3c4d5e6f",
    "vault_id": "0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9",
    "nonce_b64": base64.b64encode(bytes(range(32))).decode(),
    "dek_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "next_dek_hex": "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100",
    "seal_nonce_hex": "a0a1a2a3a4a5a6a7a8a9aaab",
    "team_wrap_b64": base64.b64encode(b"\x5a" * 68).decode(),
    "body_utf8": '{"from_version":3,"to_version":4,"member_keys":[{"user_id":"u","wrapped_dek":"é"}]}',
}

_CASES = [
    # (name, op, mode, dek_epoch, team_epoch, current?, new?)
    ("rekey-direct", "rekey", "direct", 3, 1, True, True),
    ("rekey-hierarchical-dek-only", "rekey", "hierarchical", 3, 2, True, False),
    ("rekey-hierarchical-team", "rekey", "hierarchical", 3, 2, True, True),
    ("share-direct", "share", "direct", 3, 1, True, False),
    ("share-hierarchical", "share", "hierarchical", 3, 2, True, False),
    ("index-key-direct", "index_key", "direct", 3, 1, True, False),
    ("bootstrap-direct", "bootstrap", "direct", 3, 1, False, True),
    ("create-direct", "create", "direct", 1, 1, False, True),
    ("create-hierarchical", "create", "hierarchical", 1, 1, False, True),
    ("owner-reset-direct", "owner_reset", "direct", 3, 1, False, True),
]


def build_vectors() -> dict:
    f = _FIXED
    server = private_from_scalar(f["server_scalar_hex"])
    identity = private_from_scalar(f["identity_scalar_hex"])
    current = private_from_scalar(f["current_scalar_hex"])
    new = private_from_scalar(f["new_scalar_hex"])
    body = f["body_utf8"].encode("utf-8")
    cases = []
    for name, op, mode, de, te, has_current, has_new in _CASES:
        cur_pem = public_pem(current) if has_current else None
        new_pem = public_pem(new) if has_new else None
        t = transcript(op=op, challenge_id=f["challenge_id"], nonce_b64=f["nonce_b64"],
                       user_id=f["user_id"], vault_id=f["vault_id"], mode=mode, dek_epoch=de,
                       team_epoch=te, identity_pem=public_pem(identity), current_pem=cur_pem,
                       new_pem=new_pem, body=body)
        macs = {"identity": role_mac("identity", identity, public_pem(server), t)}
        if has_current:
            macs["current-key"] = role_mac("current-key", current, public_pem(server), t)
        if has_new:
            macs["new-key"] = role_mac("new-key", new, public_pem(server), t)
        cases.append({
            "name": name, "op": op, "mode": mode, "dek_epoch": de, "team_epoch": te,
            "has_current_key": has_current, "has_new_key": has_new,
            "transcript_sha256_hex": t.hex(),
            "macs_b64url": {r: b64url(m) for r, m in macs.items()},
            "header": proof_header(f["challenge_id"], macs["identity"], macs.get("current-key"),
                                   macs.get("new-key")),
        })

    dek = bytes.fromhex(f["dek_hex"])
    next_dek = bytes.fromhex(f["next_dek_hex"])
    proof_key = private_from_scalar("44")
    pkcs8 = proof_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    sealed = seal_key_proof_key(dek, f["vault_id"], 3, public_pem(proof_key), pkcs8,
                                bytes.fromhex(f["seal_nonce_hex"]))
    check3 = dek_check(dek, f["vault_id"], 3)
    check4 = dek_check(next_dek, f["vault_id"], 4)
    next_proof_key = private_from_scalar("55")
    return {
        "schema": SCHEMA,
        "test_only": True,
        "notice": NOTICE,
        "format": "zero-knowledge key proof v1",
        "fixture_id": "zk-key-proof-v1",
        "source_paths": ["app/services/zk_key_proof.py", "static/js/ecc_crypto.js",
                         "tests/zk_key_proof_reference.py"],
        "inputs": {
            **f,
            "server_public_key_pem": public_pem(server),
            "identity_public_key_pem": public_pem(identity),
            "identity_private_key_pem": private_pem(identity),
            "current_public_key_pem": public_pem(current),
            "current_private_key_pem": private_pem(current),
            "new_public_key_pem": public_pem(new),
            "new_private_key_pem": private_pem(new),
        },
        "transcripts": cases,
        "seal": {
            "vault_id": f["vault_id"], "dek_epoch": 3, "dek_hex": f["dek_hex"],
            "proof_public_key_pem": public_pem(proof_key),
            "proof_private_pkcs8_hex": pkcs8.hex(),
            "nonce_hex": f["seal_nonce_hex"],
            "sealed_b64": base64.b64encode(sealed).decode(),
        },
        "dek_check": [
            {"vault_id": f["vault_id"], "dek_epoch": 3, "dek_hex": f["dek_hex"], "dek_check_b64": base64.b64encode(check3).decode()},
            {"vault_id": f["vault_id"], "dek_epoch": 4, "dek_hex": f["next_dek_hex"], "dek_check_b64": base64.b64encode(check4).decode()},
        ],
        "lineage": [
            {"mode": "direct", "vault_id": f["vault_id"], "prev_epoch": 3, "prev_dek_hex": f["dek_hex"],
             "next_team_epoch": 1, "next_verifier_pem": public_pem(next_proof_key),
             "next_dek_check_b64": base64.b64encode(check4).decode(), "next_team_wrap_b64": None,
             "lineage_tag_b64": base64.b64encode(lineage_tag(
                 dek, vault_id=f["vault_id"], prev_epoch=3, mode="direct", next_team_epoch=1,
                 next_verifier_pem=public_pem(next_proof_key), next_dek_check=check4,
                 next_team_wrap_b64=None)).decode()},
            {"mode": "hierarchical", "vault_id": f["vault_id"], "prev_epoch": 3, "prev_dek_hex": f["dek_hex"],
             "next_team_epoch": 3, "next_verifier_pem": public_pem(new),
             "next_dek_check_b64": None, "next_team_wrap_b64": f["team_wrap_b64"],
             "lineage_tag_b64": base64.b64encode(lineage_tag(
                 dek, vault_id=f["vault_id"], prev_epoch=3, mode="hierarchical", next_team_epoch=3,
                 next_verifier_pem=public_pem(new), next_dek_check=None,
                 next_team_wrap_b64=f["team_wrap_b64"])).decode()},
        ],
    }


def main(argv) -> int:
    """Write the vector and its manifest. Run only to create the fixture set; once frozen, a change to
    any value is a format change, not a regeneration."""
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    vector_path = FIXTURE_DIR / "zk-key-proof-v1.json"
    vector_path.write_text(json.dumps(build_vectors(), indent=2) + "\n", encoding="utf-8", newline="\n")
    manifest = {
        "schema": "dockvault-crypto-manifest-v1",
        "test_only": True,
        "notice": NOTICE,
        "format": "zero-knowledge key proof v1",
        "vectors": [{"path": vector_path.name,
                     "sha256": hashlib.sha256(vector_path.read_bytes()).hexdigest()}],
    }
    (FIXTURE_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                               encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
