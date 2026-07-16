"""Proof-of-possession (PoP) for ECC public-key registration — ECDH key-confirmation.

Registration must prove the caller holds the PRIVATE key matching the public key they
register, so a substituted / not-held key can't be registered. The scheme is a standard
ECDH key-confirmation (no signing key, no user private key on the server):

  1. The server generates a one-time EPHEMERAL P-384 keypair + a random nonce (the
     challenge) and hands the client the ephemeral PUBLIC key + nonce.
  2. The client does ECDH(user_private, server_ephemeral_public) -> shared secret, derives
     an HMAC key via HKDF, and MACs (nonce || registered_public_key_pem).
  3. The server does ECDH(server_ephemeral_private, user_public) -> the SAME shared secret
     (ECDH is symmetric), derives the same HMAC key, and checks the MAC in constant time.

Only a holder of the user private key can produce the correct MAC, so the MAC proves
possession. This module handles ONLY server-generated EPHEMERAL keys used for the
challenge — it never touches a user private key or a vault DEK (the zero-knowledge
invariant), which is why it lives here and not in app/services/ecc_crypto_service.py.
"""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Must match static/js/ecc_crypto.js computeRegistrationPoP + the tests' Python mirror.
_HKDF_SALT = b"dv-ecc-pop-v1"
_HKDF_INFO = b"registration-pop"
_CURVE = ec.SECP384R1()


def generate_challenge():
    """A one-time challenge: (server ephemeral PRIVATE key PEM, ephemeral PUBLIC key PEM,
    nonce base64). The private PEM is stored server-side transiently and never leaves it."""
    eph = ec.generate_private_key(_CURVE)
    priv_pem = eph.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = eph.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    nonce_b64 = base64.b64encode(os.urandom(32)).decode()
    return priv_pem, pub_pem, nonce_b64


def _mac(server_priv_pem: str, user_public_pem: str, nonce_b64: str) -> bytes:
    """The expected HMAC: ECDH(server_ephemeral_private, user_public) -> HKDF -> HMAC over
    (nonce || user_public_pem). Raises on malformed key material (caller maps to a 400)."""
    server_priv = serialization.load_pem_private_key(server_priv_pem.encode(), password=None)
    user_pub = serialization.load_pem_public_key(user_public_pem.encode())
    if not isinstance(user_pub, ec.EllipticCurvePublicKey):
        raise ValueError("public key is not an EC key")
    shared = server_priv.exchange(ec.ECDH(), user_pub)
    mac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=_HKDF_INFO).derive(shared)
    msg = base64.b64decode(nonce_b64) + user_public_pem.encode()
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def verify_pop(server_priv_pem: str, user_public_pem: str, nonce_b64: str, mac_b64: str) -> bool:
    """True iff `mac_b64` is the client's correct ECDH-confirmation MAC for this challenge and
    public key. Constant-time compare; any malformed input -> False (never leaks the reason)."""
    try:
        expected = _mac(server_priv_pem, user_public_pem, nonce_b64)
        provided = base64.b64decode(mac_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(expected, provided)
