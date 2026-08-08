"""Proof of possession for replacing the stored private-key envelope.

Specified by ``docs/design/vault-private-key-update-pop-v1.md``. Where this file and that document
disagree, the document is the contract.

Registering an account's public key already proves the caller holds the matching private key.
Replacing the stored envelope did not, so any ordinary session for that account could overwrite it
and permanently destroy access to every vault. This module supplies the missing proof.

It deliberately mirrors the SHAPE of the registration proof in ``ecc_pop.py`` -- a server ephemeral
key, ECDH, HKDF, HMAC -- because that shape is already implemented and reviewed. It must never
share its DOMAIN: the salt, the info string and the storage table are all distinct, so a challenge
issued for one purpose cannot be answered for the other even if a row were somehow misrouted.

The transcript binds the exact replacement bytes, which is what makes the proof specific rather
than merely present: a proof that authorised one replacement cannot install a different one.
"""

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Distinct from ecc_pop's dv-ecc-pop-v1 / registration-pop. Both values must match
# static/js/ecc_crypto.js computeKeyUpdatePoP and the pinned transcript fixture.
_HKDF_SALT = b"dv-ecc-update-pop-v1"
_HKDF_INFO = b"private-key-update-pop"
_PROTOCOL_LABEL = b"dockvault-private-key-update-pop-v1"
_SEP = b"\x00"
_CURVE = ec.SECP384R1()

CHALLENGE_TTL_SECONDS = 300  # five minutes, per the design


def generate_challenge():
    """A one-time update challenge: (server ephemeral PRIVATE key PEM, PUBLIC key PEM, nonce b64).

    The private half is held server-side only for as long as the challenge lives and never leaves
    the server. It is not a user key and never a DEK.
    """
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
    return priv_pem, pub_pem, base64.b64encode(os.urandom(32)).decode()


def public_point(public_key_pem: str) -> bytes:
    """The canonical uncompressed P-384 point, 97 bytes: 0x04 || X(48) || Y(48).

    The transcript hashes the POINT rather than the PEM so that cosmetic re-encoding of the stored
    key -- line wrapping, line endings, a trailing newline -- cannot invalidate a genuine proof.
    """
    key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("registered key is not an EC public key")
    if not isinstance(key.curve, ec.SECP384R1):
        raise ValueError("registered key is not on P-384")
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def transcript(
    challenge_id: str, nonce_b64: str, user_id: str, public_key_pem: str, envelope: str
) -> bytes:
    """The 32-byte digest the client MACs.

    Every element earns its place: the label separates this protocol from every other MAC in the
    system; the challenge id and nonce make the proof one-time and tie it to this issuance; the
    user id stops a proof for one account being presented for another; the public point binds it
    to the key actually on record; and the envelope digest binds it to this exact replacement.

    ``0x00`` separators make the concatenation unambiguous. Digests are contributed as 32 RAW
    bytes, the nonce is the base64-DECODED value, and both ids are lowercase canonical UUIDs -- all
    pinned by the design so the browser and this verifier cannot drift.
    """
    parts = [
        _PROTOCOL_LABEL,
        str(challenge_id).lower().encode("ascii"),
        base64.b64decode(nonce_b64, validate=True),
        str(user_id).lower().encode("ascii"),
        hashlib.sha256(public_point(public_key_pem)).digest(),
        hashlib.sha256(envelope.encode("utf-8")).digest(),
    ]
    return hashlib.sha256(_SEP.join(parts)).digest()


def _mac_key(server_priv_pem: str, public_key_pem: str) -> bytes:
    server_priv = serialization.load_pem_private_key(server_priv_pem.encode(), password=None)
    user_pub = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(user_pub, ec.EllipticCurvePublicKey):
        raise ValueError("registered key is not an EC public key")
    shared = server_priv.exchange(ec.ECDH(), user_pub)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=_HKDF_INFO
    ).derive(shared)


def expected_mac(
    server_priv_pem: str,
    public_key_pem: str,
    challenge_id: str,
    nonce_b64: str,
    user_id: str,
    envelope: str,
) -> bytes:
    return hmac.new(
        _mac_key(server_priv_pem, public_key_pem),
        transcript(challenge_id, nonce_b64, user_id, public_key_pem, envelope),
        hashlib.sha256,
    ).digest()


def verify_pop(
    server_priv_pem: str,
    public_key_pem: str,
    challenge_id: str,
    nonce_b64: str,
    user_id: str,
    envelope: str,
    mac_b64: str,
) -> bool:
    """True iff ``mac_b64`` proves possession of the registered key FOR THIS EXACT REPLACEMENT.

    Constant-time compare. Any malformed input returns False rather than raising, so a caller
    cannot learn which part of an attempt was wrong -- the design requires one indistinguishable
    failure for every reason a proof can fail.
    """
    try:
        expected = expected_mac(
            server_priv_pem, public_key_pem, challenge_id, nonce_b64, user_id, envelope
        )
        provided = base64.b64decode(mac_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(expected, provided)
