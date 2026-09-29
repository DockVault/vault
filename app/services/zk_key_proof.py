"""Key proof for changes to a zero-knowledge vault's keys, version 1.

Four requests hand out or fix zero-knowledge key material: creating a zero-knowledge vault, sharing one,
rotating its key and setting its name-index key. Each carries a one-time proof in the
``X-ZK-Key-Proof`` header: MACs over one server challenge and over the exact request body, showing the
caller holds, at that moment,

* their own identity private key (checked against the account's registered public key);
* the vault's current key material (checked against the vault's verifier: the team public key of a
  hierarchical vault, or a direct vault's per-epoch proof public key); and
* the private half of every public key the request installs.

Each role is an ECDH key confirmation against the server's one-time key, the construction
``ecc_update_pop`` uses, in its own domain: the salt, the protocol label, the role names and the table
differ from registration and from envelope replacement, so no MAC or challenge crosses protocols.

This module holds only the server's side: the transcript, the MAC check, the header grammar and the
shape of the stored material. It never sees a DEK or a private key other than the server's one-time key.
The client side is ``static/js/ecc_crypto.js``; both reproduce the frozen vectors in
``tests/fixtures/crypto/zk-key-proof-v1/``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROOF_LABEL = b"dockvault-zk-key-proof-v1"
PROOF_SALT = b"dv-zk-key-proof-v1"
HEADER_NAME = "X-ZK-Key-Proof"
HEADER_VERSION = "v1"

ROLE_IDENTITY = "identity"
ROLE_CURRENT_KEY = "current-key"
ROLE_NEW_KEY = "new-key"
ROLES = (ROLE_IDENTITY, ROLE_CURRENT_KEY, ROLE_NEW_KEY)

# The operations a challenge is issued for, with their transcript byte.
OPS = {"rekey": 1, "share": 2, "index_key": 3, "bootstrap": 4, "create": 5, "owner_reset": 6}
# The operations whose proof names no current key: they install the first verifier (bootstrap,
# create) or replace damaged material (owner_reset).
OPS_WITHOUT_CURRENT_KEY = frozenset({"bootstrap", "create", "owner_reset"})
MODES = {"direct": 1, "hierarchical": 2}

CHALLENGE_TTL_SECONDS = 300


def enforcement_enabled() -> bool:
    """True unless the operator has set ZK_KEY_PROOF_ENFORCE=false."""
    from app.core.config import settings
    return bool(getattr(settings, "zk_key_proof_enforce", True))


def report_at_startup(log=print) -> None:
    """Say at start when requests without a key proof are accepted. Never raises."""
    try:
        if not enforcement_enabled():
            log("⚠ Zero-knowledge key changes are accepted without a key proof "
                "(ZK_KEY_PROOF_ENFORCE=false); each such request is recorded in the audit log")
    except Exception:  # noqa: BLE001 -- a report must never stop the server starting
        pass

# The sealed proof key: version-2 envelope family, purpose byte 0x07. The server checks only this
# header and the length bounds; it cannot open the seal and does not try.
SEALED_KEY_HEADER = b"DVZ2" + bytes([0x02, 0x07, 0x00, 0x00])
SEALED_KEY_MIN_BYTES = 36
SEALED_KEY_MAX_BYTES = 8192
# A base64 string of 8192 bytes is 10924 characters; anything longer cannot be in bounds.
_SEALED_KEY_MAX_CHARS = 4 * ((SEALED_KEY_MAX_BYTES + 2) // 3)
_MAC_BYTES = 32
_MAX_HEADER_CHARS = 256
_MAX_PEM_CHARS = 4096

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_B64URL_MAC = re.compile(r"^[A-Za-z0-9_-]{43}$")
_Z = b"\x00"
_ZERO32 = bytes(32)


class MalformedProof(ValueError):
    """The header or the material does not have the shape the protocol defines. Refused before any
    challenge is consumed, so an honest client cannot destroy its own challenge with a bad request."""


# ------------------------------------------------------------------------------------ refusals
#
# Every refusal on the key-proof paths is one JSON shape, {"detail": <sentence>, "reason": <slug>}, with
# a plain-string detail and never a 401. Clients read `detail` with a substring test, and the web app
# signs a person out on a 403 whose detail contains "inactive", "terminated" or "locked", and treats one
# containing "password", "Password", "Unauthorized" or "401" as a sign-in problem -- in the current
# bundle and in the older one the desktop app ships. None of these sentences may contain any of them
# ("locked" also rules out "unlocked"). One sentence covers every failed proof: telling a caller which
# part failed helps only an attacker.

REFUSALS = {
    "zk-key-proof-required": (
        428,
        "This change needs proof that you hold this vault's key, which this version of the app cannot "
        "give. Reload the page (or update DockVault Desktop) and try again.",
    ),
    "zk-key-proof-setup-required": (
        428,
        "This vault's key check has not been set up yet. Open the vault once as a manager who holds its "
        "key, then try again.",
    ),
    "zk-key-proof-malformed": (400, "This request's key proof or key material is malformed."),
    "zk-key-proof-failed": (403, "The proof that you hold this vault's key did not check out. Try again."),
    "zk-key-proof-interactive-only": (
        403, "A temporary credential cannot set up or reset a vault's key check."),
    "zk-key-proof-stale": (
        409, "This vault's key changed while the change was being prepared. Try again."),
    "zk-key-proof-exists": (409, "This vault's key check was just set up by someone else. Try again."),
    "zk-key-proof-verifier-unusable": (
        409, "This vault's key record is inconsistent. Its owner can reset the key."),
}

# What no refusal sentence may contain (see above).
FORBIDDEN_IN_REFUSALS = ("inactive", "terminated", "locked", "password", "unauthorized", "401")


class KeyProofRefusal(Exception):
    """A refusal on a key-proof path, rendered by :func:`refusal_handler` as
    ``{"detail": <sentence>, "reason": <slug>}`` with the slug's status.

    `detail` defaults to the slug's sentence; only the malformed refusal takes a more specific one (the
    shape problem, which a caller can act on and which says nothing about any key)."""

    def __init__(self, reason: str, detail: Optional[str] = None):
        status, sentence = REFUSALS[reason]
        super().__init__(reason)
        self.reason = reason
        self.status_code = status
        self.detail = detail if detail else sentence


def malformed(message: str) -> KeyProofRefusal:
    """The 400 for a request whose header or material has the wrong shape."""
    return KeyProofRefusal("zk-key-proof-malformed", message)


async def refusal_handler(request, exc: KeyProofRefusal):
    """The application-level handler for :class:`KeyProofRefusal`."""
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail, "reason": exc.reason})


@dataclass(frozen=True)
class ProofHeader:
    challenge_id: str          # lowercase canonical UUID
    identity_mac: bytes
    current_key_mac: Optional[bytes]
    new_key_mac: Optional[bytes]


# ----------------------------------------------------------------------------------- challenge

def generate_challenge():
    """A one-time challenge: (server one-time PRIVATE key PEM, PUBLIC key PEM, nonce base64).

    The private half never leaves the server and is stored sealed for as long as the challenge lives.
    It is not a user key and never a DEK.
    """
    key = ec.generate_private_key(ec.SECP384R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_pem, public_pem, base64.b64encode(os.urandom(32)).decode()


# ------------------------------------------------------------------------------------- shapes

def public_point(public_key_pem) -> bytes:
    """The 97-byte uncompressed point of a P-384 public key PEM. Anything else is malformed.

    Points, not PEMs, are hashed into the transcript, so a cosmetic re-encoding of a stored key cannot
    break a genuine proof.
    """
    if not isinstance(public_key_pem, str) or not public_key_pem.strip() or len(public_key_pem) > _MAX_PEM_CHARS:
        raise MalformedProof("public key is not a PEM")
    try:
        key = serialization.load_pem_public_key(public_key_pem.strip().encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise MalformedProof("public key is not a PEM") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise MalformedProof("public key is not a P-384 key")
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def point_sha256(public_key_pem: Optional[str]) -> bytes:
    """SHA-256 of a key's point, or 32 zero bytes when there is no key."""
    if public_key_pem is None:
        return _ZERO32
    return hashlib.sha256(public_point(public_key_pem)).digest()


def _b64(value, name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise MalformedProof(f"{name} is required")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedProof(f"{name} is not base64") from exc


def validate_sealed_key(value) -> bytes:
    """A sealed proof key: base64, 36..8192 bytes, the version-2 header with purpose 0x07."""
    if isinstance(value, str) and len(value) > _SEALED_KEY_MAX_CHARS:
        raise MalformedProof("sealed_private_key is too large")
    raw = _b64(value, "sealed_private_key")
    if not SEALED_KEY_MIN_BYTES <= len(raw) <= SEALED_KEY_MAX_BYTES:
        raise MalformedProof("sealed_private_key has the wrong length")
    if raw[:8] != SEALED_KEY_HEADER:
        raise MalformedProof("sealed_private_key is not a sealed key-proof key")
    return raw


def validate_mac32(value, name: str) -> bytes:
    """`dek_check` and `lineage_tag`: base64 of exactly 32 bytes."""
    if isinstance(value, str) and len(value) > 64:
        raise MalformedProof(f"{name} has the wrong length")
    raw = _b64(value, name)
    if len(raw) != _MAC_BYTES:
        raise MalformedProof(f"{name} has the wrong length")
    return raw


def _mac_field(text: str, required: bool) -> Optional[bytes]:
    if text == "-" and not required:
        return None
    if not _B64URL_MAC.match(text):
        raise MalformedProof("a MAC in the proof header is malformed")
    raw = base64.urlsafe_b64decode(text + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise MalformedProof("a MAC in the proof header is not canonical")
    return raw


def parse_header(value) -> ProofHeader:
    """``v1.<challenge id>.<identity MAC>.<current-key MAC or ->.<new-key MAC or ->``.

    MACs are unpadded base64url of 32 bytes. The identity MAC is always present.
    """
    if not isinstance(value, str) or not value or len(value) > _MAX_HEADER_CHARS:
        raise MalformedProof("the proof header is malformed")
    parts = value.strip().split(".")
    if len(parts) != 5 or parts[0] != HEADER_VERSION:
        raise MalformedProof("the proof header is malformed")
    if not _UUID.match(parts[1]):
        raise MalformedProof("the proof header's challenge id is malformed")
    return ProofHeader(
        challenge_id=parts[1].lower(),
        identity_mac=_mac_field(parts[2], required=True),
        current_key_mac=_mac_field(parts[3], required=False),
        new_key_mac=_mac_field(parts[4], required=False),
    )


# ---------------------------------------------------------------------------------- transcript

def _uuid_ascii(value, name: str) -> bytes:
    s = str(value)
    if not _UUID.match(s):
        raise MalformedProof(f"{name} is not a UUID")
    return s.lower().encode("ascii")


def _u32(value, name: str) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise MalformedProof(f"{name} is out of range")
    return struct.pack(">I", value)


def transcript(*, op: str, challenge_id: str, nonce_b64: str, user_id: str, vault_id: str, mode: str,
               dek_epoch: int, team_epoch: int, identity_public_key: str,
               current_public_key: Optional[str], new_public_key: Optional[str], body: bytes) -> bytes:
    """The 32-byte digest each role MACs.

    Every field after the label has a fixed width -- one byte for the operation and the mode, 36 ASCII
    bytes for each id, the 32 raw nonce bytes, 4-byte big-endian epochs and 32-byte digests -- so the
    encoding is injective; the 0x00 bytes between them are readability. `current_public_key` is None
    for the operations that prove no current key, and `new_public_key` for a request that installs
    none; either then contributes 32 zero bytes. `body` is the request body exactly as received.
    """
    if op not in OPS:
        raise MalformedProof("unknown operation")
    if mode not in MODES:
        raise MalformedProof("unknown mode")
    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise MalformedProof("the challenge nonce is not base64") from exc
    if len(nonce) != 32:
        raise MalformedProof("the challenge nonce is not 32 bytes")
    fields = [
        PROOF_LABEL,
        bytes([OPS[op]]),
        _uuid_ascii(challenge_id, "challenge id"),
        nonce,
        _uuid_ascii(user_id, "user id"),
        _uuid_ascii(vault_id, "vault id"),
        bytes([MODES[mode]]),
        _u32(dek_epoch, "dek_epoch"),
        _u32(team_epoch, "team_epoch"),
        point_sha256(identity_public_key),
        point_sha256(current_public_key),
        point_sha256(new_public_key),
        hashlib.sha256(bytes(body)).digest(),
    ]
    return hashlib.sha256(_Z.join(fields)).digest()


# ------------------------------------------------------------------------------------------ MACs

def _role_key(role: str, server_private_pem: str, public_key_pem: str) -> bytes:
    if role not in ROLES:
        raise ValueError("unknown role")
    server = serialization.load_pem_private_key(server_private_pem.encode("ascii"), password=None)
    peer = serialization.load_pem_public_key(public_key_pem.strip().encode("ascii"))
    if not isinstance(peer, ec.EllipticCurvePublicKey) or not isinstance(peer.curve, ec.SECP384R1):
        raise ValueError("not a P-384 key")
    shared = server.exchange(ec.ECDH(), peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=PROOF_SALT,
                info=role.encode("ascii")).derive(shared)


def expected_mac(role: str, server_private_pem: str, public_key_pem: str, digest: bytes) -> bytes:
    """The MAC a holder of `public_key_pem`'s private key computes for this transcript."""
    return hmac.new(_role_key(role, server_private_pem, public_key_pem), digest, hashlib.sha256).digest()


def verify_role(role: str, server_private_pem: str, public_key_pem: str, digest: bytes,
                mac: Optional[bytes]) -> bool:
    """True iff `mac` proves possession of `public_key_pem`'s private key for this transcript.

    Constant-time compare. Any malformed input, or a missing MAC, returns False rather than raising,
    so a caller cannot learn which part of an attempt was wrong.
    """
    if not mac or not public_key_pem:
        return False
    try:
        expected = expected_mac(role, server_private_pem, public_key_pem, digest)
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(expected, bytes(mac))
