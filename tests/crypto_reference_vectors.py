"""Independent reference codecs for DockVault crypto compatibility public test vectors.

This module deliberately does not import DockVault application code.  It is a
small, explicit description of the persisted/wire formats that were readable at
the v0.10.0 boundary.  Constants in the fixture set are public test material and
must never be reused by a deployment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import uuid
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap


SCHEMA = "dockvault-crypto-vector-v1"
RELEASE = "v0.10.0"
COMMIT = "1a1b8fa9e1e80ca78d9a4154cfdb391f3f3c53a8"
NOTICE = "PUBLIC TEST VECTOR - NOT A SECRET - NEVER USED BY A DEPLOYMENT"

STANDARD_MAGIC = b"DockVault"
STANDARD_VERSION = 0x10
STANDARD_HEADER = STANDARD_MAGIC + bytes([STANDARD_VERSION, 0, 0])
STANDARD_ROOT_SALT = b"dockvault-gcm-chunk-stream-key-v1"
STANDARD_ROOT_INFO = b"at-rest-content"
STANDARD_SUBKEY_SALT = b"dockvault-gcm-chunk-subkey-v1"
STANDARD_AAD_DOMAIN = b"dockvault-chunk-aad-v1"
DIRECT_WRAP_INFO = b"vault-key-wrapping"
TEAM_PRIVATE_WRAP_INFO = b"team-privkey-wrapping-v1"
ZK_NAME_BLIND_SALT = b"dv-zk-name-bi-v1"


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def load_vector(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert_vector_metadata(value)
    return value


def assert_vector_metadata(vector: dict[str, Any]) -> None:
    if vector.get("schema") != SCHEMA:
        raise ValueError("unexpected crypto compatibility vector schema")
    if vector.get("release") != RELEASE or vector.get("commit") != COMMIT:
        raise ValueError(
            "vector is not pinned to the crypto compatibility release boundary"
        )
    if vector.get("test_only") is not True or vector.get("notice") != NOTICE:
        raise ValueError("vector does not carry the required public-test warning")


def load_unreleased_vector(path: Path) -> dict[str, Any]:
    """Load a vector for a format that no release has shipped yet.

    ``load_vector`` additionally pins the vector to a released commit, which a format introduced
    on a branch cannot satisfy. The public-test-material guards still apply and are the point of
    going through a loader at all: a fixture read with a bare ``json.loads`` silently escapes
    them, and these files must never carry production-derived material.
    """
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != SCHEMA:
        raise ValueError("unexpected crypto compatibility vector schema")
    if value.get("test_only") is not True or value.get("notice") != NOTICE:
        raise ValueError("vector does not carry the required public-test warning")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hkdf(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        ikm
    )


def _p384_private(scalar_hex: str) -> ec.EllipticCurvePrivateKey:
    scalar = int(scalar_hex, 16)
    if scalar <= 0:
        raise ValueError("P-384 private scalar must be positive")
    return ec.derive_private_key(scalar, ec.SECP384R1())


def p384_private_pem(scalar_hex: str) -> str:
    return (
        _p384_private(scalar_hex)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode("ascii")
        .rstrip("\n")
    )


def p384_private_der(scalar_hex: str) -> bytes:
    return _p384_private(scalar_hex).private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def p384_public_raw(scalar_hex: str) -> bytes:
    return (
        _p384_private(scalar_hex)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def _standard_subkey(encryption_key: str, vault_id: str, file_id: str) -> bytes:
    root = _hkdf(
        encryption_key.encode("utf-8"), salt=STANDARD_ROOT_SALT, info=STANDARD_ROOT_INFO
    )
    return _hkdf(
        root,
        salt=STANDARD_SUBKEY_SALT,
        info=uuid.UUID(vault_id).bytes + uuid.UUID(file_id).bytes,
    )


def _standard_aad(vault_id: str, file_id: str, index: int) -> bytes:
    return (
        STANDARD_AAD_DOMAIN
        + uuid.UUID(vault_id).bytes
        + uuid.UUID(file_id).bytes
        + struct.pack(">Q", index)
    )


def encode_standard_0x10(vector: dict[str, Any]) -> bytes:
    inputs = vector["inputs"]
    aes = AESGCM(
        _standard_subkey(
            inputs["encryption_key"], inputs["vault_id"], inputs["file_id"]
        )
    )
    output = bytearray(STANDARD_HEADER)
    chunks = [b64d(value) for value in inputs["chunks_b64"]]
    nonces = [bytes.fromhex(value) for value in inputs["nonces_hex"]]
    if len(chunks) != len(nonces):
        raise ValueError("one deterministic nonce is required per Standard chunk")
    for index, (chunk, nonce) in enumerate(zip(chunks, nonces, strict=True)):
        if len(nonce) != 12:
            raise ValueError("Standard AES-GCM nonces are exactly 12 bytes")
        ciphertext = aes.encrypt(
            nonce, chunk, _standard_aad(inputs["vault_id"], inputs["file_id"], index)
        )
        record = nonce + ciphertext
        output.extend(struct.pack(">I", len(record)))
        output.extend(record)
    return bytes(output)


def decode_standard_0x10(
    encoded: bytes, *, encryption_key: str, vault_id: str, file_id: str
) -> bytes:
    if not encoded.startswith(STANDARD_HEADER):
        raise ValueError("invalid Standard 0x10 header")
    aes = AESGCM(_standard_subkey(encryption_key, vault_id, file_id))
    offset = len(STANDARD_HEADER)
    plaintext = bytearray()
    index = 0
    while offset < len(encoded):
        if len(encoded) - offset < 4:
            raise ValueError("truncated Standard record length")
        size = struct.unpack(">I", encoded[offset : offset + 4])[0]
        offset += 4
        if size < 28 or size > len(encoded) - offset:
            raise ValueError("invalid Standard record size")
        record = encoded[offset : offset + size]
        offset += size
        plaintext.extend(
            aes.decrypt(
                record[:12],
                record[12:],
                _standard_aad(vault_id, file_id, index),
            )
        )
        index += 1
    return bytes(plaintext)


def _fernet_token(key_b64: str, plaintext: bytes, timestamp: int, iv: bytes) -> bytes:
    key = base64.urlsafe_b64decode(key_b64.encode("ascii"))
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("Fernet needs a 32-byte key and 16-byte IV")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key[16:]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    body = b"\x80" + struct.pack(">Q", timestamp) + iv + ciphertext
    signature = hmac.new(key[:16], body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + signature)


def encode_fernet_chunk_stream(vector: dict[str, Any]) -> bytes:
    inputs = vector["inputs"]
    chunks = [b64d(value) for value in inputs["chunks_b64"]]
    timestamps = inputs["timestamps"]
    ivs = [bytes.fromhex(value) for value in inputs["ivs_hex"]]
    if not (len(chunks) == len(timestamps) == len(ivs)):
        raise ValueError("one timestamp and IV are required per Fernet chunk")
    output = bytearray()
    for chunk, timestamp, iv in zip(chunks, timestamps, ivs, strict=True):
        token = _fernet_token(inputs["encryption_key"], chunk, int(timestamp), iv)
        output.extend(struct.pack(">I", len(token)))
        output.extend(token)
    return bytes(output)


def decode_fernet_chunk_stream(encoded: bytes, *, encryption_key: str) -> bytes:
    offset = 0
    output = bytearray()
    fernet = Fernet(encryption_key.encode("ascii"))
    while offset < len(encoded):
        if len(encoded) - offset < 4:
            raise ValueError("truncated Fernet record length")
        size = struct.unpack(">I", encoded[offset : offset + 4])[0]
        offset += 4
        if size <= 0 or size > len(encoded) - offset:
            raise ValueError("invalid Fernet record size")
        output.extend(fernet.decrypt(encoded[offset : offset + size]))
        offset += size
    return bytes(output)


def encode_zk_content(vector: dict[str, Any]) -> bytes:
    inputs = vector["inputs"]
    iv = bytes.fromhex(inputs["iv_hex"])
    return iv + AESGCM(bytes.fromhex(inputs["dek_hex"])).encrypt(
        iv, b64d(inputs["plaintext_b64"]), None
    )


def decode_zk_content(encoded: bytes, *, dek_hex: str) -> bytes:
    if len(encoded) < 28:
        raise ValueError("truncated zero-knowledge content")
    return AESGCM(bytes.fromhex(dek_hex)).decrypt(encoded[:12], encoded[12:], None)


V2_MAGIC = b"DVZ2"
V2_VERSION = 0x02
V2_PURPOSE_CONTENT = 0x04
V2_SALT = b"dockvault-zk-envelope-v2-salt-01"
V2_INFO_CONTENT = b"dockvault-zk-content-v2"
V2_CONTENT_HEADER = 28
V2_CHUNK_OVERHEAD = 28          # 12-byte nonce + 16-byte tag
V2_CONTENT_MIN = V2_CONTENT_HEADER + V2_CHUNK_OVERHEAD
V2_CHUNK_MIN = 4096
V2_CHUNK_MAX = 8 * 1024 * 1024


def _v2_content_context(vault_id: str, object_id: str, dek_epoch: int) -> bytes:
    """Field order and widths are fixed per construction; separators are decoration, not
    delimiters -- injectivity comes from the fixed widths."""
    return (
        str(uuid.UUID(vault_id)).lower().encode("ascii") + b"\x00"
        + str(uuid.UUID(object_id)).lower().encode("ascii") + b"\x00"
        + struct.pack(">I", dek_epoch)
    )


def _v2_content_aad(file_header: bytes, context: bytes, index: int, is_final: bool,
                    total_chunks: int, total_plaintext: int) -> bytes:
    aad = file_header + context + struct.pack(">Q", index) + (b"\x01" if is_final else b"\x00")
    if is_final:
        aad += struct.pack(">Q", total_chunks) + struct.pack(">Q", total_plaintext)
    return aad


def encode_zk_content_v2(vector: dict[str, Any]) -> bytes:
    """Write the chunk-framed zero-knowledge content format (purpose 0x04).

    Independent of the browser implementation on purpose: a single-byte disagreement between the
    two is indistinguishable at runtime from a working system, so the only way to catch it is to
    build the bytes twice from the specification and compare.
    """
    inputs = vector["inputs"]
    dek = bytes.fromhex(inputs["dek_hex"])
    blob_id = bytes.fromhex(inputs["blob_id_hex"])
    if len(blob_id) != 16:
        raise ValueError("blob_id must be 16 raw bytes")
    chunk_size = int(inputs["chunk_size"])
    if not V2_CHUNK_MIN <= chunk_size <= V2_CHUNK_MAX:
        raise ValueError("chunk_size out of range")
    plaintext = b64d(inputs["plaintext_b64"])
    nonces = [bytes.fromhex(n) for n in inputs["nonces_hex"]]

    file_header = (
        V2_MAGIC + bytes([V2_VERSION, V2_PURPOSE_CONTENT, 0x00, 0x00])
        + struct.pack(">I", chunk_size) + blob_id
    )
    context = _v2_content_context(inputs["vault_id"], inputs["object_id"],
                                  int(inputs["dek_epoch"]))
    key = _hkdf(dek, salt=V2_SALT, info=V2_INFO_CONTENT + b"\x00" + context + b"\x00" + blob_id)

    total = len(plaintext)
    # max(1, ...) matters: an empty file is one chunk, and ceil(0/n) is zero. An exact multiple of
    # chunk_size gets no trailing empty chunk -- that is the one case a naive loop gets wrong, and
    # it produces a blob every conforming reader rejects.
    n = max(1, -(-total // chunk_size))
    if len(nonces) != n:
        raise ValueError(f"expected {n} nonces, got {len(nonces)}")

    out = bytearray(file_header)
    for i in range(n):
        part = plaintext[i * chunk_size:(i + 1) * chunk_size]
        aad = _v2_content_aad(file_header, context, i, i == n - 1, n, total)
        out += nonces[i] + AESGCM(key).encrypt(nonces[i], part, aad)
    return bytes(out)


def decode_zk_content_v2(encoded: bytes, *, dek_hex: str, vault_id: str, object_id: str,
                         dek_epoch: int) -> bytes:
    """Read it back, deriving the framing from the stored length alone."""
    if len(encoded) < V2_CONTENT_MIN:
        raise ValueError("too short to be chunk-framed content")
    if encoded[:4] != V2_MAGIC or encoded[4] != V2_VERSION or encoded[5] != V2_PURPOSE_CONTENT:
        raise ValueError("not a version-2 content header")
    if encoded[6] != 0 or encoded[7] != 0:
        raise ValueError("reserved bytes are not zero")
    chunk_size = struct.unpack(">I", encoded[8:12])[0]
    if not V2_CHUNK_MIN <= chunk_size <= V2_CHUNK_MAX:
        raise ValueError("chunk_size out of range")
    blob_id = encoded[12:28]
    file_header = encoded[:V2_CONTENT_HEADER]

    stored = len(encoded) - V2_CONTENT_HEADER
    span = chunk_size + V2_CHUNK_OVERHEAD
    n = max(1, -(-stored // span))
    last = stored - (n - 1) * span
    # The domain check. Between the valid lengths for n chunks and for n+1 sits a 28-byte gap that
    # no file can occupy, and without this the arithmetic answers confidently for those.
    if last < V2_CHUNK_OVERHEAD or last > span or (last == V2_CHUNK_OVERHEAD and n != 1):
        raise ValueError("length does not describe a valid chunk framing")
    total = (n - 1) * chunk_size + (last - V2_CHUNK_OVERHEAD)

    context = _v2_content_context(vault_id, object_id, dek_epoch)
    key = _hkdf(bytes.fromhex(dek_hex), salt=V2_SALT,
                info=V2_INFO_CONTENT + b"\x00" + context + b"\x00" + blob_id)

    out = bytearray()
    for i in range(n):
        start = V2_CONTENT_HEADER + i * span
        end = len(encoded) if i == n - 1 else start + span
        aad = _v2_content_aad(file_header, context, i, i == n - 1, n, total)
        out += AESGCM(key).decrypt(encoded[start:start + 12], encoded[start + 12:end], aad)
    if len(out) != total:
        raise ValueError("decrypted length does not match the framing")
    return bytes(out)


def encode_private_envelope(vector: dict[str, Any]) -> dict[str, Any]:
    inputs = vector["inputs"]
    salt = bytes.fromhex(inputs["salt_hex"])
    iv = bytes.fromhex(inputs["iv_hex"])
    iterations = int(inputs["iterations"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(inputs["password"].encode("utf-8"))
    plaintext = p384_private_pem(inputs["identity_private_scalar_hex"]).encode("utf-8")
    return {
        "encrypted": b64e(iv + AESGCM(key).encrypt(iv, plaintext, None)),
        "salt": b64e(salt),
        "iterations": iterations,
    }


PRIV_ENVELOPE_V1_LABEL = "dockvault-private-key-envelope-v1"
PRIV_ENVELOPE_V1_KDF = "PBKDF2-SHA256"
PRIV_ENVELOPE_V1_CIPHER = "AES-256-GCM"


def private_envelope_v1_aad(iterations: int, salt_b64: str) -> bytes:
    """The v1 authenticated transcript.

    Written independently of the browser implementation on purpose. The AAD is a byte-exactness
    surface: any drift between the two -- a stray delimiter, a differently rendered integer, salt
    bytes instead of the salt string -- would make affected envelopes permanently unreadable. Two
    implementations agreeing is the only thing that catches that.
    """
    return (
        f"{PRIV_ENVELOPE_V1_LABEL}|{PRIV_ENVELOPE_V1_KDF}|{iterations}|"
        f"{PRIV_ENVELOPE_V1_CIPHER}|{salt_b64}"
    ).encode("utf-8")


def encode_private_envelope_v1(vector: dict[str, Any]) -> dict[str, Any]:
    inputs = vector["inputs"]
    salt = bytes.fromhex(inputs["salt_hex"])
    iv = bytes.fromhex(inputs["iv_hex"])
    iterations = int(inputs["iterations"])
    salt_b64 = b64e(salt)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(inputs["password"].encode("utf-8"))
    plaintext = p384_private_pem(inputs["identity_private_scalar_hex"]).encode("utf-8")
    return {
        "v": 1,
        "kdf": PRIV_ENVELOPE_V1_KDF,
        "iter": iterations,
        "cipher": PRIV_ENVELOPE_V1_CIPHER,
        "salt": salt_b64,
        "iv": b64e(iv),
        "ct": b64e(
            AESGCM(key).encrypt(iv, plaintext, private_envelope_v1_aad(iterations, salt_b64))
        ),
    }


def decode_private_envelope_v1(envelope: dict[str, Any], *, password: str) -> str:
    salt_b64 = envelope["salt"]
    iterations = int(envelope["iter"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=b64d(salt_b64), iterations=iterations
    ).derive(password.encode("utf-8"))
    return (
        AESGCM(key)
        .decrypt(
            b64d(envelope["iv"]),
            b64d(envelope["ct"]),
            private_envelope_v1_aad(iterations, salt_b64),
        )
        .decode("utf-8")
    )


def decode_private_envelope(envelope: dict[str, Any], *, password: str) -> str:
    salt = b64d(envelope["salt"])
    iterations = int(envelope["iterations"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(password.encode("utf-8"))
    encoded = b64d(envelope["encrypted"])
    return AESGCM(key).decrypt(encoded[:12], encoded[12:], None).decode("utf-8")


def _ecdh(private_scalar_hex: str, peer_scalar_hex: str) -> bytes:
    return _p384_private(private_scalar_hex).exchange(
        ec.ECDH(), _p384_private(peer_scalar_hex).public_key()
    )


V2_PURPOSE_DIRECT_DEK = 0x01
V2_INFO_DEK_DIRECT = b"dockvault-zk-dek-direct-v2"
V2_DIRECT_WRAP_BYTES = 68           # 8 header + 12 nonce + 32 ciphertext + 16 tag
V2_EPOCH_MIN = 1
V2_EPOCH_MAX = 0x7FFFFFFF

# The browser validates a UUID with this exact pattern and then emits the matched text verbatim.
# Deliberately NOT uuid.UUID(): that accepts braces, a urn: prefix and an unhyphenated run of 32
# hex digits, and normalises all of them -- so a vector encoded through it could carry a value the
# browser refuses, and the two runtimes would disagree about what is even encodable.
_V2_UUID_TEXT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _v2_uuid_text(value: str) -> bytes:
    """A UUID as the 36 lowercase hyphenated ASCII bytes the v2 wrap grammar binds.

    Note this is the OPPOSITE convention to the Standard-vault chunk grammar in the same product,
    which binds the raw 16 bytes. Encoding one as the other still round-trips against itself, which
    is exactly why it has to be pinned by a stored vector rather than by a round-trip test.
    """
    text = str(value).lower()
    if not _V2_UUID_TEXT.match(text):
        raise ValueError("v2 grammar needs a 36-character lowercase hyphenated uuid")
    return text.encode("ascii")


def _v2_epoch(value: int) -> bytes:
    epoch = int(value)
    if not V2_EPOCH_MIN <= epoch <= V2_EPOCH_MAX:
        raise ValueError("dek epoch out of range for the v2 grammar")
    return struct.pack(">I", epoch)


def _v2_header(purpose: int) -> bytes:
    """Magic, version, purpose, and two reserved bytes that MUST be zero.

    Reserved is a breaking-change channel rather than an extension channel: a reader treats a
    non-zero value as malformed, not as something newer it could skip.
    """
    return V2_MAGIC + bytes([V2_VERSION, purpose, 0x00, 0x00])


def _v2_direct_context(vault_id: str, recipient_user_id: str, dek_epoch: int) -> bytes:
    return (
        _v2_uuid_text(vault_id) + b"\x00"
        + _v2_uuid_text(recipient_user_id) + b"\x00"
        + _v2_epoch(dek_epoch)
    )


def encode_direct_dek_wrap_v2(vector: dict[str, Any]) -> dict[str, str]:
    """Write the version-2 direct recipient DEK wrap (purpose 0x01), independently.

    Written from the specification rather than from the browser's code, because the point of the
    exercise is that two implementations agree. The browser derives and verifies through a single
    transcript builder shared by its writer and its reader, so any self-consistent change to the
    grammar -- reordering the context, dropping the separators, encoding the uuids as raw bytes,
    widening the epoch, renaming the info label -- round-trips perfectly there and is invisible.
    This encoder is the second opinion that makes those visible.
    """
    inputs = vector["inputs"]
    header = _v2_header(V2_PURPOSE_DIRECT_DEK)
    context = _v2_direct_context(
        inputs["vault_id"], inputs["recipient_user_id"], inputs["dek_epoch"]
    )
    shared = _ecdh(
        inputs["ephemeral_private_scalar_hex"], inputs["recipient_private_scalar_hex"]
    )
    wrapping_key = _hkdf(
        shared, salt=V2_SALT, info=V2_INFO_DEK_DIRECT + b"\x00" + context
    )
    nonce = bytes.fromhex(inputs["nonce_hex"])
    if len(nonce) != 12:
        raise ValueError("the v2 wrap nonce is 12 bytes")
    dek = bytes.fromhex(inputs["dek_hex"])
    if len(dek) != 32:
        raise ValueError("the wrapped key is a 32-byte DEK")

    body = AESGCM(wrapping_key).encrypt(nonce, dek, header + context)
    wrapped = header + nonce + body
    if len(wrapped) != V2_DIRECT_WRAP_BYTES:
        raise ValueError("a v2 direct wrap is exactly 68 bytes")
    return {
        "wrapped_dek_b64": b64e(wrapped),
        "ephemeral_public_key_b64": b64e(
            p384_public_raw(inputs["ephemeral_private_scalar_hex"])
        ),
    }


def encode_hostile_direct_dek_wrap_v2(vector: dict[str, Any], plaintext: bytes) -> dict[str, str]:
    """A well-formed v2 direct wrap carrying something other than a 32-byte DEK.

    Deliberately separate from the real encoder, which refuses this -- as it should, and as the
    browser does. A reader's guards cannot be tested by a writer that will not break the rules, so
    the rule-breaking lives here, named for what it is, rather than being hand-assembled in a
    throwaway script that nothing keeps in step with the format.
    """
    inputs = vector["inputs"]
    header = _v2_header(V2_PURPOSE_DIRECT_DEK)
    context = _v2_direct_context(
        inputs["vault_id"], inputs["recipient_user_id"], inputs["dek_epoch"]
    )
    shared = _ecdh(
        inputs["ephemeral_private_scalar_hex"], inputs["recipient_private_scalar_hex"]
    )
    wrapping_key = _hkdf(
        shared, salt=V2_SALT, info=V2_INFO_DEK_DIRECT + b"\x00" + context
    )
    nonce = bytes.fromhex(inputs["nonce_hex"])
    body = AESGCM(wrapping_key).encrypt(nonce, plaintext, header + context)
    return {
        "wrapped_dek_b64": b64e(header + nonce + body),
        "ephemeral_public_key_b64": b64e(
            p384_public_raw(inputs["ephemeral_private_scalar_hex"])
        ),
    }


def decode_direct_dek_wrap_v2(
    wrapped_dek_b64: str,
    *,
    ephemeral_public_key_b64: str,
    recipient_private_scalar_hex: str,
    vault_id: str,
    recipient_user_id: str,
    dek_epoch: int,
) -> bytes:
    """Read a version-2 direct wrap, refusing everything the grammar says to refuse.

    The context is a required argument rather than something recovered from the payload: none of it
    is carried on the wire. That is the point of the construction -- a wrap that is moved to
    another vault, another recipient or another epoch does not decode, because the caller's own
    idea of where it is decrypts it or nothing does.
    """
    wrapped = b64d(wrapped_dek_b64)
    if len(wrapped) != V2_DIRECT_WRAP_BYTES:
        raise ValueError("not a v2 direct wrap: wrong length")
    if wrapped[0:4] != V2_MAGIC:
        raise ValueError("not a v2 direct wrap: bad magic")
    if wrapped[4] != V2_VERSION:
        raise ValueError("unsupported v2 version")
    if wrapped[5] != V2_PURPOSE_DIRECT_DEK:
        raise ValueError("this payload is not a direct DEK wrap")
    if wrapped[6:8] != b"\x00\x00":
        raise ValueError("reserved bytes must be zero")

    point = b64d(ephemeral_public_key_b64)
    if len(point) != 97 or point[0] != 0x04:
        raise ValueError("the ephemeral public key is an uncompressed P-384 point")
    # from_encoded_point rejects a point that is not on the curve, which is the check that stops a
    # crafted point from steering the shared secret.
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), point)

    header = _v2_header(V2_PURPOSE_DIRECT_DEK)
    context = _v2_direct_context(vault_id, recipient_user_id, dek_epoch)
    shared = _p384_private(recipient_private_scalar_hex).exchange(ec.ECDH(), peer)
    wrapping_key = _hkdf(
        shared, salt=V2_SALT, info=V2_INFO_DEK_DIRECT + b"\x00" + context
    )
    dek = AESGCM(wrapping_key).decrypt(wrapped[8:20], wrapped[20:], header + context)
    if len(dek) != 32:
        raise ValueError("a direct wrap carries exactly a 32-byte DEK")
    return dek


def encode_direct_dek_wrap(vector: dict[str, Any]) -> dict[str, str]:
    inputs = vector["inputs"]
    shared = _ecdh(
        inputs["ephemeral_private_scalar_hex"], inputs["recipient_private_scalar_hex"]
    )
    wrapping_key = _hkdf(shared, salt=b"", info=DIRECT_WRAP_INFO)
    return {
        "wrapped_dek_b64": b64e(
            aes_key_wrap(wrapping_key, bytes.fromhex(inputs["dek_hex"]))
        ),
        "ephemeral_public_key_b64": b64e(
            p384_public_raw(inputs["ephemeral_private_scalar_hex"])
        ),
    }


def decode_direct_dek_wrap(
    wrapped_dek_b64: str,
    *,
    ephemeral_public_key_b64: str,
    recipient_private_scalar_hex: str,
) -> bytes:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(), b64d(ephemeral_public_key_b64)
    )
    shared = _p384_private(recipient_private_scalar_hex).exchange(ec.ECDH(), peer)
    wrapping_key = _hkdf(shared, salt=b"", info=DIRECT_WRAP_INFO)
    return aes_key_unwrap(wrapping_key, b64d(wrapped_dek_b64))


def encode_team_private_wrap(vector: dict[str, Any]) -> dict[str, str]:
    inputs = vector["inputs"]
    shared = _ecdh(
        inputs["ephemeral_private_scalar_hex"], inputs["member_private_scalar_hex"]
    )
    wrapping_key = _hkdf(shared, salt=b"", info=TEAM_PRIVATE_WRAP_INFO)
    iv = bytes.fromhex(inputs["iv_hex"])
    wrapped = iv + AESGCM(wrapping_key).encrypt(
        iv, p384_private_der(inputs["team_private_scalar_hex"]), None
    )
    return {
        "wrapped_key_b64": b64e(wrapped),
        "ephemeral_public_key_b64": b64e(
            p384_public_raw(inputs["ephemeral_private_scalar_hex"])
        ),
    }


def decode_team_private_wrap(
    wrapped_key_b64: str,
    *,
    ephemeral_public_key_b64: str,
    member_private_scalar_hex: str,
) -> ec.EllipticCurvePrivateKey:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(), b64d(ephemeral_public_key_b64)
    )
    shared = _p384_private(member_private_scalar_hex).exchange(ec.ECDH(), peer)
    wrapping_key = _hkdf(shared, salt=b"", info=TEAM_PRIVATE_WRAP_INFO)
    encoded = b64d(wrapped_key_b64)
    der = AESGCM(wrapping_key).decrypt(encoded[:12], encoded[12:], None)
    private_key = serialization.load_der_private_key(der, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("wrapped team key is not an EC private key")
    return private_key


def _zk_name_aad(
    version: str, vault_id: str, field: str, epoch: int, object_id: str | None
) -> bytes:
    if version == "zk1":
        return f"dv-zk-name-v1|{vault_id}|{field}|{epoch}".encode("utf-8")
    if version == "zk2" and object_id:
        return f"dv-zk-name-v2|{vault_id}|{field}|{epoch}|{object_id}".encode("utf-8")
    raise ValueError("zk2 names require an object id")


def encode_zk_name(vector: dict[str, Any]) -> dict[str, str]:
    inputs = vector["inputs"]
    version = inputs["version"]
    dek = bytes.fromhex(inputs["dek_hex"])
    iv = bytes.fromhex(inputs["iv_hex"])
    aad = _zk_name_aad(
        version,
        inputs["vault_id"],
        inputs["field"],
        int(inputs["epoch"]),
        inputs.get("object_id"),
    )
    raw = iv + AESGCM(dek).encrypt(iv, inputs["plaintext"].encode("utf-8"), aad)
    blind_key = _hkdf(
        dek,
        salt=ZK_NAME_BLIND_SALT,
        info=f"{inputs['vault_id']}|{inputs['epoch']}".encode("utf-8"),
    )
    blind_index = hmac.new(
        blind_key, inputs["plaintext"].encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {"token": f"{version}:{b64e(raw)}", "blind_index": blind_index}


def decode_zk_name(
    token: str,
    *,
    dek_hex: str,
    vault_id: str,
    field: str,
    epoch: int,
    object_id: str | None = None,
) -> str:
    if token.startswith("zk2:"):
        version, encoded = "zk2", token[4:]
    elif token.startswith("zk1:"):
        version, encoded = "zk1", token[4:]
    else:
        version, encoded = "zk1", token
    raw = b64d(encoded)
    if len(raw) < 28:
        raise ValueError("truncated zero-knowledge name")
    aad = _zk_name_aad(version, vault_id, field, int(epoch), object_id)
    return (
        AESGCM(bytes.fromhex(dek_hex)).decrypt(raw[:12], raw[12:], aad).decode("utf-8")
    )
