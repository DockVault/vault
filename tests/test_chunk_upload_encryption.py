"""Resumable-upload staging chunks are sealed at rest and unseal back to the exact plaintext.

The resumable HTTP upload path writes each chunk to a per-session directory on the persistent
storage volume, then /complete streams them through the at-rest pipeline. These chunk files used to
be plaintext on disk for the life of the session. Now each is AES-GCM sealed as it streams in and
decrypted on assembly.

Pure crypto + filesystem -- no DB, no running vault -- so it runs in the offline lane. It exercises
the real module (`app.core.upload_chunk_crypto`) end to end: seal -> on-disk is ciphertext -> the
byte accounting reads the plaintext size without decrypting -> assembly yields the exact bytes back,
including a straddle assembled through the real final-file codec.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import secrets
import struct
import uuid

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module", autouse=True)
def _runtime_secrets():
    """A throwaway ENCRYPTION_KEY so the at-rest key derivation works; restored on teardown."""
    previous = {k: os.environ.get(k) for k in ("ENCRYPTION_KEY", "DATABASE_URL", "JWT_SECRET_KEY")}
    os.environ.setdefault("ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost/db")
    os.environ.setdefault("JWT_SECRET_KEY", secrets.token_hex(32))
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        from app.core import config as _config
        _config._runtime_initialized = False
    except Exception:                     # noqa: BLE001 - teardown must never fail the suite
        pass


def _crypto_ok():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


async def _stream(*pieces):
    for p in pieces:
        yield p


def _seal(dest, body_pieces, session_id, chunk_index, limit=None):
    from app.core.upload_chunk_crypto import seal_stream_to_file
    body = b"".join(body_pieces)
    lim = len(body) if limit is None else limit
    return asyncio.run(
        seal_stream_to_file(_stream(*body_pieces), dest, lim, session_id, chunk_index))


def _assemble(path, session_id, chunk_index):
    from app.core.upload_chunk_crypto import open_staged_chunk
    return b"".join(open_staged_chunk(path, session_id, chunk_index))


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_a_chunk_is_ciphertext_on_disk_and_round_trips(tmp_path):
    from app.core.upload_chunk_crypto import sealed_plaintext_size, is_sealed_chunk
    sid = uuid.uuid4()
    plaintext = b"a marker string SECRET-PAYLOAD-42 and more bytes " * 40
    dest = tmp_path / "chunk_000000"
    written, digest = _seal(dest, [plaintext], sid, 0)

    assert written == len(plaintext)
    assert digest == hashlib.sha256(plaintext).hexdigest(), "digest is over the PLAINTEXT (resume)"
    raw = dest.read_bytes()
    assert is_sealed_chunk(dest) and raw.startswith(b"DVUPLD1\x00"), "sealed header present"
    assert b"SECRET-PAYLOAD-42" not in raw, "plaintext is not readable on disk"
    assert sealed_plaintext_size(dest) == len(plaintext), "plaintext size read WITHOUT decrypting"
    assert _assemble(dest, sid, 0) == plaintext, "unseals to the exact original bytes"


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_a_multi_record_chunk_spanning_flush_boundaries_round_trips(tmp_path):
    # > 1 MiB so the writer emits several records, and delivered in odd-sized pieces so a record
    # boundary lands mid-piece.
    sid = uuid.uuid4()
    pieces = [secrets.token_bytes(700_003) for _ in range(5)]     # ~3.3 MiB across ragged pieces
    body = b"".join(pieces)
    dest = tmp_path / "chunk_000001"
    written, digest = _seal(dest, pieces, sid, 1)
    assert written == len(body)
    assert digest == hashlib.sha256(body).hexdigest()
    assert _assemble(dest, sid, 1) == body


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_accounting_sums_plaintext_not_ciphertext(tmp_path):
    """The whole reason the accounting reads a header field: a sealed chunk is LARGER on disk than
    its plaintext, but `bytes_received` must stay in plaintext units to match `total_size`."""
    from app.core.upload_chunk_crypto import sealed_plaintext_size
    sid = uuid.uuid4()
    sizes = [1_500_000, 250_000, 42]
    total_plain = 0
    for i, n in enumerate(sizes):
        dest = tmp_path / f"chunk_{i:06d}"
        body = secrets.token_bytes(n)
        _seal(dest, [body], sid, i)
        assert dest.stat().st_size > n, "on-disk ciphertext is larger than the plaintext"
        assert sealed_plaintext_size(dest) == n
        total_plain += n
    summed = sum(sealed_plaintext_size(p) for p in sorted(tmp_path.glob("chunk_*")))
    assert summed == total_plain == sum(sizes)


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_tamper_and_wrong_context_are_rejected(tmp_path):
    from app.core.upload_chunk_crypto import open_staged_chunk, StagedChunkError
    sid = uuid.uuid4()
    body = secrets.token_bytes(5000)
    dest = tmp_path / "chunk_000000"
    _seal(dest, [body], sid, 0)

    # Flip a byte inside the first record's ciphertext (past the 16-byte header + 4-byte len + nonce).
    raw = bytearray(dest.read_bytes())
    pos = 16 + 4 + 12 + 3
    raw[pos] ^= 0x01
    tampered = tmp_path / "chunk_tampered"
    tampered.write_bytes(bytes(raw))
    with pytest.raises(StagedChunkError):
        list(open_staged_chunk(tampered, sid, 0))

    # Right bytes, wrong session id -> AAD/key mismatch.
    with pytest.raises(StagedChunkError):
        list(open_staged_chunk(dest, uuid.uuid4(), 0))
    # Right bytes, wrong chunk index -> AAD mismatch (splice one chunk in for another).
    with pytest.raises(StagedChunkError):
        list(open_staged_chunk(dest, sid, 7))


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_a_truncated_sealed_chunk_is_rejected(tmp_path):
    from app.core.upload_chunk_crypto import open_staged_chunk, StagedChunkError
    sid = uuid.uuid4()
    dest = tmp_path / "chunk_000000"
    _seal(dest, [secrets.token_bytes(300_000)], sid, 0)
    raw = dest.read_bytes()
    cut = tmp_path / "chunk_cut"
    cut.write_bytes(raw[:len(raw) - 50])          # drop the tail of the last record
    with pytest.raises(StagedChunkError):
        list(open_staged_chunk(cut, sid, 0))


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_legacy_plaintext_chunk_reads_through_verbatim(tmp_path):
    """Read-old: a session that staged plaintext chunks under a pre-upgrade release must still
    assemble after the upgrade. Such a chunk has no MAGIC -> streamed through unchanged, and its
    plaintext size is its on-disk size."""
    from app.core.upload_chunk_crypto import (
        open_staged_chunk, sealed_plaintext_size, is_sealed_chunk)
    sid = uuid.uuid4()
    legacy = tmp_path / "chunk_000000"
    body = b"legacy plaintext chunk staged before the upgrade " * 5000   # > 1 MiB, multi-block read
    legacy.write_bytes(body)
    assert not is_sealed_chunk(legacy)
    assert sealed_plaintext_size(legacy) == len(body)
    assert _assemble(legacy, sid, 0) == body

    # A short legacy chunk (fewer bytes than the 16-byte header) still reads through whole.
    short = tmp_path / "chunk_000001"
    short.write_bytes(b"hi")
    assert _assemble(short, sid, 1) == b"hi"


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_oversized_body_is_refused_and_leaves_no_file(tmp_path):
    from app.services.streaming_upload import ChunkTooLarge, EmptyBody
    sid = uuid.uuid4()
    dest = tmp_path / "chunk_000000"
    with pytest.raises(ChunkTooLarge):
        _seal(dest, [b"x" * 100], sid, 0, limit=10)
    assert not dest.exists(), "the partial sealed file is removed on refusal"

    with pytest.raises(EmptyBody):
        _seal(dest, [b""], sid, 0, limit=100)
    assert not dest.exists(), "an empty body leaves no file"


@pytest.mark.skipif(not _crypto_ok(), reason="cryptography not available")
def test_assembly_through_the_real_at_rest_codec(tmp_path):
    """The end the endpoint actually runs: feed the unsealed staging chunks into the real
    Standard-vault streaming codec and confirm the final blob decrypts to the original file."""
    from app.core.upload_chunk_crypto import open_staged_chunk
    from app.services.streaming_upload import StreamingUploadContext
    from app.core.security import (
        GcmChunkStreamCodec, decrypt_gcm_chunk_stream, is_gcm_chunk_stream)

    sid = uuid.uuid4()
    vault_id = uuid.uuid4()
    file_id = uuid.uuid4()
    # Three staged chunks -> the whole file.
    parts = [secrets.token_bytes(1_400_000), secrets.token_bytes(1_400_000), secrets.token_bytes(99)]
    original = b"".join(parts)
    for i, p in enumerate(parts):
        _seal(tmp_path / f"chunk_{i:06d}", [p], sid, i)

    blob = tmp_path / "final.blob"
    ctx = StreamingUploadContext(file_id, blob, GcmChunkStreamCodec(vault_id, file_id))
    with ctx:
        for i in range(len(parts)):
            for buf in open_staged_chunk(tmp_path / f"chunk_{i:06d}", sid, i):
                if buf:
                    ctx.write_chunk(buf)
        assert ctx.get_total_size() == len(original)
        assert ctx.get_checksum() == hashlib.sha256(original).hexdigest()

    assert is_gcm_chunk_stream(blob)
    with open(blob, "rb") as fh:
        recovered = decrypt_gcm_chunk_stream(fh, vault_id, file_id)
    assert recovered == original, "the whole pipeline (seal -> unseal -> at-rest codec) round-trips"
