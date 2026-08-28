"""Seal chunked-upload staging files at rest.

Resumable HTTP uploads land each chunk in a per-session directory on the persistent storage
volume, where they used to sit as plaintext until ``/complete`` streamed them through the vault's
at-rest pipeline. This seals each staged chunk file as it is written and decrypts it back on
assembly, so a raw chunk is never readable on disk while a session is in flight.

Sealed on-disk layout of one staged chunk file::

    [MAGIC(8)][plaintext_len(8, big-endian)][record]*

where each record is ``[4-byte BE len of (nonce+ct)][12-byte nonce][ciphertext+16-byte tag]``,
encrypted under a per-session key with AAD binding (session, chunk index, record index) -- the same
framing shape as the app's ``GcmChunkStreamCodec``. The plaintext length is written at a fixed
offset once the whole chunk has streamed in (a placeholder is reserved up front and back-filled on
clean close), so the byte accounting can read a chunk's plaintext size without decrypting it.

Both the write and the read stay memory-bounded: the body is sealed one 1 MiB record at a time as
it streams, and assembly yields it back one record at a time. A 64 MiB chunk is never held whole.

Read-old: a chunk file that does NOT start with MAGIC is a legacy plaintext chunk -- staged by a
release before this change and still mid-flight across the upgrade. Its plaintext size is its
on-disk size and it is streamed through verbatim, so an upload interrupted by the upgrade still
completes. Nothing here is forward-only: the sealed bytes never leave the staging directory, and a
session either completes (assembled into the real at-rest blob) or is swept.

The key is derived deterministically from the deployment ENCRYPTION_KEY and the session id, so a
chunk written before a restart is still readable after -- the staging directory outlives the
process.
"""
from __future__ import annotations

import hashlib
import secrets
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MAGIC = b'DVUPLD1\x00'                 # 8 bytes; the '1' is the format version
_LEN_FIELD = 8                          # big-endian plaintext byte count
_HEADER_LEN = len(_MAGIC) + _LEN_FIELD  # 16
_NONCE = 12
_TAG = 16
_REC_LEN_PREFIX = 4
_FLUSH = 1024 * 1024                    # one record per MiB of plaintext -> bounded memory + record size
# A record's framed length is nonce + ciphertext(=plaintext+tag). Bound it so a corrupt length field
# cannot drive a huge read. The writer never exceeds _FLUSH plaintext per record.
_REC_MAX = _NONCE + _FLUSH + _TAG + 1024


class StagedChunkError(Exception):
    """A sealed staged chunk could not be read back (tamper, truncation, wrong session/index)."""


def _stage_key(session_id) -> bytes:
    from app.core.security import _runtime_settings, _uuid_bytes
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-upload-stage-v1', info=_uuid_bytes(session_id),
    ).derive(_runtime_settings().encryption_key.encode())


def _rec_aad(session_id, chunk_index: int, record_index: int) -> bytes:
    from app.core.security import _uuid_bytes
    # struct '>QQ' (not '>II') so neither index can silently wrap; both are tiny in practice.
    return (b'dockvault-upload-stage:' + _uuid_bytes(session_id)
            + struct.pack('>QQ', chunk_index, record_index))


def is_sealed_chunk(path: Path) -> bool:
    """Cheap, non-decrypting peek: True iff the file begins with the staged-chunk MAGIC."""
    try:
        with open(path, 'rb') as f:
            return f.read(len(_MAGIC)) == _MAGIC
    except OSError:
        return False


def sealed_plaintext_size(path: Path) -> int:
    """Plaintext byte count of a staged chunk WITHOUT decrypting it.

    A sealed chunk carries the count in its header; a legacy plaintext chunk (no MAGIC) has
    plaintext == on-disk size. Best effort: an unreadable file counts as 0 (safe-low for the
    transient-disk bound, mirroring the old ``stat`` path which also swallowed OSError).
    """
    try:
        with open(path, 'rb') as f:
            head = f.read(_HEADER_LEN)
    except OSError:
        return 0
    if len(head) == _HEADER_LEN and head[:len(_MAGIC)] == _MAGIC:
        return struct.unpack('>Q', head[len(_MAGIC):_HEADER_LEN])[0]
    try:
        return path.stat().st_size
    except OSError:
        return 0


async def seal_stream_to_file(stream, dest_path: Path, limit: int, session_id, chunk_index: int):
    """Stream an incoming body into ``dest_path``, sealed. Returns ``(plaintext_bytes, sha256_hex)``.

    Mirrors ``receive_bounded``'s contract exactly so the caller's error handling is unchanged:
    refuses to exceed ``limit`` PLAINTEXT bytes (raises ``ChunkTooLarge``), refuses an empty body
    (raises ``EmptyBody``), and removes the partial file on ANY failure. The digest is over the
    PLAINTEXT -- what a resuming client re-hashes -- taken in passing so the body is never held.
    """
    from app.services.streaming_upload import ChunkTooLarge, EmptyBody

    aesgcm = AESGCM(_stage_key(session_id))
    digest = hashlib.sha256()
    plaintext_total = 0
    state = {'record_index': 0}
    buf = bytearray()

    def _emit(handle, block: bytes):
        nonce = secrets.token_bytes(_NONCE)
        ct = aesgcm.encrypt(nonce, block, _rec_aad(session_id, chunk_index, state['record_index']))
        handle.write(struct.pack('>I', _NONCE + len(ct)) + nonce + ct)
        state['record_index'] += 1

    try:
        with open(dest_path, 'wb') as handle:
            handle.write(_MAGIC + b'\x00' * _LEN_FIELD)     # placeholder length, back-filled on clean close
            async for piece in stream:
                if not piece:
                    continue
                plaintext_total += len(piece)
                if plaintext_total > limit:
                    raise ChunkTooLarge(limit)
                digest.update(piece)
                buf.extend(piece)
                while len(buf) >= _FLUSH:
                    _emit(handle, bytes(buf[:_FLUSH]))
                    del buf[:_FLUSH]
            if buf:
                _emit(handle, bytes(buf))
            if not plaintext_total:
                raise EmptyBody()
            # Back-fill the true plaintext length at its fixed offset, now that it is known.
            handle.flush()
            handle.seek(len(_MAGIC))
            handle.write(struct.pack('>Q', plaintext_total))
    except BaseException:
        # Mirror receive_bounded: nothing else reclaims an individual temp file mid-session.
        try:
            dest_path.unlink()
        except OSError:
            pass
        raise
    return plaintext_total, digest.hexdigest()


def open_staged_chunk(path: Path, session_id, chunk_index: int):
    """Yield the plaintext of a staged chunk in order, one block at a time (memory-bounded).

    Decrypts a sealed chunk; streams a legacy plaintext chunk (no MAGIC) verbatim so an upload that
    straddled the upgrade still assembles. Raises ``StagedChunkError`` on tamper/truncation of a
    sealed chunk.
    """
    with open(path, 'rb') as f:
        head = f.read(_HEADER_LEN)
        if not (len(head) == _HEADER_LEN and head[:len(_MAGIC)] == _MAGIC):
            # Legacy plaintext chunk (or pre-upgrade in-flight): `head` is real content -- yield it,
            # then the rest of the file.
            if head:
                yield head
            while True:
                block = f.read(_FLUSH)
                if not block:
                    break
                yield block
            return
        aesgcm = AESGCM(_stage_key(session_id))
        record_index = 0
        while True:
            len_prefix = f.read(_REC_LEN_PREFIX)
            if not len_prefix:
                break                                       # clean end of records
            if len(len_prefix) != _REC_LEN_PREFIX:
                raise StagedChunkError("truncated record length prefix")
            rec_len = struct.unpack('>I', len_prefix)[0]
            if rec_len < _NONCE + _TAG or rec_len > _REC_MAX:
                raise StagedChunkError("implausible record length")
            rec = f.read(rec_len)
            if len(rec) != rec_len:
                raise StagedChunkError("truncated record")
            nonce, ct = rec[:_NONCE], rec[_NONCE:]
            try:
                pt = aesgcm.decrypt(nonce, ct, _rec_aad(session_id, chunk_index, record_index))
            except Exception as exc:                        # noqa: BLE001 - any AEAD failure is fatal here
                raise StagedChunkError("staged chunk record authentication failed") from exc
            record_index += 1
            yield pt
