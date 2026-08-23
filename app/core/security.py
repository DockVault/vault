"""
Security utilities for password hashing, encryption, and credential generation.
Implements industry-standard security practices.
"""
import bisect
import os
import secrets
import hashlib
import hmac
import base64
import struct
from array import array
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import jwt  # PyJWT (maintained); HS256-only. jwt.encode/decode signatures match the prior jose usage.

from app.core.config import initialize_runtime, runtime_is_initialized, settings


# Argon2 password hasher (winner of Password Hashing Competition)
password_hasher = PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # Memory usage in KiB (64 MB)
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of hash in bytes
    salt_len=16  # Length of salt in bytes
)

def _runtime_settings():
    """Resolve validated settings when a helper operation is first requested."""
    if not runtime_is_initialized():
        initialize_runtime(interactive=False)
    return settings


def _fernet():
    """Resolve file encryption only when a cryptographic operation is requested."""
    return Fernet(_runtime_settings().encryption_key.encode())


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a short reversible secret (e.g. a stored SMTP password) at rest with the deployment
    Fernet key. Returns a Fernet token string. Empty/None -> "" (nothing to encrypt)."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(stored: str) -> str:
    """Decrypt a value written by encrypt_secret. Back-compat: a value that is not a valid Fernet
    token (a LEGACY plaintext credential written before at-rest encryption) is returned unchanged, so
    existing profiles keep working and are transparently re-encrypted the next time they are saved."""
    if not stored:
        return ""
    try:
        return _fernet().decrypt(stored.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return stored  # legacy plaintext (pre-encryption) — used as-is until re-saved

# --- AES-256-GCM chunked at-rest stream (format version 0x10) ---------------
# The legacy at-rest format is a global-key Fernet chunk stream (encrypt_chunk /
# decrypt_chunk_stream). Fernet has no AAD, so a stored blob is not bound to the
# vault/file it belongs to — an operator with disk access could swap one file's blob
# for another's. This new format uses AES-256-GCM with a per-chunk AAD = domain ||
# vault_id || file_id || chunk_index, binding every chunk to its vault+file (no
# cross-file/vault swap) and its position (no reorder). Whole-file truncation/tamper is
# independently caught by the stored plaintext SHA-256 that download_file verifies, so
# the chunk stream itself does not need a length/EOF marker.
#
# Keying: a deployment ROOT key is derived from settings.encryption_key (same secret
# lifecycle as the Fernet stream), and each FILE gets its own subkey via
# HKDF(root, info=vault_id||file_id). Per-file subkeys keep the AES-GCM random-nonce
# collision budget per-file (~2^32 chunks) instead of deployment-wide, and add a
# key-level vault+file binding on top of the AAD.
#
# Backward compatibility: NEW Standard-vault writes use this format; OLD Fernet-stream
# files keep being read by decrypt_chunk_stream (detected by the absence of the magic
# header). Zero-knowledge vaults are unaffected (their blobs are stored verbatim);
# their swap-resistance is the client's own AEAD + the server-stored checksum, not this
# AAD (the server holds no key for a ZK vault).
def _gcm_stream_root_key():
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'dockvault-gcm-chunk-stream-key-v1',
        info=b'at-rest-content',
    ).derive(_runtime_settings().encryption_key.encode())

# Detected by comparing the FULL magic (all of GCM_STREAM_MAGIC), not a fixed-length prefix.
GCM_STREAM_MAGIC = b'DockVault'
GCM_STREAM_VERSION = 0x10  # stream-format version byte
_GCM_STREAM_HEADER = GCM_STREAM_MAGIC + bytes([GCM_STREAM_VERSION]) + b'\x00\x00'  # +2 reserved
_GCM_NONCE_SIZE = 12
_CHUNK_AAD_DOMAIN = b'dockvault-chunk-aad-v1'

# --- Format version 0x20: the same records, plus a terminal that makes truncation
# --- detectable ------------------------------------------------------------------
# 0x10 authenticates every record against its vault, file and position, so a record cannot be
# swapped or reordered. What it cannot see is a record that is simply NOT THERE: a file cut short
# decrypts perfectly up to the cut, and the only thing that noticed was the stored plaintext
# checksum -- a bare hash in a column, which is not an integrity mechanism against anyone who can
# write that column.
#
# 0x20 ends the stream with an authenticated terminal record binding the record count and the
# total plaintext length, and requires the file to end there. A truncated file now fails to
# produce a terminal, and a terminal cannot be lifted from a shorter file because it authenticates
# a different count and length.
#
# Version 0x20 rather than 0x11: a test constructs its "unknown version" probe as
# STANDARD_VERSION + 1, and a gap reads as a new generation rather than an increment.
GCM_STREAM_VERSION_V2 = 0x20
_GCM_STREAM_HEADER_V2_PREFIX = GCM_STREAM_MAGIC + bytes([GCM_STREAM_VERSION_V2]) + b'\x00\x00'
# 16 random bytes naming ONE write of an object, stored in the header and bound into every
# record's associated data.
#
# Without it a terminal authenticates only (vault, file, count, length), and any two writes of the
# same object that happen to have the same shape produce interchangeable terminals. An actor with
# disk access who kept an earlier write's terminal could then cut the current object down to a
# matching record count, reattach that terminal, and the result would authenticate as a complete
# file. The object id alone cannot separate the two writes: it is deliberately stable across a
# resumed upload, because the name is sealed against it.
#
# The same reasoning, and the same 16 bytes, already appear in the zero-knowledge content format.
_WRITE_ID_SIZE = 16
_GCM_STREAM_HEADER_V2_SIZE = len(_GCM_STREAM_HEADER_V2_PREFIX) + _WRITE_ID_SIZE
_CHUNK_AAD_DOMAIN_V2 = b'dockvault-chunk-aad-v2'
_TERMINAL_AAD_DOMAIN_V2 = b'dockvault-terminal-aad-v2'
# The marker in a record's length field that says "this is the terminal". The invariant below is
# part of the grammar, not an arithmetic coincidence of today's numbers: if a legal data record
# could ever be this long, a reader could not tell the two apart.
_TERMINAL_MARKER = 0xFFFFFFFF

# Absolute format constants, deliberately NOT configuration. An earlier draft derived the ceiling
# from the deployment's maximum file size; that is a data-loss bug, because the setting is mutable
# downward at runtime and nothing rewrites blobs, so lowering it would make every larger existing
# object permanently unreadable. A reader's willingness to parse must not depend on a value that
# can change under it.
MAX_CHUNK_SIZE = 8 * 1024 * 1024                       # above the largest writer chunk (5 MiB)
MAX_RECORD_BYTES = MAX_CHUNK_SIZE + _GCM_NONCE_SIZE + 16
# 0x20 requires at least one plaintext byte per data record (5.2), so 29. 0x10 does NOT, and this
# is not a theoretical difference: the frozen v0.10.0 release vector for 0x10 contains a
# zero-plaintext record, and the independent cross-implementation decoder pins that floor at 28.
# Applying the stricter number to the retained reader made a released, contract-pinned class of
# object permanently undownloadable: the frozen release fixture for 0x10 contains exactly such a
# record, so this is a rule the repository already pins, not a hypothetical.
MIN_RECORD_BYTES = _GCM_NONCE_SIZE + 16 + 1            # 0x20: nonce + tag + one plaintext byte
MIN_RECORD_BYTES_V1 = _GCM_NONCE_SIZE + 16             # 0x10: a zero-plaintext record is legal
# Not file-ceiling / chunk-size, which gives ~1,024 and looks generous. The resumable path's record
# count is driven by the client-chosen chunk count, capped at 200,000, plus 1 MiB sub-splitting
# inside each staged chunk -- so the largest legitimate count is around 201,024.
MAX_RECORDS = 2 ** 21
# The implied ceiling, recorded rather than enforced: with a cap on records and a cap on each
# record, the total is already bounded and a separate check for it can never fire. An earlier
# version had one, which was dead code that read like a safeguard.
MAX_TOTAL_PLAINTEXT = MAX_RECORDS * MAX_CHUNK_SIZE
# A different overhead model: Fernet's token expands the plaintext by base64 and a 57-byte
# envelope, so its records are legitimately larger than a GCM record of the same chunk.
MAX_FERNET_RECORD_BYTES = 12 * 1024 * 1024

assert MAX_RECORD_BYTES < _TERMINAL_MARKER, (
    "a legal data record must never be able to carry the terminal's length marker")


def _chunk_stream_aad_v2(vault_id, file_id, write_id: bytes, index: int) -> bytes:
    """Per-record associated data for 0x20.

    Three separations from v1, each load-bearing. The domain advances to v2, so a record lifted
    out of a 0x10 file cannot authenticate inside a 0x20 one. The terminal has a domain of its own,
    so neither can be accepted as the other. And the VERSION BYTE is bound -- not obvious, because
    the relabel-0x20-as-0x10 downgrade already fails on the domain alone; it matters for the next
    version, which might change reserved-byte semantics while keeping these domains and would
    otherwise be freely downgradeable to 0x20.

    The encoding is injective: every field after the domain is fixed-width, so the total length
    determines the domain length and therefore the field split. A future domain MUST keep that
    property -- no variable-width field without a length prefix.
    """
    if len(write_id) != _WRITE_ID_SIZE:
        raise EncryptionError("Malformed write id")
    return (_CHUNK_AAD_DOMAIN_V2 + bytes([GCM_STREAM_VERSION_V2]) + write_id
            + _uuid_bytes(vault_id) + _uuid_bytes(file_id) + struct.pack('>Q', index))


def _terminal_aad_v2(vault_id, file_id, write_id: bytes, chunk_count: int,
                     plaintext_length: int) -> bytes:
    """Associated data for the terminal record. `chunk_count` excludes the terminal itself.

    Both values are known to the writer when it writes this, and recoverable by the reader from
    its own running count and sum as it goes -- so neither has the availability problem that killed
    a related design in this project.

    Note what this does NOT do: the reader never learns these numbers from the terminal. AAD is an
    input to decryption, not an output. The terminal decrypting successfully IS the verification,
    and there is no comparison step afterwards -- any description of one is describing a value
    compared with itself.
    """
    if len(write_id) != _WRITE_ID_SIZE:
        raise EncryptionError("Malformed write id")
    return (_TERMINAL_AAD_DOMAIN_V2 + bytes([GCM_STREAM_VERSION_V2]) + write_id
            + _uuid_bytes(vault_id) + _uuid_bytes(file_id)
            + struct.pack('>Q', chunk_count) + struct.pack('>Q', plaintext_length))


def _uuid_bytes(value) -> bytes:
    """16 raw bytes of a UUID, accepting a uuid.UUID or its string form."""
    return value.bytes if isinstance(value, uuid.UUID) else uuid.UUID(str(value)).bytes


def _chunk_stream_aad(vault_id, file_id, index: int) -> bytes:
    """Per-chunk associated data binding a chunk to its vault, file, and position."""
    return _CHUNK_AAD_DOMAIN + _uuid_bytes(vault_id) + _uuid_bytes(file_id) + struct.pack('>Q', index)


def _gcm_stream_subkey(vault_id, file_id) -> bytes:
    """Per-file 32-byte AES key derived from the deployment root key. Each file having
    its own key makes the AES-GCM random-nonce collision budget per-file (~2^32 chunks)
    rather than deployment-wide, and binds the blob to its vault+file at the KEY level
    (defense in depth on top of the per-chunk AAD). Same encryption_key lifecycle."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'dockvault-gcm-chunk-subkey-v1',
        info=_uuid_bytes(vault_id) + _uuid_bytes(file_id),
    ).derive(_gcm_stream_root_key())


class GcmChunkStreamCodec:
    """Stateless-per-chunk writer codec for the AES-256-GCM chunked at-rest stream.

    On-disk: [header][record]* where header = MAGIC + 0x10 + 2 reserved and each
    record = [4-byte BE len of (nonce+ct)][12-byte nonce][ciphertext+16-byte tag].
    Each record is encrypted under this file's subkey with AAD =
    _chunk_stream_aad(vault_id, file_id, index).
    """

    def __init__(self, vault_id, file_id):
        self._aesgcm = AESGCM(_gcm_stream_subkey(vault_id, file_id))
        self._vault_id = vault_id
        self._file_id = file_id

    def header(self) -> bytes:
        return _GCM_STREAM_HEADER

    def encrypt(self, chunk: bytes, index: int) -> bytes:
        nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
        aad = _chunk_stream_aad(self._vault_id, self._file_id, index)
        ct = self._aesgcm.encrypt(nonce, chunk, aad)
        return struct.pack('>I', _GCM_NONCE_SIZE + len(ct)) + nonce + ct


class GcmChunkStreamCodecV2(GcmChunkStreamCodec):
    """Writer for format 0x20: the 0x10 records, a v2 AAD, and a terminal.

    Records are NOT required to be uniformly sized, and any rule demanding that would reject
    legitimate uploads: the resumable path re-chunks each staged chunk file at 1 MiB, so a staged
    chunk that is not a multiple of 1 MiB legally emits a short interior record. That is also why
    the header carries no chunk-size field -- there is no single size "fixed at open" for a writer
    to declare.
    """

    def __init__(self, vault_id, file_id):
        super().__init__(vault_id, file_id)
        self._records = 0
        self._plaintext = 0
        # Minted here, once per writer, and never accepted from a caller: a caller able to supply
        # it could reproduce a previous write's value and reopen the replay this closes.
        self._write_id = secrets.token_bytes(_WRITE_ID_SIZE)

    def header(self) -> bytes:
        return _GCM_STREAM_HEADER_V2_PREFIX + self._write_id

    def encrypt(self, chunk: bytes, index: int) -> bytes:
        # The writer is bounded as well as the reader. Without this a writer could emit more
        # records than its own reader accepts, producing an object that uploads successfully and
        # can never be downloaded.
        if self._records >= MAX_RECORDS:
            raise EncryptionError("Too many records for the at-rest format")
        if len(chunk) > MAX_CHUNK_SIZE:
            raise EncryptionError("Chunk exceeds the at-rest format maximum")
        # The minimum is a writer bound too. A zero-length chunk produces a 28-byte record that
        # this format's own reader refuses, so the file would upload and never download. Today the
        # streaming writer returns early on an empty chunk, which makes this unreachable rather
        # than unnecessary.
        if not chunk:
            raise EncryptionError("An empty record is not valid in this format")
        nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
        aad = _chunk_stream_aad_v2(self._vault_id, self._file_id, self._write_id, index)
        ct = self._aesgcm.encrypt(nonce, chunk, aad)
        self._records += 1
        self._plaintext += len(chunk)
        return struct.pack('>I', _GCM_NONCE_SIZE + len(ct)) + nonce + ct

    def terminal(self) -> bytes:
        """The closing record: a length marker, a nonce, and a tag over empty plaintext.

        Exactly 28 bytes after the length field, and a reader must read exactly that rather than
        reading to end-of-file -- otherwise strict EOF is unreachable and trailing bytes get
        misreported as a corrupt tag.
        """
        nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
        aad = _terminal_aad_v2(self._vault_id, self._file_id, self._write_id,
                               self._records, self._plaintext)
        tag = self._aesgcm.encrypt(nonce, b'', aad)
        return struct.pack('>I', _TERMINAL_MARKER) + nonce + tag


class IdentityChunkCodec:
    """Passthrough codec for zero-knowledge vaults: store the client's ciphertext
    verbatim with no header (parity with the previous identity-lambda behaviour)."""

    def header(self) -> bytes:
        return b''

    def encrypt(self, chunk: bytes, index: int) -> bytes:
        return chunk


def is_gcm_chunk_stream(storage_path) -> bool:
    """Cheap, non-decrypting peek: True iff the file begins with the GCM chunked-stream
    magic + version. Legacy Fernet streams start with a 4-byte chunk length (no magic),
    so they return False and route to decrypt_chunk_stream."""
    prefix_len = len(GCM_STREAM_MAGIC) + 1
    try:
        with open(storage_path, 'rb') as f:
            head = f.read(prefix_len)
    except OSError as e:
        # A transient read failure is NOT "this is some other format". Swallowing it routed a
        # healthy file to the wrong reader and reported an intact object as damaged -- the exact
        # mislabel this work exists to remove, arriving through the cheapest possible path.
        raise EncryptionError(f"Could not identify the stored format: {e}")
    return (len(head) == prefix_len
            and head[:len(GCM_STREAM_MAGIC)] == GCM_STREAM_MAGIC
            and head[len(GCM_STREAM_MAGIC)] in (GCM_STREAM_VERSION, GCM_STREAM_VERSION_V2))


def decrypt_gcm_chunk_stream(file_handle, vault_id, file_id) -> bytes:
    """Decrypt an AES-256-GCM chunked stream, authenticating each chunk against its
    per-chunk AAD (vault_id, file_id, index). Raises EncryptionError on any mismatch —
    e.g. a blob swapped in from another file/vault (file_id/vault_id differ) or reordered
    chunks (index differs)."""
    header = file_handle.read(len(_GCM_STREAM_HEADER))
    if (len(header) < len(_GCM_STREAM_HEADER)
            or header[:len(GCM_STREAM_MAGIC)] != GCM_STREAM_MAGIC):
        raise EncryptionError("Not a valid AES-GCM chunk stream")
    version = header[len(GCM_STREAM_MAGIC)]
    if version not in (GCM_STREAM_VERSION, GCM_STREAM_VERSION_V2):
        # Deliberately distinct from the malformed case above. "This file was written by a newer
        # build, update this deployment" and "this file is damaged, restore it" are different
        # instructions, and an operator given the wrong one acts on the wrong thing.
        raise EncryptionError(
            f"Unsupported at-rest format version 0x{version:02x}; this build reads "
            f"0x{GCM_STREAM_VERSION:02x} and 0x{GCM_STREAM_VERSION_V2:02x}")
    write_id = b''
    if version == GCM_STREAM_VERSION_V2:
        # The v2 header is longer than the v1 one by the write id, so it is read in two parts:
        # the shared prefix decides the version, and only then is the remainder known.
        write_id = file_handle.read(_WRITE_ID_SIZE)
        if len(write_id) != _WRITE_ID_SIZE:
            raise EncryptionError("Truncated header")
    if version == GCM_STREAM_VERSION_V2 and header[len(GCM_STREAM_MAGIC) + 1:] != b'\x00\x00':
        # Promoted to a real channel by this version: a future format may give the reserved bytes
        # meaning, and a reader that ignored them would silently misread such a file.
        raise EncryptionError("Reserved header bytes are not zero")

    aesgcm = AESGCM(_gcm_stream_subkey(vault_id, file_id))
    out = []
    index = 0
    total = 0
    terminated = False
    try:
        while True:
            length_header = file_handle.read(4)
            if not length_header or len(length_header) < 4:
                break
            rec_len = struct.unpack('>I', length_header)[0]

            if version == GCM_STREAM_VERSION_V2 and rec_len == _TERMINAL_MARKER:
                # Exactly 28 bytes, not "the rest of the file". Reading to EOF here would make the
                # trailing-bytes check below unreachable and would misreport appended junk as a
                # corrupt tag.
                record = file_handle.read(_GCM_NONCE_SIZE + 16)
                if len(record) != _GCM_NONCE_SIZE + 16:
                    raise EncryptionError("Truncated terminal record")
                aad = _terminal_aad_v2(vault_id, file_id, write_id, index, total)
                aesgcm.decrypt(record[:_GCM_NONCE_SIZE], record[_GCM_NONCE_SIZE:], aad)
                terminated = True
                break

            # Every bound is checked BEFORE the read. The reader this replaces allocated first and
            # discovered the problem second, which is how a 48-byte file reaches a 4 GiB read.
            floor = (MIN_RECORD_BYTES if version == GCM_STREAM_VERSION_V2
                     else MIN_RECORD_BYTES_V1)
            if rec_len < floor or rec_len > MAX_RECORD_BYTES:
                raise EncryptionError("Record length outside the permitted range")
            if index >= MAX_RECORDS:
                raise EncryptionError("Too many records in encrypted file")

            record = file_handle.read(rec_len)
            if len(record) != rec_len:
                raise EncryptionError("Incomplete chunk in encrypted file")
            nonce, ct = record[:_GCM_NONCE_SIZE], record[_GCM_NONCE_SIZE:]
            aad = (_chunk_stream_aad_v2(vault_id, file_id, write_id, index)
                   if version == GCM_STREAM_VERSION_V2
                   else _chunk_stream_aad(vault_id, file_id, index))
            plain = aesgcm.decrypt(nonce, ct, aad)
            out.append(plain)
            total += len(plain)
            index += 1

        if version == GCM_STREAM_VERSION_V2:
            if not terminated:
                # The clause the version bump exists for. Without it a file cut short decrypts
                # perfectly up to the cut and nothing says so.
                raise EncryptionError("Encrypted file ended without a terminal record")
            if file_handle.read(1):
                raise EncryptionError("Trailing bytes after the terminal record")
    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt AES-GCM chunk stream: {e}")
    return b''.join(out)


class GcmChunkStreamReader:
    """Reads a chunked at-rest stream without ever holding the whole plaintext.

    The whole-file reader this exists beside decrypts every record into a list and joins it, which
    costs about twice the file. Measured on 128 MB: 267.9 MB.

    The reader is built in two parts. Construction performs a **walk**: it reads each record's
    4-byte length prefix and steps over the body without reading it. That is enough to learn the
    record count and the total plaintext length, because a record's length field covers nonce,
    ciphertext and tag, so its plaintext length is `rec_len - 28`. Those two numbers are exactly
    what the 0x20 terminal's AAD binds -- so **the terminal is authenticated before anything is
    decrypted**, and truncation, substitution, reordering, a missing terminal and trailing bytes
    all become failures that happen before a caller has emitted a single byte.

    What the walk cannot see is an individual record's own tag: flipping bytes inside a body leaves
    the framing intact. That is the one failure that remains late, and callers have to be built for
    it.
    """

    def __init__(self, file_handle, vault_id, file_id):
        self._fh = file_handle
        self._vault_id = vault_id
        self._file_id = file_id

        try:
            stat = os.fstat(file_handle.fileno())
        except OSError as exc:
            raise EncryptionError(f"Failed to read file: {exc}")
        self._size = stat.st_size
        # A live blob cannot be opened by path with a link count of zero, so this is only ever 1
        # or more here; `_object_changed` looks for it reaching zero.
        self._nlink = stat.st_nlink

        # Every read below is POSITIONAL, through `_read_at`. Reading through the handle would go
        # through its buffer, and that buffer is 128 KiB: seeking between length prefixes discards
        # it and the next 4-byte read refills it, so the walk would pull 128 KiB from the device
        # per record -- 128 MiB of I/O to walk a 1 GB file, to read 4 KiB of prefixes. It would
        # also serve a small file's records out of a buffer filled before an overwrite, so a blob
        # replaced underneath a reader would go unnoticed.
        #
        # The descriptor is fetched per read rather than cached. A descriptor NUMBER is only
        # meaningful while its handle is open: if a caller closes the handle, the number is
        # recycled and the next positional read returns some unrelated file's bytes into the
        # decrypt path.
        header = self._read_at(0, len(_GCM_STREAM_HEADER))
        if (len(header) < len(_GCM_STREAM_HEADER)
                or header[:len(GCM_STREAM_MAGIC)] != GCM_STREAM_MAGIC):
            raise EncryptionError("Not a valid AES-GCM chunk stream")
        self._version = header[len(GCM_STREAM_MAGIC)]
        if self._version not in (GCM_STREAM_VERSION, GCM_STREAM_VERSION_V2):
            raise EncryptionError(
                f"Unsupported at-rest format version 0x{self._version:02x}; this build reads "
                f"0x{GCM_STREAM_VERSION:02x} and 0x{GCM_STREAM_VERSION_V2:02x}")

        self._write_id = b''
        if self._version == GCM_STREAM_VERSION_V2:
            # The header is 28 bytes for 0x20 and 12 for 0x10. Sizing it from the version is not
            # optional: starting the walk at 12 on a 0x20 file reads the first four bytes of the
            # write id as a length prefix and rejects every valid file.
            self._write_id = self._read_at(len(_GCM_STREAM_HEADER), _WRITE_ID_SIZE)
            if len(self._write_id) != _WRITE_ID_SIZE:
                raise EncryptionError("Truncated header")
            if header[len(GCM_STREAM_MAGIC) + 1:] != b'\x00\x00':
                raise EncryptionError("Reserved header bytes are not zero")

        self._data_start = (_GCM_STREAM_HEADER_V2_SIZE
                            if self._version == GCM_STREAM_VERSION_V2
                            else len(_GCM_STREAM_HEADER))
        self._aesgcm = AESGCM(_gcm_stream_subkey(vault_id, file_id))
        # One 4-byte entry per record. Deliberately not a list of tuples of (index, file offset,
        # plaintext offset, length): the index position IS the record number and both offsets are
        # prefix sums, so the tuple form stores four numbers where one is needed. At the record
        # count this format permits that is the difference between 8 MiB and 368 MiB, and this is
        # held per open reader.
        self._lengths = array('I')
        self._total_length = 0
        # Built by the random-access path only; a sequential read never touches either.
        self._plain_cum = None
        self._cache = []
        self._walk()

    # -- positional reads -------------------------------------------------------

    def _read_at(self, offset: int, size: int) -> bytes:
        """Exactly `size` bytes from `offset`, without disturbing or consulting any buffer.

        `os.pread` is one syscall and does not move the file position, so concurrent readers on one
        descriptor cannot interfere -- which the SFTP path will need.

        Windows has no `pread`. The fallback is the same operation in two calls, but it goes
        through the handle's buffer and therefore inherits everything described above: on a small
        file it can serve records that were read before the blob changed underneath it. That is
        tolerable only because it is never the deployment platform, and it is why several tests
        covering concurrent modification are POSIX-only.
        """
        if hasattr(os, "pread"):
            try:
                fd = self._fh.fileno()
            except (OSError, ValueError) as exc:
                # ValueError is what a closed handle raises, and it is not an OSError.
                raise EncryptionError(f"Failed to read file: {exc}")
            out = b''
            while len(out) < size:
                piece = os.pread(fd, size - len(out), offset + len(out))
                if not piece:
                    break
                out += piece
            return out
        try:
            self._fh.seek(offset)
            return self._fh.read(size)
        except (OSError, ValueError) as exc:
            raise EncryptionError(f"Failed to read file: {exc}")

    # -- the walk ---------------------------------------------------------------

    def _walk(self):
        """Read every length prefix, step over every body, and verify the terminal.

        Bodies are never read here, so this is not a second pass over the data. Truncation is
        caught arithmetically against the size taken at construction rather than by seeking and
        discovering a short read -- a seek past the end of a file succeeds silently, which would
        make a truncated final record invisible.
        """
        pos = self._data_start
        terminated = False
        floor = (MIN_RECORD_BYTES if self._version == GCM_STREAM_VERSION_V2
                 else MIN_RECORD_BYTES_V1)

        while pos + 4 <= self._size:
            length_header = self._read_at(pos, 4)
            if len(length_header) < 4:
                break
            rec_len = struct.unpack('>I', length_header)[0]

            if self._version == GCM_STREAM_VERSION_V2 and rec_len == _TERMINAL_MARKER:
                terminal_len = _GCM_NONCE_SIZE + 16
                if pos + 4 + terminal_len > self._size:
                    raise EncryptionError("Truncated terminal record")
                record = self._read_at(pos + 4, terminal_len)
                if len(record) != terminal_len:
                    raise EncryptionError("Truncated terminal record")
                aad = _terminal_aad_v2(self._vault_id, self._file_id, self._write_id,
                                       len(self._lengths), self._total_length)
                try:
                    self._aesgcm.decrypt(record[:_GCM_NONCE_SIZE], record[_GCM_NONCE_SIZE:], aad)
                except Exception:
                    # The count and length are AAD inputs, not values read out of the terminal, so
                    # a successful decrypt IS the check that the walk's numbers are the writer's.
                    self._raise_for_failure("Encrypted file failed terminal authentication")
                terminated = True
                pos += 4 + terminal_len
                break

            # Bounds before anything is trusted, so a corrupt length cannot make the walk
            # expensive. The floor is version-dependent: 0x10 permits a zero-plaintext record and a
            # frozen release fixture contains one.
            if rec_len < floor or rec_len > MAX_RECORD_BYTES:
                self._raise_for_failure("Record length outside the permitted range")
            if len(self._lengths) >= MAX_RECORDS:
                raise EncryptionError("Too many records in encrypted file")
            if pos + 4 + rec_len > self._size:
                self._raise_for_failure("Incomplete chunk in encrypted file")

            self._lengths.append(rec_len)
            self._total_length += rec_len - _GCM_NONCE_SIZE - 16
            pos += 4 + rec_len

        if self._version == GCM_STREAM_VERSION_V2:
            if not terminated:
                self._raise_for_failure("Encrypted file ended without a terminal record")
            if pos != self._size:
                self._raise_for_failure("Trailing bytes after the terminal record")
        # 0x10 has no terminal and no strict EOF. A stray partial length prefix at the end is
        # ignored, exactly as the whole-file reader ignores it -- this reader must not reject a
        # file the reader it replaces accepts.

    # -- what the walk learned --------------------------------------------------

    @property
    def total_length(self) -> int:
        """Total plaintext bytes. For 0x20 this is authenticated by the terminal."""
        return self._total_length

    @property
    def record_count(self) -> int:
        return len(self._lengths)

    @property
    def version(self) -> int:
        return self._version

    @property
    def length_is_authenticated(self) -> bool:
        """True only for 0x20. 0x10 has no terminal, so its length is derived but unsigned."""
        return self._version == GCM_STREAM_VERSION_V2

    # -- reading ----------------------------------------------------------------

    def _raise_for_failure(self, message: str):
        """Raise, having first asked whether the object was replaced rather than damaged.

        Used by the walk as well as by record decryption. The walk is where truncation, a missing
        terminal and a failed terminal authentication all land, and those are exactly what a
        concurrent delete produces -- so attributing only at record level would leave the entire
        open-to-first-byte window reporting routine deletes as tampering.
        """
        if self._object_changed():
            raise ObjectChangedDuringRead(
                "The stored file was replaced or deleted while it was being read")
        raise EncryptionError(message)

    def _object_changed(self) -> bool:
        """Has the blob been unlinked under this descriptor since it was opened?

        `st_nlink == 0` and nothing else. It is exact for this codebase -- a delete and a same-name
        replacement both unlink the old blob -- and it has no false positives: a live blob cannot
        be opened by path with a link count of zero.

        Two weaker signals were tried and rejected. Comparing the link count for *inequality* fires
        on an unrelated hard link, and comparing modification times fires on any tool that restores
        an mtime; both would report tampering as a routine delete, which silences the alarm instead
        of dulling it. Modification time is also unusable on its own merits: the container
        filesystem here has 10 ms granularity, and the shred runs immediately after the commit, so
        whether an overwrite moved the timestamp is a question about the filesystem rather than
        about the file.

        The cost is that an overwrite not yet followed by its unlink reports as an integrity
        failure. That is the safe direction: a spurious integrity alarm is noise, a spurious "it
        was only a delete" is a missed one.
        """
        try:
            return os.fstat(self._fh.fileno()).st_nlink == 0
        except (OSError, ValueError):
            # A closed or unusable descriptor is not evidence either way; do not claim a
            # replacement on the strength of it.
            return False

    def _decrypt_at(self, index: int, offset: int) -> bytes:
        rec_len = self._lengths[index]
        record = self._read_at(offset + 4, rec_len)
        if len(record) != rec_len:
            self._raise_for_failure("Incomplete chunk in encrypted file")
        aad = (_chunk_stream_aad_v2(self._vault_id, self._file_id, self._write_id, index)
               if self._version == GCM_STREAM_VERSION_V2
               else _chunk_stream_aad(self._vault_id, self._file_id, index))
        try:
            return self._aesgcm.decrypt(record[:_GCM_NONCE_SIZE], record[_GCM_NONCE_SIZE:], aad)
        except Exception:
            # The one failure the walk cannot pre-empt. Attribute it before calling it corruption:
            # an ordinary delete racing an ordinary read arrives here looking identical.
            self._raise_for_failure("Failed to decrypt AES-GCM chunk stream")

    # -- random access -----------------------------------------------------------

    def _plaintext_offsets(self):
        """Cumulative plaintext offsets, one per record plus a total. Built once, on demand.

        Only the random-access path needs this, so a sequential download never pays for it.

        Deriving the FILE offset from it needs no second array: a record occupies its 4-byte length
        prefix plus a 12-byte nonce plus its ciphertext plus a 16-byte tag, so its length field is
        always its plaintext length plus 28, and

            file_offset(i) = data_start + 32 * i + plaintext_offset(i)

        which is exact for both retained versions because both use the same nonce and tag sizes.
        Storing the file offsets as well would double an array that is already the largest thing
        this object holds.
        """
        if self._plain_cum is None:
            cum = array('Q')
            cum.append(0)
            total = 0
            for length in self._lengths:
                total += length - _GCM_NONCE_SIZE - 16
                cum.append(total)
            self._plain_cum = cum
        return self._plain_cum

    def _record_at(self, plaintext_offset: int) -> int:
        """Index of the record containing `plaintext_offset`."""
        cum = self._plaintext_offsets()
        return bisect.bisect_right(cum, plaintext_offset) - 1

    def _cached_record(self, index: int) -> bytes:
        """Decrypt record `index`, reusing the last two.

        The cache is not an optimisation. Clients read sequentially in small requests -- 32 KiB is
        typical -- so a 1 MiB record covers about thirty of them, and without a cache each of those
        reads decrypts the same record from scratch. Two entries rather than one, so that a read
        spanning a boundary does not evict the record the next read will want.
        """
        for cached_index, plain in self._cache:
            if cached_index == index:
                return plain
        cum = self._plaintext_offsets()
        plain = self._decrypt_at(index, self._data_start + 32 * index + cum[index])
        self._cache.append((index, plain))
        del self._cache[:-2]
        return plain

    def read_range(self, offset: int, length: int) -> bytes:
        """Plaintext bytes `[offset, offset + length)`, decrypting only the records they touch.

        Past the end returns empty; a request straddling the end returns what exists. Both match
        what a caller slicing a whole-file buffer would have got.
        """
        if length <= 0 or offset < 0:
            return b''
        cum = self._plaintext_offsets()
        total = cum[-1]
        if offset >= total:
            return b''
        end = min(offset + length, total)

        out = bytearray()
        index = self._record_at(offset)
        while len(out) < end - offset and index < len(self._lengths):
            plain = self._cached_record(index)
            start_in_record = max(0, offset - cum[index])
            wanted = (end - offset) - len(out)
            out += plain[start_in_record:start_in_record + wanted]
            index += 1
        return bytes(out)

    def records(self):
        """Yield each record's plaintext in order, holding one record at a time."""
        offset = self._data_start
        for index in range(len(self._lengths)):
            plain = self._decrypt_at(index, offset)
            offset += 4 + self._lengths[index]
            yield plain


# --- Filename / MIME encryption at rest (Standard vaults) -------------------
# Names/MIME were stored plaintext. Encrypt them at rest under the SAME deployment
# secret that protects file CONTENT (the vault password is only an access gate, not the
# content key — see the SFTP design), so the server can always derive these keys and
# backfill is EAGER for every vault (no password needed, no lazy migration).
#
#  * Per-OBJECT cipher key: HKDF(name-root, vault_id||obj_id) -> AES-256-GCM. Names are
#    short, so each (filename, mime) is a single GCM blob with AAD = field||vault||obj.
#  * Per-VAULT blind index: HMAC(name) under a per-vault key, so the same name in a vault
#    maps to the same digest. This preserves the server-side EXACT-match the app relies
#    on (SFTP path resolution, no-clobber, rename uniqueness, dedup) without storing the
#    plaintext. (No server-side substring search exists today, so exact-match suffices.)
# Zero-knowledge vaults are NOT sealed with these server-held keys — their names are
# encrypted IN THE BROWSER under the per-vault DEK (which the server never holds). Such
# blobs are stored verbatim in the SAME enc_name/enc_mime columns but carry the marker
# prefix below so the server can tell them apart and never tries (and fails) to decrypt
# them. The wire format must remain aligned with static/js/ecc_crypto.js.
#
# ZK_NAME_PREFIX MUST match the prefix the browser writes (ecc_crypto.js encryptName):
# enc_name/enc_mime for a ZK object = ZK_NAME_PREFIX + base64(iv||ciphertext+tag).
# v1 ('zk1:') binds AAD vault|field|epoch; v2 ('zk2:') ALSO binds the object id, so a sealed
# name can't be transposed between same-vault/same-epoch objects. Both are valid sealed blobs;
# v1 stays readable (additive migration), new seals are v2.
ZK_NAME_PREFIX = 'zk1:'
ZK_NAME_PREFIX_V2 = 'zk2:'
ZK_NAME_PREFIXES = (ZK_NAME_PREFIX, ZK_NAME_PREFIX_V2)


def is_zk_sealed_name(token) -> bool:
    """True if an enc_name/enc_mime blob was sealed CLIENT-SIDE for a zero-knowledge
    vault (the server has no key for it). Lets the transparent-decrypt load events and
    any server reader skip ZK blobs instead of treating them as server-decryptable.
    Accepts BOTH the v1 (zk1:) and the obj-id-bound v2 (zk2:) formats."""
    return bool(token) and str(token).startswith(ZK_NAME_PREFIXES)


def is_zk_object_bound_name(token) -> bool:
    """True only for the v2 ('zk2:') form, whose AAD also binds the object id.

    Readers accept both forms, because rows sealed before v2 exist and must stay readable.
    WRITERS should require this one: v1 binds vault, field and epoch but not the row, so a v1
    blob can be moved to another row and still authenticate -- which is the transposition v2 was
    introduced to prevent. Accepting v1 on write leaves that binding opt-out at the only boundary
    that could require it.
    """
    return bool(token) and str(token).startswith(ZK_NAME_PREFIX_V2)


def _name_encryption_root():
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-name-enc-key-v1', info=b'filename-mime',
    ).derive(_runtime_settings().encryption_key.encode())


def _name_blind_index_root():
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-name-bi-key-v1', info=b'filename-blind-index',
    ).derive(_runtime_settings().encryption_key.encode())


def _name_object_key(vault_id, obj_id) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-name-obj-v1',
        info=_uuid_bytes(vault_id) + _uuid_bytes(obj_id),
    ).derive(_name_encryption_root())


def _name_field_aad(field: str, vault_id, obj_id) -> bytes:
    return b'dockvault-field:' + field.encode() + b':' + _uuid_bytes(vault_id) + _uuid_bytes(obj_id)


def encrypt_object_field(vault_id, obj_id, plaintext: str, field: str) -> str:
    """Encrypt a small per-object string (filename or MIME) at rest. Returns base64 of
    nonce||ciphertext+tag. `field` ('name'/'mime') is bound via AAD so the two fields of
    one object aren't interchangeable."""
    aesgcm = AESGCM(_name_object_key(vault_id, obj_id))
    nonce = secrets.token_bytes(_GCM_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), _name_field_aad(field, vault_id, obj_id))
    return base64.b64encode(nonce + ct).decode('ascii')


def decrypt_object_field(vault_id, obj_id, token: str, field: str) -> str:
    """Inverse of encrypt_object_field. Raises on tamper / wrong object."""
    raw = base64.b64decode(token)
    nonce, ct = raw[:_GCM_NONCE_SIZE], raw[_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(_name_object_key(vault_id, obj_id))
    return aesgcm.decrypt(nonce, ct, _name_field_aad(field, vault_id, obj_id)).decode('utf-8')


def name_blind_index(vault_id, name: str) -> str:
    """Deterministic per-vault HMAC-SHA256 of an EXACT name, for server-side equality
    lookup without storing plaintext. Same (vault_id, name) -> same hex digest."""
    key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b'dockvault-name-bi-vault-v1', info=_uuid_bytes(vault_id),
    ).derive(_name_blind_index_root())
    return hmac.new(key, name.encode('utf-8'), hashlib.sha256).hexdigest()


def vault_password_fingerprint(password_hash: str) -> str:
    """A stable, non-reversible fingerprint of a vault's stored password hash.

    Captured when a temporary credential proves a vault's password, and re-checked on
    every SFTP access. If the vault's password is later added, changed, or rotated, its
    stored hash string changes, this fingerprint no longer matches, and the credential's
    standing proof is void — so SFTP tracks the live password exactly as the web's
    per-request check does (no proof frozen at mint outliving a rotation)."""
    return hashlib.sha256((password_hash or "").encode()).hexdigest()


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class PasswordHashingError(SecurityError):
    """Exception raised when password hashing fails."""
    pass


class PasswordVerificationError(SecurityError):
    """Exception raised when password verification fails."""
    pass


class EncryptionError(SecurityError):
    """Exception raised when encryption operations fail."""
    pass


class ObjectChangedDuringRead(EncryptionError):
    """The stored blob was replaced or deleted while it was being read.

    Separate from a plain :class:`EncryptionError` because the two mean opposite things: one is a
    damaged or tampered object, the other is an ordinary delete racing an ordinary read. Reporting
    the second as the first trains an operator to ignore the alarm that matters.

    It *subclasses* EncryptionError rather than standing alone so that a caller which does not know
    about it still handles it. Every handler of the reader this replaces catches EncryptionError,
    and a bare Exception here would escape all of them as an unhandled server error the moment a
    file is deleted mid-download. Callers that want the distinction catch this first.
    """


# Password Hashing Functions
def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        Hashed password string
        
    Raises:
        PasswordHashingError: If hashing fails
    """
    try:
        return password_hasher.hash(password)
    except Exception as e:
        raise PasswordHashingError(f"Failed to hash password: {str(e)}")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Hashed password to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        password_hasher.verify(password_hash, password)
        
        # Check if hash needs rehashing (parameters changed)
        if password_hasher.check_needs_rehash(password_hash):
            # In production, you should rehash and update the database
            pass
        
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
    except Exception:
        return False


# Temporary Credential Generation
def generate_temporary_credentials() -> Tuple[str, str, str]:
    """
    Generate temporary one-time credentials.
    
    Returns:
        Tuple of (username, credential_string, credential_hash)
    """
    # Generate a unique username for temporary access
    temp_username = f"temp_{uuid.uuid4().hex[:12]}"
    
    # Generate a 16-character alphanumeric password (enhanced security)
    # Using letters (uppercase + lowercase) and digits = 62 characters
    # 16 characters from 62-char alphabet = 62^16 ≈ 4.8×10^28 possibilities
    # (vs 12 chars = 62^12 ≈ 3.2×10^21 possibilities)
    import string
    alphabet = string.ascii_letters + string.digits
    credential_string = ''.join(secrets.choice(alphabet) for _ in range(16))
    
    # Hash the credential for storage (bcrypt - one-way hashing)
    credential_hash = hash_password(credential_string)

    return temp_username, credential_string, credential_hash


def generate_passcode(length: int = 16) -> str:
    """Generate a high-entropy alphanumeric temporary vault passcode.

    The passcode is a second access gate on a password-protected standard vault. Uses the same
    62-char alphabet + secrets.choice as the credential password; the length comes from the admin
    policy (floored at 8, defaulting to 16). A 16-char alphanumeric passcode has ~95 bits of entropy,
    so a generated passcode is strong regardless of the (custom-only) complexity toggles.
    """
    import string
    try:
        n = int(length)
    except (TypeError, ValueError):
        n = 16
    n = max(8, n)
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))


def verify_temporary_credential(credential: str, credential_hash: str) -> bool:
    """
    Verify a temporary credential against its hash.
    
    Args:
        credential: Plain text credential to verify
        credential_hash: Hashed credential to verify against
        
    Returns:
        True if credential matches, False otherwise
    """
    return verify_password(credential, credential_hash)


# File Encryption Functions
def encrypt_file_content(content: bytes) -> bytes:
    """
    Encrypt file content using Fernet (AES-128 in CBC mode).
    
    Args:
        content: Plain file content as bytes
        
    Returns:
        Encrypted content as bytes
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        return _fernet().encrypt(content)
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt content: {str(e)}")


def encrypt_chunk(chunk: bytes) -> bytes:
    """
    Encrypt a single chunk of data.
    Each chunk is encrypted independently for streaming support.
    
    Args:
        chunk: Chunk of data to encrypt
        
    Returns:
        Encrypted chunk with 4-byte length header
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        encrypted = _fernet().encrypt(chunk)
        # Prepend chunk length for streaming decryption (4 bytes, big-endian)
        import struct
        length_header = struct.pack('>I', len(encrypted))
        return length_header + encrypted
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt chunk: {str(e)}")


def decrypt_chunk_stream(file_handle):
    """
    Generator that decrypts chunks from a file handle.
    Reads 4-byte length header, then encrypted chunk, decrypts and yields.
    
    Args:
        file_handle: File handle opened in binary read mode
        
    Yields:
        Decrypted chunks
        
    Raises:
        EncryptionError: If decryption fails
    """
    import struct
    try:
        while True:
            # Read 4-byte length header
            length_header = file_handle.read(4)
            if not length_header or len(length_header) < 4:
                break
            
            chunk_length = struct.unpack('>I', length_header)[0]

            # Bounded BEFORE the read, like the GCM reader. This is the path a 48-byte file uses
            # to reach a 4 GiB allocation: a length field is four attacker-controlled bytes, and
            # this reader used to hand them straight to read(). The ceiling is Fernet's, not the
            # GCM one -- a Fernet token expands its plaintext by base64 plus a 57-byte envelope, so
            # a legitimate record here is genuinely larger than a GCM record of the same chunk.
            if chunk_length < 1 or chunk_length > MAX_FERNET_RECORD_BYTES:
                raise EncryptionError("Record length outside the permitted range")

            # Read encrypted chunk
            encrypted_chunk = file_handle.read(chunk_length)
            if len(encrypted_chunk) != chunk_length:
                raise EncryptionError("Incomplete chunk in encrypted file")
            
            # Decrypt and yield
            decrypted = _fernet().decrypt(encrypted_chunk)
            yield decrypted
    except Exception as e:
        if "Incomplete chunk" in str(e):
            raise
        raise EncryptionError(f"Failed to decrypt chunk: {str(e)}")


def decrypt_file_content(encrypted_content: bytes) -> bytes:
    """
    Decrypt file content using Fernet.
    
    Args:
        encrypted_content: Encrypted file content as bytes
        
    Returns:
        Decrypted content as bytes
        
    Raises:
        EncryptionError: If decryption fails
    """
    try:
        return _fernet().decrypt(encrypted_content)
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt content: {str(e)}")


def encrypt_string(plain_text: str) -> str:
    """
    Encrypt a string value.
    
    Args:
        plain_text: Plain text string
        
    Returns:
        Encrypted string (base64 encoded)
    """
    try:
        encrypted = _fernet().encrypt(plain_text.encode())
        return encrypted.decode()
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt string: {str(e)}")


def decrypt_string(encrypted_text: str) -> str:
    """
    Decrypt an encrypted string value.
    
    Args:
        encrypted_text: Encrypted string (base64 encoded)
        
    Returns:
        Decrypted plain text string
    """
    try:
        decrypted = _fernet().decrypt(encrypted_text.encode())
        return decrypted.decode()
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt string: {str(e)}")


# File Integrity Functions
def calculate_file_checksum(content: bytes) -> str:
    """
    Calculate SHA-256 checksum of file content.
    
    Args:
        content: File content as bytes
        
    Returns:
        Hexadecimal checksum string
    """
    return hashlib.sha256(content).hexdigest()


def verify_file_integrity(content: bytes, expected_checksum: str) -> bool:
    """
    Verify file integrity using checksum.
    
    Args:
        content: File content as bytes
        expected_checksum: Expected SHA-256 checksum
        
    Returns:
        True if checksums match, False otherwise
    """
    actual_checksum = calculate_file_checksum(content)
    return secrets.compare_digest(actual_checksum, expected_checksum)


# JWT Token Functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time delta
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=_runtime_settings().jwt_access_token_expire_minutes
        )
    
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    
    encoded_jwt = jwt.encode(
        to_encode,
        _runtime_settings().jwt_secret_key,
        algorithm=_runtime_settings().jwt_algorithm
    )
    
    return encoded_jwt


def verify_access_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT access token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token data if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            _runtime_settings().jwt_secret_key,
            algorithms=[_runtime_settings().jwt_algorithm]
        )
        return payload
    except jwt.PyJWTError:
        return None


# Session Token Generation
def generate_session_token() -> str:
    """
    Generate a secure session token.
    
    Returns:
        URL-safe session token string
    """
    return secrets.token_urlsafe(32)


# Secure Random String Generation
def generate_secure_random_string(length: int = 32) -> str:
    """
    Generate a cryptographically secure random string.
    
    Args:
        length: Length of the string in bytes (default 32)
        
    Returns:
        URL-safe random string
    """
    return secrets.token_urlsafe(length)


# Input Sanitization
def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove any path separators and null bytes
    filename = filename.replace('/', '').replace('\\', '').replace('\0', '')

    # Strip ALL control characters (C0 incl. CR/LF, and DEL) so a stored name can't later
    # inject into a response header (Content-Disposition) or corrupt logs.
    filename = ''.join(c for c in filename if ord(c) >= 32 and ord(c) != 127)

    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        # Preserve extension if present
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        if ext:
            filename = name[:255-len(ext)-1] + '.' + ext
        else:
            filename = filename[:255]
    
    # Ensure filename is not empty
    if not filename:
        filename = f"file_{uuid.uuid4().hex[:8]}"
    
    return filename


def sanitize_path_component(component: str) -> str:
    """
    Sanitize a path component (folder/vault name).
    
    Args:
        component: Original path component
        
    Returns:
        Sanitized path component
    """
    return sanitize_filename(component)
