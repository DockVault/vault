"""Serving a stored file without holding it, and without a failure arriving too late to matter.

The reader that produces the pieces is `security.GcmChunkStreamReader` (and, for the retained
formats, the generators beside it). What lives here is the other half of the problem: a streaming
response has already handed most of the plaintext to the client by the time it reaches a failure
the whole-file reader would have hit before returning anything.

Most failures do not need this. The at-rest walk authenticates the terminal before a byte is
decrypted, so truncation, a missing terminal, trailing bytes, a dropped record and a substituted
blob are all settled before the response body exists. Two are left:

- a record's own authentication tag, which cannot be known until that record is reached;
- the stored plaintext checksum, which cannot be known until the last byte has been hashed.

The first is handled by the response length: it comes from the authenticated terminal, so a stream
that stops early delivers fewer bytes than promised and the client sees a truncated response. The
second is what `verified_stream` is for.
"""

import hashlib


class ChecksumMismatch(Exception):
    """The bytes that were about to be served do not hash to what was stored for them."""


def verified_stream(chunks, expected_checksum):
    """Yield `chunks`, holding the last one back until the running checksum has been checked.

    Without the hold-back the checksum is worthless on this path: it can only be computed once
    every byte has been hashed, and by then every byte has also been sent, the response length is
    satisfied, and the client has a clean success for a file the server just decided was wrong.
    Holding one piece back means a mismatch aborts before the promised length is reached, which
    puts it in the same client-visible category as any other truncated response.

    The cost is one piece held, which is bounded by the record size and does not grow with the
    file. The two degenerate cases are the ones worth stating, because both are legal and a naive
    implementation gets them wrong:

    - **exactly one chunk.** The hold-back degenerates to buffering the whole file, which is
      correct: such a file is at most one record.
    - **empty pieces.** Hashed, then dropped. Holding one back withholds nothing, which is the same
      as not holding back at all.
    - **no bytes at all.** A zero-length file has nothing to withhold and a zero-length response
      has nothing to shorten, so this function cannot signal a mismatch for one: raising here
      happens after the response headers have gone out, and the client sees a complete success.
      That case has to be settled BEFORE the response is built -- see :meth:`BoundedDownload.
      verify_now`, which the caller uses when the response will carry no bytes.
    """
    hasher = hashlib.sha256()
    held = None

    for piece in chunks:
        hasher.update(piece)
        if not piece:
            # An empty piece is hashed and then dropped. Holding one back would withhold NOTHING:
            # the response would still deliver its full declared length and the client would see a
            # complete, successful transfer for a file the check then rejected. A reader may
            # legitimately produce one -- a zero-plaintext record is legal in the retained format,
            # and a frozen release fixture contains one -- so this is a reachable shape, not a
            # theoretical one.
            continue
        if held is not None:
            yield held
        held = piece

    if not expected_checksum:
        # Fail closed. The whole-file reader this replaces compared against the stored value and an
        # empty one never matched, so a file with no recorded checksum was refused. The column is
        # NOT NULL, so this should be unreachable -- which is exactly why it must not be the one
        # path that quietly serves anything.
        raise ChecksumMismatch("The stored file has no recorded checksum")

    if hasher.hexdigest() != expected_checksum:
        raise ChecksumMismatch(
            "The stored file does not match the checksum recorded for it")

    if held is not None:
        yield held


class BoundedDownload:
    """An open stored file, plus what a caller needs to serve it honestly.

    `total_length` is the number of plaintext bytes the response will carry. For the current
    at-rest format it comes from the authenticated terminal, and `length_is_authenticated` says so;
    for the retained formats it is the recorded size, which an adversary able to rewrite the blob
    can usually also rewrite. A caller may use it as a response length either way, but only the
    authenticated one turns a short body into evidence.
    """

    def __init__(self, handle, chunks, total_length, name, mime_type, checksum,
                 length_is_authenticated=False):
        self._handle = handle
        self._chunks = chunks
        self.total_length = total_length
        self.name = name
        self.mime_type = mime_type
        self.checksum = checksum
        self.length_is_authenticated = length_is_authenticated

    def chunks(self):
        """The plaintext, one piece at a time, with the checksum enforced before the last one."""
        return verified_stream(self._chunks, self.checksum)

    def verify_now(self):
        """Consume the whole stream and check it, before any response exists.

        For a response that will carry no bytes. The hold-back works by leaving the client short of
        a promised length, and a zero-length response cannot be made shorter -- so a mismatch there
        has to become an error status instead, which is only possible before the headers are sent.

        Only safe to call when the stream is small enough to consume eagerly, which is the point:
        the caller uses it when `total_length` is zero.
        """
        for _piece in self.chunks():
            pass

    def close(self):
        try:
            self._handle.close()
        except Exception:      # noqa: BLE001 - closing is best effort; the caller is finishing
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class RandomAccessFile:
    """A stored file a caller can read arbitrary ranges from, without holding it.

    The SFTP contract is "any offset, any order, any number of times", and it was met by keeping
    the entire plaintext in memory for as long as the client left the file open -- not for the
    length of a transfer, which is what made it the most expensive read in the system. A 120 MB
    file cost 120 MB from the moment it was opened until the moment it was closed.

    What replaces it is the index the format walk already produces plus a two-record cache, so the
    resident cost is a few bytes per record and at most two decrypted records.
    """

    def __init__(self, handle, read_range, size, name):
        self._handle = handle
        self._read_range = read_range
        self.size = size
        self.name = name

    @classmethod
    def from_bytes(cls, content: bytes, name):
        """A whole-file fallback, for a format whose record boundaries cannot be found cheaply."""
        return cls(None, lambda offset, length: content[offset:offset + length],
                   len(content), name)

    def read(self, offset: int, length: int) -> bytes:
        return self._read_range(offset, length)

    def close(self):
        if self._handle is not None:
            try:
                self._handle.close()
            except Exception:      # noqa: BLE001 - closing is best effort
                pass
            self._handle = None
