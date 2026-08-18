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

    `read_range` is present only for a format whose record boundaries are known, which today means
    the at-rest chunk stream. It is `None` for the client-encrypted blob and for the retained
    legacy format -- the first because the server holds no key and must not build a reader for it,
    the second because answering a range there means decrypting the whole file into memory. A
    caller decides whether to offer ranges by asking whether this is None, so those two are
    excluded by construction rather than by a list of special cases someone has to maintain.
    """

    def __init__(self, handle, chunks, total_length, name, mime_type, checksum,
                 length_is_authenticated=False, read_range=None):
        self._handle = handle
        self._chunks = chunks
        self.total_length = total_length
        self.name = name
        self.mime_type = mime_type
        self.checksum = checksum
        self.length_is_authenticated = length_is_authenticated
        self.read_range = read_range

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
        """A whole-file fallback, for a format whose record boundaries cannot be found cheaply.

        The clamping matters: a slice interprets a negative offset or length from the end of the
        buffer, so `content[0:-5]` would return almost the whole file where the indexed reader
        returns nothing. Two implementations of one contract have to answer degenerate arguments
        the same way, whether or not a caller can currently produce them.
        """
        def _slice(offset: int, length: int) -> bytes:
            if length <= 0 or offset < 0 or offset >= len(content):
                return b''
            return content[offset:offset + length]

        return cls(None, _slice, len(content), name)

    def read(self, offset: int, length: int) -> bytes:
        return self._read_range(offset, length)

    def close(self):
        if self._handle is not None:
            try:
                self._handle.close()
            except Exception:      # noqa: BLE001 - closing is best effort
                pass
            self._handle = None


class ByteRange:
    """One satisfiable byte range, resolved against a known total length.

    `start` and `last` are both inclusive, matching the wire format rather than Python slicing,
    because every value that goes into a `Content-Range` header is inclusive and converting in
    only one direction keeps the off-by-one in one place.
    """

    __slots__ = ("start", "last", "total")

    def __init__(self, start: int, last: int, total: int):
        self.start = start
        self.last = last
        self.total = total

    @property
    def length(self) -> int:
        return self.last - self.start + 1

    def content_range(self) -> str:
        return f"bytes {self.start}-{self.last}/{self.total}"

    def __eq__(self, other):
        return (isinstance(other, ByteRange) and other.start == self.start
                and other.last == self.last and other.total == self.total)

    def __repr__(self):
        return f"ByteRange({self.start}, {self.last}, {self.total})"


#: Returned when the header names a range that cannot be satisfied. Distinct from `None`, which
#: means "serve the whole thing": the two lead to different status codes, and collapsing them
#: would turn a 416 into a silent full download of a file the client explicitly did not ask for.
UNSATISFIABLE = object()


def parse_byte_range(header, total_length: int):
    """Resolve a `Range` request header against a known length.

    Returns a :class:`ByteRange`, or `None` to serve the whole representation, or
    :data:`UNSATISFIABLE`.

    `None` is the answer for anything malformed, and that is the specified behaviour rather than
    leniency for its own sake: RFC 7233 says a recipient that cannot understand a Range header
    MUST ignore it. Rejecting instead would make a client that sends a header we do not parse
    unable to download at all, which is a worse failure than sending it more bytes than it asked
    for.

    Deliberately not supported, and ignored rather than half-served:

    * **Multiple ranges.** Answering them means a `multipart/byteranges` body. Serving only the
      first range while reporting `206` would be a lie a client cannot detect -- it would assemble
      the parts it asked for out of bytes it did not get -- so the whole representation is safer.
    * **Anything but `bytes`.** No other unit is registered here, and an unknown unit is exactly
      the case the ignore rule exists for.

    A suffix range (`bytes=-500`, meaning the last 500 bytes) IS supported, and clamps: asking for
    more than exists yields the whole representation as a range rather than an error.
    """
    if not header or total_length < 0:
        return None

    text = header.strip()
    if "=" not in text:
        return None
    unit, _, spec = text.partition("=")
    if unit.strip().lower() != "bytes":
        return None

    spec = spec.strip()
    if "," in spec:
        return None
    if "-" not in spec:
        return None

    first, _, last = spec.partition("-")
    first, last = first.strip(), last.strip()

    # A zero-length representation can satisfy no range at all. Handled before the arithmetic
    # because `total_length - 1` would otherwise name byte -1 as the last one.
    if total_length == 0:
        return UNSATISFIABLE

    if not first:
        # Suffix: the last N bytes. "bytes=-0" asks for the last nothing, which is unsatisfiable
        # rather than empty -- an empty 206 would claim to carry a range it does not.
        if not last.isdigit():
            return None
        want = int(last)
        if want == 0:
            return UNSATISFIABLE
        start = max(0, total_length - want)
        return ByteRange(start, total_length - 1, total_length)

    if not first.isdigit():
        return None
    start = int(first)
    if start >= total_length:
        return UNSATISFIABLE

    if not last:
        return ByteRange(start, total_length - 1, total_length)
    if not last.isdigit():
        return None
    end = int(last)
    if end < start:
        return None
    # Clamped, not refused: a client that asks past the end gets what exists, which is what the
    # reader underneath would have returned anyway.
    return ByteRange(start, min(end, total_length - 1), total_length)
