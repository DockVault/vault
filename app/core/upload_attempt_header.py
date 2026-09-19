"""The attempt token a zero-knowledge upload declares, checked against the bytes it actually sends.

A version-2 zero-knowledge file opens with a 28-byte header that travels in the clear::

    magic(4) 'DVZ2' | version(1) | purpose(1) | reserved(2) | chunk size(4) | attempt token(16)

The client declares that same token when it opens the upload session (``blob_id``), and the server
already refuses a resume that declares a different one. What it could not see was a client whose
DECLARED token and SEALED token had drifted apart -- one that re-minted on a resume, or passed the
value twice from two reads. Such a file uploads happily, completes, and can never be opened: the key
is derived from the token in the header, and every frame after a re-mint belongs to another key.

The server never interprets the token or holds a key; it only compares two values it was handed.
So this is an integrity check on a well-meaning client, not a boundary against a hostile one -- a
caller who wants to corrupt their own upload has easier ways.

Pure and dependency-free so both halves are testable without a request or a database.
"""
from __future__ import annotations

#: magic + version 2 + purpose 0x04 (content). Anything else is not a version-2 content header --
#: notably the legacy whole-file format, which opens with a random 12-byte IV -- and is not checked.
V2_CONTENT_PREFIX = b"DVZ2\x02\x04"
V2_CONTENT_HEADER_BYTES = 28
_TOKEN = slice(12, 28)


def header_token_mismatch(head: bytes, declared_blob_id) -> bool:
    """True when ``head`` opens a version-2 content file whose token is NOT ``declared_blob_id``.

    ``head`` is the first bytes of transport chunk 0 (up to 28). A session that declared a token
    must deliver a chunk 0 of at least 28 bytes, WHATEVER it starts with: a first chunk of one to
    five bytes cannot even be told apart from "some other format", and the rest of the header would
    then ride in chunk 1, which is never looked at -- on disk the first 28 bytes would be a valid
    header carrying a token the session never declared. Both real writers clear that bar: the
    smallest version-2 file is 56 bytes, and the smallest legacy body is a 12-byte nonce plus a
    16-byte tag, exactly 28.

    Past that, a body that does not start with the version-2 content prefix is some other format
    and is left alone (the legacy format opens with a random nonce).
    """
    if not declared_blob_id:
        return False
    if len(head) < V2_CONTENT_HEADER_BYTES:
        return True
    if head[:len(V2_CONTENT_PREFIX)] != V2_CONTENT_PREFIX:
        return False
    try:
        declared = bytes.fromhex(declared_blob_id)
    except (TypeError, ValueError):
        return True
    return bytes(head[_TOKEN]) != declared


class HeadPeek:
    """Pass a byte stream through untouched while keeping a copy of its first ``n`` bytes.

    The chunk body is streamed straight to sealed staging and is never held whole, so the header
    has to be captured in passing rather than read back afterwards.
    """

    def __init__(self, stream, n: int = V2_CONTENT_HEADER_BYTES):
        self._stream = stream
        self._n = n
        self.head = bytearray()

    async def __aiter__(self):
        async for piece in self._stream:
            if len(self.head) < self._n and piece:
                self.head.extend(piece[:self._n - len(self.head)])
            yield piece
